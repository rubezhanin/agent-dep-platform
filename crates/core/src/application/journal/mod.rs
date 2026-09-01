//! Recovery journal (TZ §17.3 / §18 + ADR-0006).
//!
//! Every state-changing operation goes through this journal before
//! the mutation touches the filesystem and again after it
//! completes. The journal row is the single source of truth for
//! "what was I doing last time the app died" — recovery is purely a
//! function of the rows in this table plus the filesystem state.
//!
//! State machine (per ADR-0006):
//!
//! ```text
//!   (nothing) --prepare--> prepared
//!     prepared --begin-writing--> writing
//!     writing --begin-committing--> committing
//!     committing --complete--> committed
//!     committing --fail--> failed
//!     committed --rollback--> rolled_back
//!     prepared | writing --rollback--> rolled_back
//! ```
//!
//! All transitions are enforced by `JournalService::transition`.
//! Terminal statuses (`committed`, `rolled_back`, `failed`) accept
//! no further transitions; the journal is then read-only history.

use chrono::{DateTime, Utc};
use serde_json::Value as Json;
use sqlx::SqlitePool;
use std::str::FromStr;
use uuid::Uuid;

use crate::error::{CoreError, CoreResult};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Maximum size of `effect_json` per operation, in bytes. ADR-0006
/// caps at 1 MB. Larger effects must be split (1.x: stream to
/// separate file; MVP: caller must trim).
pub const MAX_EFFECT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationType {
    Deploy,
    Rollback,
    Plan,
    Audit,
}

impl OperationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Deploy => "deploy",
            Self::Rollback => "rollback",
            Self::Plan => "plan",
            Self::Audit => "audit",
        }
    }

    pub fn parse(s: &str) -> CoreResult<Self> {
        Ok(match s {
            "deploy" => Self::Deploy,
            "rollback" => Self::Rollback,
            "plan" => Self::Plan,
            "audit" => Self::Audit,
            other => {
                return Err(CoreError::ErrSchemaInvalid {
                    path: "operations.type".to_string(),
                    reason: format!("unknown type: {other}"),
                })
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OperationStatus {
    Prepared,
    Writing,
    Committing,
    Committed,
    RolledBack,
    Failed,
}

impl OperationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Writing => "writing",
            Self::Committing => "committing",
            Self::Committed => "committed",
            Self::RolledBack => "rolled_back",
            Self::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> CoreResult<Self> {
        Ok(match s {
            "prepared" => Self::Prepared,
            "writing" => Self::Writing,
            "committing" => Self::Committing,
            "committed" => Self::Committed,
            "rolled_back" => Self::RolledBack,
            "failed" => Self::Failed,
            other => {
                return Err(CoreError::ErrSchemaInvalid {
                    path: "operations.status".to_string(),
                    reason: format!("unknown status: {other}"),
                })
            }
        })
    }

    /// `true` for `prepared` / `writing` / `committing`. These are
    /// the rows the recovery process picks up.
    pub fn is_non_terminal(&self) -> bool {
        matches!(self, Self::Prepared | Self::Writing | Self::Committing)
    }

    /// `true` for `committed` / `rolled_back` / `failed`. These are
    /// history and never re-touched by recovery.
    pub fn is_terminal(&self) -> bool {
        !self.is_non_terminal()
    }
}

#[derive(Debug, Clone)]
pub struct Operation {
    pub id: Uuid,
    pub op_type: OperationType,
    pub status: OperationStatus,
    pub plan_hash: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub effect: Json,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

pub struct JournalService {
    pool: SqlitePool,
}

type OpRow = (
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    Option<String>,
);

impl JournalService {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create a new operation in `prepared` status. The `effect`
    /// JSON is snapshotted at this point so recovery can resume
    /// without re-reading external state (per ADR-0006).
    pub async fn prepare(
        &self,
        op_type: OperationType,
        plan_hash: &str,
        effect: Json,
    ) -> CoreResult<Operation> {
        if plan_hash.is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "operations.plan_hash".to_string(),
                reason: "plan_hash must not be empty".to_string(),
            });
        }
        let effect_text = serialize_effect(&effect)?;

        let id = Uuid::new_v4();
        let started_at = Utc::now();
        let id_str = id.to_string();
        let started_at_str = iso8601(started_at);
        let type_str = op_type.as_str();

        sqlx::query(
            "INSERT INTO operations (operation_id, type, status, plan_hash, \
             started_at, effect_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(&id_str)
        .bind(type_str)
        .bind(OperationStatus::Prepared.as_str())
        .bind(plan_hash)
        .bind(&started_at_str)
        .bind(&effect_text)
        .execute(&self.pool)
        .await?;

        Ok(Operation {
            id,
            op_type,
            status: OperationStatus::Prepared,
            plan_hash: plan_hash.to_string(),
            started_at,
            finished_at: None,
            effect,
            error: None,
        })
    }

    /// Read a single operation by id.
    pub async fn get(&self, op_id: Uuid) -> CoreResult<Option<Operation>> {
        let row: Option<OpRow> = sqlx::query_as(
            "SELECT operation_id, type, status, plan_hash, started_at, \
             finished_at, effect_json, error FROM operations WHERE operation_id = ?1",
        )
        .bind(op_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_op).transpose()
    }

    /// All non-terminal operations, oldest first. Used by recovery.
    pub async fn list_non_terminal(&self) -> CoreResult<Vec<Operation>> {
        let rows: Vec<OpRow> = sqlx::query_as(
            "SELECT operation_id, type, status, plan_hash, started_at, \
             finished_at, effect_json, error FROM operations \
             WHERE status IN ('prepared','writing','committing') \
             ORDER BY started_at ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_op).collect()
    }

    /// `prepared -> writing`. The first time the operation actually
    /// touches the filesystem.
    pub async fn begin_writing(&self, op_id: Uuid) -> CoreResult<()> {
        self.transition(op_id, OperationStatus::Writing, None).await
    }

    /// `writing -> committing`. The mutation phase is over; the
    /// journal is about to flip to `committed`.
    pub async fn begin_committing(&self, op_id: Uuid) -> CoreResult<()> {
        self.transition(op_id, OperationStatus::Committing, None)
            .await
    }

    /// `committing -> committed`. The mutation is on disk and
    /// verified. Sets `finished_at`.
    pub async fn complete(&self, op_id: Uuid) -> CoreResult<()> {
        self.transition(op_id, OperationStatus::Committed, None)
            .await
    }

    /// `* (non-terminal or committed) -> rolled_back`. Sets
    /// `finished_at`. Used by the rollback command and by recovery
    /// when the operation never reached the committed state.
    pub async fn rollback(&self, op_id: Uuid) -> CoreResult<()> {
        self.transition(op_id, OperationStatus::RolledBack, None)
            .await
    }

    /// `* (non-terminal) -> failed`. Sets `finished_at` and the
    /// `error` column. Terminal. Failures are not retried by
    /// recovery (per ADR-0006).
    pub async fn fail(&self, op_id: Uuid, error: &str) -> CoreResult<()> {
        self.transition(op_id, OperationStatus::Failed, Some(error.to_string()))
            .await
    }

    /// Force-fail any non-terminal operation older than the most
    /// recent `keep` non-terminal ones. Returns the number of rows
    /// marked `failed` with a synthetic "stale operation aborted"
    /// error. Per ADR-0006, the default `keep` is 100.
    pub async fn gc_stale(&self, keep: u32) -> CoreResult<u32> {
        let mut tx = self.pool.begin().await?;
        // Select IDs of non-terminal ops beyond the keep window.
        let stale: Vec<(String,)> = sqlx::query_as(
            "SELECT operation_id FROM operations \
             WHERE status IN ('prepared','writing','committing') \
             ORDER BY started_at DESC \
             LIMIT -1 OFFSET ?1",
        )
        .bind(keep as i64)
        .fetch_all(&mut *tx)
        .await?;
        if stale.is_empty() {
            tx.commit().await?;
            return Ok(0);
        }
        let now = iso8601(Utc::now());
        let mut count = 0u32;
        for (id,) in &stale {
            let n = sqlx::query(
                "UPDATE operations SET status = 'failed', finished_at = ?1, \
                 error = COALESCE(error, '') || 'stale operation aborted at startup' \
                 WHERE operation_id = ?2 AND status IN ('prepared','writing','committing')",
            )
            .bind(&now)
            .bind(id)
            .execute(&mut *tx)
            .await?;
            count += n.rows_affected() as u32;
        }
        tx.commit().await?;
        Ok(count)
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    async fn transition(
        &self,
        op_id: Uuid,
        to: OperationStatus,
        error: Option<String>,
    ) -> CoreResult<()> {
        // Read current state to enforce the machine.
        let current = self
            .get(op_id)
            .await?
            .ok_or_else(|| CoreError::ErrSchemaInvalid {
                path: "operations.operation_id".to_string(),
                reason: format!("operation {} not found", op_id),
            })?;

        if !is_valid_transition(current.status, to) {
            return Err(CoreError::ErrSchemaInvalid {
                path: "operations.status".to_string(),
                reason: format!(
                    "invalid transition for {}: {:?} -> {:?}",
                    op_id, current.status, to
                ),
            });
        }

        let now = Utc::now();
        let now_str = iso8601(now);

        if matches!(to, OperationStatus::Failed) {
            sqlx::query(
                "UPDATE operations SET status = ?1, finished_at = ?2, error = ?3 \
                 WHERE operation_id = ?4",
            )
            .bind(to.as_str())
            .bind(&now_str)
            .bind(error.as_deref().unwrap_or(""))
            .bind(op_id.to_string())
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query(
                "UPDATE operations SET status = ?1, finished_at = ?2 \
                 WHERE operation_id = ?3",
            )
            .bind(to.as_str())
            // Only stamp finished_at for terminal states; mid-flight
            // transitions (prepared -> writing) don't get one.
            .bind(if to.is_terminal() {
                Some(&now_str)
            } else {
                None
            })
            .bind(op_id.to_string())
            .execute(&self.pool)
            .await?;
        }
        let _ = now;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// Returns `true` if `from -> to` is a legal transition.
///
/// - `Prepared -> Writing`
/// - `Writing -> Committing`
/// - `Committing -> Committed | Failed`
/// - `Committed -> RolledBack` (explicit rollback command)
/// - `Prepared | Writing -> RolledBack` (recovery: nothing or partial)
/// - `* (non-terminal) -> Failed` (catch-all error)
fn is_valid_transition(from: OperationStatus, to: OperationStatus) -> bool {
    use OperationStatus::*;
    match (from, to) {
        (Prepared, Writing) => true,
        (Writing, Committing) => true,
        (Committing, Committed) => true,
        (Committed, RolledBack) => true,
        (Prepared, RolledBack) => true,
        (Writing, RolledBack) => true,
        // Catch-all: any non-terminal -> Failed (per ADR-0006 the
        // journal may fail at any open state). Committed /
        // RolledBack / Failed are terminal and not re-entered.
        (Prepared | Writing | Committing, Failed) => true,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Row helpers
// ---------------------------------------------------------------------------

fn row_to_op(row: OpRow) -> CoreResult<Operation> {
    let (id, ty, status, plan_hash, started_at, finished_at, effect_json, error) = row;
    let id = Uuid::parse_str(&id).map_err(|e| CoreError::ErrSchemaInvalid {
        path: "operations.operation_id".to_string(),
        reason: format!("bad UUID: {e}"),
    })?;
    let op_type = OperationType::parse(&ty)?;
    let status = OperationStatus::parse(&status)?;
    let started_at = parse_iso8601(&started_at)?;
    let finished_at = match finished_at {
        Some(s) => Some(parse_iso8601(&s)?),
        None => None,
    };
    let effect: Json =
        serde_json::from_str(&effect_json).map_err(|e| CoreError::ErrSchemaInvalid {
            path: "operations.effect_json".to_string(),
            reason: format!("bad JSON: {e}"),
        })?;
    Ok(Operation {
        id,
        op_type,
        status,
        plan_hash,
        started_at,
        finished_at,
        effect,
        error,
    })
}

fn iso8601(dt: DateTime<Utc>) -> String {
    // Millisecond precision so back-to-back ops in the same test
    // (or quick CLI runs) don't share a timestamp and make
    // ORDER BY started_at non-deterministic. ADR-0006 says the
    // journal is local; the slight loss of human readability is
    // acceptable.
    dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn parse_iso8601(s: &str) -> CoreResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| CoreError::ErrSchemaInvalid {
            path: "timestamp".to_string(),
            reason: format!("bad ISO 8601: {e}"),
        })
}

fn serialize_effect(effect: &Json) -> CoreResult<String> {
    let text = serde_json::to_string(effect).map_err(|e| CoreError::ErrSchemaInvalid {
        path: "operations.effect_json".to_string(),
        reason: format!("effect is not serializable: {e}"),
    })?;
    if text.len() > MAX_EFFECT_BYTES {
        return Err(CoreError::ErrSchemaInvalid {
            path: "operations.effect_json".to_string(),
            reason: format!(
                "effect too large: {} bytes (cap {})",
                text.len(),
                MAX_EFFECT_BYTES
            ),
        });
    }
    Ok(text)
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod journal_tests;

// Allow `FromStr` for ergonomic call sites (unused in MVP but
// useful in tests and 1.x).
impl FromStr for OperationType {
    type Err = CoreError;
    fn from_str(s: &str) -> CoreResult<Self> {
        Self::parse(s)
    }
}
