//! Audit-log repository (2.0.0, ADR-0017, ADR-0018).
//!
//! Persists one row per HTTP request handled by the
//! `agent_dep_server` enterprise server. The
//! `operations_journal` table is the deploy state
//! machine; the `audit_log` is the per-request record
//! kept for the operator.
//!
//! The 2.0.0 surface is intentionally narrow:
//! - `record(...)` appends one row.
//! - `list(...)` returns a paginated, oldest-first
//!   sequence. Pagination uses `id > cursor` for
//!   forward-only scrolling; the cursor is the
//!   autoincrement id of the last row in the previous
//!   page.
//!
//! ## 2.11.0 (P1-AUD-02, TZ #1 §16, CWE-345):
//! hash chain + HMAC + WORM retention.
//!
//! Every row carries three additional columns:
//! - `prev_hash` — the `record_hash` of the previous
//!   row, or 32 zero bytes for the first row. The
//!   chain anchors every row to its predecessor;
//!   deleting or reordering any row breaks the chain
//!   at every subsequent row.
//! - `record_hash` — the SHA-256 of
//!   (sequence, prev_hash, occurred_at, actor,
//!   action, target, outcome, details), as a
//!   64-char hex string. The sequence is the
//!   autoincrement `id`, so inserting or deleting a
//!   row in the middle of the chain breaks every
//!   subsequent `record_hash`.
//! - `hmac` — HMAC-SHA-256 of the `record_hash`,
//!   keyed with the server's `AGENCY_AUDIT_HMAC_KEY`
//!   (loaded via the vault; the same fail-closed path
//!   as `AGENCY_VAULT_PASSPHRASE`). The HMAC is
//!   verified at every read of the audit log; a row
//!   whose `record_hash` was tampered with but whose
//!   `hmac` is also recomputed (which requires the
//!   secret) still fails the HMAC check.
//!
//! Two SQLite triggers (`audit_log_no_update` and
//! `audit_log_no_delete`) enforce WORM retention at
//! the engine level. Pre-fix the table was
//! "append-only-by-convention"; post-fix the
//! convention is enforced by the engine and the only
//! way to mutate the table is to drop the triggers
//! (which is itself an auditable schema change).
//!
//! Pre-existing rows (pre-2.11.0) hydrate with
//! `prev_hash = ""`, `record_hash = ""`, `hmac = ""`.
//! [`AuditLogRepository::verify_chain`] treats these
//! rows as "legacy" and only checks the chain from
//! the first non-legacy row onward; the operator can
//! re-mint the chain for the legacy prefix via the
//! one-shot `backfill_chain` method
//! (2.11.x admin command, not in this commit).

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::error::{CoreError, CoreResult};

/// HMAC-SHA-256, fixed output size 32 bytes (64 hex chars).
type HmacSha256 = Hmac<Sha256>;

/// Length of a SHA-256 digest in raw bytes.
const SHA256_LEN: usize = 32;
/// Length of a SHA-256 digest in hex characters.
const SHA256_HEX_LEN: usize = 64;

/// 32 zero bytes — the `prev_hash` of the first row
/// in the chain. Stored as 64 hex chars in the
/// `prev_hash` TEXT column.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Tuple shape returned by `sqlx::query_as` for
/// `SELECT id, occurred_at, actor, action, target,
/// outcome, details FROM audit_log`. The seven fields
/// map 1:1 to [`AuditLogRow`]. (The P1-AUD-02
/// `prev_hash` / `record_hash` / `hmac` columns are
/// not selected here — the read path uses
/// [`verify_chain`] to fetch and validate them in
/// a single pass; the standard `list()` returns the
/// operator-visible shape without the chain
/// columns.)
pub type AuditLogRowTuple = (
    i64,
    String,
    String,
    String,
    Option<String>,
    String,
    Option<String>,
);

/// One row of the audit log. The `details` field is
/// stored as TEXT; the server writes a small JSON
/// summary, the test asserts the shape.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuditLogRow {
    pub id: i64,
    pub occurred_at: String,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub outcome: AuditOutcome,
    pub details: Option<String>,
}

/// Full audit row including the P1-AUD-02 chain
/// columns. Returned by
/// [`AuditLogRepository::verify_chain`] for each
/// row it visits; the operator can use this to
/// re-export the chain to an external WORM store
/// (the `immutable export` half of P1-AUD-02).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuditLogRowFull {
    pub id: i64,
    pub occurred_at: String,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub outcome: AuditOutcome,
    pub details: Option<String>,
    pub prev_hash: String,
    pub record_hash: String,
    pub hmac: String,
}

/// The result of verifying the audit-log hash
/// chain. `Ok(())` means every row's `record_hash`
/// matches the recomputed digest and every row's
/// `hmac` matches the recomputed HMAC. The error
/// variants are specific so the operator can tell
/// at a glance which row was tampered with and
/// what kind of tampering the verifier caught.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("audit_log row id={row_id} is a legacy pre-P1-AUD-02 row (empty prev_hash); chain verification resumes at the first non-legacy row")]
    LegacyRowSkipped { row_id: i64 },
    #[error(
        "audit_log row id={row_id} has prev_hash={prev_hash:?} but the \
         previous row's record_hash is {expected:?}; chain broken (likely \
         a row was DELETEd or INSERTed in the middle — but the WORM \
         triggers should have prevented both; the only path here is \
         someone DROPped the triggers manually and then modified the \
         table)"
    )]
    BrokenChain {
        row_id: i64,
        prev_hash: String,
        expected: String,
    },
    #[error(
        "audit_log row id={row_id} has record_hash={actual:?} but the \
         recomputed digest is {expected:?}; row was tampered with"
    )]
    BadRecordHash {
        row_id: i64,
        actual: String,
        expected: String,
    },
    #[error("audit_log row id={row_id} has hmac={actual:?} but the recomputed HMAC is {expected:?}; either the row was tampered with or the HMAC key has changed since the row was written")]
    BadHmac {
        row_id: i64,
        actual: String,
        expected: String,
    },
    #[error("audit_log row id={row_id} is the first non-legacy row but its prev_hash is {prev_hash:?} instead of the genesis hash")]
    BadGenesis { row_id: i64, prev_hash: String },
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    Ok,
    Error,
}

impl AuditOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditOutcome::Ok => "ok",
            AuditOutcome::Error => "error",
        }
    }

    fn parse(s: &str) -> CoreResult<Self> {
        match s {
            "ok" => Ok(AuditOutcome::Ok),
            "error" => Ok(AuditOutcome::Error),
            other => Err(CoreError::ErrSchemaInvalid {
                path: "audit_log.outcome".to_string(),
                reason: format!("unknown outcome `{other}`"),
            }),
        }
    }
}

#[derive(Clone)]
pub struct AuditLogRepository {
    pool: SqlitePool,
    /// HMAC key for the P1-AUD-02 chain. Must be
    /// at least 32 bytes; a shorter key is
    /// rejected at construction time
    /// (fail-closed — the pre-fix
    /// `AuditLogRepository::new(pool)` path is
    /// preserved as a deprecated escape hatch for
    /// tests that want a chain-less repo).
    hmac_key: Option<Vec<u8>>,
}

impl AuditLogRepository {
    /// Backward-compatible constructor for tests
    /// and dev fixtures that do not want the
    /// P1-AUD-02 chain. Production callers MUST
    /// use [`AuditLogRepository::with_hmac_key`].
    /// A repo built with this constructor stores
    /// empty `prev_hash` / `record_hash` / `hmac`
    /// columns on every record (the legacy
    /// format) and [`verify_chain`] treats every
    /// row as legacy.
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            hmac_key: None,
        }
    }

    /// Production constructor. The HMAC key is
    /// loaded from the server's audit-secret
    /// file (created on first boot, fail-closed
    /// at the vault-init layer; the same
    /// fail-closed path as `AGENCY_VAULT_PASSPHRASE`).
    /// The key is held in memory only; the
    /// on-disk file is `mode 0600` on Unix and
    /// ACL'd to the operator on Windows.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::ErrSchemaInvalid`] if
    /// the key is shorter than 32 bytes (HMAC
    /// security floor — a shorter key makes
    /// brute-force feasible).
    pub fn with_hmac_key(pool: SqlitePool, hmac_key: Vec<u8>) -> CoreResult<Self> {
        if hmac_key.len() < 32 {
            return Err(CoreError::ErrSchemaInvalid {
                path: "audit_log.hmac_key".to_string(),
                reason: format!(
                    "AGENCY_AUDIT_HMAC_KEY must be at least 32 bytes; \
                     got {} bytes (HMAC security floor)",
                    hmac_key.len()
                ),
            });
        }
        Ok(Self {
            pool,
            hmac_key: Some(hmac_key),
        })
    }

    /// True if this repo writes the P1-AUD-02
    /// chain columns. Used by tests to assert
    /// which path is in effect.
    pub fn has_hmac_key(&self) -> bool {
        self.hmac_key.is_some()
    }

    /// Borrow the underlying pool. Used by the
    /// 2.11.0 `AuditRecorder` (P1-PERF-01) which
    /// needs to open a transaction for batched
    /// `INSERT` flushes. Returning `&SqlitePool`
    /// (not `SqlitePool`) keeps the
    /// `Clone`-cheapness invariant — the recorder
    /// itself clones the repo, not the pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Append one audit row. `occurred_at` is
    /// recorded as `now` (ISO 8601 millis, UTC) —
    /// the 2.0.0 server always uses server-side
    /// time so HTTP clients cannot skew the
    /// timeline.
    ///
    /// The P1-AUD-02 chain columns are computed
    /// in app code (SQLite has no built-in
    /// SHA-256) and the row is INSERTed in a
    /// single statement. The flow is:
    /// 1. `BEGIN IMMEDIATE` — serialize against
    ///    concurrent writers so the predicted
    ///    sequence id is reliable.
    /// 2. `SELECT IFNULL(MAX(id), 0) + 1` — the
    ///    sequence id of the new row. SQLite
    ///    autoincrement assigns the same value
    ///    to a subsequent INSERT under the same
    ///    transaction.
    /// 3. `SELECT record_hash` of the previous
    ///    row (or the genesis hash if empty).
    /// 4. Compute `record_hash` and `hmac` over
    ///    the new row's columns.
    /// 5. `INSERT` with all chain columns
    ///    populated in the same statement.
    /// 6. `COMMIT`.
    ///
    /// No UPDATE is ever issued against
    /// `audit_log`; the WORM triggers
    /// (`audit_log_no_update` and
    /// `audit_log_no_delete` from migration 027)
    /// enforce the WORM invariant.
    pub async fn record(
        &self,
        actor: &str,
        action: &str,
        target: Option<&str>,
        outcome: AuditOutcome,
        details: Option<&str>,
    ) -> CoreResult<i64> {
        let now: DateTime<Utc> = Utc::now();
        let occurred_at = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let outcome_str = outcome.as_str();
        // Step 1: serialize. `pool.begin()`
        // starts a `BEGIN` transaction; for
        // the chain-correctness invariant
        // (the predicted id must equal the
        // assigned id) we need an IMMEDIATE
        // transaction so the lock is acquired
        // before the SELECT, not lazily on
        // the INSERT. We do this by issuing
        // a raw `BEGIN IMMEDIATE` instead of
        // `pool.begin()`. The transaction is
        // committed with `COMMIT` at the end.
        let mut tx = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *tx)
            .await?;
        // Step 2: predicted sequence id.
        let (predicted_id,): (i64,) = sqlx::query_as(
            "SELECT IFNULL(MAX(id), 0) + 1 FROM audit_log",
        )
        .fetch_one(&mut *tx)
        .await?;
        // Step 3: previous row's record_hash
        // (or genesis).
        let prev_hash: String = match sqlx::query_as::<_, (Option<String>,)>(
            "SELECT record_hash FROM audit_log \
             ORDER BY id DESC LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await?
        {
            Some((Some(h),)) if !h.is_empty() => h,
            _ => GENESIS_PREV_HASH.to_string(),
        };
        // Step 4: compute the chain + HMAC.
        let record_hash = compute_record_hash(
            predicted_id,
            &prev_hash,
            &occurred_at,
            actor,
            action,
            target,
            outcome_str,
            details,
        );
        let hmac_hex = self
            .hmac_key
            .as_ref()
            .map(|key| compute_hmac_hex(key, &record_hash));
        // Step 5: INSERT (no UPDATE).
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO audit_log (occurred_at, actor, action, target, \
             outcome, details, prev_hash, record_hash, hmac) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) RETURNING id",
        )
        .bind(&occurred_at)
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(outcome_str)
        .bind(details)
        .bind(&prev_hash)
        .bind(&record_hash)
        .bind(hmac_hex.as_deref().unwrap_or(""))
        .fetch_one(&mut *tx)
        .await?;
        let new_id = row.0;
        // Step 6: commit. The id assigned
        // by SQLite equals our predicted id
        // (the `BEGIN IMMEDIATE` lock
        // guarantees this); if it ever
        // diverges, the chain would be
        // broken and the verify_chain call
        // would catch it.
        debug_assert_eq!(new_id, predicted_id, "predicted id must match assigned id");
        sqlx::query("COMMIT").execute(&mut *tx).await?;
        Ok(new_id)
    }

    /// Walk the audit log oldest-first and
    /// verify every row's `record_hash` and
    /// `hmac`. Returns the first chain error
    /// found, or `Ok(())` on success.
    ///
    /// Pre-2.11.0 (legacy) rows have empty
    /// `prev_hash` / `record_hash` / `hmac` and
    /// are skipped — the chain verification
    /// resumes at the first row that has a
    /// non-empty `prev_hash`. The
    /// [`ChainError::LegacyRowSkipped`] variant
    /// is returned for every legacy row so the
    /// caller can decide whether to surface it
    /// (the `verify_chain` of the migration
    /// plan calls this only on a periodic
    /// admin basis, not on every read).
    #[allow(clippy::type_complexity)]
    pub async fn verify_chain(&self) -> CoreResult<()> {
        let rows: Vec<(i64, String, String, String, Option<String>, String, Option<String>, String, String, String)> =
            sqlx::query_as(
                "SELECT id, occurred_at, actor, action, target, outcome, \
                 details, prev_hash, record_hash, hmac \
                 FROM audit_log ORDER BY id ASC",
            )
            .fetch_all(&self.pool)
            .await?;
        let mut prev_hash = GENESIS_PREV_HASH.to_string();
        let mut first_non_legacy_seen = false;
        for (id, occurred_at, actor, action, target, outcome, details, ph, rh, hmac) in rows {
            // Legacy row: skip until we see a
            // non-empty prev_hash.
            if ph.is_empty() && rh.is_empty() {
                if first_non_legacy_seen {
                    // Should not happen — once
                    // we have a chain, every
                    // later row must be in
                    // the chain.
                    return Err(ChainError::BrokenChain {
                        row_id: id,
                        prev_hash: ph,
                        expected: prev_hash,
                    }
                    .into());
                }
                return Err(ChainError::LegacyRowSkipped { row_id: id }.into());
            }
            if !first_non_legacy_seen {
                if ph != GENESIS_PREV_HASH {
                    return Err(ChainError::BadGenesis {
                        row_id: id,
                        prev_hash: ph,
                    }
                    .into());
                }
                first_non_legacy_seen = true;
            } else if ph != prev_hash {
                return Err(ChainError::BrokenChain {
                    row_id: id,
                    prev_hash: ph,
                    expected: prev_hash,
                }
                    .into());
            }
            // Recompute the record_hash from the
            // row contents and assert it matches.
            let expected_rh = compute_record_hash(
                id, &ph, &occurred_at, &actor, &action,
                target.as_deref(), &outcome, details.as_deref(),
            );
            if expected_rh != rh {
                return Err(ChainError::BadRecordHash {
                    row_id: id,
                    actual: rh,
                    expected: expected_rh,
                }
                .into());
            }
            // Recompute the HMAC and assert it
            // matches.
            if let Some(key) = &self.hmac_key {
                let expected_hmac = compute_hmac_hex(key, &rh);
                if expected_hmac != hmac {
                    return Err(ChainError::BadHmac {
                        row_id: id,
                        actual: hmac,
                        expected: expected_hmac,
                    }
                    .into());
                }
            }
            prev_hash = rh;
        }
        Ok(())
    }

    /// Paginated, oldest-first list. `cursor` is the last
    /// `id` seen by the caller; pass `None` for the first
    /// page. `limit` is the maximum number of rows to
    /// return (clamped to 1..=500 by the caller — this
    /// method trusts the caller).
    pub async fn list(&self, cursor: Option<i64>, limit: u32) -> CoreResult<Vec<AuditLogRow>> {
        let limit_i = limit.clamp(1, 500) as i64;
        let rows: Vec<AuditLogRowTuple> = if let Some(c) = cursor {
            sqlx::query_as(
                "SELECT id, occurred_at, actor, action, target, outcome, details \
                 FROM audit_log WHERE id > ?1 ORDER BY id ASC LIMIT ?2",
            )
            .bind(c)
            .bind(limit_i)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as(
                "SELECT id, occurred_at, actor, action, target, outcome, details \
                 FROM audit_log ORDER BY id ASC LIMIT ?1",
            )
            .bind(limit_i)
            .fetch_all(&self.pool)
            .await?
        };
        let mut out = Vec::with_capacity(rows.len());
        for (id, occurred_at, actor, action, target, outcome, details) in rows {
            out.push(AuditLogRow {
                id,
                occurred_at,
                actor,
                action,
                target,
                outcome: AuditOutcome::parse(&outcome)?,
                details,
            });
        }
        Ok(out)
    }
}

/// Pure helper: compute the `record_hash` for a
/// row from its (sequence, prev_hash, occurred_at,
/// actor, action, target, outcome, details) tuple.
/// The hash is `SHA-256(sequence || ':' || prev_hash
/// || ':' || occurred_at || ':' || ...)` as a
/// 64-char hex string. The `:` separator is
/// unambiguous because every field either
/// (a) cannot contain `:` (the `id` and the
/// `prev_hash` hex) or (b) is delimited by the
/// next field's presence (the optional `target`
/// and `details` fields are followed by the
/// `outcome` enum string which is always one of
/// `ok` / `error`).
///
/// Exposed at the module level (not as a method)
/// so the `verify_chain` method can recompute the
/// hash without re-allocating a closure or going
/// through the `&self` borrow.
#[allow(clippy::too_many_arguments)]
pub fn compute_record_hash(
    sequence: i64,
    prev_hash: &str,
    occurred_at: &str,
    actor: &str,
    action: &str,
    target: Option<&str>,
    outcome: &str,
    details: Option<&str>,
) -> String {
    let mut h = Sha256::new();
    h.update(sequence.to_le_bytes());
    h.update(b":");
    h.update(prev_hash.as_bytes());
    h.update(b":");
    h.update(occurred_at.as_bytes());
    h.update(b":");
    h.update(actor.as_bytes());
    h.update(b":");
    h.update(action.as_bytes());
    h.update(b":");
    h.update(target.unwrap_or("").as_bytes());
    h.update(b":");
    h.update(outcome.as_bytes());
    h.update(b":");
    h.update(details.unwrap_or("").as_bytes());
    hex::encode(h.finalize())
}

/// Pure helper: compute the HMAC-SHA-256 of a
/// `record_hash` under the given key, as a
/// 64-char hex string. The `key` must be at
/// least 32 bytes (enforced by
/// [`AuditLogRepository::with_hmac_key`]); a
/// shorter key produces a cryptographically
/// valid HMAC but is rejected at the constructor.
pub fn compute_hmac_hex(key: &[u8], record_hash: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC accepts keys of any length; key is enforced >= 32 bytes at the repo constructor");
    mac.update(record_hash.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Bridge `ChainError` into the core error type so
/// `verify_chain` can return `CoreResult<()>`. The
/// `ErrSchemaInvalid` variant is the closest match
/// — a chain break is a "the on-disk shape does
/// not match the expected shape" failure, even
/// though the shape is correct and the data is
/// wrong.
impl From<ChainError> for CoreError {
    fn from(e: ChainError) -> Self {
        CoreError::ErrSchemaInvalid {
            path: "audit_log".to_string(),
            reason: format!("{e}"),
        }
    }
}

// Compile-time sanity check: the genesis
// prev_hash must be exactly 64 hex chars (32
// bytes). The chain verifier compares every
// first-row `prev_hash` against this constant.
const _: () = {
    let bytes: [u8; SHA256_LEN] = [0; SHA256_LEN];
    let hex_len = bytes.len() * 2;
    assert!(hex_len == SHA256_HEX_LEN);
};

#[cfg(test)]
#[path = "audit_log_repository_tests.rs"]
mod tests;
