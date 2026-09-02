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

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::SqlitePool;

use crate::error::{CoreError, CoreResult};

/// Tuple shape returned by `sqlx::query_as` for
/// `SELECT id, occurred_at, actor, action, target,
/// outcome, details FROM audit_log`. The seven fields
/// map 1:1 to [`AuditLogRow`].
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

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    Ok,
    Error,
}

impl AuditOutcome {
    fn as_str(self) -> &'static str {
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
}

impl AuditLogRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Append one audit row. `occurred_at` is recorded as
    /// `now` (ISO 8601 millis, UTC) — the 2.0.0 server
    /// always uses server-side time so HTTP clients cannot
    /// skew the timeline.
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
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO audit_log (occurred_at, actor, action, target, outcome, details) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) RETURNING id",
        )
        .bind(occurred_at)
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(outcome_str)
        .bind(details)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
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

#[cfg(test)]
#[path = "audit_log_repository_tests.rs"]
mod tests;
