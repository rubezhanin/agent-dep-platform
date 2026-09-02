//! 2.2.0 approvals workflow (ADR-0020).
//!
//! One row per `POST /v1/deploys` request. The row
//! stays in `pending` until an admin approves or
//! rejects it, then the operator reports back via
//! the `applied` transition.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::{CoreError, CoreResult};

/// 2.4.0 — the three supported environments. A
/// future 2.5.x may add a custom-environment
/// field; for 2.4.0 the enum is hard-coded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Dev,
    Staging,
    Production,
}

impl Environment {
    pub fn as_str(self) -> &'static str {
        match self {
            Environment::Dev => "dev",
            Environment::Staging => "staging",
            Environment::Production => "production",
        }
    }

    pub fn parse(s: &str) -> CoreResult<Self> {
        match s {
            "dev" => Ok(Environment::Dev),
            "staging" => Ok(Environment::Staging),
            "production" => Ok(Environment::Production),
            other => Err(CoreError::ErrSchemaInvalid {
                path: "environment".to_string(),
                reason: format!("unknown environment `{other}`"),
            }),
        }
    }

    /// All known environments, in the order the
    /// `GET /v1/environments` endpoint serves
    /// them.
    pub fn all() -> &'static [Environment] {
        &[
            Environment::Dev,
            Environment::Staging,
            Environment::Production,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pending,
    Approved,
    Rejected,
    Applied,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pending => "pending",
            Status::Approved => "approved",
            Status::Rejected => "rejected",
            Status::Applied => "applied",
        }
    }

    fn parse(s: &str) -> CoreResult<Self> {
        match s {
            "pending" => Ok(Status::Pending),
            "approved" => Ok(Status::Approved),
            "rejected" => Ok(Status::Rejected),
            "applied" => Ok(Status::Applied),
            other => Err(CoreError::ErrSchemaInvalid {
                path: "pending_deploys.status".to_string(),
                reason: format!("unknown status `{other}`"),
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingDeployRow {
    pub id: i64,
    pub system_id: String,
    pub plan_summary: String,
    pub requested_by: i64,
    pub requested_at: String,
    pub status: Status,
    pub environment: Environment,
    pub target_id: Option<i64>,
    pub approved_by: Option<i64>,
    pub approved_at: Option<String>,
    pub rejection_reason: Option<String>,
    pub applied_at: Option<String>,
}

#[derive(Clone)]
pub struct PendingDeployRepository {
    pool: SqlitePool,
}

impl PendingDeployRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert a new `pending` row. The plan summary
    /// is the JSON string the operator submitted (the
    /// server re-runs the plan to keep the
    /// `system_id` honest, so this is the fresh
    /// snapshot). `environment` defaults to `Dev` if
    /// not provided (2.4.0). `target_id` is optional
    /// (2.5.0): NULL means the deploy predates the
    /// fleet registry or the operator is using the
    /// legacy `--target <path>` CLI path.
    pub async fn request(
        &self,
        system_id: &str,
        plan_summary: &str,
        requested_by: i64,
        environment: Environment,
        target_id: Option<i64>,
    ) -> CoreResult<PendingDeployRow> {
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO pending_deploys \
             (system_id, plan_summary, requested_by, requested_at, status, \
              environment, target_id) \
             VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6) RETURNING id",
        )
        .bind(system_id)
        .bind(plan_summary)
        .bind(requested_by)
        .bind(&now_str)
        .bind(environment.as_str())
        .bind(target_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(PendingDeployRow {
            id: row.0,
            system_id: system_id.to_string(),
            plan_summary: plan_summary.to_string(),
            requested_by,
            requested_at: now_str,
            status: Status::Pending,
            environment,
            target_id,
            approved_by: None,
            approved_at: None,
            rejection_reason: None,
            applied_at: None,
        })
    }

    /// Read a single row by id.
    pub async fn get(&self, id: i64) -> CoreResult<Option<PendingDeployRow>> {
        let row: Option<PendingDeployRowTuple> = sqlx::query_as(
            "SELECT id, system_id, plan_summary, requested_by, requested_at, \
                    status, environment, target_id, approved_by, approved_at, \
                    rejection_reason, applied_at \
             FROM pending_deploys WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(decode_row).transpose()
    }

    /// List rows, oldest-first. `status_filter` and
    /// `environment_filter` are both optional.
    pub async fn list(
        &self,
        status_filter: Option<Status>,
        environment_filter: Option<Environment>,
        limit: u32,
    ) -> CoreResult<Vec<PendingDeployRow>> {
        let limit_i = limit.clamp(1, 500) as i64;
        let rows: Vec<PendingDeployRowTuple> = match (status_filter, environment_filter) {
            (None, None) => {
                sqlx::query_as(
                    "SELECT id, system_id, plan_summary, requested_by, requested_at, \
                        status, environment, target_id, approved_by, approved_at, \
                        rejection_reason, applied_at \
                 FROM pending_deploys ORDER BY id ASC LIMIT ?1",
                )
                .bind(limit_i)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(s), None) => {
                sqlx::query_as(
                    "SELECT id, system_id, plan_summary, requested_by, requested_at, \
                        status, environment, target_id, approved_by, approved_at, \
                        rejection_reason, applied_at \
                 FROM pending_deploys WHERE status = ?1 \
                 ORDER BY id ASC LIMIT ?2",
                )
                .bind(s.as_str())
                .bind(limit_i)
                .fetch_all(&self.pool)
                .await?
            }
            (None, Some(e)) => {
                sqlx::query_as(
                    "SELECT id, system_id, plan_summary, requested_by, requested_at, \
                        status, environment, target_id, approved_by, approved_at, \
                        rejection_reason, applied_at \
                 FROM pending_deploys WHERE environment = ?1 \
                 ORDER BY id ASC LIMIT ?2",
                )
                .bind(e.as_str())
                .bind(limit_i)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(s), Some(e)) => {
                sqlx::query_as(
                    "SELECT id, system_id, plan_summary, requested_by, requested_at, \
                        status, environment, target_id, approved_by, approved_at, \
                        rejection_reason, applied_at \
                 FROM pending_deploys WHERE status = ?1 AND environment = ?2 \
                 ORDER BY id ASC LIMIT ?3",
                )
                .bind(s.as_str())
                .bind(e.as_str())
                .bind(limit_i)
                .fetch_all(&self.pool)
                .await?
            }
        };
        rows.into_iter().map(decode_row).collect()
    }

    /// Flip `pending` → `approved`. Returns the new
    /// row, or `None` if the id does not exist OR is
    /// not in `pending` state.
    pub async fn approve(&self, id: i64, approved_by: i64) -> CoreResult<Option<PendingDeployRow>> {
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let affected = sqlx::query(
            "UPDATE pending_deploys \
             SET status = 'approved', approved_by = ?1, approved_at = ?2, \
                 rejection_reason = NULL \
             WHERE id = ?3 AND status = 'pending'",
        )
        .bind(approved_by)
        .bind(&now_str)
        .bind(id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if affected == 0 {
            return Ok(None);
        }
        self.get(id).await
    }

    /// Flip `pending` → `rejected`. Returns the new
    /// row, or `None` if the id does not exist OR is
    /// not in `pending` state.
    pub async fn reject(
        &self,
        id: i64,
        approved_by: i64,
        reason: Option<&str>,
    ) -> CoreResult<Option<PendingDeployRow>> {
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let affected = sqlx::query(
            "UPDATE pending_deploys \
             SET status = 'rejected', approved_by = ?1, approved_at = ?2, \
                 rejection_reason = ?3 \
             WHERE id = ?4 AND status = 'pending'",
        )
        .bind(approved_by)
        .bind(&now_str)
        .bind(reason)
        .bind(id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if affected == 0 {
            return Ok(None);
        }
        self.get(id).await
    }

    /// Flip `approved` → `applied`. The operator
    /// reports back after running the deploy locally.
    pub async fn mark_applied(&self, id: i64) -> CoreResult<Option<PendingDeployRow>> {
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let affected = sqlx::query(
            "UPDATE pending_deploys \
             SET status = 'applied', applied_at = ?1 \
             WHERE id = ?2 AND status = 'approved'",
        )
        .bind(&now_str)
        .bind(id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if affected == 0 {
            return Ok(None);
        }
        self.get(id).await
    }
}

type PendingDeployRowTuple = (
    i64,
    String,
    String,
    i64,
    String,
    String,
    String,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn decode_row(row: PendingDeployRowTuple) -> CoreResult<PendingDeployRow> {
    let (
        id,
        system_id,
        plan_summary,
        requested_by,
        requested_at,
        status,
        environment,
        target_id,
        approved_by,
        approved_at,
        rejection_reason,
        applied_at,
    ) = row;
    Ok(PendingDeployRow {
        id,
        system_id,
        plan_summary,
        requested_by,
        requested_at,
        status: Status::parse(&status)?,
        environment: Environment::parse(&environment)?,
        target_id,
        approved_by,
        approved_at,
        rejection_reason,
        applied_at,
    })
}

#[cfg(test)]
#[path = "pending_deploys_repository_tests.rs"]
mod tests;
