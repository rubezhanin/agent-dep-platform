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
    /// 2.11.0 (P1-D-01b, CWE-494): the
    /// `targets.version` value at
    /// `request_deploy` time. The
    /// `mark_applied` freshness
    /// check re-verifies the current
    /// `targets.version` against
    /// this value and refuses to
    /// apply the deploy on a
    /// mismatch. `None` for
    /// pre-P1-D-01a rows
    /// (backfilled to `NULL` at
    /// migration 022); the check
    /// is a no-op for those rows.
    pub target_config_version: Option<i64>,
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
            // P1-D-01c follow-up: copy
            // `targets.version` into this
            // field. For now the
            // freshness check on
            // `mark_applied` is a
            // no-op for rows where this
            // is `None` (the pre-P1-D-01c
            // backfill case).
            requested_by,
            requested_at: now_str,
            status: Status::Pending,
            environment,
            target_id,
            target_config_version: None,
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
                    status, environment, target_id, target_config_version, \
                    approved_by, approved_at, \
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
                        status, environment, target_id, target_config_version, \
                        approved_by, approved_at, \
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
                        status, environment, target_id, target_config_version, \
                        approved_by, approved_at, \
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
                        status, environment, target_id, target_config_version, \
                        approved_by, approved_at, \
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
                        status, environment, target_id, target_config_version, \
                        approved_by, approved_at, \
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
    ///
    /// 2.11.0 (P1-D-01b, TZ #1 §10 / D-01,
    /// CWE-494): if the row carries a
    /// `target_config_version` (the
    /// `targets.version` value at
    /// `request_deploy` time), the
    /// current `targets.version` for
    /// the same `target_id` MUST
    /// match. A mismatch means the
    /// target was reconfigured
    /// between approval and apply
    /// (a `PUT /v1/targets/:id`,
    /// e.g. an operator hand-edited
    /// the path or the environment).
    /// Applying the deploy anyway
    /// would be a CWE-494: a
    /// different artifact than the
    /// one the operator approved
    /// would land. The post-fix
    /// `mark_applied` rejects the
    /// call with a typed
    /// `ErrStaleDeployment` and the
    /// row stays in `approved` —
    /// the operator can re-issue
    /// the deploy (which captures
    /// the new `target_config_version`)
    /// or roll back the target
    /// config.
    ///
    /// Pre-P1-D-01 rows (those with
    /// `target_config_version IS NULL`)
    /// are accepted as before — the
    /// P1-D-01a migration backfilled
    /// `NULL`, and the freshness
    /// check is a no-op for them. A
    /// follow-up P1-D-01d commit
    /// will mark those rows
    /// `rejected` and require a
    /// re-issue.
    pub async fn mark_applied(&self, id: i64) -> CoreResult<Option<PendingDeployRow>> {
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        // 2.11.0 (P1-D-01b): freshness
        // check. If the row carries a
        // `target_config_version`, the
        // current `targets.version`
        // for the same `target_id`
        // must match. The check is a
        // SELECT (not a CHECK
        // constraint) because the
        // failure mode is a typed
        // `ErrStaleDeployment` that
        // carries both the captured
        // version and the current one
        // for the audit log.
        let row = self.get(id).await?;
        if let Some(r) = row.as_ref() {
            if let Some(captured) = r.target_config_version {
                if r.status == Status::Approved {
                    let current: Option<i64> =
                        sqlx::query_as("SELECT version FROM targets WHERE id = ?1")
                            .bind(r.target_id)
                            .fetch_optional(&self.pool)
                            .await?
                            .map(|(v,): (i64,)| v);
                    match current {
                        Some(now_version) if now_version == captured => {
                            // OK: the
                            // target has
                            // not been
                            // reconfigured
                            // since the
                            // deploy was
                            // requested.
                        }
                        Some(now_version) => {
                            return Err(CoreError::ErrStaleDeployment {
                                deploy_id: id,
                                target_id: r
                                    .target_id
                                    .expect("target_id NOT NULL after migration 018"),
                                captured_version: captured,
                                current_version: now_version,
                                kind: "target_config_version".to_string(),
                            });
                        }
                        None => {
                            // The target
                            // row is gone
                            // (deleted
                            // between
                            // request and
                            // apply). This
                            // is also a
                            // CWE-494 — the
                            // row we
                            // recorded the
                            // intent for
                            // no longer
                            // exists.
                            return Err(CoreError::ErrStaleDeployment {
                                deploy_id: id,
                                target_id: r
                                    .target_id
                                    .expect("target_id NOT NULL after migration 018"),
                                captured_version: captured,
                                current_version: -1,
                                kind: "target_config_version (target row missing)".to_string(),
                            });
                        }
                    }
                }
            }
        }
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

    /// 2.5.2 / ADR-0033: list every
    /// `pending_deploys` row that still has
    /// `target_id = NULL` (i.e. a pre-2.5.0
    /// deploy that the operator hasn't yet
    /// re-bound to the target registry). The
    /// operator uses this as a backfill
    /// checklist.
    ///
    /// The `environment_filter` is optional;
    /// if `Some`, only orphans in that
    /// environment are returned. The result is
    /// sorted by `requested_at` (oldest first)
    /// so the operator works through the
    /// backlog chronologically.
    pub async fn list_orphans(
        &self,
        environment_filter: Option<Environment>,
    ) -> CoreResult<Vec<PendingDeployRow>> {
        let rows: Vec<PendingDeployRowTuple> = match environment_filter {
            Some(e) => {
                sqlx::query_as(
                    "SELECT id, system_id, plan_summary, requested_by, requested_at, \
                        status, environment, target_id, target_config_version, \
                        approved_by, approved_at, \
                        rejection_reason, applied_at \
                 FROM pending_deploys WHERE target_id IS NULL AND environment = ?1 \
                 ORDER BY requested_at ASC",
                )
                .bind(e.as_str())
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as(
                    "SELECT id, system_id, plan_summary, requested_by, requested_at, \
                        status, environment, target_id, target_config_version, \
                        approved_by, approved_at, \
                        rejection_reason, applied_at \
                 FROM pending_deploys WHERE target_id IS NULL \
                 ORDER BY requested_at ASC",
                )
                .fetch_all(&self.pool)
                .await?
            }
        };
        rows.into_iter().map(decode_row).collect()
    }

    /// 2.5.2 / ADR-0033: explicit backfill. The
    /// caller (the CLI) is responsible for
    /// resolving the target name to an id via
    /// `TargetRepository::find_by_env_name` first;
    /// this method is a pure UPDATE. Returns
    /// the updated row, or `None` if the id
    /// does not exist.
    pub async fn set_target_id(
        &self,
        id: i64,
        target_id: i64,
    ) -> CoreResult<Option<PendingDeployRow>> {
        let affected = sqlx::query("UPDATE pending_deploys SET target_id = ?1 WHERE id = ?2")
            .bind(target_id)
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
        target_config_version,
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
        target_config_version,
        approved_by,
        approved_at,
        rejection_reason,
        applied_at,
    })
}

#[cfg(test)]
#[path = "pending_deploys_repository_tests.rs"]
mod tests;
