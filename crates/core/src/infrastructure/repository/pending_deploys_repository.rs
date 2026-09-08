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
    /// 2.11.0 (P1-D-01c, CWE-494): the
    /// `source_snapshots.id` (UUID)
    /// the plan was built against.
    /// `mark_applied` re-verifies
    /// that the row still exists.
    pub source_snapshot_id: Option<String>,
    /// 2.11.0 (P1-D-01c, CWE-494): the
    /// resolved HEAD `commit_sha`
    /// at `request` time.
    /// `mark_applied` re-verifies it
    /// against the current
    /// `source_snapshots.commit_sha`.
    pub commit_sha: Option<String>,
    /// 2.11.0 (P1-D-01c, CWE-494):
    /// SHA-256 of the canonical
    /// `plan_summary` bytes. The
    /// apply path recomputes the
    /// hash and refuses to apply if
    /// it differs (catches
    /// hand-edits in the DB and
    /// version-skew between server
    /// restarts).
    pub plan_hash: Option<String>,
    /// 2.11.0 (P1-D-01c, CWE-494):
    /// the policy-set version in
    /// force at `request` time.
    /// Currently the constant
    /// `DEFAULT_POLICY_SET_VERSION`
    /// ("1.0.0"); a 2.12.0
    /// follow-up will turn this
    /// into a per-tenant
    /// versioned table.
    pub policy_set_version: Option<String>,
    /// 2.11.0 (P1-D-01c, CWE-494):
    /// SHA-256 of the
    /// `(path, sha256, size_bytes)`
    /// tuples for the snapshot
    /// (sorted lexicographically by
    /// path). A file added or
    /// removed in the source
    /// between request and apply
    /// trips the freshness check.
    pub artifact_manifest_hash: Option<String>,
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
    ///
    /// 2.11.0 (P1-D-01c, CWE-494): the
    /// `request` call now also takes
    /// the optional
    /// `source_snapshot_id`. When
    /// present, the row is created
    /// with the `DeploymentIntent`
    /// fields populated from the
    /// snapshot at `request` time:
    /// - `commit_sha` — read from
    ///   `source_snapshots.commit_sha`.
    /// - `plan_hash` — SHA-256 of the
    ///   canonical `plan_summary`
    ///   bytes.
    /// - `artifact_manifest_hash` —
    ///   SHA-256 of the
    ///   `(path, sha256, size_bytes)`
    ///   tuples for the snapshot
    ///   (sorted lexicographically
    ///   by path). A file added or
    ///   removed between request and
    ///   apply will trip the
    ///   `mark_applied` freshness
    ///   check.
    /// - `policy_set_version` — the
    ///   policy set in force at
    ///   request time (a constant
    ///   `DEFAULT_POLICY_SET_VERSION`
    ///   for now; a 2.12.0 follow-up
    ///   will turn this into a
    ///   per-tenant versioned table).
    /// - `target_config_version` —
    ///   the current `targets.version`
    ///   for `target_id`. P1-D-01b
    ///   already wired the
    ///   `mark_applied` freshness
    ///   check for this field.
    ///
    /// When `source_snapshot_id` is
    /// `None` (a pre-P1-D-01c caller
    /// that does not know about
    /// snapshots), the new columns
    /// are `NULL` and the
    /// `mark_applied` freshness
    /// check is a no-op for them
    /// (the migration backfill
    /// case). The check is
    /// activated as soon as the
    /// caller starts passing a
    /// `Some(...)` source_snapshot_id.
    #[allow(clippy::too_many_arguments)]
    pub async fn request(
        &self,
        system_id: &str,
        plan_summary: &str,
        requested_by: i64,
        environment: Environment,
        target_id: Option<i64>,
        source_snapshot_id: Option<&str>,
    ) -> CoreResult<PendingDeployRow> {
        // 2.11.0 (P1-D-01c): populate
        // the `DeploymentIntent`
        // fields from the snapshot +
        // target. A failure here is
        // a hard error (the operator
        // asked for a deploy with a
        // snapshot id that does not
        // exist; we refuse to
        // insert a row that would
        // pass the `mark_applied`
        // freshness check on a
        // stale source).
        let mut commit_sha: Option<String> = None;
        let mut plan_hash: Option<String> = None;
        let mut artifact_manifest_hash: Option<String> = None;
        let policy_set_version: Option<String> = Some(DEFAULT_POLICY_SET_VERSION.to_string());
        let mut target_config_version: Option<i64> = None;
        if let Some(snapshot_id) = source_snapshot_id {
            // 1. commit_sha from
            //    source_snapshots.
            let row: Option<(String,)> =
                sqlx::query_as("SELECT commit_sha FROM source_snapshots WHERE id = ?1")
                    .bind(snapshot_id)
                    .fetch_optional(&self.pool)
                    .await?;
            let sha: String = row
                .ok_or_else(|| CoreError::ErrSchemaInvalid {
                    path: "pending_deploys.source_snapshot_id".to_string(),
                    reason: format!("source_snapshot `{snapshot_id}` does not exist"),
                })?
                .0;
            commit_sha = Some(sha);
            // 2. plan_hash =
            //    SHA-256(canonical
            //    plan_summary).
            plan_hash = Some(sha256_hex(plan_summary.as_bytes()));
            // 3. artifact_manifest_hash
            //    = SHA-256 of the
            //    sorted
            //    (path, sha256,
            //    size_bytes) tuples.
            artifact_manifest_hash =
                Some(compute_artifact_manifest_hash(&self.pool, snapshot_id).await?);
        }
        if let Some(t) = target_id {
            // target_config_version =
            // current targets.version.
            let row: Option<(i64,)> = sqlx::query_as("SELECT version FROM targets WHERE id = ?1")
                .bind(t)
                .fetch_optional(&self.pool)
                .await?;
            target_config_version = row.map(|(v,)| v);
        }
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO pending_deploys \
             (system_id, plan_summary, requested_by, requested_at, status, \
              environment, target_id, \
              source_snapshot_id, commit_sha, plan_hash, \
              policy_set_version, artifact_manifest_hash, target_config_version) \
             VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6, \
                     ?7, ?8, ?9, ?10, ?11, ?12) RETURNING id",
        )
        .bind(system_id)
        .bind(plan_summary)
        .bind(requested_by)
        .bind(&now_str)
        .bind(environment.as_str())
        .bind(target_id)
        .bind(source_snapshot_id)
        .bind(&commit_sha)
        .bind(&plan_hash)
        .bind(&policy_set_version)
        .bind(&artifact_manifest_hash)
        .bind(target_config_version)
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
            target_config_version,
            source_snapshot_id: source_snapshot_id.map(String::from),
            commit_sha,
            plan_hash,
            policy_set_version,
            artifact_manifest_hash,
            approved_by: None,
            approved_at: None,
            rejection_reason: None,
            applied_at: None,
        })
    }

    /// Read a single row by id.
    pub async fn get(&self, id: i64) -> CoreResult<Option<PendingDeployRow>> {
        let row: Option<PendingDeployRowRaw> = sqlx::query_as(
            "SELECT id, system_id, plan_summary, requested_by, requested_at, \
                    status, environment, target_id, target_config_version, \
                    source_snapshot_id, commit_sha, plan_hash, \
                    policy_set_version, artifact_manifest_hash, \
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
        let rows: Vec<PendingDeployRowRaw> = match (status_filter, environment_filter) {
            (None, None) => {
                sqlx::query_as(
                    "SELECT id, system_id, plan_summary, requested_by, requested_at, \
                        status, environment, target_id, target_config_version, \
                        source_snapshot_id, commit_sha, plan_hash, \
                        policy_set_version, artifact_manifest_hash, \
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
                        source_snapshot_id, commit_sha, plan_hash, \
                        policy_set_version, artifact_manifest_hash, \
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
                        source_snapshot_id, commit_sha, plan_hash, \
                        policy_set_version, artifact_manifest_hash, \
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
                        source_snapshot_id, commit_sha, plan_hash, \
                        policy_set_version, artifact_manifest_hash, \
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
            // 2.11.0 (P1-D-01c, CWE-494):
            // freshness checks for the
            // remaining `DeploymentIntent`
            // fields. A mismatch on any of
            // them returns a typed
            // `ErrStaleDeployment` and the
            // row stays in `approved`.
            if r.status == Status::Approved {
                // a. `source_snapshot_id` —
                // the row must still exist
                // in `source_snapshots`.
                if let Some(snapshot_id) = r.source_snapshot_id.as_deref() {
                    let snap_exists: Option<(String,)> =
                        sqlx::query_as("SELECT id FROM source_snapshots WHERE id = ?1")
                            .bind(snapshot_id)
                            .fetch_optional(&self.pool)
                            .await?;
                    if snap_exists.is_none() {
                        return Err(CoreError::ErrStaleDeployment {
                            deploy_id: id,
                            target_id: r.target_id.expect("target_id NOT NULL after migration 018"),
                            captured_version: 0,
                            current_version: -1,
                            kind: "source_snapshot_id (snapshot deleted)".to_string(),
                        });
                    }
                    // b. `commit_sha` — the
                    // current `commit_sha`
                    // for the same snapshot
                    // must match what we
                    // recorded.
                    if let Some(captured_sha) = r.commit_sha.as_deref() {
                        let current: Option<(String,)> =
                            sqlx::query_as("SELECT commit_sha FROM source_snapshots WHERE id = ?1")
                                .bind(snapshot_id)
                                .fetch_optional(&self.pool)
                                .await?;
                        if let Some((cur_sha,)) = current {
                            if cur_sha != captured_sha {
                                return Err(CoreError::ErrStaleDeployment {
                                    deploy_id: id,
                                    target_id: r
                                        .target_id
                                        .expect("target_id NOT NULL after migration 018"),
                                    captured_version: 0,
                                    current_version: 0,
                                    kind: format!(
                                        "commit_sha (was `{captured_sha}`, now `{cur_sha}`)"
                                    ),
                                });
                            }
                        }
                    }
                    // c. `artifact_manifest_hash`
                    // — recompute the
                    // canonical hash from
                    // `snapshot_files` and
                    // compare to the recorded
                    // value.
                    if let Some(captured_amh) = r.artifact_manifest_hash.as_deref() {
                        let current_amh =
                            compute_artifact_manifest_hash(&self.pool, snapshot_id).await?;
                        if current_amh != captured_amh {
                            return Err(CoreError::ErrStaleDeployment {
                                deploy_id: id,
                                target_id: r
                                    .target_id
                                    .expect("target_id NOT NULL after migration 018"),
                                captured_version: 0,
                                current_version: 0,
                                kind: "artifact_manifest_hash (files added/removed/modified)"
                                    .to_string(),
                            });
                        }
                    }
                }
                // d. `plan_hash` — recompute
                // SHA-256 of the current
                // `plan_summary` (the row's
                // own value) and compare to
                // the recorded value.
                if let Some(captured_ph) = r.plan_hash.as_deref() {
                    let current_ph = sha256_hex(r.plan_summary.as_bytes());
                    if current_ph != captured_ph {
                        return Err(CoreError::ErrStaleDeployment {
                            deploy_id: id,
                            target_id: r.target_id.expect("target_id NOT NULL after migration 018"),
                            captured_version: 0,
                            current_version: 0,
                            kind: "plan_hash (plan_summary edited)".to_string(),
                        });
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
        let rows: Vec<PendingDeployRowRaw> = match environment_filter {
            Some(e) => {
                sqlx::query_as(
                    "SELECT id, system_id, plan_summary, requested_by, requested_at, \
                        status, environment, target_id, target_config_version, \
                        source_snapshot_id, commit_sha, plan_hash, \
                        policy_set_version, artifact_manifest_hash, \
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
                        source_snapshot_id, commit_sha, plan_hash, \
                        policy_set_version, artifact_manifest_hash, \
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

// 2.11.0 (P1-D-01c): sqlx caps
// anonymous tuples at 16 fields;
// `PendingDeployRow` now has 18
// columns (5 new
// `DeploymentIntent` fields
// added by P1-D-01c), so we use
// a named-fields struct with
// `#[derive(sqlx::FromRow)]`. The
// struct is private because
// `decode_row` is the only thing
// that needs it; the public API
// is `PendingDeployRow` (the
// higher-level decoded form).
#[derive(sqlx::FromRow)]
struct PendingDeployRowRaw {
    id: i64,
    system_id: String,
    plan_summary: String,
    requested_by: i64,
    requested_at: String,
    status: String,
    environment: String,
    target_id: Option<i64>,
    target_config_version: Option<i64>,
    source_snapshot_id: Option<String>,
    commit_sha: Option<String>,
    plan_hash: Option<String>,
    policy_set_version: Option<String>,
    artifact_manifest_hash: Option<String>,
    approved_by: Option<i64>,
    approved_at: Option<String>,
    rejection_reason: Option<String>,
    applied_at: Option<String>,
}

fn decode_row(row: PendingDeployRowRaw) -> CoreResult<PendingDeployRow> {
    Ok(PendingDeployRow {
        id: row.id,
        system_id: row.system_id,
        plan_summary: row.plan_summary,
        requested_by: row.requested_by,
        requested_at: row.requested_at,
        status: Status::parse(&row.status)?,
        environment: Environment::parse(&row.environment)?,
        target_id: row.target_id,
        target_config_version: row.target_config_version,
        source_snapshot_id: row.source_snapshot_id,
        commit_sha: row.commit_sha,
        plan_hash: row.plan_hash,
        policy_set_version: row.policy_set_version,
        artifact_manifest_hash: row.artifact_manifest_hash,
        approved_by: row.approved_by,
        approved_at: row.approved_at,
        rejection_reason: row.rejection_reason,
        applied_at: row.applied_at,
    })
}

// 2.11.0 (P1-D-01c, CWE-494):
// the policy set version that
// `request()` writes into the
// `pending_deploys.policy_set_version`
// column. A future 2.12.0 will
// turn this into a per-tenant
// versioned table; the constant
// matches the 2.11.0 server
// baseline.
const DEFAULT_POLICY_SET_VERSION: &str = "1.0.0";

// 2.11.0 (P1-D-01c): SHA-256 hex of
// arbitrary bytes. Used for
// `plan_hash` and the
// `artifact_manifest_hash`
// canonicalization.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// 2.11.0 (P1-D-01c): compute the
// canonical `artifact_manifest_hash`
// for a `source_snapshots` row.
// The canonical form is the
// `snapshot_files` rows for the
// snapshot, sorted lexicographically
// by `relative` path, concatenated as
// `path\nsha256\nsize_bytes\n`
// (LF-separated, no escaping), and
// then SHA-256 hashed. Adding,
// removing, or modifying a file
// in the snapshot between
// `request_deploy` and `mark_applied`
// changes the hash and trips the
// freshness check.
async fn compute_artifact_manifest_hash(
    pool: &SqlitePool,
    snapshot_id: &str,
) -> CoreResult<String> {
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT relative, sha256, size_bytes \
         FROM snapshot_files \
         WHERE snapshot_id = ?1 \
         ORDER BY relative ASC",
    )
    .bind(snapshot_id)
    .fetch_all(pool)
    .await?;
    let mut buf: Vec<u8> = Vec::new();
    for (rel, sha, size) in rows {
        buf.extend_from_slice(rel.as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(sha.as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(size.to_string().as_bytes());
        buf.push(b'\n');
    }
    Ok(sha256_hex(&buf))
}

#[cfg(test)]
#[path = "pending_deploys_repository_tests.rs"]
mod tests;
