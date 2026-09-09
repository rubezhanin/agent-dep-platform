//! HTTP handler functions for the 2.1.0 server.

use agent_dep_core::infrastructure::repository::audit_log_repository::AuditOutcome;
use agent_dep_core::infrastructure::repository::users_repository::Role;
use axum::{
    extract::{Extension, Path as AxPath, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use agent_dep_core::infrastructure::repository::targets_repository::PathKind;

use crate::auth::AuthenticatedUser;
use crate::plan;
use crate::ServerState;

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub cursor: Option<i64>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct AuditPage {
    pub items: Vec<agent_dep_core::infrastructure::repository::audit_log_repository::AuditLogRow>,
    pub next_cursor: Option<i64>,
}

pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status": "ok"})))
}

/// 2.11.0 (B4, audit): in-process
/// recorder metrics. Returns the
/// `AuditRecorderStats` (currently
/// just `dropped_to_sync_total`).
/// Admin-only (auth + role guard
/// wired in `lib.rs`). Designed
/// for the C4 Prometheus
/// follow-up — the response body
/// is already the JSON shape that
/// `metrics-exporter-prometheus`
/// would render for a
/// `Gauge`-style counter.
pub async fn audit_stats(
    State(state): State<ServerState>,
    Extension(_user): Extension<AuthenticatedUser>,
) -> impl IntoResponse {
    (StatusCode::OK, Json(state.audit.stats()))
}

pub async fn list_audit(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    Query(q): Query<AuditQuery>,
) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(50);
    let res = state.audit.list(q.cursor, limit).await;
    match res {
        Ok(rows) => {
            let next_cursor = rows
                .last()
                .map(|r| r.id)
                .filter(|_| rows.len() as u32 == limit);
            let action = "GET /v1/audit";
            let details = Some(json!({"limit": limit, "cursor": q.cursor}).to_string());
            state.audit.record_async(
                &user.name,
                action,
                None,
                AuditOutcome::Ok,
                details.as_deref(),
            );
            (
                StatusCode::OK,
                Json(AuditPage {
                    items: rows,
                    next_cursor,
                }),
            )
                .into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    "GET /v1/audit",
                    None,
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SystemSummary {
    pub source_id: String,
    pub snapshot_id: String,
    pub commit_sha: String,
    pub agent_count: i64,
    pub created_at: String,
}

pub async fn list_systems(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> impl IntoResponse {
    let action = "GET /v1/systems".to_string();
    let result = list_active_snapshots(state.db.pool()).await;
    match result {
        Ok(rows) => {
            let details = Some(json!({"count": rows.len()}).to_string());
            // P1-PERF-01 (TZ #1 §19): batched /
            // non-durable audit for successful
            // GETs. The flush task lands this on
            // disk within `flush_interval`
            // (default 1 s) or when the batch
            // hits `batch_size` (default 100)
            // events, whichever comes first.
            state.audit.record_async(
                &user.name,
                &action,
                None,
                AuditOutcome::Ok,
                details.as_deref(),
            );
            (StatusCode::OK, Json(rows)).into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    &action,
                    None,
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

async fn list_active_snapshots(pool: &sqlx::SqlitePool) -> anyhow::Result<Vec<SystemSummary>> {
    let rows: Vec<(String, String, String, i64, String)> = sqlx::query_as(
        "SELECT s.id, s.source_id, s.commit_sha, s.agent_count, s.created_at \
         FROM source_snapshots s \
         WHERE s.status = 'active' \
         ORDER BY s.created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, source_id, commit_sha, agent_count, created_at)| SystemSummary {
                source_id,
                snapshot_id: id,
                commit_sha,
                agent_count,
                created_at,
            },
        )
        .collect())
}

#[derive(Debug, Deserialize)]
pub struct PlanRequest {
    /// P0-F-07 (TZ #1 §8 F-07, CWE-22,
    /// Appendix A.5): the registered source
    /// ID (UUID) to plan against. The pre-fix
    /// field was `catalog: String` — a
    /// caller-supplied filesystem path —
    /// which let any authenticated user
    /// ask the server to read any path on
    /// disk (CWE-22 Path Traversal). The
    /// post-fix field is an opaque ID that
    /// the server resolves against the
    /// pre-registered `sources` table: the
    /// server reads the path FROM the DB,
    /// not FROM the request. Callers must
    /// first register a source via
    /// `POST /v1/sources` (or the CLI
    /// `agency sources add`) and only then
    /// reference it here.
    pub source_id: String,
    /// The system.yaml body, as a UTF-8 string. The CLI
    /// uses `read_to_string`; the server accepts the body
    /// directly so the operator does not have to ship the
    /// file separately.
    pub system_yaml: String,
    /// P1-D-01d (TZ #1 §10 / D-01d,
    /// CWE-494): the optional
    /// `source_snapshots.id` (UUID)
    /// the plan should be built
    /// against. When present, the
    /// server loads the stored agents
    /// / divisions / skills from the
    /// snapshot row instead of
    /// re-ingesting the live working
    /// copy. See `DeployRequestBody::source_snapshot_id`
    /// for the matching deploy-time
    /// field and the CWE-345 source
    /// confusion guard.
    #[serde(default)]
    pub source_snapshot_id: Option<String>,
}

pub async fn plan_system(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<PlanRequest>,
) -> impl IntoResponse {
    let action = "POST /v1/systems/plan".to_string();
    // P0-F-07 (TZ #1 §8 F-07, CWE-22,
    // Appendix A.5): the pre-fix code
    // accepted `req.catalog: String` (a
    // caller-supplied filesystem path)
    // and read it directly. Post-fix: the
    // request carries an opaque `source_id`
    // (UUID), and the server resolves the
    // path from the pre-registered
    // `sources` table. The caller never
    // influences the filesystem path the
    // server ingests.
    // P1-D-01d: the `/v1/systems/plan`
    // endpoint accepts the same
    // `source_snapshot_id` as
    // `/v1/deploys` (see `PlanRequest`).
    // We forward it to the plan fn so a
    // plan preview is also reproducible
    // against a stored snapshot.
    match plan::compute_plan_from_source(
        state.db.pool(),
        &req.source_id,
        &req.system_yaml,
        req.source_snapshot_id.as_deref(),
    )
    .await
    {
        Ok((_resolved_source_id, summary, _resolved_snap_id)) => {
            let target = format!("system:{}", summary.system_id);
            let details = Some(json!({"wrote": summary.writes.len()}).to_string());
            // 2.10.0 (P1-AUD-FIX, CWE-778):
            // plan is a mutation (writes
            // happen) — use `record_sync`
            // to guarantee the audit row
            // is durable before the 200
            // returns. The pre-fix
            // `record_async` could lose
            // the row on a crash inside
            // the 1s flush window.
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    &action,
                    Some(&target),
                    AuditOutcome::Ok,
                    details.as_deref(),
                )
                .await;
            (StatusCode::OK, Json(summary)).into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    &action,
                    None,
                    AuditOutcome::Error,
                    Some(&format!("plan error: {e}")),
                )
                .await;
            (
                StatusCode::BAD_REQUEST,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

pub async fn rollback_operation(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    AxPath(id): AxPath<Uuid>,
) -> impl IntoResponse {
    let action = format!("POST /v1/rollback/{id}");
    let db_path = default_db_path();
    match agent_dep_cli::commands::rollback::rollback_at(id, &db_path).await {
        Ok(summary) => {
            let target = format!("operation:{id}");
            let details = Some(
                json!({
                    "restored": summary.restored,
                    "kept_current": summary.kept_current,
                    "failed": summary.failed.len(),
                })
                .to_string(),
            );
            // 2.10.0 (P1-AUD-FIX, CWE-778):
            // rollback is a mutation
            // (filesystem writes) — sync.
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    &action,
                    Some(&target),
                    AuditOutcome::Ok,
                    details.as_deref(),
                )
                .await;
            (StatusCode::OK, Json(summary)).into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    &action,
                    Some(&format!("operation:{id}")),
                    AuditOutcome::Error,
                    Some(&format!("rollback error: {e}")),
                )
                .await;
            (
                StatusCode::BAD_REQUEST,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// 2.1.0 — /v1/users endpoints (admin only).
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub name: String,
    pub role: Role,
}

#[derive(Debug, Serialize)]
pub struct UserView {
    pub id: i64,
    pub name: String,
    pub role: Role,
    pub created_at: String,
    pub last_seen_at: Option<String>,
    pub disabled_at: Option<String>,
}

fn to_view(u: &agent_dep_core::infrastructure::repository::users_repository::UserRow) -> UserView {
    UserView {
        id: u.id,
        name: u.name.clone(),
        role: u.role,
        created_at: u.created_at.clone(),
        last_seen_at: u.last_seen_at.clone(),
        disabled_at: u.disabled_at.clone(),
    }
}

pub async fn list_users(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> impl IntoResponse {
    let action = "GET /v1/users";
    match state.users.list().await {
        Ok(rows) => {
            let views: Vec<UserView> = rows.iter().map(to_view).collect();
            let details = Some(json!({"count": views.len()}).to_string());
            // 2.11.0 (B4, audit CWE-778):
            // list_users exposes the
            // user roster (names +
            // roles + token hashes'
            // metadata). On a crash
            // inside the 1s async-flush
            // window, an attacker who
            // enumerated the user
            // list would not be
            // visible in the audit log.
            // Use `record_sync` for
            // durability.
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    None,
                    AuditOutcome::Ok,
                    details.as_deref(),
                )
                .await;
            (StatusCode::OK, Json(views)).into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    None,
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

pub async fn create_user(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<CreateUserRequest>,
) -> impl IntoResponse {
    let action = "POST /v1/users";
    let target = format!("user:{}", req.name);
    match state.users.create(&req.name, req.role).await {
        Ok(created) => {
            let details = Some(json!({"role": created.user.role.as_str()}).to_string());
            // 2.10.0 (P1-AUD-FIX, CWE-778):
            // user creation is a
            // mutation — sync.
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Ok,
                    details.as_deref(),
                )
                .await;
            let view = to_view(&created.user);
            (
                StatusCode::CREATED,
                Json(json!({
                    "id": view.id,
                    "name": view.name,
                    "role": view.role,
                    "created_at": view.created_at,
                    "token": created.token,
                })),
            )
                .into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("create error: {e}")),
                )
                .await;
            (
                StatusCode::BAD_REQUEST,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

pub async fn disable_user(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    AxPath(id): AxPath<i64>,
) -> impl IntoResponse {
    let action = "DELETE /v1/users/:id";
    let target = format!("user:{id}");
    match state.users.disable(id).await {
        Ok(true) => {
            let _ = state
                .audit
                .record_sync(&user.name, action, Some(&target), AuditOutcome::Ok, None)
                .await;
            (StatusCode::NO_CONTENT, ()).into_response()
        }
        Ok(false) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(r#"{"reason":"already disabled or not found"}"#),
                )
                .await;
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "user not found or already disabled"})),
            )
                .into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

pub async fn rotate_user_token(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    AxPath(id): AxPath<i64>,
) -> impl IntoResponse {
    let action = "POST /v1/users/:id/rotate";
    let target = format!("user:{id}");
    match state.users.rotate_token(id).await {
        Ok(Some(new_token)) => {
            let _ = state
                .audit
                .record_sync(&user.name, action, Some(&target), AuditOutcome::Ok, None)
                .await;
            (StatusCode::OK, Json(json!({"id": id, "token": new_token}))).into_response()
        }
        Ok(None) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(r#"{"reason":"user not found or disabled"}"#),
                )
                .await;
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "user not found or disabled"})),
            )
                .into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// 2.2.0 — /v1/deploys endpoints (ADR-0020).
// ---------------------------------------------------------------------------

use agent_dep_core::infrastructure::repository::pending_deploys_repository::{
    Environment, PendingDeployRow, Status as DeployStatus,
};

#[derive(Debug, Serialize)]
pub struct DeployView {
    pub id: i64,
    pub system_id: String,
    pub plan_summary: String,
    pub requested_by: i64,
    pub requested_at: String,
    pub status: DeployStatus,
    pub environment: Environment,
    /// 2.5.0 — nullable for legacy 2.4.0 deploys
    /// and for operators still on the path-based
    /// CLI. Populated when the request body
    /// includes `"target": "<name>"`.
    pub target_id: Option<i64>,
    /// P1-D-01d (TZ #1 §10 / D-01d,
    /// CWE-494): the
    /// `source_snapshots.id` the plan
    /// was built against. `null` for
    /// legacy deploys that used the
    /// re-ingest path (no snapshot
    /// pinned). When present, the
    /// `mark_applied` freshness
    /// check verifies the snapshot
    /// still exists.
    pub source_snapshot_id: Option<String>,
    pub approved_by: Option<i64>,
    pub approved_at: Option<String>,
    pub rejection_reason: Option<String>,
    pub applied_at: Option<String>,
}

fn deploy_view(r: &PendingDeployRow) -> DeployView {
    DeployView {
        id: r.id,
        system_id: r.system_id.clone(),
        plan_summary: r.plan_summary.clone(),
        requested_by: r.requested_by,
        requested_at: r.requested_at.clone(),
        status: r.status,
        environment: r.environment,
        target_id: r.target_id,
        source_snapshot_id: r.source_snapshot_id.clone(),
        approved_by: r.approved_by,
        approved_at: r.approved_at.clone(),
        rejection_reason: r.rejection_reason.clone(),
        applied_at: r.applied_at.clone(),
    }
}

#[derive(Debug, Deserialize)]
pub struct DeployRequestBody {
    /// P0-F-07 (TZ #1 §8 F-07, CWE-22,
    /// Appendix A.5): the pre-fix
    /// `catalog: String` was a caller-
    /// supplied filesystem path. The
    /// post-fix `source_id: String` is
    /// an opaque UUID that the server
    /// resolves against the pre-registered
    /// `sources` table. The caller never
    /// influences the filesystem path the
    /// server ingests. (Same fix as
    /// `PlanRequest::source_id` — both
    /// endpoints share the same contract.)
    pub source_id: String,
    pub system_yaml: String,
    /// 2.4.0 — optional. Defaults to `dev` when
    /// omitted (the 2.2.0 behaviour).
    #[serde(default)]
    pub environment: Option<Environment>,
    /// 2.5.0 — optional. The operator-typed
    /// target name; the server resolves it
    /// through the `targets` table. Must match
    /// the deploy's environment if both are
    /// provided. `None` is allowed (the legacy
    /// 2.4.0 path-based CLI keeps working).
    #[serde(default)]
    pub target: Option<String>,
    /// P1-D-01d (TZ #1 §10 / D-01d,
    /// CWE-494 Download of Code Without
    /// Integrity Check): the optional
    /// `source_snapshots.id` (UUID)
    /// the plan should be built
    /// against. When present, the
    /// server loads the stored agents
    /// / divisions / skills from the
    /// snapshot row instead of
    /// re-ingesting the live working
    /// copy. The plan is therefore
    /// pinned to the exact commit the
    /// operator approved; later edits
    /// to the working copy cannot
    /// change the deploy that the
    /// pending_deploys row records.
    /// The snapshot's `source_id`
    /// MUST equal the request's
    /// `source_id` (CWE-345
    /// source-confusion guard) — a
    /// mismatch returns 400.
    /// `None` is allowed (the 2.11.0
    /// `agency` CLI and the SPA
    /// before it learns about
    /// `GET /v1/sources/{id}/snapshots`
    /// still use the re-ingest path;
    /// those rows have
    /// `pending_deploys.source_snapshot_id = NULL`
    /// and the `mark_applied`
    /// freshness check is a no-op for
    /// them).
    #[serde(default)]
    pub source_snapshot_id: Option<String>,
}

pub async fn request_deploy(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<DeployRequestBody>,
) -> impl IntoResponse {
    let action = "POST /v1/deploys";
    // 2.5.0: resolve the optional `target` name
    // BEFORE the plan runs. The lookup is
    // cheap (indexed by `(environment, name)`)
    // and we want a 4xx for an unknown target
    // even if the plan would otherwise succeed.
    let env = req.environment.unwrap_or(Environment::Dev);
    // 2.5.3 (ADR-0033 follow-up):
    // `pending_deploys.target_id` is
    // now NOT NULL. The legacy
    // `target: None` path is gone
    // for `POST /v1/deploys`; the
    // operator must declare the
    // target at request time. The
    // CLI path (`agency deploy
    // apply --target <name>`) is
    // updated separately.
    let target_name = match req.target.as_deref() {
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "target is required (2.5.3: pending_deploys.target_id is NOT NULL). \
                              Set `target` in the request body."
                })),
            )
                .into_response();
        }
        Some(n) => n,
    };
    let target_id: Option<i64> = match state.targets.find_by_env_name(env, target_name).await {
        Ok(Some(row)) => Some(row.id),
        Ok(None) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    None,
                    AuditOutcome::Error,
                    Some(&format!(
                        "target `{target_name}` not found in environment `{}`",
                        env.as_str()
                    )),
                )
                .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!(
                        "target `{target_name}` not found in environment `{}`",
                        env.as_str()
                    )
                })),
            )
                .into_response();
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    None,
                    AuditOutcome::Error,
                    Some(&format!("target lookup: {e}")),
                )
                .await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::error_response::from_any_error(&e),
            )
                .into_response();
        }
    };
    // P1-D-01d: forward the caller-supplied
    // `source_snapshot_id` (if any) to the
    // plan fn. The plan fn returns the
    // resolved snap id (as a String) so we
    // can write it into
    // `pending_deploys.source_snapshot_id`
    // — that is what enables the
    // `mark_applied` freshness check (CWE-494).
    match plan::compute_plan_from_source(
        state.db.pool(),
        &req.source_id,
        &req.system_yaml,
        req.source_snapshot_id.as_deref(),
    )
    .await
    {
        Ok((_source_id, summary, snap_id)) => {
            let plan_json = match serde_json::to_string(&summary) {
                Ok(s) => s,
                Err(e) => {
                    let _ = state
                        .audit
                        .record_sync(
                            &user.name,
                            action,
                            None,
                            AuditOutcome::Error,
                            Some(&format!("serialise plan: {e}")),
                        )
                        .await;
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        crate::error_response::from_any_error(&e),
                    )
                        .into_response();
                }
            };
            match state
                .deploys
                .request(
                    &summary.system_id,
                    &plan_json,
                    user.id,
                    env,
                    target_id,
                    snap_id.as_deref(),
                )
                .await
            {
                Ok(row) => {
                    let target = format!("deploy:{}", row.id);
                    let details = Some(
                        json!({
                            "system_id": row.system_id,
                            "writes": summary.writes.len(),
                            "environment": row.environment.as_str(),
                            // 2.11.0 (P1-D-01d):
                            // include the
                            // resolved snap id
                            // in the audit
                            // row so the
                            // operator can
                            // trace which
                            // snapshot the
                            // plan was built
                            // against. `null`
                            // means the
                            // legacy
                            // re-ingest path
                            // was used.
                            "source_snapshot_id": row.source_snapshot_id,
                        })
                        .to_string(),
                    );
                    // 2.10.0 (P1-AUD-FIX, CWE-778):
                    // request_deploy is a
                    // mutation (filesystem
                    // writes) — sync.
                    let _ = state
                        .audit
                        .record_sync(
                            &user.name,
                            action,
                            Some(&target),
                            AuditOutcome::Ok,
                            details.as_deref(),
                        )
                        .await;
                    let view = deploy_view(&row);
                    (
                        StatusCode::CREATED,
                        Json(serde_json::json!({
                            "deploy": view,
                            "plan": summary,
                        })),
                    )
                        .into_response()
                }
                Err(e) => {
                    let _ = state
                        .audit
                        .record_sync(
                            &user.name,
                            action,
                            None,
                            AuditOutcome::Error,
                            Some(&format!("persist: {e}")),
                        )
                        .await;
                    // 2.11.0 (P1-D-02, TZ #1
                    // §10 / D-02, CWE-362):
                    // the target already
                    // has a non-terminal
                    // `pending` or
                    // `approved` row. 409
                    // is the right status
                    // (the request was
                    // valid, but the
                    // target's state
                    // conflicts). The
                    // `from_core_error`
                    // mapping turns
                    // `ErrTargetBusy` into
                    // a typed
                    // `"deploy.target_busy"`
                    // response; other
                    // errors fall through
                    // to the 500 path.
                    if let agent_dep_core::error::CoreError::ErrTargetBusy { .. } = &e {
                        (
                            StatusCode::CONFLICT,
                            crate::error_response::from_core_error(&e).1,
                        )
                            .into_response()
                    } else {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            crate::error_response::from_core_error(&e).1,
                        )
                            .into_response()
                    }
                }
            }
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    None,
                    AuditOutcome::Error,
                    Some(&format!("plan error: {e}")),
                )
                .await;
            (
                StatusCode::BAD_REQUEST,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ListDeploysQuery {
    pub status: Option<DeployStatus>,
    /// 2.4.0 — filter by environment.
    pub env: Option<Environment>,
    pub limit: Option<u32>,
}

pub async fn list_deploys(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    Query(q): Query<ListDeploysQuery>,
) -> impl IntoResponse {
    let action = "GET /v1/deploys";
    let limit = q.limit.unwrap_or(50);
    match state.deploys.list(q.status, q.env, limit).await {
        Ok(rows) => {
            let views: Vec<DeployView> = rows.iter().map(deploy_view).collect();
            let details = Some(
                json!({
                    "count": views.len(),
                    "status_filter": q.status.map(|s| s.as_str()),
                    "env_filter": q.env.map(|e| e.as_str()),
                })
                .to_string(),
            );
            state.audit.record_async(
                &user.name,
                action,
                None,
                AuditOutcome::Ok,
                details.as_deref(),
            );
            (StatusCode::OK, Json(views)).into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    None,
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

pub async fn get_deploy(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    AxPath(id): AxPath<i64>,
) -> impl IntoResponse {
    let action = "GET /v1/deploys/:id";
    let target = format!("deploy:{id}");
    match state.deploys.get(id).await {
        Ok(Some(row)) => {
            let _ = state
                .audit
                .record_sync(&user.name, action, Some(&target), AuditOutcome::Ok, None)
                .await;
            (StatusCode::OK, Json(deploy_view(&row))).into_response()
        }
        Ok(None) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(r#"{"reason":"not found"}"#),
                )
                .await;
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "deploy not found"})),
            )
                .into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

pub async fn approve_deploy(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    AxPath(id): AxPath<i64>,
) -> impl IntoResponse {
    let action = "POST /v1/deploys/:id/approve";
    let target = format!("deploy:{id}");
    match state.deploys.approve(id, user.id).await {
        Ok(Some(row)) => {
            let details = Some(json!({"status": "approved"}).to_string());
            // 2.10.0 (P1-AUD-FIX, CWE-778):
            // approve is a deploy state
            // mutation — sync.
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Ok,
                    details.as_deref(),
                )
                .await;
            (StatusCode::OK, Json(deploy_view(&row))).into_response()
        }
        Ok(None) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(r#"{"reason":"not pending"}"#),
                )
                .await;
            (
                StatusCode::CONFLICT,
                Json(json!({"error": "deploy is not pending"})),
            )
                .into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RejectBody {
    pub reason: Option<String>,
}

pub async fn reject_deploy(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    AxPath(id): AxPath<i64>,
    Json(req): Json<RejectBody>,
) -> impl IntoResponse {
    let action = "POST /v1/deploys/:id/reject";
    let target = format!("deploy:{id}");
    match state
        .deploys
        .reject(id, user.id, req.reason.as_deref())
        .await
    {
        Ok(Some(row)) => {
            let details = Some(
                json!({
                    "status": "rejected",
                    "reason": req.reason,
                })
                .to_string(),
            );
            // 2.10.0 (P1-AUD-FIX, CWE-778):
            // reject is a deploy state
            // mutation — sync.
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Ok,
                    details.as_deref(),
                )
                .await;
            (StatusCode::OK, Json(deploy_view(&row))).into_response()
        }
        Ok(None) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(r#"{"reason":"not pending"}"#),
                )
                .await;
            (
                StatusCode::CONFLICT,
                Json(json!({"error": "deploy is not pending"})),
            )
                .into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

pub async fn mark_applied(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    AxPath(id): AxPath<i64>,
) -> impl IntoResponse {
    let action = "POST /v1/deploys/:id/applied";
    let target = format!("deploy:{id}");
    match state.deploys.mark_applied(id).await {
        Ok(Some(row)) => {
            let _ = state
                .audit
                .record_sync(&user.name, action, Some(&target), AuditOutcome::Ok, None)
                .await;
            (StatusCode::OK, Json(deploy_view(&row))).into_response()
        }
        Ok(None) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(r#"{"reason":"not approved"}"#),
                )
                .await;
            (
                StatusCode::CONFLICT,
                Json(json!({"error": "deploy is not approved"})),
            )
                .into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            // 2.11.0 (P1-D-01b /
            // P1-D-02, TZ #1 §10 /
            // D-01 + D-02, CWE-494 +
            // CWE-362): a stale
            // deploy (drift between
            // approval and apply on
            // any
            // `DeploymentIntent`
            // field, or a fence
            // mismatch because
            // another apply landed
            // for the same target)
            // is a 409, not a 500.
            // `from_core_error` maps
            // `ErrStaleDeployment` to
            // `(409, "deploy.stale")`.
            // Other errors fall
            // through to the generic
            // 500 path.
            if let agent_dep_core::error::CoreError::ErrStaleDeployment { .. } = &e {
                (
                    StatusCode::CONFLICT,
                    crate::error_response::from_core_error(&e).1,
                )
                    .into_response()
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    crate::error_response::from_core_error(&e).1,
                )
                    .into_response()
            }
        }
    }
}

fn default_db_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("AGENCY_SERVER_DATA_DIR") {
        if !p.trim().is_empty() {
            return std::path::PathBuf::from(p).join("data").join("agency.db");
        }
    }
    if let Ok(p) = std::env::var("AGENCY_DATA_DIR") {
        if !p.trim().is_empty() {
            return std::path::PathBuf::from(p).join("data").join("agency.db");
        }
    }
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    home.join(".agency-server").join("data").join("agency.db")
}

// ---------------------------------------------------------------------------
// 2.3.0 - /v1/secrets endpoints (ADR-0021).
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateSecretBody {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSecretBody {
    pub value: String,
}

pub async fn list_secrets(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> impl IntoResponse {
    let action = "GET /v1/secrets";
    match state.secrets.list().await {
        Ok(rows) => {
            let details = Some(json!({"count": rows.len()}).to_string());
            // 2.11.0 (B4, audit CWE-778):
            // list_secrets is `GET` but
            // exposes the *names* of all
            // secrets in the vault
            // (and the `count`). On a
            // crash inside the 1s
            // async-flush window, an
            // attacker who exfiltrated
            // the secret names would
            // not be visible in the
            // audit log. Use
            // `record_sync` to
            // guarantee durability
            // before the 200 returns.
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    None,
                    AuditOutcome::Ok,
                    details.as_deref(),
                )
                .await;
            (StatusCode::OK, Json(rows)).into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    None,
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

pub async fn get_secret(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    AxPath(name): AxPath<String>,
) -> impl IntoResponse {
    let action = "GET /v1/secrets/:name";
    let target = format!("secret:{name}");
    // 2.10.0 (B3, audit CWE-598
    // Information Exposure Through
    // Query Strings in GET Request):
    // GET /v1/secrets/:name is
    // GONE. Pre-fix, this handler
    // returned the plaintext value
    // over a GET — the value landed
    // in Caddy access logs, browser
    // history, prefetch caches, and
    // accidental curl retries. The
    // new path is
    // `POST /v1/secrets/:name/reveal`
    // with a mandatory `reason` field
    // in the body and an Admin role
    // gate. The 410 Gone + `Link`
    // header gives the operator a
    // clear migration path; the
    // audit row records the attempt
    // (so a stuck client surfaces in
    // the log instead of silently
    // retrying forever).
    let _ = state
        .audit
        .record_sync(
            &user.name,
            action,
            Some(&target),
            AuditOutcome::Error,
            Some(r#"{"reason":"deprecated; use POST /v1/secrets/:name/reveal"}"#),
        )
        .await;
    (
        StatusCode::GONE,
        [(
            axum::http::header::LINK,
            "</v1/secrets/:name/reveal>; rel=\"successor-version\"",
        )],
        Json(json!({
            "code": "schema.gone",
            "kind": "client",
            "hint": "GET /v1/secrets/:name is removed in 2.10.0. \
                     Use POST /v1/secrets/:name/reveal with body \
                     {\"reason\": \"<why>\"} (Admin role required)."
        })),
    )
        .into_response()
}

/// 2.10.0 (B3, audit CWE-598):
/// reveal a secret's plaintext
/// value. Admin role only. Body
/// MUST include a non-empty
/// `reason` string that is logged
/// in the audit row. Response
/// carries `Cache-Control:
/// no-store, no-cache,
/// must-revalidate` + `Pragma:
/// no-cache` so HTTP caches and
/// the browser back-button do not
/// retain the plaintext.
#[derive(Debug, Deserialize)]
pub struct RevealSecretBody {
    pub reason: String,
}

pub async fn reveal_secret(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    AxPath(name): AxPath<String>,
    Json(req): Json<RevealSecretBody>,
) -> impl IntoResponse {
    let action = "POST /v1/secrets/:name/reveal";
    let target = format!("secret:{name}");
    // Reject empty / whitespace-only
    // reasons. The audit row is the
    // long-term record of "why did
    // an operator pull this secret?"
    // — a blank reason defeats the
    // purpose.
    if req.reason.trim().is_empty() {
        let _ = state
            .audit
            .record_sync(
                &user.name,
                action,
                Some(&target),
                AuditOutcome::Error,
                Some(r#"{"reason":"missing reason in request body"}"#),
            )
            .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "code": "schema.invalid",
                "kind": "client",
                "hint": "request body must include non-empty `reason` \
                         explaining why the secret is being revealed"
            })),
        )
            .into_response();
    }
    match state.secrets.get_value(&name).await {
        Ok(value) => {
            // Store the operator-supplied
            // reason in the audit details
            // so post-hoc "who pulled what
            // and why" queries have a
            // human-readable answer.
            let details = json!({ "reason": req.reason }).to_string();
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Ok,
                    Some(&details),
                )
                .await;
            (
                StatusCode::OK,
                [
                    (
                        axum::http::header::CACHE_CONTROL,
                        "no-store, no-cache, must-revalidate, private",
                    ),
                    (axum::http::header::PRAGMA, "no-cache"),
                    (axum::http::header::EXPIRES, "0"),
                ],
                Json(json!({ "name": value.name, "value": value.value })),
            )
                .into_response()
        }
        Err(e) => {
            // Do NOT include the value
            // (or even the name) in the
            // error response — surface
            // only a generic 404.
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("read: {e}")),
                )
                .await;
            (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response()
        }
    }
}

pub async fn create_secret(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<CreateSecretBody>,
) -> impl IntoResponse {
    let action = "POST /v1/secrets";
    let target = format!("secret:{}", req.name);
    match state.secrets.create(&req.name, &req.value, user.id).await {
        Ok(row) => {
            // 2.10.0 (P1-AUD-FIX, CWE-778):
            // secret create is a vault
            // mutation — sync.
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Ok,
                    Some(&format!("version={}", row.version)),
                )
                .await;
            (StatusCode::CREATED, Json(row)).into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("create: {e}")),
                )
                .await;
            (
                StatusCode::BAD_REQUEST,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

pub async fn update_secret(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    AxPath(name): AxPath<String>,
    Json(req): Json<UpdateSecretBody>,
) -> impl IntoResponse {
    let action = "PUT /v1/secrets/:name";
    let target = format!("secret:{name}");
    match state.secrets.update(&name, &req.value, user.id).await {
        Ok(Some(row)) => {
            // 2.10.0 (P1-AUD-FIX, CWE-778):
            // secret update is a vault
            // mutation — sync.
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Ok,
                    Some(&format!("version={}", row.version)),
                )
                .await;
            (StatusCode::OK, Json(row)).into_response()
        }
        Ok(None) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(r#"{"reason":"not found"}"#),
                )
                .await;
            (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("update: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

pub async fn delete_secret(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    AxPath(name): AxPath<String>,
) -> impl IntoResponse {
    let action = "DELETE /v1/secrets/:name";
    let target = format!("secret:{name}");
    match state.secrets.delete(&name).await {
        Ok(true) => {
            let _ = state
                .audit
                .record_sync(&user.name, action, Some(&target), AuditOutcome::Ok, None)
                .await;
            (StatusCode::NO_CONTENT, ()).into_response()
        }
        Ok(false) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(r#"{"reason":"not found"}"#),
                )
                .await;
            (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("delete: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// 2.4.0 — /v1/environments endpoint (ADR-0022).
// ---------------------------------------------------------------------------

pub async fn list_environments(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> impl IntoResponse {
    let action = "GET /v1/environments";
    let names: Vec<&'static str> = Environment::all().iter().map(|e| e.as_str()).collect();
    let _ = state
        .audit
        .record_sync(&user.name, action, None, AuditOutcome::Ok, None)
        .await;
    (StatusCode::OK, Json(json!({ "environments": names }))).into_response()
}

// ---------------------------------------------------------------------------
// 2.5.0 — /v1/targets endpoints (ADR-0023).
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateTargetBody {
    pub name: String,
    pub environment: Environment,
    pub path: String,
    /// 2.5.1 (ADR-0029): POSIX vs Windows path
    /// discriminator. Defaults to `posix` for
    /// backwards compatibility with 2.5.0
    /// callers that don't send the field.
    #[serde(default)]
    pub path_kind: Option<PathKind>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListTargetsQuery {
    /// 2.5.0 — optional environment filter.
    #[serde(default)]
    pub env: Option<Environment>,
}

pub async fn list_targets(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    Query(q): Query<ListTargetsQuery>,
) -> impl IntoResponse {
    let action = "GET /v1/targets";
    match state.targets.list(q.env).await {
        Ok(rows) => {
            let details = Some(
                json!({
                    "count": rows.len(),
                    "env_filter": q.env.map(|e| e.as_str()),
                })
                .to_string(),
            );
            state.audit.record_async(
                &user.name,
                action,
                None,
                AuditOutcome::Ok,
                details.as_deref(),
            );
            (StatusCode::OK, Json(rows)).into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    None,
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

pub async fn get_target(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    AxPath(id): AxPath<i64>,
) -> impl IntoResponse {
    let action = "GET /v1/targets/:id";
    let target = format!("target:{id}");
    match state.targets.get(id).await {
        Ok(Some(row)) => {
            let _ = state
                .audit
                .record_sync(&user.name, action, Some(&target), AuditOutcome::Ok, None)
                .await;
            (StatusCode::OK, Json(row)).into_response()
        }
        Ok(None) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(r#"{"reason":"not found"}"#),
                )
                .await;
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "target not found"})),
            )
                .into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

pub async fn create_target(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<CreateTargetBody>,
) -> impl IntoResponse {
    let action = "POST /v1/targets";
    let target = format!("target:{}:{}", req.environment.as_str(), req.name);
    let path_kind = req.path_kind.unwrap_or(PathKind::Posix);
    match state
        .targets
        .create(
            &req.name,
            req.environment,
            &req.path,
            path_kind,
            req.description.as_deref(),
        )
        .await
    {
        Ok(row) => {
            // 2.10.0 (P1-AUD-FIX, CWE-778):
            // target create is a fleet
            // mutation — sync.
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Ok,
                    Some(&format!("id={}", row.id)),
                )
                .await;
            (StatusCode::CREATED, Json(row)).into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("create: {e}")),
                )
                .await;
            (
                StatusCode::BAD_REQUEST,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

pub async fn delete_target(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    AxPath(id): AxPath<i64>,
) -> impl IntoResponse {
    let action = "DELETE /v1/targets/:id";
    let target = format!("target:{id}");
    match state.targets.delete(id).await {
        Ok(true) => {
            let _ = state
                .audit
                .record_sync(&user.name, action, Some(&target), AuditOutcome::Ok, None)
                .await;
            (StatusCode::NO_CONTENT, ()).into_response()
        }
        Ok(false) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(r#"{"reason":"not found"}"#),
                )
                .await;
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "target not found"})),
            )
                .into_response()
        }
        Err(e) => {
            let _ = state
                .audit
                .record_sync(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::error_response::from_any_error(&e),
            )
                .into_response()
        }
    }
}

// (TargetRow is re-exported via the `core` crate. The
// route handlers above use it through that re-export
// path; there is no need to also re-export it here.)
