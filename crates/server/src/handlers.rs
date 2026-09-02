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
            let _ = state
                .audit
                .record(
                    &user.name,
                    action,
                    None,
                    AuditOutcome::Ok,
                    details.as_deref(),
                )
                .await;
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
                .record(
                    &user.name,
                    "GET /v1/audit",
                    None,
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
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
            let _ = state
                .audit
                .record(
                    &user.name,
                    &action,
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
                .record(
                    &user.name,
                    &action,
                    None,
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
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
    /// The catalog root (must be a local directory). The
    /// server re-ingests in-memory; nothing is written to
    /// the DB by the plan step.
    pub catalog: String,
    /// The system.yaml body, as a UTF-8 string. The CLI
    /// uses `read_to_string`; the server accepts the body
    /// directly so the operator does not have to ship the
    /// file separately.
    pub system_yaml: String,
}

pub async fn plan_system(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<PlanRequest>,
) -> impl IntoResponse {
    let action = "POST /v1/systems/plan".to_string();
    match plan::compute_plan(&req.catalog, &req.system_yaml).await {
        Ok(summary) => {
            let target = format!("system:{}", summary.system_id);
            let details = Some(json!({"wrote": summary.writes.len()}).to_string());
            let _ = state
                .audit
                .record(
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
                .record(
                    &user.name,
                    &action,
                    None,
                    AuditOutcome::Error,
                    Some(&format!("plan error: {e}")),
                )
                .await;
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
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
            let _ = state
                .audit
                .record(
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
                .record(
                    &user.name,
                    &action,
                    Some(&format!("operation:{id}")),
                    AuditOutcome::Error,
                    Some(&format!("rollback error: {e}")),
                )
                .await;
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
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
            let _ = state
                .audit
                .record(
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
                .record(
                    &user.name,
                    action,
                    None,
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
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
            let _ = state
                .audit
                .record(
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
                .record(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("create error: {e}")),
                )
                .await;
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
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
                .record(&user.name, action, Some(&target), AuditOutcome::Ok, None)
                .await;
            (StatusCode::NO_CONTENT, ()).into_response()
        }
        Ok(false) => {
            let _ = state
                .audit
                .record(
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
                .record(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
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
                .record(&user.name, action, Some(&target), AuditOutcome::Ok, None)
                .await;
            (StatusCode::OK, Json(json!({"id": id, "token": new_token}))).into_response()
        }
        Ok(None) => {
            let _ = state
                .audit
                .record(
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
                .record(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
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
        approved_by: r.approved_by,
        approved_at: r.approved_at.clone(),
        rejection_reason: r.rejection_reason.clone(),
        applied_at: r.applied_at.clone(),
    }
}

#[derive(Debug, Deserialize)]
pub struct DeployRequestBody {
    pub catalog: String,
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
    let target_id: Option<i64> = match req.target.as_deref() {
        None => None,
        Some(name) => match state.targets.find_by_env_name(env, name).await {
            Ok(Some(row)) => Some(row.id),
            Ok(None) => {
                let _ = state
                    .audit
                    .record(
                        &user.name,
                        action,
                        None,
                        AuditOutcome::Error,
                        Some(&format!(
                            "target `{name}` not found in environment `{}`",
                            env.as_str()
                        )),
                    )
                    .await;
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": format!(
                            "target `{name}` not found in environment `{}`",
                            env.as_str()
                        )
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                let _ = state
                    .audit
                    .record(
                        &user.name,
                        action,
                        None,
                        AuditOutcome::Error,
                        Some(&format!("target lookup: {e}")),
                    )
                    .await;
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        },
    };
    match plan::compute_plan(&req.catalog, &req.system_yaml).await {
        Ok(summary) => {
            let plan_json = match serde_json::to_string(&summary) {
                Ok(s) => s,
                Err(e) => {
                    let _ = state
                        .audit
                        .record(
                            &user.name,
                            action,
                            None,
                            AuditOutcome::Error,
                            Some(&format!("serialise plan: {e}")),
                        )
                        .await;
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": e.to_string()})),
                    )
                        .into_response();
                }
            };
            match state
                .deploys
                .request(&summary.system_id, &plan_json, user.id, env, target_id)
                .await
            {
                Ok(row) => {
                    let target = format!("deploy:{}", row.id);
                    let details = Some(
                        json!({
                            "system_id": row.system_id,
                            "writes": summary.writes.len(),
                            "environment": row.environment.as_str(),
                        })
                        .to_string(),
                    );
                    let _ = state
                        .audit
                        .record(
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
                        .record(
                            &user.name,
                            action,
                            None,
                            AuditOutcome::Error,
                            Some(&format!("persist: {e}")),
                        )
                        .await;
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": e.to_string()})),
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            let _ = state
                .audit
                .record(
                    &user.name,
                    action,
                    None,
                    AuditOutcome::Error,
                    Some(&format!("plan error: {e}")),
                )
                .await;
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
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
            let _ = state
                .audit
                .record(
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
                .record(
                    &user.name,
                    action,
                    None,
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
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
                .record(&user.name, action, Some(&target), AuditOutcome::Ok, None)
                .await;
            (StatusCode::OK, Json(deploy_view(&row))).into_response()
        }
        Ok(None) => {
            let _ = state
                .audit
                .record(
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
                .record(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
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
            let _ = state
                .audit
                .record(
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
                .record(
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
                .record(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
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
            let _ = state
                .audit
                .record(
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
                .record(
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
                .record(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
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
                .record(&user.name, action, Some(&target), AuditOutcome::Ok, None)
                .await;
            (StatusCode::OK, Json(deploy_view(&row))).into_response()
        }
        Ok(None) => {
            let _ = state
                .audit
                .record(
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
                .record(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
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
            let _ = state
                .audit
                .record(
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
                .record(
                    &user.name,
                    action,
                    None,
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
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
    match state.secrets.get_value(&name).await {
        Ok(value) => {
            let _ = state
                .audit
                .record(&user.name, action, Some(&target), AuditOutcome::Ok, None)
                .await;
            (
                StatusCode::OK,
                Json(json!({ "name": value.name, "value": value.value })),
            )
                .into_response()
        }
        Err(e) => {
            // Do NOT include the value (or even the
            // name) in the error response - surface
            // only a generic 404.
            let _ = state
                .audit
                .record(
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
            let _ = state
                .audit
                .record(
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
                .record(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("create: {e}")),
                )
                .await;
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
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
            let _ = state
                .audit
                .record(
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
                .record(
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
                .record(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("update: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
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
                .record(&user.name, action, Some(&target), AuditOutcome::Ok, None)
                .await;
            (StatusCode::NO_CONTENT, ()).into_response()
        }
        Ok(false) => {
            let _ = state
                .audit
                .record(
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
                .record(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("delete: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
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
        .record(&user.name, action, None, AuditOutcome::Ok, None)
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
            let _ = state
                .audit
                .record(
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
                .record(
                    &user.name,
                    action,
                    None,
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
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
                .record(&user.name, action, Some(&target), AuditOutcome::Ok, None)
                .await;
            (StatusCode::OK, Json(row)).into_response()
        }
        Ok(None) => {
            let _ = state
                .audit
                .record(
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
                .record(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
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
    match state
        .targets
        .create(
            &req.name,
            req.environment,
            &req.path,
            req.description.as_deref(),
        )
        .await
    {
        Ok(row) => {
            let _ = state
                .audit
                .record(
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
                .record(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("create: {e}")),
                )
                .await;
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
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
                .record(&user.name, action, Some(&target), AuditOutcome::Ok, None)
                .await;
            (StatusCode::NO_CONTENT, ()).into_response()
        }
        Ok(false) => {
            let _ = state
                .audit
                .record(
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
                .record(
                    &user.name,
                    action,
                    Some(&target),
                    AuditOutcome::Error,
                    Some(&format!("db error: {e}")),
                )
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    }
}

// (TargetRow is re-exported via the `core` crate. The
// route handlers above use it through that re-export
// path; there is no need to also re-export it here.)
