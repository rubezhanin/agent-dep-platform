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
