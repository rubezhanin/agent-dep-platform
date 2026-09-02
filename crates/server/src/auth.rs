//! Per-user RBAC middleware (2.1.0, ADR-0019).
//!
//! Replaces the 2.0.0 single-bearer-token middleware
//! with a `UserRepository` lookup. The token's
//! sha256-hashed form is matched against the
//! `users` table; the resulting `UserRow` (name +
//! role) is attached to the request extensions and
//! the audit log writes the user `name` as the
//! `actor`. Unauthenticated requests still record
//! `actor = "anonymous"` on a 401 so the operator
//! sees brute-force probes.

use agent_dep_core::infrastructure::repository::audit_log_repository::AuditOutcome;
use agent_dep_core::infrastructure::repository::users_repository::Role;
use axum::{
    extract::{Request, State},
    http::HeaderMap,
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::state::ServerState;

/// Per-request extension carrying the authenticated
/// user. Handlers grab this via
/// `axum::Extension<AuthenticatedUser>` and check
/// `role` for their endpoint.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub id: i64,
    pub name: String,
    pub role: Role,
}

pub async fn require_bearer(
    State(state): State<ServerState>,
    request: Request,
    next: Next,
) -> Response {
    let headers = request.headers().clone();
    let path = request.uri().path().to_string();
    let method = request.method().to_string();
    let token = match extract_bearer(&headers) {
        Some(t) => t,
        None => {
            return unauthorized(&state, &method, &path, "missing Authorization header").await;
        }
    };
    match state.users.find_by_token(&token).await {
        Ok(Some(user)) => {
            let user_id = user.id;
            let repo = state.users.clone();
            tokio::spawn(async move {
                let _ = repo.touch_last_seen(user_id).await;
            });
            let mut request = request;
            request.extensions_mut().insert(AuthenticatedUser {
                id: user.id,
                name: user.name,
                role: user.role,
            });
            next.run(request).await
        }
        Ok(None) => unauthorized(&state, &method, &path, "invalid bearer token").await,
        Err(e) => {
            tracing::warn!(error = %e, "users.find_by_token failed");
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "auth subsystem unavailable"})),
            )
                .into_response()
        }
    }
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let h = headers.get(axum::http::header::AUTHORIZATION)?;
    let s = h.to_str().ok()?;
    let prefix = "Bearer ";
    if s.len() <= prefix.len() {
        return None;
    }
    if !s.starts_with(prefix) {
        return None;
    }
    Some(s[prefix.len()..].trim().to_string())
}

async fn unauthorized(state: &ServerState, method: &str, path: &str, reason: &str) -> Response {
    let action = format!("{method} {path}");
    let details = json!({"reason": reason}).to_string();
    if let Err(e) = state
        .audit
        .record(
            "anonymous",
            &action,
            None,
            AuditOutcome::Error,
            Some(&details),
        )
        .await
    {
        tracing::warn!(error = %e, "audit record failed for 401");
    }
    (
        axum::http::StatusCode::UNAUTHORIZED,
        axum::Json(json!({"error": "unauthorized"})),
    )
        .into_response()
}

/// Per-route role-check inner function. Wired by
/// `lib::router` via `axum::middleware::from_fn_with_state`.
pub async fn check_role(state: ServerState, request: Request, next: Next) -> Response {
    let allowed: Vec<Role> = request
        .extensions()
        .get::<AllowedRoles>()
        .cloned()
        .unwrap_or_default()
        .0;
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let action = format!("{method} {path}");
    let user = request.extensions().get::<AuthenticatedUser>().cloned();
    match user {
        Some(u) if allowed.contains(&u.role) => next.run(request).await,
        Some(u) => {
            let details = json!({
                "reason": "role not allowed",
                "user_role": u.role.as_str(),
            })
            .to_string();
            let _ = state
                .audit
                .record(&u.name, &action, None, AuditOutcome::Error, Some(&details))
                .await;
            (
                axum::http::StatusCode::FORBIDDEN,
                axum::Json(json!({"error": "forbidden"})),
            )
                .into_response()
        }
        None => {
            let _ = state
                .audit
                .record(
                    "anonymous",
                    &action,
                    None,
                    AuditOutcome::Error,
                    Some(r#"{"reason":"no auth extension"}"#),
                )
                .await;
            (
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(json!({"error": "unauthorized"})),
            )
                .into_response()
        }
    }
}

/// Extension type carrying the allowed roles for
/// `check_role`. The router inserts this into the
/// request before calling the layer.
#[derive(Clone, Default)]
pub struct AllowedRoles(pub Vec<Role>);
