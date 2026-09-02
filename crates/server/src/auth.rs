//! Bearer-token authentication middleware (2.0.0).
//!
//! Every request to a non-`/v1/health` endpoint must
//! carry `Authorization: Bearer <token>`. The token
//! is loaded at startup from
//! `<data>/server.token` and held in the
//! `ServerState`. Requests that fail the check are
//! rejected with 401 and an `audit_log` row is
//! written with `outcome = "error"`.

use agent_dep_core::infrastructure::repository::audit_log_repository::AuditOutcome;
use axum::{
    extract::{Request, State},
    http::HeaderMap,
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::ServerState;

pub async fn require_bearer(
    State(state): State<ServerState>,
    request: Request,
    next: Next,
) -> Response {
    let headers = request.headers().clone();
    let path = request.uri().path().to_string();
    let method = request.method().to_string();
    match extract_bearer(&headers) {
        Some(t) if constant_time_eq(t.as_bytes(), state.token.as_bytes()) => {
            next.run(request).await
        }
        _ => unauthorized(state, &method, &path).await,
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

/// Constant-time byte comparison; the token is 43 chars
/// of base64-url, so any timing leak is tiny but we
/// pay the cost for the principle.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn unauthorized(state: ServerState, method: &str, path: &str) -> Response {
    let action = format!("{method} {path}");
    let outcome = AuditOutcome::Error;
    let details = json!({"reason": "missing or invalid bearer token"}).to_string();
    if let Err(e) = state
        .audit
        .record("anonymous", &action, None, outcome, Some(&details))
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
