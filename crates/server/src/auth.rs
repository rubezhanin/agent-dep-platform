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
    // P0-SENT-01 (TZ #2 WP-0.3, CWE-287,
    // Appendix A.4): short-circuit on an
    // empty bearer BEFORE the DB lookup.
    //
    // The pre-fix code accepted any
    // non-empty `Authorization: Bearer <X>`
    // header, including `Bearer ""` (the
    // `extract_bearer` above does not reject
    // the empty token). The DB lookup would
    // then compute `sha256("")` and find a
    // user with the `token_hash` sentinel,
    // authenticating the request as that
    // user.
    //
    // Post-fix: an empty bearer is rejected
    // here, before any DB query. The DB
    // sentinel is now `NULL` (not
    // `sha256("")`), and a `WHERE token_hash = ?1`
    // lookup with a non-NULL bind parameter
    // can never match a NULL row, but the
    // short-circuit is defense-in-depth and
    // also avoids the SHA-256 computation on
    // the hot path.
    if token.is_empty() {
        return unauthorized(&state, &method, &path, "empty bearer token").await;
    }
    match state.users.find_by_token(&token).await {
        Ok(Some(user)) => {
            // 2.7.8 (ADR-0036): enforce
            // local bearer expiry. OIDC
            // users get a non-NULL
            // `token_expires_at`; bearer-
            // token users (2.0.0-2.7.7)
            // have `NULL` and never
            // expire.
            if let Some(expires_at) = user.token_expires_at.as_deref() {
                if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(expires_at) {
                    if expires <= chrono::Utc::now() {
                        return unauthorized(
                            &state,
                            &method,
                            &path,
                            "token expired, refresh required",
                        )
                        .await;
                    }
                }
            }
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

/// 2.11.0 (P1-F-03b, TZ #2 WP-3.3, CWE-613):
/// per-request auth middleware that
/// prefers the `agency_session` cookie
/// and falls back to the legacy
/// `Authorization: Bearer` header.
///
/// Behaviour:
/// 1. **Cookie first.** If a session
///    cookie is present and the
///    `SessionRepository::find` returns
///    a valid row, the row is converted
///    to an `AuthenticatedUser` via the
///    `users` repository (the session
///    only stores `user_id`; the role
///    comes from the user row, which is
///    the single source of truth for
///    role) and the request proceeds.
/// 2. **Bearer fallback.** If the
///    cookie path returns `None` (no
///    cookie, unknown id, expired, or
///    revoked), the middleware tries
///    the legacy bearer path. A
///    `tracing::warn!` is emitted on
///    every hit so the operator can
///    track the migration.
/// 3. **Both miss → 401.** The
///    response shape matches
///    `require_bearer`'s 401 so the SPA
///    can treat them uniformly.
///
/// The legacy `require_bearer`
/// middleware is still wired (for
/// non-migrated callers) and is left
/// in place for one release. New
/// routes should use
/// `require_session_or_bearer`.
pub async fn require_session_or_bearer(
    State(state): State<ServerState>,
    request: Request,
    next: Next,
) -> Response {
    let headers = request.headers().clone();
    let path = request.uri().path().to_string();
    let method = request.method().to_string();
    // 1. Try the session cookie.
    if let Some(sid) = crate::session_cookie::parse_session_cookie(&headers) {
        match state.sessions.find(&sid).await {
            Ok(Some(row)) => {
                // Session is valid. Look up
                // the user for role /
                // name. The session only
                // carries `user_id`; the
                // role is the user's, not
                // the session's, so the
                // `users` table is the
                // single source of truth.
                // A disabled user gets
                // 401 even with a valid
                // session — disable takes
                // effect immediately.
                match state.users.find_by_id(row.user_id).await {
                    Ok(Some(user)) if user.disabled_at.is_none() => {
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
                        return next.run(request).await;
                    }
                    Ok(_) => {
                        return unauthorized(&state, &method, &path, "session user is disabled")
                            .await;
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "require_session_or_bearer: users.find_by_id failed",
                        );
                        return (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            axum::Json(json!({"error": "auth subsystem unavailable"})),
                        )
                            .into_response();
                    }
                }
            }
            Ok(None) => {
                // Cookie present but the
                // session is unknown /
                // revoked / expired. Fall
                // through to the bearer
                // path; the cookie will
                // still be there on the
                // next request unless the
                // SPA also calls
                // `/logout` to clear it.
                tracing::debug!(
                    "require_session_or_bearer: cookie present but session invalid; \
                     falling back to bearer"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "require_session_or_bearer: sessions.find failed");
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(json!({"error": "auth subsystem unavailable"})),
                )
                    .into_response();
            }
        }
    }
    // 2. Bearer fallback (legacy path).
    //    Emit a deprecation warning so
    //    the operator can see the
    //    migration progress in the
    //    server log.
    tracing::warn!(
        "P1-F-03b: bearer auth used (no valid session cookie); \
         this path is deprecated and will be removed in 2.12.0"
    );
    require_bearer(State(state), request, next).await
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
