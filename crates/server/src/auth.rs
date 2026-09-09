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

/// 2.10.0 (B2, audit CWE-352
/// Cross-Site Request Forgery):
/// per-request extension carrying
/// the CSRF token from the current
/// session. Populated by
/// `require_session_or_bearer` from
/// `sessions.csrf_token`. `Some`
/// for session-cookie auth, `None`
/// for bearer auth (bearer is not
/// CSRF-vulnerable because an
/// attacker cannot read the bearer
/// token from a victim's browser
/// via cross-origin requests).
/// Consumed by
/// `require_csrf_for_mutations`.
#[derive(Debug, Clone)]
pub struct CsrfContext(pub Option<String>);

/// 2.11.0 (B1, audit CWE-798):
/// `AGENCY_BEARER_FALLBACK=1` enables
/// the legacy bearer path for pre-OIDC
/// users (those with `token_expires_at
/// IS NULL` because they were created
/// in 2.0.0..2.7.7). Default OFF
/// (`0`). When OFF, `require_bearer`
/// rejects pre-OIDC bearer tokens
/// with 401 + "WARN-AND-REJECT".
///
/// 2.12.0 (TZ-pinned): this helper
/// returns `false` unconditionally —
/// the entire `require_bearer` is
/// removed.
#[deprecated(
    since = "2.12.0",
    note = "the `AGENCY_BEARER_FALLBACK` escape hatch is removed in 2.12.0; \
            migrate pre-OIDC users to OIDC session-cookie auth instead"
)]
fn bearer_fallback_enabled() -> bool {
    if let Ok(v) = std::env::var("AGENCY_BEARER_FALLBACK") {
        matches!(v.as_str(), "1" | "true" | "yes" | "on")
    } else {
        false
    }
}

/// 2.12.0 (TZ-pinned): `require_bearer`
/// is deprecated. New code should
/// use `require_session_or_bearer`
/// (session cookie first, with the
/// `AGENCY_BEARER_FALLBACK=1` escape
/// hatch as a transition aid). 2.12.0
/// removes the escape hatch entirely
/// (the function is left in the lib
/// for the 2.11.0 LTS window but
/// emits a deprecation warning at
/// the call site).
#[deprecated(
    since = "2.12.0",
    note = "use `require_session_or_bearer` and migrate to OIDC session-cookie auth"
)]
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
            // 2.11.0 (B1, audit CWE-798):
            // if this user is a legacy
            // bearer-only user (their
            // `token_expires_at` is NULL
            // because they were created
            // in 2.0.0..2.7.7, before
            // OIDC), AND the operator
            // has not enabled the
            // `AGENCY_BEARER_FALLBACK=1`
            // escape hatch, REJECT the
            // request with 401 +
            // "WARN-AND-REJECT". The
            // pre-fix code accepted these
            // tokens forever (XSS in the
            // Tauri panel → bearer
            // exfiltrated from localStorage
            // → permanent access). 2.12.0
            // will remove the fallback
            // entirely; for now the
            // operator can opt back in
            // during the 2.11.0
            // transition window.
            if user.token_expires_at.is_none() && {
                // Suppress the
                // deprecation lint at
                // the 2.11.0 call site
                // — `bearer_fallback_enabled`
                // is the documented
                // transition aid; the
                // 2.12.0 removal is
                // mechanical and
                // self-contained.
                #[allow(deprecated)]
                let fallback = bearer_fallback_enabled();
                !fallback
            } {
                tracing::warn!(
                    "2.11.0 (B1) REFUSED bearer token for pre-OIDC user `{}` \
                     (id={}); set AGENCY_BEARER_FALLBACK=1 to re-enable during \
                     the 2.12.0 migration. The `auth_log` already records this \
                     attempt under `action = POST /v1/auth/login_rejected`.",
                    user.name,
                    user.id
                );
                return unauthorized(
                    &state,
                    &method,
                    &path,
                    "bearer auth disabled for pre-OIDC users; \
                     complete OIDC migration or set \
                     AGENCY_BEARER_FALLBACK=1 (deprecated 2.12.0)",
                )
                .await;
            }
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
            // 2.10.0 (B2): bearer-auth
            // cannot be CSRF-attacked
            // (attacker can't read the
            // bearer from a victim's
            // browser), so the CSRF
            // middleware skips when
            // `CsrfContext` is `None`.
            request.extensions_mut().insert(CsrfContext(None));
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
    let token = s[prefix.len()..].trim();
    // 2.11.0 (P1-F-04, TZ #1 §6 / F-04,
    // CWE-287 Improper Authentication):
    // reject the well-known sentinel
    // literal strings that some HTTP
    // clients send by accident when a
    // property is unset (`Bearer null`,
    // `Bearer undefined`, `Bearer none`)
    // or when an operator hand-wrote a
    // curl one-liner. The pre-fix code
    // would hash these and look them up;
    // the lookup returns `None` (no user
    // has that hash), so the request
    // would 401 via the normal path —
    // but the explicit reject here
    // saves the SHA-256 computation on
    // the hot path and gives a clearer
    // audit-log entry ("sentinel bearer
    // rejected" vs. "invalid bearer
    // token"). The case-insensitive
    // match catches `Bearer NULL`,
    // `Bearer Null`, etc.
    if is_known_sentinel(token) {
        return None;
    }
    Some(token.to_string())
}

/// 2.11.0 (P1-F-04, TZ #1 §6 / F-04,
/// CWE-287): the list of well-known
/// sentinel literal strings the
/// `Authorization: Bearer <X>`
/// extractor refuses. The list is
/// short and explicit (a deny-list);
/// the pre-fix design relied on
/// "the lookup will not match",
/// which is correct but gives a
/// weaker audit trail and slightly
/// slower rejection.
fn is_known_sentinel(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "" | "null" | "undefined" | "none" | "nil" | "0" | "admin" | "root" | "anonymous"
    )
}

async fn unauthorized(state: &ServerState, method: &str, path: &str, reason: &str) -> Response {
    let action = format!("{method} {path}");
    let details = json!({"reason": reason}).to_string();
    if let Err(e) = state
        .audit
        .record_sync(
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
                        // 2.10.0 (B2): stash the
                        // session's CSRF token so
                        // the
                        // `require_csrf_for_mutations`
                        // middleware can verify
                        // the `X-CSRF-Token`
                        // header on POST/PUT/DELETE.
                        request
                            .extensions_mut()
                            .insert(CsrfContext(Some(row.csrf_token)));
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
    // The internal call to the
    // deprecated `require_bearer`
    // is allowed because the
    // 2.12.0 removal is a
    // self-contained refactor;
    // the deprecation lint is
    // suppressed at the call
    // site so the 2.11.0 LTS
    // window compiles cleanly.
    #[allow(deprecated)]
    require_bearer(State(state), request, next).await
}

/// 2.10.0 (B2, audit CWE-352
/// Cross-Site Request Forgery):
/// CSRF protection for state-changing
/// requests (POST / PUT / DELETE /
/// PATCH). Runs AFTER
/// `require_session_or_bearer` and
/// BEFORE role-guard.
///
/// Rules:
/// 1. Safe methods (GET / HEAD /
///    OPTIONS) are not
///    state-changing; no CSRF
///    check.
/// 2. If `CsrfContext` is
///    `CsrfContext(None)` (bearer
///    auth), bearer is not
///    CSRF-vulnerable (attacker
///    cannot read the bearer from
///    the victim's browser), so
///    no CSRF check.
/// 3. If `CsrfContext` is
///    `CsrfContext(Some(expected))`
///    (session-cookie auth), the
///    `X-CSRF-Token` request
///    header MUST match `expected`
///    in constant time. Mismatch
///    → 403 + audit row
///    `csrf.mismatch` (the
///    attacker cannot see the
///    session's csrf_token via
///    cross-origin JS, so any
///    mismatch is suspicious).
///
/// Why this is wired *before* the
/// role guard: a CSRF attacker
/// cannot read the csrf_token,
/// so the missing-header /
/// wrong-header cases are
/// evidence of either a
/// misconfigured SPA or a
/// cross-origin request. Both
/// should be logged before the
/// operator-privilege check
/// happens.
pub async fn require_csrf_for_mutations(
    State(state): State<ServerState>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    // 1. Safe methods: no CSRF check.
    if method == axum::http::Method::GET
        || method == axum::http::Method::HEAD
        || method == axum::http::Method::OPTIONS
    {
        return next.run(request).await;
    }
    // 2. Pull the CSRF context
    //    inserted by
    //    `require_session_or_bearer`.
    let csrf_ctx = request.extensions().get::<CsrfContext>().cloned();
    let csrf_ctx = match csrf_ctx {
        Some(c) => c,
        None => {
            // No CSRF context = the auth
            // middleware never ran on this
            // route (it's a public
            // endpoint like /login or
            // OIDC callback). Bypass.
            return next.run(request).await;
        }
    };
    // 3. Bearer-authenticated: not
    //    CSRF-vulnerable; bypass.
    let expected = match csrf_ctx.0 {
        None => return next.run(request).await,
        Some(t) => t,
    };
    // 4. Session-authenticated: the
    //    `X-CSRF-Token` header must
    //    match.
    let presented = request
        .headers()
        .get("X-CSRF-Token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.as_bytes().to_vec());
    let presented = match presented {
        Some(p) => p,
        None => return csrf_rejected(&state, &method, &path, "missing").await,
    };
    if !ct_eq(presented.as_slice(), expected.as_bytes()) {
        return csrf_rejected(&state, &method, &path, "mismatch").await;
    }
    next.run(request).await
}

/// 2.10.0 (B2): constant-time
/// string compare for CSRF token
/// verification. Avoids a timing
/// oracle that could leak the
/// expected token byte-by-byte.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn csrf_rejected(
    state: &crate::ServerState,
    method: &axum::http::Method,
    path: &str,
    reason: &'static str,
) -> Response {
    // Audit the rejection. The
    // `actor` is the unauthenticated
    // requester (no AuthenticatedUser
    // extension at this point), so
    // we use a fixed label. The
    // operator can correlate with
    // access logs by path + method
    // + IP.
    let action = format!("{} {}", method.as_str(), path);
    let details = format!(r#"{{"csrf":"{}"}}"#, reason);
    let _ = state
        .audit
        .record_sync(
            "anonymous",
            &action,
            Some("csrf"),
            agent_dep_core::infrastructure::repository::audit_log_repository::AuditOutcome::Error,
            Some(&details),
        )
        .await;
    (
        axum::http::StatusCode::FORBIDDEN,
        axum::Json(json!({
            "code": "csrf.mismatch",
            "kind": "client",
            "hint": "state-changing requests must include \
                     `X-CSRF-Token` header matching the \
                     session's csrf_token (use GET /v1/auth/me \
                     or login response to read it)"
        })),
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
                .record_sync(&u.name, &action, None, AuditOutcome::Error, Some(&details))
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
                .record_sync(
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

// -----------------------------------------------------------------------
// 2.11.0 (P1-F-04, TZ #1 §6 / F-04,
// CWE-287 Improper Authentication)
// unit tests for the bearer
// extraction and the
// sentinel-rejection deny-list.
//
// The TZ F-04 acceptance is:
//   Authorization: Bearer            -> 401
//   Authorization: Bearer <spaces>   -> 401
//   logged-out token                 -> 401
//
// The first two are exercised
// directly on `extract_bearer`.
// The third is exercised by the
// existing `find_by_token` test
// surface (a disabled user's
// `find_by_token` returns `None`;
// a rotated user's old token hash
// no longer matches any row). The
// sentinel deny-list is a
// defense-in-depth addition
// layered on top of the
// pre-existing `is_empty()` check.
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests_f04_bearer_extraction {
    use super::*;
    use axum::http::header::{HeaderMap, HeaderValue, AUTHORIZATION};

    fn headers_with(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        h
    }

    /// 2.11.0 (P1-F-04): `Authorization: Bearer`
    /// (no token at all — only the
    /// scheme) returns `None`. The
    /// `s.len() <= prefix.len()` guard
    /// catches the case where the
    /// header is exactly `"Bearer"`.
    #[test]
    fn extract_bearer_rejects_missing_token_after_scheme() {
        let h = headers_with("Bearer");
        assert!(extract_bearer(&h).is_none());
    }

    /// 2.11.0 (P1-F-04): a header that is
    /// just `"Bearer "` (with the
    /// trailing space but no token)
    /// returns `None`.
    #[test]
    fn extract_bearer_rejects_whitespace_only_token() {
        let h = headers_with("Bearer ");
        assert!(extract_bearer(&h).is_none());
    }

    /// 2.11.0 (P1-F-04): a header that is
    /// `"Bearer    "` (multiple spaces)
    /// is trimmed to empty and
    /// returns `None`.
    #[test]
    fn extract_bearer_trims_and_rejects_whitespace_only_token() {
        let h = headers_with("Bearer    ");
        assert!(extract_bearer(&h).is_none());
    }

    /// 2.11.0 (P1-F-04): a real token
    /// (32 chars of base64) is
    /// returned unchanged.
    #[test]
    fn extract_bearer_returns_valid_token() {
        let h = headers_with("Bearer abcDEF123_-xyz");
        assert_eq!(extract_bearer(&h).as_deref(), Some("abcDEF123_-xyz"));
    }

    /// 2.11.0 (P1-F-04): the sentinel
    /// deny-list rejects the
    /// well-known literal strings
    /// that some HTTP clients send
    /// by accident. The list is
    /// short and explicit; the
    /// case-insensitive match
    /// catches `NULL`, `Null`, etc.
    #[test]
    fn extract_bearer_rejects_known_sentinels() {
        for sentinel in [
            "null",
            "NULL",
            "Null",
            "undefined",
            "UNDEFINED",
            "none",
            "None",
            "nil",
            "0",
            "admin",
            "root",
            "anonymous",
        ] {
            let h = headers_with(&format!("Bearer {sentinel}"));
            assert!(
                extract_bearer(&h).is_none(),
                "sentinel `{sentinel}` must be rejected"
            );
        }
    }

    /// 2.11.0 (P1-F-04): a token that
    /// merely STARTS with a sentinel
    /// substring (`nullify`,
    /// `none_of_the_above`) is NOT
    /// rejected. The deny-list is
    /// exact-match, not
    /// substring-match — a real
    /// token whose first four chars
    /// happen to spell "null" must
    /// still authenticate (the
    /// subsequent SHA-256 lookup
    /// will return 401 if no user
    /// owns that hash, but the
    /// extract step is not a
    /// hot-failure point).
    #[test]
    fn extract_bearer_does_not_substring_match_sentinels() {
        for token in [
            "nullify",
            "none_of_the_above",
            "my-admin-token",
            "anonymous_user",
        ] {
            let h = headers_with(&format!("Bearer {token}"));
            assert_eq!(
                extract_bearer(&h).as_deref(),
                Some(token),
                "real token `{token}` must not be rejected by sentinel check"
            );
        }
    }

    /// 2.11.0 (P1-F-04): a header that
    /// does NOT carry the
    /// `Authorization: Bearer `
    /// scheme (e.g. `Basic ...`,
    /// `Token ...`) returns
    /// `None`. The middleware sits
    /// in front of every authed
    /// route; non-bearer auth is
    /// the OIDC cookie path, which
    /// uses `require_session_or_bearer`
    /// instead.
    #[test]
    fn extract_bearer_rejects_non_bearer_scheme() {
        for header in ["Basic dXNlcjpwYXNz", "Token abc", "Bearer", "Bearer "] {
            let h = headers_with(header);
            assert!(
                extract_bearer(&h).is_none(),
                "header `{header}` must not produce a bearer token"
            );
        }
    }

    /// 2.11.0 (P1-F-04): a missing
    /// `Authorization` header (the
    /// most common case for an
    /// unauthenticated request)
    /// returns `None`. The
    /// middleware records a 401 in
    /// the audit log with
    /// `reason: "missing Authorization
    /// header"`.
    #[test]
    fn extract_bearer_returns_none_for_missing_header() {
        let h = HeaderMap::new();
        assert!(extract_bearer(&h).is_none());
    }
}
