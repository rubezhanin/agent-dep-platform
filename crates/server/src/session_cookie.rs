//! 2.11.0 (P1-F-03b, TZ #2 WP-3.3, CWE-613)
//! session cookie helpers.
//!
//! The 2.10.0 OIDC flow stored the local
//! bearer in the JSON body of
//! `/v1/auth/oidc/callback`; the SPA held
//! it in JS memory. That design is
//! XSS-vulnerable: any reflected XSS
//! (or a malicious dependency that
//! touches `localStorage`) reads the
//! bearer and the attacker impersonates
//! the user. The bearer is also
//! un-revocable server-side (the
//! `logout_handler` only invalidates it
//! if the `Authorization` header is
//! present in the logout request).
//!
//! P1-F-03b switches the canonical auth
//! artifact from "bearer in JSON" to
//! "server-side session id in an
//! HttpOnly+Secure+SameSite=Strict
//! cookie". The SPA never sees the
//! session id; the browser sends the
//! cookie automatically on every
//! request to the same origin. The
//! server holds the only copy of the
//! secret material; the cookie value
//! is a 32-byte random base64url
//! identifier that maps 1:1 to a row
//! in the `sessions` table (P1-F-03a).
//!
//! The legacy bearer is still returned
//! in the JSON body for one release
//! (so a frontend migration can land
//! independently of the server
//! upgrade) and `require_bearer` is
//! still wired but with a deprecation
//! warning on every hit. The new
//! `require_session_or_bearer`
//! middleware in `auth.rs` prefers
//! the session cookie and falls back
//! to the bearer for that one
//! release.
//!
//! Cookie attributes (per RFC 6265 +
//! OWASP "Session Management Cheat
//! Sheet"):
//! - `HttpOnly`: JavaScript cannot
//!   read the cookie. Mitigates XSS
//!   exfiltration.
//! - `Secure`: the cookie is only
//!   sent over HTTPS. Mitigates
//!   network sniffing. Configurable
//!   via `AGENCY_COOKIE_SECURE`
//!   (default `true`); dev /
//!   integration tests set
//!   `AGENCY_COOKIE_SECURE=0` to
//!   allow plain-HTTP localhost.
//! - `SameSite=Strict`: the cookie
//!   is not sent on cross-site
//!   navigations. Mitigates CSRF
//!   (the operator's CSRF posture is
//!   defense-in-depth — the
//!   `X-CSRF-Token` header check is
//!   also wired for state-changing
//!   requests).
//! - `Path=/`: the cookie is sent
//!   on every request to the
//!   server.
//! - `Max-Age=3600`: the browser
//!   drops the cookie after 1h of
//!   idleness. This matches the
//!   server-side `IDLE_TTL_SECS`
//!   constant. The absolute cap
//!   (`ABSOLUTE_TTL_SECS = 8h`) is
//!   enforced server-side only —
//!   browsers do not natively
//!   support a "max session
//!   lifetime" attribute.

use axum::http::HeaderMap;

/// Cookie name. Surfaced as a constant so
/// the login / refresh / logout
/// handlers, the middleware, and the
/// integration tests all agree on
/// the spelling (one typo here and
/// the whole auth path silently
/// breaks).
pub const SESSION_COOKIE_NAME: &str = "agency_session";

/// Idle expiry in seconds. Matches
/// `agent_dep_core::infrastructure::repository::sessions_repository::IDLE_TTL_SECS`
/// but the duplicate constant is
/// intentional: the cookie is set
/// on the HTTP response and the
/// server cannot update a browser's
/// `Max-Age` mid-flight. The
/// server-side value is the
/// authoritative one; the cookie
/// value is a hint to the browser.
/// If they ever drift the server
/// wins (an expired server-side
/// session is rejected with 401
/// regardless of what the browser
/// still holds).
pub const SESSION_COOKIE_MAX_AGE_SECS: i64 = 3600;

/// Build a `Set-Cookie` header value
/// that installs a fresh session
/// cookie on the client.
///
/// `secure` is the `Secure` flag. It
/// MUST be `true` in production
/// (HTTPS) and `false` only in dev
/// / integration tests over plain
/// HTTP localhost. The caller
/// passes the value from
/// `OidcConfig::cookie_secure`.
pub fn make_session_cookie_header(session_id: &str, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{name}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}",
        name = SESSION_COOKIE_NAME,
        value = session_id,
        max_age = SESSION_COOKIE_MAX_AGE_SECS,
        secure = secure_attr,
    )
}

/// Build a `Set-Cookie` header value
/// that expires the session cookie
/// on the client. Sent on
/// `/v1/auth/oidc/logout` so a
/// stolen browser session does not
/// stay alive after the user
/// explicitly logged out (the
/// server-side `revoke` is the
/// authoritative step; the cookie
/// clear is the cosmetic one).
pub fn clear_session_cookie_header(secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{name}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{secure}",
        name = SESSION_COOKIE_NAME,
        secure = secure_attr,
    )
}

/// Parse the session id from a request's
/// `Cookie` header. Returns `None` for:
/// - no `Cookie` header at all,
/// - a `Cookie` header with no
///   `agency_session=<value>` pair,
/// - an empty value (`agency_session=`,
///   which the server would reject
///   anyway).
///
/// The lookup is a linear scan over
/// the cookie pairs; cookies are
/// small and there are at most a
/// handful in practice (the server
/// does not set many). The
/// alternative — a `HashMap` from
/// the full header string — adds
/// allocations without a real
/// performance win.
pub fn parse_session_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let trimmed = pair.trim();
        if let Some(rest) = trimmed.strip_prefix(SESSION_COOKIE_NAME) {
            // Expect `=value` next.
            let value = rest.strip_prefix('=')?;
            if value.is_empty() {
                return None;
            }
            return Some(value.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn make_cookie_contains_all_required_attributes() {
        let cookie = make_session_cookie_header("abc123", true);
        assert!(cookie.starts_with("agency_session=abc123"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Max-Age=3600"));
        assert!(
            cookie.contains("Secure"),
            "Secure must be present when called with secure=true"
        );
    }

    #[test]
    fn make_cookie_omits_secure_when_requested() {
        let cookie = make_session_cookie_header("abc123", false);
        assert!(!cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));
    }

    #[test]
    fn clear_cookie_sets_max_age_zero() {
        let cookie = clear_session_cookie_header(true);
        assert!(cookie.starts_with("agency_session="));
        assert!(cookie.contains("Max-Age=0"));
        assert!(cookie.contains("Secure"));
    }

    #[test]
    fn clear_cookie_omits_secure_when_disabled() {
        let cookie = clear_session_cookie_header(false);
        assert!(cookie.contains("Max-Age=0"));
        assert!(!cookie.contains("Secure"));
    }

    #[test]
    fn parse_returns_value_for_present_cookie() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            "other=foo; agency_session=abc123; trailing=bar"
                .parse()
                .unwrap(),
        );
        assert_eq!(parse_session_cookie(&h).as_deref(), Some("abc123"));
    }

    #[test]
    fn parse_returns_value_when_cookie_is_only_pair() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            "agency_session=abc".parse().unwrap(),
        );
        assert_eq!(parse_session_cookie(&h).as_deref(), Some("abc"));
    }

    #[test]
    fn parse_returns_none_when_no_cookie_header() {
        let h = HeaderMap::new();
        assert!(parse_session_cookie(&h).is_none());
    }

    #[test]
    fn parse_returns_none_when_session_cookie_absent() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            "other=foo; another=bar".parse().unwrap(),
        );
        assert!(parse_session_cookie(&h).is_none());
    }

    #[test]
    fn parse_returns_none_for_empty_value() {
        // `agency_session=` is treated as
        // missing — a clear-cookie response
        // sends exactly that, and the
        // middleware should not try to
        // look it up.
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            "agency_session=".parse().unwrap(),
        );
        assert!(parse_session_cookie(&h).is_none());
    }

    #[test]
    fn parse_handles_untrimmed_whitespace() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            "  agency_session=abc123  ;  other=foo  ".parse().unwrap(),
        );
        assert_eq!(parse_session_cookie(&h).as_deref(), Some("abc123"));
    }
}
