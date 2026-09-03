//! 2.7.6 OIDC authentication (ADR-0034).
//!
//! Implements the OIDC authorization-code
//! flow as an alternative to bearer-token
//! auth. The bearer-token path is unchanged;
//! OIDC is opt-in via env vars and runs in
//! parallel.
//!
//! 2.7.6 scope is the framework (config,
//! state map, role mapping, user
//! provisioning, mock client + tests).
//! The `RealOidcClient` that does the actual
//! `openidconnect` wire-protocol exchange is
//! a 2.7.7 follow-up — its absence is the
//! reason the env vars don't enable
//! "real" production use yet.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use rand::RngCore;

use agent_dep_core::error::CoreResult;
use agent_dep_core::infrastructure::repository::audit_log_repository::AuditOutcome;
use agent_dep_core::infrastructure::repository::users_repository::{Role, UserRepository};

use crate::auth::AuthenticatedUser;
use crate::oidc_client::CallbackInput;
use crate::ServerState;

/// Configuration for the OIDC client. Read
/// at server start from env vars.
#[derive(Debug, Clone, Default)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub role_claim: String,
    pub admin_groups: Vec<String>,
    pub operator_groups: Vec<String>,
    /// When true, the OIDC endpoints serve
    /// a mock flow (for local development
    /// without a real IdP). 2.7.6 ships
    /// with this true by default; 2.7.7
    /// switches the default to false and
    /// requires a real IdP.
    pub mock: bool,
}

impl OidcConfig {
    /// Read config from environment variables.
    pub fn from_env() -> Self {
        let split = |s: &str| s.split_whitespace().map(String::from).collect();
        Self {
            issuer: std::env::var("AGENCY_OIDC_ISSUER").unwrap_or_default(),
            client_id: std::env::var("AGENCY_OIDC_CLIENT_ID").unwrap_or_default(),
            client_secret: std::env::var("AGENCY_OIDC_CLIENT_SECRET").ok(),
            redirect_uri: std::env::var("AGENCY_OIDC_REDIRECT_URI").unwrap_or_default(),
            scopes: split(
                &std::env::var("AGENCY_OIDC_SCOPES")
                    .unwrap_or_else(|_| "openid email profile".to_string()),
            ),
            role_claim: std::env::var("AGENCY_OIDC_ROLE_CLAIM")
                .unwrap_or_else(|_| "groups".to_string()),
            admin_groups: split(&std::env::var("AGENCY_OIDC_ADMIN_GROUPS").unwrap_or_default()),
            operator_groups: split(
                &std::env::var("AGENCY_OIDC_OPERATOR_GROUPS").unwrap_or_default(),
            ),
            // 2.7.7 (ADR-0035): the default
            // flipped from `1` (2.7.6) to `0`
            // (2.7.7). The real wire-protocol
            // client is the new default.
            // Operators who were relying on
            // the mock in production must set
            // `AGENCY_OIDC_MOCK=1` explicitly
            // (typically only in dev / CI).
            mock: std::env::var("AGENCY_OIDC_MOCK")
                .ok()
                .map(|s| s == "1" || s == "true")
                .unwrap_or(false),
        }
    }

    /// True iff OIDC is enabled (env vars
    /// present or `AGENCY_OIDC_MOCK=1`).
    pub fn is_enabled(&self) -> bool {
        !self.issuer.is_empty() || self.mock
    }
}

/// In-memory state for the OIDC flow: maps
/// the `state` token (CSRF) to the
/// (verifier, nonce, created_at) tuple.
pub type OidcPending = Arc<Mutex<HashMap<String, PendingAuth>>>;

#[derive(Debug, Clone)]
pub struct PendingAuth {
    pub pkce_verifier: String,
    pub nonce: String,
    pub created_at: std::time::Instant,
}

impl PendingAuth {
    pub fn is_expired(&self, max_age: std::time::Duration) -> bool {
        self.created_at.elapsed() > max_age
    }
}

/// Map IdP claims to a local `Role`. The
/// `role_claim` field of the ID token is
/// expected to be a JSON array of strings
/// (e.g. `["sre", "admin"]`) or a single
/// string.
pub fn map_claims_to_role(
    claims: &serde_json::Value,
    role_claim: &str,
    admin_groups: &[String],
    operator_groups: &[String],
) -> Role {
    let value = claims.get(role_claim);
    let groups: Vec<String> = match value {
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    };
    if groups.iter().any(|g| admin_groups.iter().any(|a| a == g)) {
        Role::Admin
    } else if groups
        .iter()
        .any(|g| operator_groups.iter().any(|o| o == g))
    {
        Role::Operator
    } else {
        Role::Viewer
    }
}

/// Generate a 32-byte random state, base64url.
pub fn generate_state() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate a 32-byte PKCE verifier, base64url.
pub fn generate_pkce_verifier() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate a 16-byte nonce, base64url.
pub fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Derive a PKCE S256 `code_challenge`
/// from a verifier. The verifier is a
/// high-entropy random string; the
/// challenge is
/// `BASE64URL(SHA256(verifier))`.
pub fn pkce_challenge_from_verifier(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(verifier.as_bytes());
    let digest = h.finalize();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// The login handler. Generates state +
/// PKCE + nonce, stores them in the
/// pending map, and returns the IdP's
/// authorize URL.
pub fn handle_login(state: &ServerState) -> CoreResult<(String, String)> {
    if !state.oidc.is_enabled() {
        return Err(agent_dep_core::error::CoreError::ErrSchemaInvalid {
            path: "oidc.config".to_string(),
            reason: "OIDC not configured (set AGENCY_OIDC_ISSUER et al.)".to_string(),
        });
    }
    let state_token = generate_state();
    let pkce = generate_pkce_verifier();
    let nonce = generate_nonce();
    let code_challenge = pkce_challenge_from_verifier(&pkce);
    let mut pending = state.oidc_pending.lock().expect("oidc_pending lock");
    pending.insert(
        state_token.clone(),
        PendingAuth {
            pkce_verifier: pkce,
            nonce: nonce.clone(),
            created_at: std::time::Instant::now(),
        },
    );
    // 2.7.7 (ADR-0035): delegate URL
    // assembly to the configured
    // `OidcClient` (real or mock).
    let authorize_url = state.oidc_client.authorize_url(
        &state_token,
        &code_challenge,
        &nonce,
    )?;
    Ok((authorize_url, state_token))
}

/// Validate an OIDC state token.
pub fn validate_state(pending: &OidcPending, state_param: &str) -> CoreResult<PendingAuth> {
    let mut pending = pending.lock().expect("oidc_pending lock");
    let entry = pending.remove(state_param);
    match entry {
        Some(e) if !e.is_expired(std::time::Duration::from_secs(600)) => Ok(e),
        Some(_) => Err(agent_dep_core::error::CoreError::ErrSchemaInvalid {
            path: "oidc.state".to_string(),
            reason: "state expired".to_string(),
        }),
        None => Err(agent_dep_core::error::CoreError::ErrSchemaInvalid {
            path: "oidc.state".to_string(),
            reason: "unknown state".to_string(),
        }),
    }
}

/// Result of `/v1/auth/oidc/callback`.
#[derive(Debug, Clone)]
pub struct OidcCallbackResult {
    pub token: String,
    pub user: AuthenticatedUser,
}

/// Map IdP claims to a local user, create
/// if first login, issue a bearer token.
pub async fn provision_user_from_claims(
    state: &ServerState,
    claims: &serde_json::Value,
) -> CoreResult<OidcCallbackResult> {
    let sub = claims.get("sub").and_then(|v| v.as_str()).ok_or_else(|| {
        agent_dep_core::error::CoreError::ErrSchemaInvalid {
            path: "oidc.claims".to_string(),
            reason: "missing `sub` claim".to_string(),
        }
    })?;
    let email = claims.get("email").and_then(|v| v.as_str()).unwrap_or(sub);
    let name = claims
        .get("preferred_username")
        .and_then(|v| v.as_str())
        .unwrap_or(email);
    let role = map_claims_to_role(
        claims,
        &state.oidc.role_claim,
        &state.oidc.admin_groups,
        &state.oidc.operator_groups,
    );
    let users = UserRepository::new(state.db.pool().clone());
    let user = match users.find_by_external_id(sub).await.map_err(|e| {
        agent_dep_core::error::CoreError::ErrSchemaInvalid {
            path: "oidc.provision".to_string(),
            reason: format!("find_by_external_id: {e}"),
        }
    })? {
        Some(existing) => existing,
        None => users
            .create_with_external_id(name, role, sub)
            .await
            .map_err(|e| agent_dep_core::error::CoreError::ErrSchemaInvalid {
                path: "oidc.provision".to_string(),
                reason: format!("create: {e}"),
            })?,
    };
    // Issue a fresh bearer token for the
    // local user.
    use agent_dep_core::infrastructure::repository::users_repository::{
        generate_token, sha256_hex,
    };
    let token = generate_token();
    let token_hash = sha256_hex(token.as_bytes());
    state
        .users
        .store_token_hash(user.id, &token_hash)
        .await
        .map_err(|e| agent_dep_core::error::CoreError::ErrSchemaInvalid {
            path: "oidc.provision".to_string(),
            reason: format!("store token: {e}"),
        })?;
    let _ = state
        .audit
        .record(
            &user.name,
            "oidc.login",
            Some(&format!("user:{}", user.id)),
            AuditOutcome::Ok,
            Some(&format!("{{\"sub\":\"{sub}\"}}")),
        )
        .await;
    Ok(OidcCallbackResult {
        token,
        user: AuthenticatedUser {
            id: user.id,
            name: user.name.clone(),
            role: user.role,
        },
    })
}

/// Test helper: build claims with a hard-coded
/// test user. Used by the integration test
/// and by the mock-IdP scenario.
pub fn mock_oidc_claims() -> serde_json::Value {
    serde_json::json!({
        "sub": "oidc:test:user-1",
        "email": "test-user@example.com",
        "preferred_username": "test-user",
        "groups": []
    })
}

// ---------------------------------------------------------------------------
// Axum handlers (2.7.6, ADR-0034).
// ---------------------------------------------------------------------------

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;

/// 302-redirect to the IdP's `/authorize`
/// endpoint. Generates `state` (CSRF) and
/// PKCE and nonce, stores them in
/// `state.oidc_pending`, and returns the
/// authorize URL.
pub async fn login_handler(State(state): State<ServerState>) -> Response {
    match handle_login(&state) {
        Ok((authorize_url, _state_token)) => {
            // 302 redirect.
            (
                StatusCode::FOUND,
                [(axum::http::header::LOCATION, authorize_url)],
            )
                .into_response()
        }
        Err(e) => {
            tracing::warn!("OIDC login: {e}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": format!("{e}")})),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

/// 200-OK with `{token, user}` on success.
/// The SPA stores the token and uses it as
/// a bearer for subsequent requests.
///
/// 2.7.7 (ADR-0035): exchanges the
/// authorization code via the configured
/// `OidcClient` (real or mock) BEFORE
/// provisioning the local user.
pub async fn callback_handler(
    State(state): State<ServerState>,
    Query(q): Query<CallbackQuery>,
) -> Response {
    // 1. Verify state.
    let pending = match validate_state(&state.oidc_pending, &q.state) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("{e}")})),
            )
                .into_response();
        }
    };
    // 2. Exchange the code via the
    //    configured OidcClient.
    let claims = match state
        .oidc_client
        .exchange_code(CallbackInput {
            code: q.code.clone(),
            state: q.state.clone(),
            pkce_verifier: pending.pkce_verifier.clone(),
            nonce: pending.nonce.clone(),
        })
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("OIDC callback exchange_code: {e}");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("{e}")})),
            )
                .into_response();
        }
    };
    // 3. Build the claims JSON the
    //    framework expects.
    let claims_json = serde_json::json!({
        "sub": claims.sub,
        "email": claims.email,
        "preferred_username": claims.preferred_username,
        state.oidc.role_claim.clone(): claims.role_claim_value,
    });
    // 4. Provision the local user.
    match provision_user_from_claims(&state, &claims_json).await {
        Ok(out) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "token": out.token,
                "user": {
                    "id": out.user.id,
                    "name": out.user.name,
                    "role": format!("{:?}", out.user.role),
                }
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Tests (2.7.6)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_claims_admin_groups_promote_to_admin() {
        let claims = serde_json::json!({
            "sub": "u1",
            "email": "u1@example.com",
            "groups": ["sre", "admin"]
        });
        let role = map_claims_to_role(
            &claims,
            "groups",
            &["admin".to_string()],
            &["sre".to_string()],
        );
        assert_eq!(role, Role::Admin);
    }

    #[test]
    fn map_claims_operator_groups_promote_to_operator() {
        let claims = serde_json::json!({
            "sub": "u1",
            "groups": ["sre"]
        });
        let role = map_claims_to_role(
            &claims,
            "groups",
            &["admin".to_string()],
            &["sre".to_string()],
        );
        assert_eq!(role, Role::Operator);
    }

    #[test]
    fn map_claims_default_to_viewer() {
        let claims = serde_json::json!({
            "sub": "u1",
            "groups": ["random"]
        });
        let role = map_claims_to_role(
            &claims,
            "groups",
            &["admin".to_string()],
            &["sre".to_string()],
        );
        assert_eq!(role, Role::Viewer);
    }

    #[test]
    fn map_claims_single_string_role_claim() {
        let claims = serde_json::json!({
            "sub": "u1",
            "groups": "admin"
        });
        let role = map_claims_to_role(
            &claims,
            "groups",
            &["admin".to_string()],
            &["sre".to_string()],
        );
        assert_eq!(role, Role::Admin);
    }

    #[test]
    fn map_claims_missing_role_claim_defaults_viewer() {
        let claims = serde_json::json!({"sub": "u1"});
        let role = map_claims_to_role(&claims, "groups", &[], &[]);
        assert_eq!(role, Role::Viewer);
    }

    #[test]
    fn generate_state_is_43_chars_base64url() {
        let s = generate_state();
        // 32 bytes -> 43 chars base64url no-pad.
        assert_eq!(s.len(), 43);
        // base64url alphabet.
        for c in s.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "non-base64url char: {c}"
            );
        }
    }

    #[test]
    fn generate_state_and_nonce_are_unique() {
        let a = generate_state();
        let b = generate_state();
        assert_ne!(a, b);
        let x = generate_nonce();
        let y = generate_nonce();
        assert_ne!(x, y);
    }

    #[test]
    fn validate_state_matching_token() {
        let pending: OidcPending = Arc::new(Mutex::new(HashMap::new()));
        pending.lock().unwrap().insert(
            "abc".to_string(),
            PendingAuth {
                pkce_verifier: "v".to_string(),
                nonce: "n".to_string(),
                created_at: std::time::Instant::now(),
            },
        );
        let entry = validate_state(&pending, "abc").expect("match");
        assert_eq!(entry.pkce_verifier, "v");
    }

    #[test]
    fn validate_state_rejects_unknown_token() {
        let pending: OidcPending = Arc::new(Mutex::new(HashMap::new()));
        let err = validate_state(&pending, "missing").expect_err("must reject");
        assert!(format!("{err:?}").contains("unknown state"));
    }

    #[test]
    fn validate_state_rejects_expired_token() {
        let pending: OidcPending = Arc::new(Mutex::new(HashMap::new()));
        pending.lock().unwrap().insert(
            "abc".to_string(),
            PendingAuth {
                pkce_verifier: "v".to_string(),
                nonce: "n".to_string(),
                // Backdate so it's already expired.
                created_at: std::time::Instant::now() - std::time::Duration::from_secs(700),
            },
        );
        let err = validate_state(&pending, "abc").expect_err("must reject expired");
        assert!(format!("{err:?}").contains("expired"));
    }

    /// 2.7.7 (ADR-0035): the default
    /// for `AGENCY_OIDC_MOCK` flipped
    /// from `1` (2.7.6) to `0` (2.7.7).
    /// The real wire-protocol client is
    /// the new default. Operators who
    /// were relying on the mock in
    /// production must set
    /// `AGENCY_OIDC_MOCK=1` explicitly.
    #[test]
    fn oidc_mock_default_is_false_in_277() {
        // Clear any inherited value.
        std::env::remove_var("AGENCY_OIDC_MOCK");
        let cfg = OidcConfig::from_env();
        assert!(
            !cfg.mock,
            "2.7.7 must default AGENCY_OIDC_MOCK to false (real client)"
        );
    }

    /// 2.7.7: AGENCY_OIDC_MOCK=1
    /// explicitly selects the mock.
    #[test]
    fn oidc_mock_env_var_overrides_to_true() {
        std::env::set_var("AGENCY_OIDC_MOCK", "1");
        let cfg = OidcConfig::from_env();
        std::env::remove_var("AGENCY_OIDC_MOCK");
        assert!(cfg.mock, "AGENCY_OIDC_MOCK=1 must select the mock client");
    }

    /// 2.7.7: `pkce_challenge_from_verifier`
    /// is the S256 derivation. The
    /// framework passes the result as
    /// `code_challenge` to the IdP. The
    /// IdP then computes
    /// `BASE64URL(SHA256(verifier))` and
    /// compares. We don't assert against
    /// a specific IdP here; we just check
    /// the function is deterministic and
    /// non-empty.
    #[test]
    fn pkce_challenge_is_deterministic_and_nonempty() {
        let a = pkce_challenge_from_verifier("verifier-1");
        let b = pkce_challenge_from_verifier("verifier-1");
        let c = pkce_challenge_from_verifier("verifier-2");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.len() > 40);
    }
}
