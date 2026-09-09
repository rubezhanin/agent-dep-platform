//! Real IdP integration test harness (Phase 0, Q2 = real IdP).
//!
//! Provides infrastructure for spinning up a real Keycloak instance
//! (via `testcontainers`-style Docker or docker-compose) and running
//! OIDC flow tests against it. Mocks are NOT used here — this is the
//! *real-IdP* path required to prove F-01 (refresh subject confusion),
//! F-02 (discovery strict validation), and F-03 (session architecture)
//! end-to-end.
//!
//! **Escape hatch:** when `SKIP_REAL_IDP_TESTS=1` is set in the
//! environment, the harness skip()'s every test. This is the
//! "windows-latest fast loop" path — docker may not be available,
//! and we still want the test file to compile.
//!
//! **Production vs test:**
//! - In production, the agency-server is configured to talk to a
//!   real IdP (the operator's Keycloak / Auth0 / Okta / etc.) via
//!   `AGENCY_OIDC_ISSUER`, `AGENCY_OIDC_CLIENT_ID`, etc.
//! - In tests, we bring up a local Keycloak via docker-compose
//!   (`tools/keycloak/realm.json` is the agency realm definition).
//!
//! References:
//! - `TZ_agent-dep-platform-REMEDIATION-PLAN.md` §4.8 (Phase 0 harness)
//! - `TZ_agent-dep-platform-ENTERPRISE-FINAL-TZ.md` §6 (F-01, F-02, F-03)
//! - `TZ_agent-dep-platform-HARDENING-TZ.md` WP-0.4 (nonce, header)
//! - `docs/AGENT_DOD.md` §2 (CWE + Exploit scenario)
//! - `docker-compose.yml` (Phase 0 keycloak service)

// ============================================================================
// TestIdpConfig — minimal config bundle
// ============================================================================

/// Configuration for a test Keycloak instance.
///
/// In Phase 0 this is a stub — the real implementation lands when
/// P0-F-01 (OIDC refresh subject binding) closes. The fields are
/// the minimum needed to drive a `client_credentials` or
/// `authorization_code` flow.
#[derive(Debug, Clone)]
pub struct TestIdpConfig {
    /// Issuer URL (e.g. `http://localhost:8080/realms/agency`).
    pub issuer: String,
    /// OAuth2 client_id.
    pub client_id: String,
    /// OAuth2 client_secret.
    pub client_secret: String,
    /// Redirect URI (e.g. `http://localhost:9999/v1/auth/oidc/callback`).
    pub redirect_uri: String,
    /// JWKS URL (derived from issuer in real Keycloak, but
    /// explicit here so tests don't need to discover it).
    pub jwks_url: String,
}

impl TestIdpConfig {
    /// Default config matching the docker-compose Keycloak service
    /// + the `tools/keycloak/realm.json` agency realm.
    pub fn default_local() -> Self {
        Self {
            issuer: "http://localhost:8081/realms/agency".to_string(),
            client_id: "agency-server".to_string(),
            // The realm.json is a fixture — the secret is committed
            // in the realm file (it is a TEST client, not a
            // production one). The test IdP is unreachable from
            // outside the test docker network.
            client_secret: "test-client-secret-do-not-use-in-prod".to_string(),
            redirect_uri: "http://localhost:9999/v1/auth/oidc/callback".to_string(),
            jwks_url: "http://localhost:8081/realms/agency/protocol/openid-connect/certs"
                .to_string(),
        }
    }
}

// ============================================================================
// TestKeycloak — Docker harness
// ============================================================================

/// A running Keycloak instance for one test.
///
/// **Lifecycle:**
/// 1. `TestKeycloak::start().await` — boots Keycloak via
///    `docker run` (or `testcontainers`-style), waits for the
///    health endpoint, loads `tools/keycloak/realm.json` if not
///    already loaded.
/// 2. Tests use the methods (`login_user`, `forge_id_token`, etc.)
///    to drive flows.
/// 3. `Drop` (or explicit `.shutdown().await`) tears down the
///    container.
///
/// **Phase 0 status:** the harness struct compiles but its
/// `start()` method is a stub returning `unimplemented!()`. The
/// real implementation lands in Phase 1 when the first F-01
/// integration test needs it.
pub struct TestKeycloak {
    pub config: TestIdpConfig,
    /// Container ID or docker-compose service name (for shutdown).
    container_id: Option<String>,
}

impl TestKeycloak {
    /// Start a fresh Keycloak container. Honors `SKIP_REAL_IDP_TESTS=1`
    /// by returning a "skip" sentinel that all tests should detect
    /// and `return` early on.
    pub async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        if std::env::var("SKIP_REAL_IDP_TESTS").as_deref() == Ok("1") {
            // Honor the escape hatch — return a dummy config so
            // tests that just need a config can still construct
            // without docker.
            return Ok(Self {
                config: TestIdpConfig::default_local(),
                container_id: None,
            });
        }

        // Phase 0 placeholder. Real implementation:
        //   1. `docker run -d --name agency-test-keycloak -p 8081:8080 \
        //        -v $PWD/tools/keycloak/realm.json:/opt/keycloak/data/import/realm.json \
        //        quay.io/keycloak/keycloak:24.0 start-dev --import-realm`
        //   2. Wait for `curl -f http://localhost:8081/health/ready` to return 200.
        //   3. Return Self { config: TestIdpConfig::default_local(), container_id: Some(id) }.
        //
        // For now we just return the dummy config so the harness
        // compiles. Tests that actually need the real IdP will
        // un-ignore and call this method.
        Ok(Self {
            config: TestIdpConfig::default_local(),
            container_id: None,
        })
    }

    /// Shut down the container. Idempotent — safe to call multiple
    /// times (e.g. in Drop + explicit).
    pub async fn shutdown(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(id) = self.container_id.take() {
            // Real impl: `docker rm -f {id}`.
            let _ = id; // suppress unused warning
        }
        Ok(())
    }

    /// Returns `true` if this is a real (running) IdP or a skip-dummy.
    pub fn is_real(&self) -> bool {
        self.container_id.is_some()
    }
}

impl Drop for TestKeycloak {
    fn drop(&mut self) {
        // Best-effort sync shutdown. For full async cleanup,
        // call `.shutdown().await` explicitly in the test.
        if let Some(id) = self.container_id.take() {
            // Real impl: `docker rm -f {id}`.
            let _ = id;
        }
    }
}

// ============================================================================
// Test user
// ============================================================================

/// A user in the test IdP's realm.
#[derive(Debug, Clone)]
pub struct TestUser {
    pub username: String,
    pub email: String,
    /// Pre-set password (the test realm uses simple passwords
    /// for the fixture users; never use this in production).
    pub password: String,
    /// OIDC claims the user is expected to have.
    pub claims: TestClaims,
}

#[derive(Debug, Clone, Default)]
pub struct TestClaims {
    pub sub: String,
    pub tenant: String,
    pub roles: Vec<String>,
    /// Nonce stored at login time; refresh-flow tests will
    /// validate the ID token's `nonce` claim against this.
    pub nonce: Option<String>,
}

impl TestUser {
    pub fn alice() -> Self {
        Self {
            username: "alice".to_string(),
            email: "alice@agency.example".to_string(),
            password: "test-alice-password".to_string(),
            claims: TestClaims {
                sub: "alice@agency.example".to_string(),
                tenant: "tenant-a".to_string(),
                roles: vec!["agency:viewer".to_string()],
                nonce: None,
            },
        }
    }

    pub fn bob() -> Self {
        Self {
            username: "bob".to_string(),
            email: "bob@agency.example".to_string(),
            password: "test-bob-password".to_string(),
            claims: TestClaims {
                sub: "bob@agency.example".to_string(),
                tenant: "tenant-b".to_string(),
                roles: vec!["agency:admin".to_string()],
                nonce: None,
            },
        }
    }
}

// ============================================================================
// Login / token helpers
// ============================================================================

impl TestKeycloak {
    /// Log a test user in via the password grant. Returns the
    /// issued tokens (id_token, refresh_token, access_token).
    ///
    /// **Phase 0:** stub. Real impl uses `reqwest` to POST to the
    /// token endpoint with `grant_type=password`.
    pub async fn login(&self, _user: &TestUser) -> Result<TestTokens, Box<dyn std::error::Error>> {
        if !self.is_real() {
            return Err("TestKeycloak is in skip-dummy mode; \
                        unset SKIP_REAL_IDP_TESTS and start a real Keycloak"
                .into());
        }
        // Phase 0 stub.
        unimplemented!("Phase 0 stub — implement when F-01 test lands")
    }

    /// Forge an ID token with caller-controlled claims, signed by
    /// an attacker-controlled key. Used to test the
    /// header-allowlist (P0-HDR-01) and refresh-subject-binding
    /// (P0-F-01) defenses.
    pub async fn forge_id_token(
        &self,
        _rt: &str,
        _claims: &TestClaims,
    ) -> Result<String, Box<dyn std::error::Error>> {
        if !self.is_real() {
            return Err("TestKeycloak is in skip-dummy mode".into());
        }
        unimplemented!("Phase 0 stub — implement when A.1 / A.3 tests land")
    }
}

/// The three token types returned by an OIDC login.
#[derive(Debug, Clone)]
pub struct TestTokens {
    pub id_token: String,
    pub access_token: String,
    pub refresh_token: String,
}

// ============================================================================
// Future seed scenarios (Phase 1 candidates)
// ============================================================================
//
// P0-F-01 / P0-F-02 / P0-F-03 / P0-NONCE-01 / P0-HDR-01 have all closed
// in 2.7.0..2.7.7 (the corresponding executable specs live in
// `crates/server/src/oidc_client.rs::tests::rejects_jku_header` and
// the http_integration.rs::oidc_refresh_* family). The original
// `// ```rust,ignore` doc-block for `a1_oidc_refresh_subject_
// confusion_replay` was removed in 2.11.0 (P1-TD-01) — the doc
// block was dead documentation (rustdoc never executes `rust,ignore`
// fences), and the sister-file pointer in
// `crates/core/tests/security_replays.rs` covered the same role.
//
// New real-IdP replay tests will be added (not pre-seeded) when the
// next Phase 2 / 3 finding needs an end-to-end Keycloak harness.
// ============================================================================

// ============================================================================
// Test runner notes
// ============================================================================
//
// `cargo test -p agent_dep_server --test oidc_real_idp` runs all
// tests in this file. With Phase 0 stubs, all tests are
// un-`#[ignore]`'d but panic with `unimplemented!()` or return
// "skip-dummy mode" — depending on whether SKIP_REAL_IDP_TESTS=1.
//
// Phase 0 exit criterion for this file:
//   cargo build -p agent_dep_server --tests   → success
//   cargo test -p agent_dep_server --test oidc_real_idp
//     → 0 tests (or all "skip-dummy mode" returns which are
//       treated as test failure, so the test count must be 0)
//
// Phase 1 exit criterion (after F-01 closes):
//   docker compose up -d keycloak
//   cargo test -p agent_dep_server --test oidc_real_idp -- --include-ignored
//     → at least the A.1 test (subject confusion replay) is PASS
//     → at least the A.2 test (nonce replay) is PASS
