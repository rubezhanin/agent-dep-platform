//! Security replay tests — 5 seed scenarios from TZ #2 Appendix A
//! + 1 base scenario from TZ #1 §6 (F-01).
//!
//! Each `#[test] #[ignore = "phase N: <FINDING-ID>"]` is a placeholder
//! that becomes a real test when the corresponding finding is closed.
//!
//! **Pattern (the 12-point DoD rule from `docs/AGENT_DOD.md`):**
//! 1. A finding is closed only when an integration / replay test
//!    reproduces the original exploit and proves it is now denied.
//! 2. The replay test is the *executable specification* of the fix.
//! 3. Removing the `#[ignore]` happens in the same commit that
//!    closes the finding — never separately.
//!
//! **How to use this file:**
//! - `cargo test -p agent_dep_core --test security_replays`
//!   runs only the un-`#[ignore]`'d tests (none yet — all are
//!   placeholders).
//! - `cargo test -p agent_dep_core --test security_replays -- --include-ignored`
//!   lists every test (each fails / panics with the placeholder
//!   message until the finding is closed).
//! - To close a finding: implement the test body, remove
//!   `#[ignore]`, run with `--include-ignored` and confirm PASS.
//!
//! **Status (2026-09-07, Phase 0):** all 5 seed tests are `#[ignore]`d.
//! First un-ignore happens when P0-F-01 / P0-SENT-01 / P0-NONCE-01 /
//! P0-HDR-01 / P0-F-05 close (Phase 1).
//!
//! References:
//! - `TZ_agent-dep-platform-REMEDIATION-PLAN.md` §4.6 (Phase 0 seed)
//! - `TZ_agent-dep-platform-HARDENING-TZ.md` Appendix A (5 scenarios)
//! - `TZ_agent-dep-platform-ENTERPRISE-FINAL-TZ.md` §6 (F-01 base scenario)
//! - `docs/AGENT_DOD.md` §1 п.4 (integration test required per finding)

// ============================================================================
// A.1 — F-01 / TZ #1 §6: OIDC refresh subject confusion
// ============================================================================
//
// **Threat:** attacker intercepts refresh_token_A (belongs to user A),
// presents it in a request whose ID token claims sub=B. The naive
// validation trusts the ID token's sub, which the attacker controls.
//
// **Current behavior (pre-fix):** refresh succeeds, server issues
// new tokens for "user B" with attacker-controlled refresh_token_A.
//
// **Expected behavior (post-fix):** server compares the ID token's sub
// against the original session's stored sub (tied to the refresh token)
// and rejects on mismatch (CWE-287).
//
// **Closing finding:** P0-F-01 (Phase 1, complex L).
//
// When un-ignored, this test must:
//  1. Spin up a fake OIDC issuer (or use the real-IdP harness).
//  2. Issue refresh_token_A for sub=alice@agency.example.
//  3. Build a request with refresh_token_A and a forged ID token
//     whose `sub` claim is `bob@agency.example`.
//  4. Assert the refresh handler returns 401 / TokenError::SubjectMismatch.

#[test]
#[ignore = "phase 1: P0-F-01 — TZ #1 §6 F-01"]
fn a1_oidc_refresh_subject_confusion() {
    // Placeholder. Implement when P0-F-01 lands.
    //
    // The test body will look like:
    //
    //   #[tokio::test]
    //   async fn a1_oidc_refresh_subject_confusion() {
    //       let harness = real_idp::TestKeycloak::start().await.unwrap();
    //       let alice = harness.user("alice").await.unwrap();
    //       let bob = harness.user("bob").await.unwrap();
    //       let rt = harness.login(&alice).await.unwrap();
    //       let forged = harness
    //           .forge_id_token(&rt, &bob.claims())
    //           .await
    //           .unwrap();
    //       let result = agency_server::oidc::refresh_handler(&rt, &forged, &harness.pool)
    //           .await;
    //       assert!(matches!(
    //           result,
    //           Err(oidc::TokenError::SubjectMismatch)
    //       ));
    //   }
    unimplemented!("P0-F-01 — implement when refresh subject binding lands");
}

// ============================================================================
// A.2 — P0-NONCE-01 / TZ #2 WP-0.4: OIDC refresh with empty nonce
// ============================================================================
//
// **Threat:** the refresh-path validation uses
// `expected_nonce: &str = ""` and the comparison degenerates to
// `assert_eq!(presented.nonce.as_deref(), Some(""))`. Any ID token
// with `nonce: null` passes the check. Real IdPs (Keycloak) send a
// per-session nonce that the refresh path should validate, so this
// passes the wrong tokens silently on real IdPs too.
//
// **Current behavior (pre-fix):** refresh succeeds with empty-nonce
// ID tokens that the user never saw.
//
// **Expected behavior (post-fix):** the refresh path uses
// `Option<&str>` and `assert_eq!(presented.nonce, Some(expected_nonce))`
// with the nonce stored at login. Empty expected_nonce is impossible
// by construction (CWE-287).
//
// **Closing finding:** P0-NONCE-01 (Phase 1, simple S).
//
// When un-ignored, this test must:
//  1. Use the real-IdP harness to login as a user (which stores a
//     real nonce in the session).
//  2. Refresh with a forged ID token whose `nonce` claim is `null`
//     OR a different value than what the session stored.
//  3. Assert the refresh handler returns 401 / TokenError::NonceMismatch.

#[test]
#[ignore = "phase 1: P0-NONCE-01 — TZ #2 WP-0.4 / Appendix A.2"]
fn a2_oidc_refresh_with_empty_nonce_passes() {
    unimplemented!(
        "P0-NONCE-01 — implement when refresh nonce becomes Option<&str> with \
         assert_eq! against session-stored nonce"
    );
}

// ============================================================================
// A.3 — P0-HDR-01 / TZ #2 WP-0.4: JWT with jku / x5u / crit header
// ============================================================================
//
// **Threat:** the JWT decoder accepts arbitrary header fields including
// `jku` (JWK Set URL), `x5u` (X.509 URL), `x5c` (X.509 chain),
// `jwk` (embedded key), and `crit` (critical extensions). An attacker
// forges a token with `jku: https://evil.example/jwks` and the
// validator fetches & trusts the attacker's keys. This is the classic
// "JWT alg confusion" attack, generalized to header fields.
//
// **Current behavior (pre-fix):** header fields are passed through
// to the signature-verification path, which (depending on the
// library used) may follow `jku` and trust attacker keys.
//
// **Expected behavior (post-fix):** the decoder explicitly
// allowlists `alg` + `kid`. Any header containing `crit`, `jku`,
// `x5u`, `x5c`, or `jwk` is rejected as a parsing error
// (CWE-345).
//
// **Closing finding:** P0-HDR-01 (Phase 1, simple S).
//
// When un-ignored, this test must:
//  1. Build a JWT with header `{ "alg": "RS256", "kid": "k1", "jku": "https://evil/jwks" }`
//     and a body signed with the attacker's key.
//  2. Submit to the ID-token validator.
//  3. Assert rejection with TokenError::DisallowedHeaderField("jku").
//  4. Repeat for `x5u`, `x5c`, `jwk`, `crit`.

#[test]
#[ignore = "phase 1: P0-HDR-01 — TZ #2 WP-0.4 / Appendix A.3"]
fn a3_jwt_with_jku_header_uses_attacker_jwks() {
    unimplemented!(
        "P0-HDR-01 — implement when header allowlist (alg + kid only) is added to \
         decode_jwt_header; test must cover crit/jku/x5u/x5c/jwk"
    );
}

// ============================================================================
// A.4 — P0-SENT-01 / TZ #2 WP-0.3: empty bearer matches sha256("") sentinel
// ============================================================================
//
// **Threat:** the `users.token_hash` column is NOT NULL. To represent
// "no token issued yet" (admin user, system user), the code stores
// `sha256("")` as a sentinel value. The bearer middleware computes
// `sha256(presented_token)` and looks up the user. An attacker
// presenting `Authorization: Bearer ""` (or no header at all in
// some misconfigured client) computes `sha256("")` which collides
// with the sentinel. **If the admin user has the sentinel, the
// attacker is admin.**
//
// **Current behavior (pre-fix):** an empty bearer can match a
// sentinel-hashed user. The admin's empty token = full admin
// access (CWE-287).
//
// **Expected behavior (post-fix):**
//  1. `users.token_hash` becomes nullable (NULL = "no token issued").
//  2. Migration `migrations/018_users_nullable_token_hash.sql`
//     flips NOT NULL → NULL and rewrites sentinel rows to NULL.
//  3. The bearer middleware short-circuits on `presented == ""` →
//     401, regardless of any DB state.
//  4. Sentinel sha256("") value is forbidden in new INSERTs
//     (CHECK constraint or app-level guard).
//
// **Closing finding:** P0-SENT-01 (Phase 1, medium M — needs migration).
//
// When un-ignored, this test must:
//  1. Insert a user with token_hash = sha256("") (the sentinel).
//  2. Call `auth::require_bearer("")`.
//  3. Assert 401 Unauthorized (NOT a successful auth).
//  4. Repeat with token_hash = NULL — also 401.
//  5. Insert a real token, call with that token — assert 200.

#[test]
#[ignore = "phase 1: P0-SENT-01 — TZ #2 WP-0.3 / Appendix A.4"]
fn a4_empty_bearer_matches_sha256_empty_sentinel() {
    unimplemented!(
        "P0-SENT-01 — implement when token_hash becomes nullable + middleware \
         short-circuits on empty bearer"
    );
}

// ============================================================================
// A.5 — P0-F-05 / TZ #2 WP-2.1: vault placeholder secret in production
// ============================================================================
//
// **Threat:** `boot_default_state()` accepts `AGENCY_VAULT_PASSPHRASE =
// "unset-rotate-before-first-use"` (a placeholder) without warning.
// The server derives its encryption keys from this passphrase, so
// any attacker who knows the placeholder can decrypt every secret
// in the vault. The placeholder is also in the public repo (env
// example, docs), so it's not even a secret-by-obscurity.
//
// **Current behavior (pre-fix):** server boots in production with
// a known passphrase, derives predictable keys, and serves
// plaintext secrets to any caller that knows the placeholder
// (CWE-798).
//
// **Expected behavior (post-fix):**
//  1. `boot_default_state` rejects the placeholder in release
//     builds (`#[cfg(not(debug_assertions))]`).
//  2. `AGENCY_VAULT_PASSPHRASE_FILE` is the preferred path;
//     passphrase entropy is checked (≥ 80 bits) at load.
//  3. Admin token is stored in `server.token` file (mode 0600),
//     and any code path that logs the boot state must redact it.
//  4. Per-install salt is generated on first boot and persisted
//     to the data dir (not in the env).
//
// **Closing finding:** P0-F-05 (Phase 1, medium M — needs salt +
// entropy check + token file).
//
// When un-ignored, this test must:
//  1. Set `AGENCY_VAULT_PASSPHRASE = "unset-rotate-before-first-use"`.
//  2. Call `boot_default_state()`.
//  3. Assert it returns Err(VaultError::PlaceholderPassphraseRejected).
//  4. Set low-entropy passphrase (`"abc"`), assert entropy check fires.
//  5. Set high-entropy passphrase via file, assert success.

#[test]
#[ignore = "phase 1: P0-F-05 — TZ #2 WP-2.1 / Appendix A.5 — see \
            crates/server/tests/vault_replay.rs for the executable spec; \
            this placeholder remains here as a domain-level pointer \
            (vault init lives in crates/server, not crates/core)"]
fn a5_vault_placeholder_secret_accepted_in_production() {
    // The real executable spec is in
    // `crates/server/tests/vault_replay.rs` (10 tests
    // covering placeholder rejection, low-entropy
    // rejection, *_FILE preference, per-install salt
    // generation/stability/wrong-length, and end-to-end
    // AES-GCM isolation between two installs with the
    // same passphrase but different salts).
    //
    // We do NOT move the spec into `crates/core` because
    // `vault_init` is a `crates/server` module (the
    // boot path is server-specific). The `#[ignore]` is
    // left in place so `security_replays --include-ignored`
    // still surfaces this slot as "intentionally deferred
    // to a sister file".
}

// ============================================================================
// Future seed scenarios (Phase 2 candidates)
// ============================================================================
//
// These are NOT yet seeded as `#[ignore]` tests because they correspond
// to P1 / P2 finding'ы that close later. They will be added when the
// finding is opened (i.e. when work begins on the corresponding Phase).
//
// P1-F-02 (OIDC discovery strict validation) — TZ #1 §6
//   Attack: issuer=https://attacker.example, present real IdP's discovery
//   but rewritten issuer field. Validator trusts discovery. → Reject.
//
// P1-F-04 (empty bearer) — TZ #1 §6
//   Attack: Authorization: Bearer "    " (whitespace). Validator
//   trims and compares to "" — sentinel collision if F-01 not fixed.
//
// P1-G-01 / G-02 (Git URL policy + SSRF) — TZ #1 §7 + TZ #2 WP-3.3
//   Attack: catalog URL = http://169.254.169.254/... (cloud metadata)
//   or file:///etc/passwd. Validator accepts. → Reject.
//
// P1-S-02 / S-03 (plugin timeout + output cap) — TZ #1 §9 + TZ #2 WP-1.2
//   Attack: plugin that sleeps for 1 hour, or writes 4 GiB to stdout.
//   Validator hangs / OOMs. → Timeout + cap.
//
// P1-D-01 (immutable DeploymentIntent) — TZ #1 §10
//   Attack: approval was for commit_sha=X, deploy tries commit_sha=Y.
//   Server accepts (stale approval). → Reject with STALE_APPROVAL.
//
// P2-UI-06 (Tauri CSP) — TZ #2 WP-3.1
//   Attack: XSS in Tauri panel via reflected header. With no CSP,
//   script executes. → CSP enforces default-src 'self'.
//
// P2-MCP-01 (YAML escape in MCP manifest) — TZ #2 WP-3.4
//   Attack: agent name = `"; system: rm -rf / #`. Naive heredoc
//   string concat interpolates the payload. → YAML-escape.

// ============================================================================
// Test runner notes
// ============================================================================
//
// `cargo test -p agent_dep_core --test security_replays` runs only
// the un-`#[ignore]`'d tests. With all 5 still ignored, the output
// is:
//
//   running 5 tests
//   test a1_oidc_refresh_subject_confusion ... ignored
//   test a2_oidc_refresh_with_empty_nonce_passes ... ignored
//   test a3_jwt_with_jku_header_uses_attacker_jwks ... ignored
//   test a4_empty_bearer_matches_sha256_empty_sentinel ... ignored
//   test a5_vault_placeholder_secret_accepted_in_production ... ignored
//   test result: ok. 0 passed; 0 failed; 5 ignored
//
// To verify the placeholders compile and the file is wired up,
// run with `--include-ignored` — every test panics with
// `unimplemented!()` until the corresponding finding is closed.
