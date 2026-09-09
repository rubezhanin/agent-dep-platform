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
// Phase 0 seed scenarios (A.1..A.5): removed in 2.11.0 (P1-TD-01).
// ============================================================================
//
// The 5 placeholder `#[test] #[ignore]` slots that previously lived
// here (a1_oidc_refresh_subject_confusion / a2_oidc_refresh_with_empty_
// nonce_passes / a3_jwt_with_jku_header_uses_attacker_jwks /
// a4_empty_bearer_matches_sha256_empty_sentinel /
// a5_vault_placeholder_secret_accepted_in_production) have been
// DELETED because each of the corresponding P0 findings (P0-F-01 /
// P0-NONCE-01 / P0-HDR-01 / P0-SENT-01 / P0-F-05) is now closed and
// the *executable spec* for the fix lives in a sister file:
//
//   P0-F-01    -> crates/server/tests/http_integration.rs::
//                 oidc_refresh_rejects_subject_mismatch
//   P0-NONCE-01-> crates/server/tests/http_integration.rs::
//                 oidc_refresh_endpoint_returns_new_token_and_expiry
//                 + crates/server/src/oidc_client.rs::tests::
//                 validate_jwt_rejects_nonce_mismatch
//   P0-HDR-01  -> crates/server/src/oidc_client.rs::tests::
//                 rejects_jku_header (+ x5u / x5c / jwk / crit)
//   P0-SENT-01 -> crates/server/tests/http_integration.rs::
//                 audit_requires_bearer_token + P0-SENT-01 unit tests
//   P0-F-05    -> crates/server/tests/vault_replay.rs (10 tests)
//
// The `crates/core` crate no longer hosts OIDC, vault, or
// bearer-middleware code — the executable specs above are the
// authoritative test for the fix. This file is intentionally
// empty of `#[test]` functions until the next Phase 2 / 3 finding
// needs a `core`-level regression test; new placeholders will be
// added (not pre-seeded) when the corresponding finding opens.
//

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
//   running 0 tests
//   test result: ok. 0 passed; 0 failed; 0 ignored
//
// To verify the placeholders compile and the file is wired up,
// run with `--include-ignored` — every test panics with
// `unimplemented!()` until the corresponding finding is closed.
