//! Multi-tenant test harness (Phase 0, ADR-0042).
//!
//! Provides infrastructure for proving cross-tenant isolation.
//! The actual isolation logic lands in Phase 2 (MT-01..MT-04); this
//! file is the *harness* that future multi-tenant tests will use.
//!
//! **What this file is:**
//! - `TestTenants` — builder for two isolated tenant contexts.
//! - `assert_cross_tenant_blocked` — runs an operation that should
//!   be denied because the actor tenant ≠ resource owner tenant.
//! - Helper to seed a snapshot / target / user as a specific tenant.
//!
//! **What this file is NOT:**
//! - The actual multi-tenant enforcement (that's in every
//!   repository constructor, lands in Phase 2).
//! - Production code. `#[cfg(test)]` only — not compiled into
//!   release builds (per the project policy: integration tests in
//!   `crates/<crate>/tests/`, exercising only the public API).
//!
//! **How to use this harness (once Phase 2 lands):**
//!
//! ```rust,ignore
//! use crate::tenancy::*;
//!
//! #[tokio::test]
//! async fn tenant_a_cannot_deploy_to_tenant_b_target() {
//!     let t = TestTenants::new().await;
//!     let target_id = t.seed_target("tgt-b").await;
//!
//!     let result = t
//!         .as_a()
//!         .deploy_to(target_id, /* plan */ ...)
//!         .await;
//!
//!     assert_cross_tenant_blocked(result);
//! }
//! ```
//!
//! References:
//! - `TZ_agent-dep-platform-REMEDIATION-PLAN.md` §4.7 (Phase 0 harness)
//! - `docs/adr/0042-multi-tenant-schema.md` (schema, RLS, cache key)
//! - `docs/RISK_REGISTER.md` RR-004..006 (residual risks from this ADR)
//! - `docs/AGENT_DOD.md` §2 (CWE + Exploit scenario reporting)

// ============================================================================
// Placeholder tenant context (will be replaced by real TenantContext
// in Phase 2 when MT-01..MT-04 land).
// ============================================================================

/// Identifies a tenant in the test harness.
///
/// The shape mirrors the future production `TenantContext` (built
/// from the OIDC `tenant` claim per ADR-0042). For now it carries
/// only the `tenant_id` string; future phases may add roles,
/// scopes, and per-tenant feature flags.
#[derive(Debug, Clone)]
pub struct TestTenant {
    pub tenant_id: String,
}

impl TestTenant {
    pub fn new(tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
        }
    }
}

// ============================================================================
// TestTenants — pair builder
// ============================================================================

/// A pair of isolated tenants for cross-tenant assertion tests.
///
/// Every helper method that takes a resource ID will run the
/// operation as `tenant_a`; tests that need the inverse should
/// use `.as_b()` or construct a fresh harness.
pub struct TestTenants {
    pub tenant_a: TestTenant,
    pub tenant_b: TestTenant,
}

impl TestTenants {
    /// Build a fresh pair with default IDs (`tenant-a`, `tenant-b`).
    ///
    /// In Phase 2 this will also create the bootstrap rows
    /// (users, audit_log entry) for each tenant in a real test
    /// database. For Phase 0 it just allocates the strings.
    pub fn new() -> Self {
        Self {
            tenant_a: TestTenant::new("tenant-a"),
            tenant_b: TestTenant::new("tenant-b"),
        }
    }

    /// Build a pair with caller-supplied IDs (for tests that
    /// need to assert specific naming).
    pub fn with_ids(a: impl Into<String>, b: impl Into<String>) -> Self {
        Self {
            tenant_a: TestTenant::new(a),
            tenant_b: TestTenant::new(b),
        }
    }

    /// Returns the actor context for tenant A.
    pub fn as_a(&self) -> &TestTenant {
        &self.tenant_a
    }

    /// Returns the actor context for tenant B.
    pub fn as_b(&self) -> &TestTenant {
        &self.tenant_b
    }
}

impl Default for TestTenants {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Cross-tenant assertion helper
// ============================================================================

/// Asserts that `result` represents a "cross-tenant operation was
/// denied" outcome. Acceptable denial shapes:
///
/// - HTTP 403 (Forbidden) — explicit tenant-mismatch
/// - HTTP 404 (Not Found) — the row is invisible to this tenant
///   (the *more secure* answer: don't even leak existence)
/// - Typed repository error `RepositoryError::TenantMismatch`
/// - Typed repository error `RepositoryError::NotFound` (when the
///   repository's contract is to return NotFound rather than
///   TenantMismatch — the tenant isolation is enforced at the
///   SQL boundary, not surfaced as a distinct error)
///
/// **Usage:**
///
/// ```rust,ignore
/// let result: Result<Target, RepoError> = t.as_a().load(target_id).await;
/// tenancy::assert_cross_tenant_blocked(result);
/// ```
///
/// Panics if the result is `Ok` (the cross-tenant operation
/// succeeded — ISOLATION BROKEN). Panics with a helpful message
/// identifying which test failed.
pub fn assert_cross_tenant_blocked<T, E>(result: Result<T, E>)
where
    E: std::fmt::Debug,
{
    match result {
        Ok(_) => panic!(
            "CROSS-TENANT ISOLATION BROKEN: expected denied/forbidden/notfound, \
             but operation succeeded. The repository returned a resource to a \
             tenant that does not own it. Check WHERE clause includes \
             tenant_id, and TenantContext is correctly threaded through the \
             call path."
        ),
        Err(e) => {
            // We deliberately do NOT assert on the specific error
            // shape here — Phase 2 will lock that down per-repo.
            // For now any Err is acceptable, with the understanding
            // that production code review will verify the error
            // doesn't leak existence information.
            let _ = e; // suppress unused warning when test is permissive
        }
    }
}

// ============================================================================
// Future seed scenarios (Phase 2 candidates)
// ============================================================================
//
// These will be implemented when MT-01..MT-04 land. They mirror
// the security_replays.rs pattern: each test is a closed
// exploit-scenario for a specific isolation gap.
//
// ```rust,ignore
// #[tokio::test]
// #[ignore = "phase 2: MT-01"]
// async fn mt01_target_lookup_filters_by_tenant() {
//     let t = TestTenants::new().await;
//     let b_target = t.seed_target_as_b("tgt-b-only").await;
//     // A attempts to load B's target.
//     let result = repository::targets::find(&t.tenant_a, &b_target.id).await;
//     assert_cross_tenant_blocked(result);
// }
//
// #[tokio::test]
// #[ignore = "phase 2: MT-02"]
// async fn mt02_audit_log_filters_by_tenant() {
//     // A attempts to read B's audit log entry.
// }
//
// #[tokio::test]
// #[ignore = "phase 2: MT-03"]
// async fn mt03_cache_key_includes_tenant() {
//     // Seed B's snapshot, then attempt to read A's cache.
// }
//
// #[tokio::test]
// #[ignore = "phase 2: MT-04"]
// async fn mt04_secret_lookup_filters_by_tenant() {
//     // A attempts to read B's vault secret.
// }
// ```
// ============================================================================

// ============================================================================
// Test runner notes
// ============================================================================
//
// `cargo test -p agent_dep_core --test tenancy` runs the harness
// self-tests (currently empty — the harness is pure infrastructure,
// not tests). When Phase 2 lands, this file will gain
// `#[tokio::test]` integration tests, each `#[ignore = "phase 2: MT-NN"]`
// and un-`#[ignore]`'d as the corresponding MT-NN is closed.
//
// To verify the file is wired up correctly in Phase 0:
//   cargo test -p agent_dep_core --test tenancy
//   → running 0 tests
//   → test result: ok. 0 passed; 0 failed
//
// To verify the harness compiles in isolation:
//   cargo build -p agent_dep_core --tests
