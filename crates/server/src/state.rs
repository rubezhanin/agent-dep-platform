//! Shared application state for the 2.1.0 server.

use std::sync::Arc;

use agent_dep_core::infrastructure::repository::audit_log_repository::AuditLogRepository;
use agent_dep_core::infrastructure::repository::pending_deploys_repository::PendingDeployRepository;
use agent_dep_core::infrastructure::repository::secrets_repository::SecretRepository;
use agent_dep_core::infrastructure::repository::targets_repository::TargetRepository;
use agent_dep_core::infrastructure::repository::users_repository::UserRepository;
use agent_dep_core::infrastructure::sqlite::Db;

use crate::oidc::{OidcConfig, OidcPending};
use crate::oidc_client::OidcClient;

#[derive(Clone)]
pub struct ServerState {
    pub db: Db,
    pub audit: AuditLogRepository,
    /// 2.1.0: per-user lookup. The 2.0.0 single-token
    /// field is gone — the `users` table is the only
    /// source of truth.
    pub users: UserRepository,
    /// 2.2.0: approvals workflow state machine.
    pub deploys: PendingDeployRepository,
    /// 2.3.0: encrypted secret store.
    pub secrets: SecretRepository,
    /// 2.5.0: fleet — named target registry.
    pub targets: TargetRepository,
    /// 2.7.6 (ADR-0034): OIDC config. When
    /// `is_enabled()` is false, the OIDC endpoints
    /// return 503 "not configured". Bearer-token
    /// auth is unaffected.
    pub oidc: OidcConfig,
    /// 2.7.6: in-memory map of `state` -> (PKCE
    /// verifier, nonce, created_at). Single-process
    /// only. A shared store (DB or Redis) is a
    /// 2.7.x enhancement for multi-process
    /// deployments.
    pub oidc_pending: OidcPending,
    /// 2.7.7 (ADR-0035): the OIDC wire-protocol
    /// client. `MockOidcClient` when
    /// `AGENCY_OIDC_MOCK=1`; `RealOidcClient`
    /// otherwise. The 2.7.7 default is
    /// `AGENCY_OIDC_MOCK=0` (real client) — a
    /// behavioural break from 2.7.6's
    /// `AGENCY_OIDC_MOCK=1` default.
    pub oidc_client: Arc<dyn OidcClient>,
    /// Retained for 2.0.0→2.1.0 migration: if the
    /// `users` table is empty on first start and this
    /// is `Some(legacy)`, the server creates an
    /// `admin` user with `token_hash = sha256(legacy)`
    /// so existing scripts keep working.
    pub legacy_token: Arc<Option<String>>,
}
