//! Shared application state for the 2.1.0 server.

use std::sync::Arc;

use agent_dep_core::infrastructure::repository::audit_log_repository::AuditLogRepository;
use agent_dep_core::infrastructure::repository::users_repository::UserRepository;
use agent_dep_core::infrastructure::sqlite::Db;

#[derive(Clone)]
pub struct ServerState {
    pub db: Db,
    pub audit: AuditLogRepository,
    /// 2.1.0: per-user lookup. The 2.0.0 single-token
    /// field is gone — the `users` table is the only
    /// source of truth.
    pub users: UserRepository,
    /// Retained for 2.0.0→2.1.0 migration: if the
    /// `users` table is empty on first start and this
    /// is `Some(legacy)`, the server creates an
    /// `admin` user with `token_hash = sha256(legacy)`
    /// so existing scripts keep working.
    pub legacy_token: Arc<Option<String>>,
}
