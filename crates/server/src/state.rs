//! Shared application state for the 2.0.0 server.

use std::sync::Arc;

use agent_dep_core::infrastructure::repository::audit_log_repository::AuditLogRepository;
use agent_dep_core::infrastructure::sqlite::Db;

#[derive(Clone)]
pub struct ServerState {
    pub db: Db,
    pub audit: AuditLogRepository,
    /// Bearer token used by `auth::require_bearer`.
    /// Wrapped in `Arc` so the middleware can compare
    /// by reference without copying the 43-char string.
    pub token: Arc<String>,
}
