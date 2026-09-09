//! 3.0.0 (A5, audit): the Tauri
//! host boots an embedded
//! `axum` server (the same
//! router `agency-server`
//! uses) on `127.0.0.1:0` and
//! the IPC commands proxy
//! HTTP requests to it.
//!
//! ## Why
//!
//! Pre-3.0.0 had a duplicate
//! handler set: one axum
//! handler in
//! `crates/server/src/handlers.rs`,
//! one Tauri command in
//! `crates/tauri-app/src/ipc/*.rs`,
//! for the same business
//! operation (e.g. "list
//! sources"). The two paths
//! diverged over time — the
//! OIDC login flow, the
//! Prometheus metrics, the
//! audit log rows, the
//! rate-limiter counters all
//! landed on the HTTP side
//! but never reached the Tauri
//! IPC side. A5 collapses the
//! two surfaces so the Tauri
//! app exposes the full 2.x
//! HTTP API automatically and
//! the IPC layer is a thin
//! proxy (one HTTP `GET` per
//! command).
//!
//! ## Scope of this commit
//!
//! - The embedded server is
//!   booted at app setup and
//!   its bound URL is stored
//!   in `AppState::server_url`.
//! - The first IPC command
//!   (`list_sources`) is
//!   migrated to the proxy
//!   pattern. The other 8
//!   commands keep their
//!   pre-existing Tauri-
//!   side logic with a
//!   `// 3.0.0 (A5, audit,
//!   TODO)` marker so a
//!   follow-up series of
//!   3.1 / 3.2 commits
//!   finishes the migration.
//! - A new integration test
//!   boots the embedded
//!   server, hits the same
//!   URL over HTTP via
//!   `reqwest`, and asserts
//!   the IPC and HTTP paths
//!   return the same JSON.
//!
//! ## Why bind 127.0.0.1 (not
//! 0.0.0.0)
//!
//! The embedded server is a
//! private IPC transport. It
//! MUST NOT be reachable from
//! the network. Binding
//! `0.0.0.0` would expose the
//! 2.x HTTP API (and any
//! OIDC-protected session
//! cookies) to the LAN. The
//! `setup` is `127.0.0.1:0` and
//! the port is kernel-assigned
//! (and thus unpredictable, so
//! an attacker on the same
//! host has to guess).
//! Production `agency-server`
//! is the separate process
//! bound per the operator's
//! `AGENCY_BIND_*` config; the
//! embedded server is
//! IPC-only.

use std::net::SocketAddr;
use std::sync::Arc;

use agent_dep_core::infrastructure::sqlite::Db;
use agent_dep_server::audit_recorder::AuditRecorder;
use agent_dep_server::metrics::Metrics;
use agent_dep_server::oidc::OidcConfig;
use agent_dep_server::oidc_client::{MockOidcClient, OidcClient};
use agent_dep_server::rate_limit::RateLimiter;
use agent_dep_server::ServerState;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::info;

/// What the embedded server
/// returns to the Tauri
/// `setup` closure. The
/// `AppState` is enriched
/// with the `server_url` so
/// the IPC proxy layer knows
/// where to send HTTP
/// requests.
pub struct EmbeddedServerHandle {
    /// The local URL the
    /// embedded server is
    /// bound to (e.g.
    /// `http://127.0.0.1:54321`).
    /// Stored in
    /// `AppState::server_url`
    /// for the IPC proxy.
    pub url: String,
    /// The bound `SocketAddr`
    /// (the port half is
    /// kernel-assigned since
    /// we bind `:0`).
    pub addr: SocketAddr,
    /// The background task
    /// serving the axum
    /// router. Held so a
    /// future graceful-shutdown
    /// path (Tauri's
    /// `RunEvent::ExitRequested`)
    /// can `await` the
    /// in-flight requests
    /// before the app
    /// exits. For 3.0.0 the
    /// handle is dropped (the
    /// task is cancelled when
    /// the Tauri runtime
    /// shuts down).
    pub join: JoinHandle<()>,
}

/// 3.0.0 (A5, audit): boot
/// the embedded `axum`
/// server and return the
/// bound URL.
///
/// Takes only the `Db` (the
/// Tauri app already owns
/// the pool; the embedded
/// server shares it) so the
/// `setup` closure can boot
/// the server BEFORE
/// constructing the final
/// `AppState` (which needs
/// the bound URL).
pub async fn boot(db: &Db) -> anyhow::Result<EmbeddedServerHandle> {
    let pool = db.pool().clone();
    let audit_repo =
        agent_dep_core::infrastructure::repository::audit_log_repository::AuditLogRepository::new(
            pool.clone(),
        );
    let users = agent_dep_core::infrastructure::repository::users_repository::UserRepository::new(
        pool.clone(),
    );
    let deploys = agent_dep_core::infrastructure::repository::pending_deploys_repository::PendingDeployRepository::new(pool.clone());
    let secrets =
        agent_dep_core::infrastructure::repository::secrets_repository::SecretRepository::new(
            pool.clone(),
            "embedded-tauri-passphrase-not-used",
            &[0u8;
                agent_dep_core::infrastructure::repository::secrets_repository::INSTALL_SALT_LEN],
        )
        .expect("vault init (embedded)");
    let targets =
        agent_dep_core::infrastructure::repository::targets_repository::TargetRepository::new(
            pool.clone(),
        );
    let oidc_pending = std::sync::Arc::new(
        agent_dep_core::infrastructure::repository::oidc_pending_repository::OidcPendingRepository::new(pool.clone()),
    );
    let oidc_client: Arc<dyn OidcClient> = Arc::new(MockOidcClient);
    let sessions =
        agent_dep_core::infrastructure::repository::sessions_repository::SessionRepository::new(
            pool.clone(),
        );
    let idempotency = agent_dep_core::infrastructure::repository::idempotency_repository::IdempotencyRepository::new(pool.clone());
    let audit = AuditRecorder::direct_with_metrics(audit_repo, Metrics::new());
    let server_state = ServerState {
        db: db.clone(),
        audit,
        users,
        deploys,
        secrets,
        targets,
        oidc: OidcConfig::default(),
        oidc_pending,
        oidc_client,
        legacy_token: Arc::new(None),
        sessions,
        cookie_secure: false,
        idempotency,
        rate_limiter: Arc::new(RateLimiter::new()),
        max_body_bytes: Arc::new(std::sync::atomic::AtomicU32::new(
            agent_dep_server::rate_limit::MAX_BODY_BYTES,
        )),
        max_header_count: Arc::new(std::sync::atomic::AtomicU32::new(
            agent_dep_server::rate_limit::MAX_HEADER_COUNT,
        )),
        metrics: Metrics::new(),
    };
    let app = agent_dep_server::router(server_state);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let url = format!("http://{addr}");
    info!(%url, "3.0.0 (A5): embedded axum server bound");
    let join = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = %e, "embedded axum server exited with error");
        }
    });
    Ok(EmbeddedServerHandle { url, addr, join })
}
