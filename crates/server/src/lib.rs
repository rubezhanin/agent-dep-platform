//! Library surface for the `agency-server` crate.
//!
//! 2.0.0: integration tests link against this lib to
//! bind a real `axum` router on a random port. The
//! `main.rs` binary is a thin wrapper that constructs
//! the production `ServerState` and calls `axum::serve`.

pub mod auth;
pub mod catalog;
pub mod handlers;
pub mod plan;
pub mod state;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agent_dep_core::infrastructure::repository::audit_log_repository::AuditLogRepository;
use agent_dep_core::infrastructure::sqlite::connect;
use anyhow::{Context, Result};
use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use base64::Engine;
use rand::RngCore;
use tower_http::trace::TraceLayer;

pub use state::ServerState;

pub fn router(state: ServerState) -> Router {
    let authed = Router::new()
        .route("/v1/audit", get(handlers::list_audit))
        .route("/v1/systems", get(handlers::list_systems))
        .route("/v1/systems/plan", post(handlers::plan_system))
        .route("/v1/rollback/:id", post(handlers::rollback_operation))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_bearer,
        ));
    Router::new()
        .route("/v1/health", get(handlers::health))
        .merge(authed)
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

/// Read the bearer token from `path`. If the file does
/// not exist, generate a 256-bit random token, persist
/// it, and return it. The file is created with mode
/// 0600 on POSIX (best effort — `std::fs` does not
/// expose a portable chmod, so we wrap the file in a
/// directory that already has restrictive permissions).
pub fn ensure_token(path: &Path) -> Result<String> {
    if path.is_file() {
        let s =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let trimmed = s.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    std::fs::write(path, &token).with_context(|| format!("write {}", path.display()))?;
    set_token_file_mode(path);
    Ok(token)
}

#[cfg(unix)]
fn set_token_file_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn set_token_file_mode(_path: &Path) {}

pub fn default_data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("AGENCY_SERVER_DATA_DIR") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(p) = std::env::var("AGENCY_DATA_DIR") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".agency-server")
}

pub fn default_db_path() -> PathBuf {
    default_data_dir().join("data").join("agency.db")
}

/// Boot a `ServerState` for the hermetic default
/// data dir. Used by the production `main.rs`.
pub async fn boot_default_state() -> Result<ServerState> {
    let data_dir = default_data_dir();
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("create_dir_all {}", data_dir.display()))?;
    let token = ensure_token(&data_dir.join("server.token"))?;
    let db_path = default_db_path();
    std::fs::create_dir_all(db_path.parent().unwrap())?;
    let db = connect(&db_path).await?;
    db.migrate().await?;
    let audit = AuditLogRepository::new(db.pool().clone());
    Ok(ServerState {
        db,
        audit,
        token: Arc::new(token),
    })
}

pub fn parse_port(args: &[String]) -> u16 {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--port" {
            if let Some(v) = args.get(i + 1) {
                if let Ok(n) = v.parse::<u16>() {
                    if n != 0 {
                        return n;
                    }
                }
            }
        }
        i += 1;
    }
    0
}

pub async fn run(addr: SocketAddr) -> Result<()> {
    let state = boot_default_state().await?;
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    eprintln!("agency-server listening on http://{addr}");
    axum::serve(listener, app)
        .await
        .with_context(|| "axum::serve")?;
    Ok(())
}
