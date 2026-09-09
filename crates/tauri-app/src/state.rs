//! Application state injected into every Tauri command via `tauri::State<AppState>`.

use agent_dep_core::infrastructure::content_store::ContentStore;
use agent_dep_core::infrastructure::sqlite::Db;
use agent_dep_hermes_adapter::HermesAdapter;
use std::path::PathBuf;
use std::sync::Arc;

pub struct AppState {
    pub db: Db,
    pub cas: ContentStore,
    pub paths: AppPaths,
    pub config: AppConfig,
    pub hermes: Arc<HermesAdapter>,
    /// 3.0.0 (A5, audit): the
    /// URL of the embedded
    /// `axum` server. The
    /// IPC commands proxy
    /// HTTP requests to
    /// `server_url` instead
    /// of re-implementing
    /// the business
    /// logic on the Tauri
    /// side. `None` only
    /// during the
    /// pre-`setup` window
    /// (the IPC commands
    /// are not callable
    /// before `setup`
    /// completes, so the
    /// `None` case is
    /// unreachable from
    /// the IPC layer).
    pub server_url: Arc<Option<String>>,
}

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub app_data_dir: PathBuf,
    pub cas_root: PathBuf,
    pub db_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub log_level: String,
}
