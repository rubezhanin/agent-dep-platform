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
