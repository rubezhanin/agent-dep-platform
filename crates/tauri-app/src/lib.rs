//! Tauri 2 host for the Agent Deployment Platform.

mod ipc;
mod ipc_error;
mod state;
mod tracing_init;

pub use state::{AppConfig, AppPaths, AppState};
pub use tracing_init::TracingGuard;

use std::sync::Arc;
use tauri::Manager;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn run() -> tauri::Result<()> {
    tauri::Builder::default()
        .setup(|app| {
            // Resolve app data dir.
            let app_data_dir =
                app.path()
                    .app_data_dir()
                    .map_err(|e| -> Box<dyn std::error::Error> {
                        format!("app_data_dir: {e}").into()
                    })?;
            std::fs::create_dir_all(&app_data_dir)?;

            // Initialize tracing.
            let guard =
                tracing_init::init(&app_data_dir).map_err(|e| -> Box<dyn std::error::Error> {
                    format!("tracing init: {e}").into()
                })?;
            app.manage(guard);
            tracing::info!("Tauri app starting up (MVP-0)");

            // Initialize DB.
            let db_path = app_data_dir.join("data").join("agent-dep.db");
            std::fs::create_dir_all(db_path.parent().unwrap())?;
            let db_path_for_connect = db_path.clone();
            let db = tauri::async_runtime::block_on(async move {
                agent_dep_core::infrastructure::sqlite::connect(&db_path_for_connect).await
            })
            .map_err(|e| -> Box<dyn std::error::Error> { format!("db connect: {e}").into() })?;
            tauri::async_runtime::block_on(async { db.migrate().await })
                .map_err(|e| -> Box<dyn std::error::Error> { format!("db migrate: {e}").into() })?;

            // Initialize CAS.
            let cas_root = app_data_dir.join("cas");
            let cas =
                agent_dep_core::infrastructure::content_store::ContentStore::new(cas_root.clone())
                    .map_err(|e| -> Box<dyn std::error::Error> { format!("cas: {e}").into() })?;

            // Hermes adapter.
            let hermes_home = agent_dep_hermes_adapter::paths::default_hermes_home()
                .unwrap_or_else(|| app_data_dir.join("hermes"));
            let hermes = Arc::new(agent_dep_hermes_adapter::HermesAdapter::new(hermes_home));

            // Compose AppState.
            let state = AppState {
                db,
                cas,
                paths: AppPaths {
                    app_data_dir,
                    cas_root,
                    db_path,
                },
                config: AppConfig {
                    log_level: "info".into(),
                },
                hermes,
            };
            app.manage(state);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ipc::catalog::list_agents,
            ipc::sources::list_sources,
            ipc::systems::list_systems,
            ipc::plans::compute,
            ipc::deployments::list_deployments,
            ipc::backups::list_backups,
            ipc::hermes::detect,
            ipc::security::scan,
            ipc::logs::tail,
        ])
        .run(tauri::generate_context!())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }
}
