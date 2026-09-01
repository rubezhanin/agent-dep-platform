use crate::ipc_error::IpcResult;
use crate::state::AppState;
use agent_dep_core::dto::SystemSummary;
use agent_dep_core::infrastructure::repository::deployed_artifacts_repository::DeployedArtifactsRepository;
use tauri::State;

/// MVP-1.0: systems are not stored in the database (the
/// `system.yaml` lives in the user's Git repo, per ADR-0004).
/// The best signal we have about which systems have been
/// touched is the distinct `system_id` column in
/// `deployed_artifacts`. We synthesize a `SystemSummary` per
/// distinct id, with an empty name/version (the v2 schema
/// carries those on the lock file, not the artifact table).
#[tauri::command]
pub async fn list_systems(state: State<'_, AppState>) -> IpcResult<Vec<SystemSummary>> {
    let repo = DeployedArtifactsRepository::new(state.db.pool().clone());
    let ids = repo.list_distinct_systems().await?;
    Ok(ids
        .into_iter()
        .map(|id| SystemSummary {
            id,
            name: String::new(),
            version: String::new(),
        })
        .collect())
}
