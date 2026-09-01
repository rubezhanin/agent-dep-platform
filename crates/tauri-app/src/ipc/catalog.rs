use crate::ipc_error::IpcResult;
use crate::state::AppState;
use agent_dep_core::dto::AgentSummary;
use agent_dep_core::infrastructure::repository::IngestRepository;
use tauri::State;

#[tauri::command]
pub async fn list_agents(state: State<'_, AppState>) -> IpcResult<Vec<AgentSummary>> {
    let repo = IngestRepository::new(state.db.pool().clone());
    let rows = repo.list_agents_in_latest_snapshot().await?;
    Ok(rows
        .into_iter()
        .map(|a| AgentSummary {
            id: a.id,
            name: a.name,
            version: a.version,
        })
        .collect())
}
