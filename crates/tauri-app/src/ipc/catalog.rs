use crate::ipc_error::IpcResult;
use agent_dep_core::dto::AgentSummary;

#[tauri::command]
pub async fn list_agents() -> IpcResult<Vec<AgentSummary>> {
    Ok(vec![])
}
