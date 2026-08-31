use crate::ipc_error::IpcResult;
use agent_dep_core::dto::SystemSummary;

#[tauri::command]
pub async fn list_systems() -> IpcResult<Vec<SystemSummary>> {
    Ok(vec![])
}
