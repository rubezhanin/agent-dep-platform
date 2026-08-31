use crate::ipc_error::IpcResult;
use agent_dep_core::dto::SourceSummary;

#[tauri::command]
pub async fn list_sources() -> IpcResult<Vec<SourceSummary>> {
    Ok(vec![])
}
