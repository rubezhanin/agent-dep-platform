use crate::ipc_error::IpcResult;
use agent_dep_core::dto::LogLine;

#[tauri::command]
pub async fn tail(_n: usize) -> IpcResult<Vec<LogLine>> {
    Ok(vec![])
}
