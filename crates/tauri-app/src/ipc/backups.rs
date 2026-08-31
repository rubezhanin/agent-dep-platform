use crate::ipc_error::IpcResult;
use agent_dep_core::dto::BackupSummary;

#[tauri::command]
pub async fn list_backups() -> IpcResult<Vec<BackupSummary>> {
    Ok(vec![])
}
