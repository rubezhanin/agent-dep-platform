use crate::ipc_error::{IpcError, IpcResult};
use agent_dep_core::dto::ScanResult;

#[tauri::command]
pub async fn scan(_source_id: String) -> IpcResult<ScanResult> {
    Err(IpcError::Internal(
        "security.scan: not yet implemented (MVP-0 stub)".into(),
    ))
}
