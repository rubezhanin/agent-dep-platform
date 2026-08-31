use crate::ipc_error::{IpcError, IpcResult};
use agent_dep_core::dto::Plan;

#[tauri::command]
pub async fn compute(_system_id: String) -> IpcResult<Plan> {
    Err(IpcError::Internal(
        "plans.compute: not yet implemented (MVP-0 stub)".into(),
    ))
}
