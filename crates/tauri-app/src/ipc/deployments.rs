use crate::ipc_error::IpcResult;
use agent_dep_core::dto::DeploymentSummary;

#[tauri::command]
pub async fn list_deployments() -> IpcResult<Vec<DeploymentSummary>> {
    Ok(vec![])
}
