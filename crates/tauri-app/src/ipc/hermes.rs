use crate::ipc_error::IpcResult;
use crate::state::AppState;
use agent_dep_hermes_adapter::types::RuntimeInfo;
use agent_dep_hermes_adapter::RuntimeAdapter;
use tauri::State;

#[tauri::command]
pub async fn detect(state: State<'_, AppState>) -> IpcResult<RuntimeInfo> {
    state.hermes.detect().map_err(Into::into)
}
