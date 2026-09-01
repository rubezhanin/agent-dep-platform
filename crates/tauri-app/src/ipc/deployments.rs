use crate::ipc_error::IpcResult;
use crate::state::AppState;
use agent_dep_core::application::journal::JournalService;
use agent_dep_core::dto::DeploymentSummary;
use tauri::State;

/// Most-recent 50 operations of any kind. MVP-1.0 does not
/// yet separate `deploy` from `rollback` in the UI; both
/// types show up in the same history list.
#[tauri::command]
pub async fn list_deployments(state: State<'_, AppState>) -> IpcResult<Vec<DeploymentSummary>> {
    let journal = JournalService::new(state.db.pool().clone());
    let ops = journal.list_recent(50).await?;
    Ok(ops
        .into_iter()
        .map(|op| DeploymentSummary {
            id: op.id.to_string(),
            system_id: op.plan_hash.chars().take(12).collect::<String>(),
            status: op.status.as_str().to_string(),
            created_at: op.started_at.to_rfc3339(),
        })
        .collect())
}
