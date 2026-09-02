use crate::ipc_error::IpcResult;
use crate::state::AppState;
use agent_dep_core::domain::source::SourceKind;
use agent_dep_core::dto::SourceSummary;
use agent_dep_core::infrastructure::repository::IngestRepository;
use tauri::State;

#[tauri::command]
pub async fn list_sources(state: State<'_, AppState>) -> IpcResult<Vec<SourceSummary>> {
    let repo = IngestRepository::new(state.db.pool().clone());
    let sources = repo.list_sources().await?;
    let out = sources
        .into_iter()
        .map(|s| {
            let url = match &s.kind {
                SourceKind::Local { path } => path.display().to_string(),
                SourceKind::GitHttps { url } | SourceKind::GitSsh { url } => url.clone(),
            };
            SourceSummary {
                id: s.id.to_string(),
                url,
                commit_sha: s.pinned_ref.unwrap_or_default(),
            }
        })
        .collect();
    Ok(out)
}
