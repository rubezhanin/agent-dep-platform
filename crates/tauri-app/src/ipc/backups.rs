use crate::ipc_error::IpcResult;
use crate::state::AppState;
use agent_dep_core::dto::BackupSummary;
use chrono::{DateTime, Utc};
use std::path::Path;
use tauri::State;
use walkdir::WalkDir;

/// Walk every `.backups/` directory under `<hermes_home>/plugins/`
/// (where `agency deploy install` writes them via the deploy
/// service) and return one `BackupSummary` per file. We do NOT
/// scan app-wide for backup directories on purpose: the MVP-1.0
/// contract is that the platform owns backups under its own
/// tree; user-created backup directories are out of scope.
#[tauri::command]
pub async fn list_backups(state: State<'_, AppState>) -> IpcResult<Vec<BackupSummary>> {
    let mut out = Vec::new();
    let plugins_root = state.hermes.hermes_home().join("plugins");
    if !plugins_root.is_dir() {
        return Ok(out);
    }
    for entry in WalkDir::new(&plugins_root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // Match `<…>/.backups/<file>`. We check the parent
        // directory's name so any nested depth is fine.
        let Some(parent) = path.parent() else {
            continue;
        };
        if parent.file_name().and_then(|s| s.to_str()) != Some(".backups") {
            continue;
        }
        let mtime = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| {
                let dt: DateTime<Utc> = DateTime::<Utc>::from_timestamp(d.as_secs() as i64, 0)
                    .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap());
                dt.to_rfc3339()
            })
            .unwrap_or_default();
        out.push(BackupSummary {
            id: format!(
                "{}|{}",
                parent.display(),
                path.file_name().and_then(|s| s.to_str()).unwrap_or("")
            ),
            path: rel_to_hermes(path, state.hermes.hermes_home()),
            created_at: mtime,
        });
    }
    // Newest first.
    out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(out)
}

fn rel_to_hermes(p: &Path, root: &Path) -> String {
    p.strip_prefix(root)
        .map(|r| r.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| p.display().to_string())
}
