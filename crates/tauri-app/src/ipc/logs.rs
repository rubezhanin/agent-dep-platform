use crate::ipc_error::IpcResult;
use crate::state::AppState;
use agent_dep_core::dto::LogLine;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use tauri::State;

/// Tail the most recent N JSON-lines from the daily log
/// file (`<app_data_dir>/logs/app.json`). If the file is
/// missing or shorter than N lines, returns whatever was
/// found. The trailing bytes of a partial line (the file
/// is being actively appended to) are dropped.
#[tauri::command]
pub async fn tail(state: State<'_, AppState>, n: usize) -> IpcResult<Vec<LogLine>> {
    let n = n.min(1000); // hard cap
    let path = state.paths.app_data_dir.join("logs").join("app.json");
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let f = match File::open(&path) {
        Ok(f) => f,
        Err(_) => return Ok(Vec::new()),
    };
    // Read at most 256 KiB from the end. Each line is one
    // JSON object; on average ~250 bytes, so 256 KiB is
    // ~1000 lines — enough for any UI page.
    const READ_WINDOW: u64 = 256 * 1024;
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(READ_WINDOW);
    let mut reader = BufReader::new(f);
    let _ = reader.seek(SeekFrom::Start(start));
    let mut lines: Vec<String> = Vec::new();
    for line in reader.lines().map_while(Result::ok) {
        if line.is_empty() {
            continue;
        }
        lines.push(line);
    }
    // Drop a leading partial line if we did not start at 0.
    if start > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    // Keep only the last N.
    let start_idx = lines.len().saturating_sub(n);
    let window = &lines[start_idx..];

    let mut out = Vec::with_capacity(window.len());
    for raw in window {
        let v: serde_json::Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ts = v
            .get("timestamp")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        let level = v
            .get("level")
            .and_then(|l| l.as_str())
            .unwrap_or("")
            .to_string();
        let target = v
            .get("fields")
            .and_then(|f| f.get("target"))
            .or_else(|| v.get("target"))
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        let message = v
            .get("fields")
            .and_then(|f| f.get("message"))
            .or_else(|| v.get("message"))
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        out.push(LogLine {
            ts,
            level,
            target,
            message,
        });
    }
    Ok(out)
}
