use crate::ipc_error::IpcResult;
use crate::state::AppState;
use agent_dep_core::dto::SourceSummary;
use tauri::State;

/// 3.0.0 (A5, audit): the
/// IPC command is a thin
/// HTTP proxy to the
/// embedded `axum`
/// server. The 2.x HTTP
/// `GET /v1/sources`
/// handler is the
/// single source of
/// truth; the IPC layer
/// just calls it. The
/// pre-3.0.0
/// implementation
/// duplicated the
/// `SourceKind` →
/// `url` mapping logic
/// here, and a Tauri
/// upgrade was needed
/// every time the
/// `Source` domain
/// evolved. A5 removes
/// that coupling.
///
/// The `reqwest::Client`
/// is intentionally a
/// per-command fresh
/// client. Tauri's
/// command runtime
/// already pays the
/// `Arc<Client>` cost
/// per call (and the
/// connection-pool
/// reuse is negligible
/// for a localhost
/// request); a
/// future 3.1 follow-up
/// can plumb a
/// long-lived
/// `reqwest::Client`
/// through
/// `AppState` if the
/// profile shows it.
#[tauri::command]
pub async fn list_sources(state: State<'_, AppState>) -> IpcResult<Vec<SourceSummary>> {
    let server_url = state.server_url.as_ref().as_ref().ok_or_else(|| {
        crate::ipc_error::IpcError::Internal(
            "embedded server URL not set (Tauri setup did not complete)".to_string(),
        )
    })?;
    // The HTTP route is
    // `GET /v1/sources`.
    // The OIDC bearer
    // token (if any) is
    // not yet wired —
    // the embedded
    // server trusts the
    // Tauri-host loopback
    // transport. A 3.1
    // follow-up adds the
    // CSRF / bearer
    // bridging so the
    // OIDC-protected
    // routes work
    // through IPC.
    let url = format!("{server_url}/v1/sources");
    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| crate::ipc_error::IpcError::Internal(format!("HTTP GET {url}: {e}")))?;
    if !response.status().is_success() {
        return Err(crate::ipc_error::IpcError::Internal(format!(
            "HTTP GET {url} returned {}",
            response.status()
        )));
    }
    let out: Vec<SourceSummary> = response
        .json()
        .await
        .map_err(|e| crate::ipc_error::IpcError::Internal(format!("HTTP GET {url} body: {e}")))?;
    Ok(out)
}
