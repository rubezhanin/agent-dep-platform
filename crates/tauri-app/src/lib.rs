//! Tauri 2 host for the Agent Deployment Platform.

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn run() -> tauri::Result<()> {
    tauri::Builder::default()
        .setup(|_app| {
            tracing::info!("Tauri app starting up (MVP-0 stub)");
            Ok(())
        })
        .run(tauri::generate_context!())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }
}
