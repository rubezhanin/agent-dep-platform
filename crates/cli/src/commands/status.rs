use crate::output;
use agent_dep_core::error::{CoreError, CoreResult};
use agent_dep_hermes_adapter::detection::detect_hermes;
use agent_dep_hermes_adapter::paths::default_hermes_home;
use std::path::PathBuf;

pub async fn run() -> CoreResult<()> {
    let home: PathBuf = default_hermes_home().unwrap_or_else(|| PathBuf::from("."));
    output::header("Runtime status");
    match detect_hermes(&home) {
        Ok(info) => {
            output::kv("hermes", "found");
            output::kv("version", &info.version);
            output::kv("home", &info.home.display().to_string());
            output::kv("plugin_dir", &info.plugin_dir.display().to_string());
            Ok(())
        }
        Err(CoreError::ErrHermesNotFound) => {
            output::kv("hermes", "not found");
            output::hint("install Hermes or set HERMES_HOME");
            Ok(()) // Status is informational, not a hard error.
        }
        Err(e) => Err(e),
    }
}
