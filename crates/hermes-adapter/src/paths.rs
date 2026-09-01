//! Hermes paths (HERMES_HOME, plugin dir).

use std::path::PathBuf;

pub fn default_hermes_home() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("HERMES_HOME") {
        return Some(PathBuf::from(p));
    }
    dirs_home().map(|h| h.join(".hermes"))
}

#[cfg(target_os = "windows")]
fn dirs_home() -> Option<PathBuf> {
    std::env::var("USERPROFILE").ok().map(PathBuf::from)
}

#[cfg(not(target_os = "windows"))]
fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

pub fn plugin_dir(home: &std::path::Path) -> std::path::PathBuf {
    home.join("plugins")
}

/// Same as `plugin_dir` but returns a `Result` so callers in
/// the application layer can report the resolution failure.
pub fn hermes_plugins_dir(
    home: &std::path::Path,
) -> Result<std::path::PathBuf, agent_dep_core::error::CoreError> {
    if !home.is_dir() {
        return Err(agent_dep_core::error::CoreError::ErrHermesNotFound);
    }
    Ok(home.join("plugins"))
}
