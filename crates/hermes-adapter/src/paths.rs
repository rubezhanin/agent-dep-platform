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
