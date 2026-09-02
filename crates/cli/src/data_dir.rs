//! CLI data directory resolution.
//!
//! Per ADR-0004 the SQLite DB lives under a per-user data dir. The
//! Tauri app uses `app.path().app_data_dir()`; the CLI uses
//! `$AGENCY_DATA_DIR` if set, otherwise
//! `$USERPROFILE/.agency` (Windows) or `$HOME/.agency` (other) and
//! puts the DB at `<data>/data/agency.db`.

use std::path::PathBuf;

pub fn default_data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("AGENCY_DATA_DIR") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".agency")
}

pub fn default_db_path() -> PathBuf {
    default_data_dir().join("data").join("agency.db")
}

/// Per-app-data-dir cache for Git working copies used by
/// `agency catalog add` (1.1.0). The structure is
/// `<data>/sources/<source_id>/` and survives across
/// re-ingest runs so `agency catalog update` only does
/// `git fetch` rather than `git clone`.
pub fn default_working_copy_root() -> PathBuf {
    default_data_dir().join("sources")
}

/// Default Hermes home for `agency mcp add` (1.3.0).
/// Falls back to `<app_data_dir>/hermes/` if no real
/// Hermes install is found on the host.
pub fn default_hermes_home() -> PathBuf {
    if let Ok(p) = std::env::var("AGENCY_HERMES_HOME") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Some(p) = agent_dep_hermes_adapter::paths::default_hermes_home() {
        return p;
    }
    default_data_dir().join("hermes")
}

/// 1.5.1 (ADR-0016) — content-addressed backup store root.
/// Per `ContentStore` layout, content lives at
/// `<root>/sha256/ab/cd/abcdef...`. Override with
/// `AGENCY_CAS_ROOT` for tests.
pub fn default_cas_root() -> PathBuf {
    if let Ok(p) = std::env::var("AGENCY_CAS_ROOT") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    default_data_dir().join("cas")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_var_overrides_home() {
        // SAFETY: tests in this module do not read AGENCY_DATA_DIR
        // outside the override; we set it for the duration of the call.
        // SAFETY: single-threaded test runtime; no other thread reads
        // the env var here.
        let prev = std::env::var("AGENCY_DATA_DIR").ok();
        // SAFETY: see above.
        unsafe {
            std::env::set_var("AGENCY_DATA_DIR", "X:/custom/agency");
        }
        let p = default_data_dir();
        match prev {
            Some(v) => unsafe { std::env::set_var("AGENCY_DATA_DIR", v) },
            None => unsafe { std::env::remove_var("AGENCY_DATA_DIR") },
        }
        assert_eq!(p, PathBuf::from("X:/custom/agency"));
    }

    #[test]
    fn default_db_path_lives_under_data_subdir() {
        let prev = std::env::var("AGENCY_DATA_DIR").ok();
        unsafe {
            std::env::remove_var("AGENCY_DATA_DIR");
        }
        let p = default_db_path();
        match prev {
            Some(v) => unsafe { std::env::set_var("AGENCY_DATA_DIR", v) },
            None => unsafe { std::env::remove_var("AGENCY_DATA_DIR") },
        }
        assert!(p.ends_with("data/agency.db") || p.ends_with("data\\agency.db"));
    }
}
