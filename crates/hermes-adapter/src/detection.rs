//! Hermes detection (MVP-0: minimal — check `hermes` CLI in PATH via `which`,
//! plus presence of `HERMES_HOME` or default `~/.hermes`).

use crate::paths::{default_hermes_home, plugin_dir};
use crate::types::RuntimeInfo;
use agent_dep_core::error::{CoreError, CoreResult};
use std::path::Path;
use which::which;

pub fn detect_hermes(home_override: &Path) -> CoreResult<RuntimeInfo> {
    // 1. Check that `hermes` CLI is on PATH.
    let hermes_bin = which("hermes").map_err(|_| CoreError::ErrHermesNotFound)?;

    // 2. Determine home: override > HERMES_HOME > ~/.hermes.
    let home = if home_override.as_os_str().is_empty() {
        default_hermes_home().ok_or(CoreError::ErrHermesNotFound)?
    } else {
        home_override.to_path_buf()
    };

    // 3. Plugin dir under home.
    let pdir = plugin_dir(&home);

    // 4. Version: from `hermes --version` (best effort). Empty if it fails.
    let version = read_hermes_version(&hermes_bin).unwrap_or_else(|_| "unknown".to_string());

    Ok(RuntimeInfo {
        version,
        home,
        plugin_dir: pdir,
    })
}

fn read_hermes_version(bin: &Path) -> std::io::Result<String> {
    let out = std::process::Command::new(bin).arg("--version").output()?;
    if !out.status.success() {
        return Err(std::io::Error::other("non-zero exit"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
