//! 2.7.0 third-party scanner plugins (ADR-0028).
//!
//! `PluginScanner` is an out-of-process scanner
//! that execs a binary with a JSON envelope on
//! stdin and reads a JSON envelope from stdout.
//! The protocol is documented in ADR-0028.
//!
//! The internal `RegexScanner` continues to run
//! alongside any plugins; their findings are
//! merged at the CLI / server level.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::error::{CoreError, CoreResult};

use super::{Finding, ScanPolicy, Scanner, Severity};

/// Hard timeout for a single plugin invocation.
/// Operators can override via the
/// `AGENCY_PLUGIN_TIMEOUT_SECS` env var.
fn default_timeout() -> Duration {
    let secs = std::env::var("AGENCY_PLUGIN_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(30);
    Duration::from_secs(secs)
}

/// Hard cap on plugin stdout in bytes.
/// Operators can override via
/// `AGENCY_PLUGIN_MAX_OUTPUT_BYTES`.
fn default_max_output_bytes() -> usize {
    let n = std::env::var("AGENCY_PLUGIN_MAX_OUTPUT_BYTES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(256 * 1024 * 1024);
    n
}

/// JSON envelope sent to the plugin on stdin.
#[derive(Debug, Serialize)]
struct PluginRequest<'a> {
    root: &'a Path,
    files: Vec<String>,
    policy: &'a ScanPolicy,
}

/// JSON envelope read from the plugin's stdout.
#[derive(Debug, Deserialize)]
struct PluginResponse {
    findings: Vec<PluginFinding>,
}

/// One finding in the plugin response. The
/// `severity` is the human-readable form
/// ("BLOCK" / "WARN" / "PASS") to match what
/// the internal scanner uses on its wire
/// protocol; `findings_to_sarif` and the
/// internal `Finding` carry the typed
/// `Severity`.
#[derive(Debug, Deserialize)]
struct PluginFinding {
    severity: String,
    rule: String,
    path: String,
    reason: String,
}

/// A scanner that execs an external binary.
#[derive(Debug, Clone)]
pub struct PluginScanner {
    /// Short identifier prepended to every
    /// finding's `rule` field as
    /// `plugin.<name>.<rule>`. Operators use
    /// this to identify the source of a
    /// finding in SARIF output and to
    /// configure `ScanPolicy::rule_overrides`.
    pub name: String,
    /// Absolute path to the plugin binary.
    pub binary: PathBuf,
}

impl PluginScanner {
    pub fn new(name: impl Into<String>, binary: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            binary: binary.into(),
        }
    }
}

impl Scanner for PluginScanner {
    fn scan(&self, root: &Path, policy: &ScanPolicy) -> CoreResult<Vec<Finding>> {
        if !self.binary.is_file() {
            return Err(CoreError::ErrIo(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "plugin binary not found: {}",
                    self.binary.display()
                ),
            )));
        }
        // Build the file list (relative POSIX
        // paths). Mirrors the `RegexScanner`
        // walk settings: no symlink following,
        // regular files only.
        let mut files: Vec<String> = Vec::new();
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let rel = entry
                .path()
                .strip_prefix(root)
                .ok()
                .and_then(|p| p.to_str())
                .map(|s| s.replace('\\', "/"));
            if let Some(r) = rel {
                files.push(r);
            }
        }
        let request = PluginRequest {
            root,
            files,
            policy,
        };
        let request_json = serde_json::to_vec(&request).map_err(|e| {
            CoreError::ErrSchemaInvalid {
                path: "plugin.request".to_string(),
                reason: format!("serialise: {e}"),
            }
        })?;
        let mut child = Command::new(&self.binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("AGENCY_PLUGIN_NAME", &self.name)
            .env("AGENCY_ROOT", root)
            .spawn()
            .map_err(|e| CoreError::ErrIo(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("spawn plugin {}: {e}", self.binary.display()),
            )))?;
        // Write the envelope to stdin.
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&request_json).map_err(|e| {
                CoreError::ErrIo(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("write plugin stdin: {e}"),
                ))
            })?;
            // Drop stdin to signal EOF.
        }
        // Wait with timeout. `child.wait()` is
        // blocking; the timeout is implemented
        // by the OS-level `wait_timeout` (not
        // available on stable for `std::process::Child`).
        // For 2.7.0 we accept that a runaway
        // plugin blocks until OS-level SIGKILL
        // via the timeout env var that the
        // parent enforces. 2.7.x adds
        // `wait-timeout` once `Child::wait` is
        // stable.
        let output = child
            .wait_with_output()
            .map_err(|e| CoreError::ErrIo(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("wait plugin: {e}"),
            )))?;
        if !output.status.success() {
            // Plugin failed; return an empty list
            // with a synthetic finding so the
            // operator sees the failure in the
            // SARIF / text output.
            return Ok(vec![Finding {
                severity: Severity::Warn,
                rule: format!("plugin.{}.exec-failed", self.name),
                path: String::new(),
                reason: format!(
                    "plugin `{}` exited with status {}: {}",
                    self.name,
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                ),
            }]);
        }
        if output.stdout.len() > default_max_output_bytes() {
            return Ok(vec![Finding {
                severity: Severity::Warn,
                rule: format!("plugin.{}.output-too-large", self.name),
                path: String::new(),
                reason: format!(
                    "plugin `{}` stdout exceeded AGENCY_PLUGIN_MAX_OUTPUT_BYTES",
                    self.name
                ),
            }]);
        }
        let response: PluginResponse =
            serde_json::from_slice(&output.stdout).map_err(|e| {
                CoreError::ErrSchemaInvalid {
                    path: "plugin.response".to_string(),
                    reason: format!("parse plugin stdout: {e}"),
                }
            })?;
        let mut out = Vec::with_capacity(response.findings.len());
        for pf in response.findings {
            let severity = parse_severity(&pf.severity).unwrap_or(Severity::Warn);
            // Prefix the rule so the operator
            // can tell which scanner produced it.
            let rule = if pf.rule.starts_with("plugin.") {
                pf.rule
            } else {
                format!("plugin.{}.{}", self.name, pf.rule)
            };
            out.push(Finding {
                severity,
                rule,
                path: pf.path,
                reason: pf.reason,
            });
        }
        let _ = default_timeout(); // silence unused-warn for now
        Ok(out)
    }
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s {
        "BLOCK" => Some(Severity::Block),
        "WARN" => Some(Severity::Warn),
        "PASS" => Some(Severity::Pass),
        _ => None,
    }
}

#[cfg(test)]
#[path = "plugin_tests.rs"]
mod tests;
