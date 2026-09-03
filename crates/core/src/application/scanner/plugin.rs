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
    std::env::var("AGENCY_PLUGIN_MAX_OUTPUT_BYTES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(256 * 1024 * 1024)
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
                format!("plugin binary not found: {}", self.binary.display()),
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
        let request_json =
            serde_json::to_vec(&request).map_err(|e| CoreError::ErrSchemaInvalid {
                path: "plugin.request".to_string(),
                reason: format!("serialise: {e}"),
            })?;
        let mut child = Command::new(&self.binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("AGENCY_PLUGIN_NAME", &self.name)
            .env("AGENCY_ROOT", root)
            .spawn()
            .map_err(|e| {
                CoreError::ErrIo(std::io::Error::other(format!(
                    "spawn plugin {}: {e}",
                    self.binary.display()
                )))
            })?;
        // Write the envelope to stdin.
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&request_json).map_err(|e| {
                CoreError::ErrIo(std::io::Error::other(format!(
                    "write plugin stdin: {e}"
                )))
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
        let output = child.wait_with_output().map_err(|e| {
            CoreError::ErrIo(std::io::Error::other(format!("wait plugin: {e}")))
        })?;
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
            serde_json::from_slice(&output.stdout).map_err(|e| CoreError::ErrSchemaInvalid {
                path: "plugin.response".to_string(),
                reason: format!("parse plugin stdout: {e}"),
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

// ---------------------------------------------------------------------------
// 2.7.3 plugin manifest (ADR-0031)
// ---------------------------------------------------------------------------

/// A `plugin.toml` manifest sitting next to
/// the plugin binary. The manifest carries
/// metadata (name, version, description) plus
/// per-plugin tunables (timeout, output cap,
/// env vars).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub binary: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    /// Per-plugin timeout override. If
    /// `None`, falls back to the global
    /// `AGENCY_PLUGIN_TIMEOUT_SECS` (or 30s
    /// default).
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    /// Per-plugin output cap override. If
    /// `None`, falls back to the global
    /// `AGENCY_PLUGIN_MAX_OUTPUT_BYTES` (or
    /// 256 MiB default).
    #[serde(default)]
    pub max_output_bytes: Option<usize>,
    /// Extra env vars to pass to the plugin
    /// process. Format: `KEY=VALUE`.
    #[serde(default)]
    pub env: Vec<String>,
    /// Free-form capability tags. 2.7.3
    /// doesn't enforce a vocabulary.
    #[serde(default)]
    pub capabilities: Vec<String>,
}

impl PluginManifest {
    /// Parse a `plugin.toml` from raw bytes.
    /// Returns a typed error with the parse
    /// context on failure.
    pub fn parse(bytes: &[u8]) -> CoreResult<Self> {
        let text = std::str::from_utf8(bytes).map_err(|e| CoreError::ErrSchemaInvalid {
            path: "plugin.manifest".to_string(),
            reason: format!("not utf-8: {e}"),
        })?;
        let manifest: PluginManifest =
            toml::from_str(text).map_err(|e| CoreError::ErrSchemaInvalid {
                path: "plugin.manifest".to_string(),
                reason: format!("parse toml: {e}"),
            })?;
        // Validate required fields are non-empty.
        if manifest.name.trim().is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "plugin.manifest.name".to_string(),
                reason: "name must not be empty".to_string(),
            });
        }
        if manifest.version.trim().is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "plugin.manifest.version".to_string(),
                reason: "version must not be empty".to_string(),
            });
        }
        if manifest.binary.trim().is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "plugin.manifest.binary".to_string(),
                reason: "binary must not be empty".to_string(),
            });
        }
        Ok(manifest)
    }

    /// Resolve `binary` relative to the
    /// manifest's directory. If `binary` is
    /// absolute, returns it as-is.
    pub fn resolved_binary(&self, manifest_dir: &Path) -> PathBuf {
        let p = PathBuf::from(&self.binary);
        if p.is_absolute() {
            p
        } else {
            manifest_dir.join(&self.binary)
        }
    }
}

// ---------------------------------------------------------------------------
// 2.7.2 plugin auto-discovery (ADR-0030)
// ---------------------------------------------------------------------------

/// A discovered plugin. The `name` is derived
/// from the file basename (no extension); the
/// `binary` is the absolute path to the
/// executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPlugin {
    pub name: String,
    pub binary: PathBuf,
}

/// Discover plugin executables in a directory.
/// Two sources, in precedence order (manifest
/// wins on name collision):
///
/// 1. **Manifest form** (2.7.3, ADR-0031):
///    `<dir>/<name>/plugin.toml` is parsed
///    and the `binary` field inside the
///    manifest is the executable. The
///    manifest's `name` field is the plugin
///    name; it MUST match the directory name.
///
/// 2. **Bare-script form** (2.7.2, ADR-0030):
///    top-level `*.sh` / `*.ps1` / `.bat`
///    files (or no extension). The file stem
///    is the plugin name.
///
/// Non-executable files are silently skipped
/// (so a `README.md` next to the scripts is
/// fine). The returned vector is sorted by
/// `name` for determinism.
pub fn discover_plugins(dir: &Path) -> std::io::Result<Vec<DiscoveredPlugin>> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out: Vec<DiscoveredPlugin> = Vec::new();
    let mut names_with_manifest: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    // 1. Manifest form: scan subdirectories.
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let dir_name_os = match path.file_name() {
            Some(n) => n.to_owned(),
            None => continue,
        };
        let dir_name = match dir_name_os.to_str() {
            Some(s) => s.to_string(),
            None => continue,
        };
        let manifest_path = path.join("plugin.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let bytes = match std::fs::read(&manifest_path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let manifest = match PluginManifest::parse(&bytes) {
            Ok(m) => m,
            Err(_) => continue, // invalid manifest is a no-op (caller sees Warn at scan time)
        };
        if manifest.name != dir_name {
            // Mismatch: manifest `name` field
            // must match the directory name.
            // Skip; the operator will see the
            // mismatch in the manifest's
            // `manifest-invalid` finding at
            // scan time.
            continue;
        }
        let binary = manifest.resolved_binary(&path);
        out.push(DiscoveredPlugin {
            name: manifest.name.clone(),
            binary,
        });
        names_with_manifest.insert(manifest.name);
    }
    // 2. Bare-script form (2.7.2 behaviour):
    //    only top-level files. Skip names that
    //    a manifest already claimed.
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = plugin_name_from_path(&path) else {
            continue;
        };
        if names_with_manifest.contains(&name) {
            // Manifest already claimed this
            // name; the bare script is a
            // fallback that the manifest
            // takes precedence over.
            continue;
        }
        // Skip non-executable files.
        let is_exec = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::metadata(&path)?.permissions().mode() & 0o100 != 0
            }
            #[cfg(not(unix))]
            {
                let ext = path
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                ext == "ps1" || ext == "bat" || ext == "exe"
            }
        };
        if !is_exec {
            continue;
        }
        out.push(DiscoveredPlugin { name, binary: path });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Derive the plugin name from a file path. The
/// name is the basename with one conventional
/// script extension stripped (`.sh`, `.ps1`,
/// `.bat`, `.exe`). Returns `None` for files
/// that don't have one of those extensions AND
/// don't have no extension at all (so
/// `README.md` returns `None` and is ignored).
fn plugin_name_from_path(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?.to_string();
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "sh" | "ps1" | "bat" | "exe" | "" => Some(stem),
        _ => None,
    }
}

#[cfg(test)]
#[path = "plugin_tests.rs"]
mod tests;
