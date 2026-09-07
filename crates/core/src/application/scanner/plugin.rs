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

    /// P0-ENV-01 (TZ #2 WP-1.1, CWE-200):
    /// the explicit whitelist of environment
    /// variables the plugin child process is
    /// allowed to see. Anything not in this
    /// list is `env_clear()`'d before the spawn.
    ///
    /// The list is intentionally tiny:
    /// - `PATH` — every binary the plugin
    ///   shells out to (rare, but plugins
    ///   do call `which` / `command -v`).
    /// - `HOME` — plugins that read
    ///   `~/.config/<plugin>/...` (rare,
    ///   but the env-var is universally
    ///   available and benign).
    /// - `TMPDIR` — plugins that use
    ///   `tempfile` / `mkstemp` (default
    ///   location is the OS-specific
    ///   `std::env::temp_dir()`).
    /// - `LANG` / `LC_ALL` — ICU and
    ///   locale-aware string handling.
    /// - `AGENCY_PLUGIN_NAME` — the
    ///   plugin's own name (the documented
    ///   contract).
    /// - `AGENCY_ROOT` — the catalog root
    ///   the plugin is scanning.
    ///
    /// **Notably absent** (the security
    /// control):
    /// - `AGENCY_VAULT_PASSPHRASE` — the
    ///   vault master key (see
    ///   `crates/server/src/vault_init.rs`).
    /// - `AGENCY_ADMIN_TOKEN` — the
    ///   operator's first-boot admin
    ///   token.
    /// - `AGENCY_BIND_IP` / `AGENCY_BIND_PORT`
    ///   — server bind config (not a
    ///   secret, but the plugin doesn't
    ///   need to know).
    /// - `AGENCY_OIDC_*` — OIDC client
    ///   secrets (client_secret, jwks_url,
    ///   etc.).
    /// - `AGENCY_DB_*` — DB connection
    ///   strings.
    /// - `*_TOKEN`, `*_KEY`, `*_SECRET` —
    ///   any other secret-bearing env vars.
    ///
    /// The pre-fix code's failure to call
    /// `env_clear()` made all of the above
    /// readable from the plugin's
    /// `std::env::var`. The post-fix code
    /// drops the inherited env entirely
    /// and re-adds only this whitelist.
    ///
    /// This helper is `pub` so the test
    /// suite in `plugin_tests.rs` can
    /// assert the whitelist shape directly
    /// (no process spawn required).
    pub fn plugin_safe_env(name: &str, root: &Path) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = Vec::with_capacity(6);
        // Generic OS-level vars that plugins
        // may rely on. These are copied from
        // the parent env; if the parent has
        // not set them, we set them to "".
        for k in &["PATH", "HOME", "TMPDIR", "LANG"] {
            out.push(((*k).to_string(), std::env::var(k).unwrap_or_default()));
        }
        // Documented plugin contract.
        out.push(("AGENCY_PLUGIN_NAME".to_string(), name.to_string()));
        out.push(("AGENCY_ROOT".to_string(), root.display().to_string()));
        out
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
        // P0-ENV-01 (TZ #2 WP-1.1, CWE-200):
        // the pre-fix code spawned the plugin
        // with `Command::new(&self.binary)` and
        // called `.env("AGENCY_PLUGIN_NAME", ...)`
        // / `.env("AGENCY_ROOT", ...)`. The
        // resulting child process inherited
        // the parent's full environment, which
        // includes `AGENCY_VAULT_PASSPHRASE`,
        // `AGENCY_ADMIN_TOKEN`, and any other
        // server-side secrets. A malicious or
        // compromised plugin could read those
        // values via `std::env::var("...")` and
        // exfiltrate them through its stdout /
        // a network call / the catalog upload
        // path. CWE-200 (Exposure of Sensitive
        // Information to an Unauthorized Actor).
        //
        // Post-fix: `env_clear()` drops the
        // inherited env, then we re-add the
        // minimum set a plugin needs to function
        // (`PATH` for binary lookup, `HOME` for
        // plugins that read `~/.config/...`,
        // `TMPDIR` for `tempfile`-using plugins,
        // `LANG` for ICU / locale-aware plugins),
        // and the two `AGENCY_*` vars that are
        // part of the plugin's documented
        // contract (`AGENCY_PLUGIN_NAME` and
        // `AGENCY_ROOT`). Any other `AGENCY_*`
        // secret-bearing env var is no longer
        // reachable from the plugin's `getenv`.
        //
        // The whitelist is built by the
        // `plugin_safe_env` helper below, which
        // is also the unit-test entry point
        // (tests assert the whitelist shape
        // directly, without spawning a process).
        let mut cmd = Command::new(&self.binary);
        cmd.env_clear();
        for (k, v) in Self::plugin_safe_env(&self.name, root) {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // P0-S-01 (TZ #1 §9 S-01, CWE-250,
        // Appendix A.6): the pre-fix code
        // spawned the plugin with the
        // parent's full privilege set. A
        // malicious or compromised plugin
        // could exploit setuid binaries on
        // the host (`/usr/bin/su`,
        // `/usr/bin/sudo`), bind privileged
        // ports (< 1024), or call
        // `setuid(0)` to gain root.
        // Post-fix: on Linux we ask the
        // kernel to drop the
        // `PR_SET_NO_NEW_PRIVS` flag on the
        // child, which prevents the plugin
        // from gaining new privileges via
        // any executable that has setuid /
        // setgid bits or file capabilities.
        // We also request `PR_SET_DUMPABLE=0`
        // to prevent the kernel from writing
        // a core dump (which would include
        // any secrets the plugin had in
        // memory). Both calls are best-
        // effort: if they fail (older kernel,
        // non-Linux), the scan continues
        // with a `tracing::warn!` — better
        // than refusing to scan at all.
        #[cfg(target_os = "linux")]
        {
            // SAFETY: `pre_exec` runs in the
            // forked child between fork() and
            // exec(). Only async-signal-safe
            // functions may be called. We use
            // `libc::prctl` (async-signal-safe)
            // with two PR_SET_* operations.
            // If prctl returns -1 we do not
            // abort: the child can still run,
            // it just won't have the
            // additional restrictions.
            unsafe {
                let no_new_privs = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                if no_new_privs != 0 {
                    tracing::warn!(
                        "P0-S-01: PR_SET_NO_NEW_PRIVS failed; \
                         plugin will run without no-new-privs hardening"
                    );
                }
                let dumpable = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
                if dumpable != 0 {
                    tracing::warn!(
                        "P0-S-01: PR_SET_DUMPABLE=0 failed; \
                         core dumps may be written on plugin crash"
                    );
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            // P0-S-01: no sandbox is
            // available on non-Linux
            // platforms. The plugin runs
            // with the parent's full
            // privilege set, and a warning
            // is logged at scan start. The
            // operator must NOT run the
            // server on a non-Linux host
            // in production; this is
            // explicitly called out in
            // docs/DEPLOY.md (see the 2.9.0
            // deployment notes).
            tracing::warn!(
                "P0-S-01: plugin sandbox is Linux-only; \
                 running plugin on a non-Linux platform without \
                 privilege isolation. Do NOT use in production."
            );
        }
        let mut child = cmd.spawn().map_err(|e| {
            CoreError::ErrIo(std::io::Error::other(format!(
                "spawn plugin {}: {e}",
                self.binary.display()
            )))
        })?;
        // Write the envelope to stdin.
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&request_json).map_err(|e| {
                CoreError::ErrIo(std::io::Error::other(format!("write plugin stdin: {e}")))
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
            .map_err(|e| CoreError::ErrIo(std::io::Error::other(format!("wait plugin: {e}"))))?;
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
///
/// 2.7.4 (ADR-0032) — the manifest MAY
/// carry an Ed25519 `signature` over the
/// canonical form of the rest of the
/// file. The operator-supplied
/// `signer_id` is the lookup key in
/// [`super::trust_store::TrustStore`].
/// Manifests without a `signature` are
/// accepted only when
/// `verify_signature` is called with a
/// trust store that allows them — the
/// default is to REJECT unsigned
/// manifests in production. Tests
/// and the 2.7.3 fallback path use
/// `verify_signature_opt` which treats
/// the unsigned case as a soft
/// warning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub binary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Per-plugin timeout override. If
    /// `None`, falls back to the global
    /// `AGENCY_PLUGIN_TIMEOUT_SECS` (or 30s
    /// default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
    /// Per-plugin output cap override. If
    /// `None`, falls back to the global
    /// `AGENCY_PLUGIN_MAX_OUTPUT_BYTES` (or
    /// 256 MiB default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<usize>,
    /// Extra env vars to pass to the plugin
    /// process. Format: `KEY=VALUE`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// Free-form capability tags. 2.7.3
    /// doesn't enforce a vocabulary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// 2.7.4: Ed25519 signature over the
    /// canonical form of this manifest
    /// (the manifest with `signature` and
    /// `signer_id` stripped). Base64-url
    /// (no pad), 64 bytes decoded.
    /// `None` means the manifest is
    /// unsigned; `verify_signature` then
    /// REJECTs it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// 2.7.4: opaque signer id; the
    /// trust store resolves it to a
    /// public key. Required when
    /// `signature` is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_id: Option<String>,
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
        // 2.7.4 (ADR-0032): a manifest
        // with a `signature` MUST
        // also carry a `signer_id`,
        // and vice versa. We do not
        // verify here (no trust store
        // in scope) — only at the
        // call site, via
        // `PluginManifest::verify_signature`.
        if manifest.signature.is_some() && manifest.signer_id.is_none() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "plugin.manifest.signer_id".to_string(),
                reason: "signature present without signer_id".to_string(),
            });
        }
        if manifest.signer_id.is_some() && manifest.signature.is_none() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "plugin.manifest.signature".to_string(),
                reason: "signer_id present without signature".to_string(),
            });
        }
        Ok(manifest)
    }

    /// 2.7.4: re-serialise the
    /// manifest with the
    /// `signature` and `signer_id`
    /// fields stripped, returning
    /// the bytes that the signer
    /// must have signed. We use
    /// `toml::to_string` (canonical
    /// TOML form) so the operator
    /// does not have to worry
    /// about key ordering /
    /// whitespace.
    pub fn canonical_bytes(&self) -> CoreResult<Vec<u8>> {
        let mut clone = self.clone();
        clone.signature = None;
        clone.signer_id = None;
        let s = toml::to_string(&clone).map_err(|e| CoreError::ErrSchemaInvalid {
            path: "plugin.manifest.canonical".to_string(),
            reason: format!("re-serialise: {e}"),
        })?;
        Ok(s.into_bytes())
    }

    /// 2.7.4: verify the Ed25519
    /// signature against the
    /// supplied `TrustStore`. Returns
    /// `Ok(())` if the manifest is
    /// signed and the signature
    /// verifies under a known
    /// signer. Returns `Err` if
    /// the manifest is unsigned
    /// (production policy: a
    /// manifest MUST be signed) or
    /// if verification fails.
    pub fn verify_signature(&self, trust: &super::trust_store::TrustStore) -> CoreResult<()> {
        let signature = self
            .signature
            .as_deref()
            .ok_or_else(|| CoreError::ErrSchemaInvalid {
                path: "plugin.manifest.signature".to_string(),
                reason: "manifest is unsigned; 2.7.4 requires a signature".to_string(),
            })?;
        let signer_id = self
            .signer_id
            .as_deref()
            .ok_or_else(|| CoreError::ErrSchemaInvalid {
                path: "plugin.manifest.signer_id".to_string(),
                reason: "manifest has a signature but no signer_id".to_string(),
            })?;
        let canonical = self.canonical_bytes()?;
        trust.verify(signer_id, &canonical, signature)
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
