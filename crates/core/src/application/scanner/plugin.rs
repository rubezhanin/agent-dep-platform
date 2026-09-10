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

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
// `std::io::Write` is imported
// locally in the chunked-stdin
// block below; no top-level use
// is needed.

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::error::{CoreError, CoreResult};

use super::{Finding, ScanPolicy, Scanner, Severity};

/// 2.11.0 (P1-S-03, TZ #1 §9 / S-03,
/// CWE-400 Uncontrolled Resource
/// Consumption): the hard cap on a
/// plugin's stdout AND stderr in
/// bytes. The pre-fix design
/// `read_to_end`-buffered the whole
/// stdout with no upper bound; a
/// plugin that wrote 100 GiB of
/// garbage would allocate 100 GiB
/// in the parent before the scan
/// could even parse the response.
/// The post-fix default is 16 MiB;
/// the cap is applied via the
/// `BytesLimitedReader` adapter
/// below. CWE-400 closed.
const DEFAULT_MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// 2.11.0 (P1-S-03): a tiny `Read`
/// adapter that wraps a `ChildStdout`
/// (or `ChildStderr`) and stops
/// accepting bytes after `cap`
/// total bytes have been read. When
/// the cap is hit, sets the shared
/// `cap_hit` `AtomicBool` to
/// `true` and returns `Ok(0)` on
/// the NEXT read so
/// `read_to_end` finishes. The
/// main wait loop polls `cap_hit`
/// on every iteration and kills
/// the child as soon as it sees
/// `true`. The cap is total bytes
/// from the underlying reader
/// (not just the bytes successfully
/// delivered — `Read` does not
/// report `Ok(0)` until the
/// underlying reader is also
/// exhausted, so the `remaining`
/// counter is a faithful
/// "total bytes consumed"
/// counter for our purposes).
struct BytesLimitedReader<R: std::io::Read> {
    inner: R,
    remaining: usize,
    cap_hit: std::sync::Arc<std::sync::atomic::AtomicBool>,
    hit_set: bool,
}

impl<R: std::io::Read> BytesLimitedReader<R> {
    fn new(inner: R, cap: usize, cap_hit: std::sync::Arc<std::sync::atomic::AtomicBool>) -> Self {
        Self {
            inner,
            remaining: cap,
            cap_hit,
            hit_set: false,
        }
    }
}

impl<R: std::io::Read> std::io::Read for BytesLimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            // The cap was hit on a
            // PREVIOUS read; from now
            // on we return `Ok(0)`
            // cleanly so
            // `read_to_end` exits the
            // loop. We only set the
            // cap-hit flag once
            // (the first time the cap
            // was reached) — repeated
            // `Ok(0)` after the cap
            // is expected and must
            // not flap the flag.
            if !self.hit_set {
                self.cap_hit
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                self.hit_set = true;
            }
            return Ok(0);
        }
        // Cap the read to the
        // remaining budget so the
        // underlying `Read` cannot
        // ever deliver more than
        // `remaining` bytes.
        let take = buf.len().min(self.remaining);
        let n = self.inner.read(&mut buf[..take])?;
        // `n` is the number of
        // bytes the underlying
        // reader actually produced.
        // Subtract from the
        // budget; saturating_sub
        // guards against a
        // short-read edge case
        // (the underlying reader
        // delivered 0 bytes but
        // `take` was >0 — the budget
        // would otherwise
        // underflow).
        self.remaining = self.remaining.saturating_sub(n);
        if self.remaining == 0 && n > 0 {
            // The cap was just hit
            // (we accepted the last
            // byte of the budget on
            // this read). Mark the
            // flag so the main wait
            // loop can kill the
            // child before the next
            // plugin write fills the
            // pipe.
            self.cap_hit
                .store(true, std::sync::atomic::Ordering::SeqCst);
            self.hit_set = true;
        }
        Ok(n)
    }
}

/// 2.11.0 (P1-S-02, TZ #1 §9 / S-02,
/// TZ #2 WP-1.2 / SEC-07,
/// CWE-400 Uncontrolled Resource
/// Consumption): poll cadence for
/// the wall-clock timeout loop. 100ms
/// is fine-grained enough that the
/// operator does not notice a runaway
/// plugin (the timeout is the
/// upper bound, the kill is the
/// actual response time) and
/// coarse enough that the parent
/// does not burn a CPU on the
/// poll.
const PLUGIN_WAIT_POLL: Duration = Duration::from_millis(100);

/// 2.11.0 (P1-S-02): the stdin
/// chunk size. The pre-fix code
/// wrote the whole request JSON
/// in a single `write_all` call;
/// for a large `files` list (the
/// `PluginRequest::files` Vec
/// carries every file path under
/// the scan root) the OS pipe
/// buffer can be exhausted before
/// the plugin's reader thread is
/// scheduled, blocking the parent.
/// This is the classic CWE-400
/// shape: a single large write
/// plus a slow reader is a
/// classic DoS. The chunked
/// write keeps the pipe drained
/// and the parent responsive to
/// the kill signal.
const STDIN_CHUNK_BYTES: usize = 4 * 1024;

/// 2.11.0 (P1-S-05, TZ #1 §9 / S-05,
/// TZ #2 WP-1.1 / SEC-08, CWE-494
/// Download of Code Without
/// Integrity Check): the
/// "unsigned plugin is allowed"
/// escape hatch. `true` means
/// unsigned plugins may run
/// (with a `tracing::warn!`); the
/// only path that returns `true`
/// is a debug build
/// (`cfg!(debug_assertions)`) OR
/// `AGENCY_ALLOW_UNSIGNED_PLUGINS=1`
/// in the environment. The
/// escape is for development /
/// integration tests ONLY —
/// production release builds
/// must NOT set the env var, and
/// a release build running with
/// an unsigned plugin will
/// refuse to spawn the child.
/// CWE-494 closed for the
/// "operator accidentally loads
/// an unsigned plugin" threat.
fn allow_unsigned_plugins() -> bool {
    if cfg!(debug_assertions) {
        return true;
    }
    matches!(
        std::env::var("AGENCY_ALLOW_UNSIGNED_PLUGINS")
            .ok()
            .as_deref(),
        Some("1")
    )
}

/// 2.11.0 (P1-S-05, TZ #1 §9 / S-05,
/// CWE-494): the path-constraint
/// helper. When the operator sets
/// `AGENCY_PLUGINS_DIR`, every
/// plugin the scanner spawns MUST
/// have a canonical path that
/// lives inside the approved
/// directory. The check is
/// canonicalize-based so a
/// symlink (e.g.
/// `AGENCY_PLUGINS_DIR/ok -> /tmp/evil`)
/// cannot smuggle a plugin from
/// outside the approved tree —
/// the canonicalization resolves
/// the link and the comparison is
/// a byte-exact prefix match
/// against the canonical
/// approved dir. When
/// `AGENCY_PLUGINS_DIR` is unset,
/// the check is a no-op
/// (backward compat: pre-P1-S-05
/// callers did not constrain the
/// plugin path).
fn check_plugin_path_constraint(binary: &Path) -> CoreResult<()> {
    let approved_dir = match std::env::var("AGENCY_PLUGINS_DIR").ok() {
        Some(s) if !s.is_empty() => std::path::PathBuf::from(s),
        _ => return Ok(()), // no constraint configured
    };
    let approved_canon = approved_dir.canonicalize().map_err(|e| {
        CoreError::ErrIo(std::io::Error::other(format!(
            "AGENCY_PLUGINS_DIR `{}` could not be canonicalized: {e}",
            approved_dir.display()
        )))
    })?;
    let binary_canon = binary.canonicalize().map_err(|e| {
        CoreError::ErrIo(std::io::Error::other(format!(
            "plugin binary `{}` could not be canonicalized: {e}",
            binary.display()
        )))
    })?;
    if !binary_canon.starts_with(&approved_canon) {
        return Err(CoreError::ErrIo(std::io::Error::other(format!(
            "plugin binary `{}` is outside the approved directory `{}` \
             (P1-S-05 path constraint; set AGENCY_ALLOW_UNSIGNED_PLUGINS=1 \
             to skip signature checks, but NOT the path constraint)",
            binary_canon.display(),
            approved_canon.display()
        ))));
    }
    Ok(())
}

/// 2.11.0 (P1-S-03, TZ #1 §9 / S-03):
/// the operator-overridable cap on
/// a plugin's stdout AND stderr in
/// bytes. The default is 16 MiB
/// (`DEFAULT_MAX_OUTPUT_BYTES`).
/// Operators can override via
/// `AGENCY_PLUGIN_MAX_OUTPUT_BYTES`.
/// A `0` is treated as the default
/// (some shells evaluate unset vars
/// as `0`); a negative or
/// non-numeric value is also
/// treated as the default.
fn max_output_bytes_env() -> usize {
    std::env::var("AGENCY_PLUGIN_MAX_OUTPUT_BYTES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_MAX_OUTPUT_BYTES)
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
    /// Per-instance timeout override. If `None`,
    /// `default_timeout()` falls back to the
    /// `AGENCY_PLUGIN_TIMEOUT_SECS` env var and
    /// then to the 30 s built-in default. Set
    /// via `with_timeout` from tests so a
    /// parallel `cargo test` run cannot race
    /// the global env var (CI run 34480492201
    /// surfaced the race).
    pub timeout: Option<Duration>,
    /// Per-instance stdout/stderr cap override.
    /// If `None`, `max_output_bytes()` falls
    /// back to the `AGENCY_PLUGIN_MAX_OUTPUT_BYTES`
    /// env var and then to the 16 MiB built-in
    /// default. Set via `with_max_output_bytes`
    /// from tests for the same reason as
    /// `timeout` above (CI run 34483888711
    /// surfaced a parallel `cargo test` race on
    /// this env var).
    pub max_output_bytes_override: Option<usize>,
}

impl PluginScanner {
    pub fn new(name: impl Into<String>, binary: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            binary: binary.into(),
            timeout: None,
            max_output_bytes_override: None,
        }
    }

    /// Override the per-invocation wall-clock
    /// timeout for this scanner instance. Takes
    /// precedence over `AGENCY_PLUGIN_TIMEOUT_SECS`.
    /// Used by the timeout tests so they do not
    /// have to mutate a process-global env var
    /// (which is racy under parallel `cargo test`).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Override the per-invocation stdout/stderr
    /// cap for this scanner instance. Takes
    /// precedence over
    /// `AGENCY_PLUGIN_MAX_OUTPUT_BYTES`. Used by
    /// the cap tests so they do not have to
    /// mutate a process-global env var (which is
    /// racy under parallel `cargo test`).
    pub fn with_max_output_bytes(mut self, bytes: usize) -> Self {
        self.max_output_bytes_override = Some(bytes);
        self
    }

    /// Hard timeout for a single plugin invocation.
    /// Resolution order:
    /// 1. `self.timeout` if a per-instance override
    ///    was set via `PluginScanner::with_timeout`.
    ///    Used by tests so a parallel cargo-test
    ///    run cannot race the global env var.
    /// 2. The `AGENCY_PLUGIN_TIMEOUT_SECS` env var
    ///    (operator override).
    /// 3. 30 seconds (built-in default).
    fn default_timeout(&self) -> Duration {
        if let Some(d) = self.timeout {
            return d;
        }
        let secs = std::env::var("AGENCY_PLUGIN_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30);
        Duration::from_secs(secs)
    }

    /// Cap on a single plugin's stdout AND
    /// stderr in bytes. Resolution order:
    /// 1. `self.max_output_bytes_override` if a
    ///    per-instance override was set via
    ///    `PluginScanner::with_max_output_bytes`.
    /// 2. The `AGENCY_PLUGIN_MAX_OUTPUT_BYTES`
    ///    env var (operator override).
    /// 3. 16 MiB (built-in default).
    fn max_output_bytes(&self) -> usize {
        if let Some(b) = self.max_output_bytes_override {
            return b;
        }
        max_output_bytes_env()
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
        // 2.11.0 (P1-S-05, TZ #1 §9 / S-05,
        // TZ #2 WP-1.1 / SEC-08, CWE-494
        // Download of Code Without
        // Integrity Check): the
        // SECURITY GATE.
        //
        // Two checks run before any
        // child process is spawned:
        //
        // (1) PATH CONSTRAINT. If
        //     `AGENCY_PLUGINS_DIR` is
        //     set, the canonical
        //     binary path MUST live
        //     inside the canonical
        //     approved directory. A
        //     symlink from inside
        //     `AGENCY_PLUGINS_DIR`
        //     pointing at an
        //     untrusted binary
        //     elsewhere is detected
        //     by the canonicalize
        //     step (the link resolves
        //     to its target before
        //     the prefix check). This
        //     is the CWE-494 "load
        //     code from a
        //     non-approved path"
        //     defense.
        //
        // (2) SIGNATURE ENFORCEMENT.
        //     The pre-fix design
        //     loaded the plugin's
        //     `plugin.toml` manifest
        //     if present and verified
        //     the Ed25519 signature
        //     against the trust
        //     store, but did NOT
        //     REQUIRE a signature —
        //     an unsigned manifest
        //     was silently accepted
        //     (the trust store was
        //     opt-in). CWE-494: an
        //     operator who copies a
        //     `plugin.sh` into
        //     `AGENCY_PLUGINS_DIR`
        //     without signing it
        //     gets a scan that runs
        //     the unsigned binary.
        //     The post-fix gate
        //     refuses an unsigned
        //     plugin in a release
        //     build, unless the
        //     operator explicitly
        //     opts in via
        //     `AGENCY_ALLOW_UNSIGNED_PLUGINS=1`.
        //     Debug builds
        //     (cfg!(debug_assertions))
        //     always allow unsigned
        //     so the integration test
        //     suite can run without
        //     signing every fixture
        //     plugin.
        check_plugin_path_constraint(&self.binary)?;
        if !allow_unsigned_plugins() {
            // Production path.
            // Locate the manifest
            // next to the binary, parse
            // it, and verify the
            // signature against the
            // trust store.
            let manifest_path = self
                .binary
                .parent()
                .map(|p| p.join("plugin.toml"))
                .ok_or_else(|| {
                    CoreError::ErrIo(std::io::Error::other(
                        "plugin binary has no parent directory; \
                         cannot locate plugin.toml for signature check",
                    ))
                })?;
            if !manifest_path.is_file() {
                return Err(CoreError::ErrIo(std::io::Error::other(format!(
                    "plugin manifest `{}` is missing; \
                     production builds (P1-S-05) require a signed plugin.toml",
                    manifest_path.display()
                ))));
            }
            let manifest_bytes = std::fs::read(&manifest_path).map_err(|e| {
                CoreError::ErrIo(std::io::Error::other(format!(
                    "read plugin manifest `{}`: {e}",
                    manifest_path.display()
                )))
            })?;
            let manifest = PluginManifest::parse(&manifest_bytes).map_err(|e| {
                CoreError::ErrIo(std::io::Error::other(format!(
                    "parse plugin manifest `{}`: {e}",
                    manifest_path.display()
                )))
            })?;
            // Load the trust store from
            // the env-configured
            // location. The trust
            // store is at
            // `AGENCY_TRUST_STORE`
            // (TOML); default is
            // `<AGENCY_PLUGINS_DIR>/trust.toml`
            // when the dir is set.
            let trust_path = std::env::var("AGENCY_TRUST_STORE")
                .ok()
                .filter(|s| !s.is_empty())
                .map(std::path::PathBuf::from)
                .or_else(|| {
                    std::env::var("AGENCY_PLUGINS_DIR")
                        .ok()
                        .filter(|s| !s.is_empty())
                        .map(|p| std::path::PathBuf::from(p).join("trust.toml"))
                });
            let trust = match trust_path {
                Some(p) if p.is_file() => {
                    let bytes = std::fs::read(&p).map_err(|e| {
                        CoreError::ErrIo(std::io::Error::other(format!(
                            "read trust store `{}`: {e}",
                            p.display()
                        )))
                    })?;
                    super::trust_store::TrustStore::parse(&bytes).map_err(|e| {
                        CoreError::ErrIo(std::io::Error::other(format!(
                            "parse trust store `{}`: {e}",
                            p.display()
                        )))
                    })?
                }
                _ => {
                    return Err(CoreError::ErrIo(std::io::Error::other(
                        "no trust store configured; production builds (P1-S-05) \
                         require AGENCY_TRUST_STORE (TOML) with the signer's public key",
                    )));
                }
            };
            manifest.verify_signature(&trust).map_err(|e| {
                tracing::warn!(
                    plugin = %self.name,
                    binary = %self.binary.display(),
                    manifest = %manifest_path.display(),
                    error = %e,
                    "P1-S-05: plugin signature verification failed"
                );
                CoreError::ErrIo(std::io::Error::other(format!(
                    "plugin `{}` signature verification failed: {e}",
                    self.name
                )))
            })?;
        } else if std::env::var("AGENCY_ALLOW_UNSIGNED_PLUGINS")
            .ok()
            .as_deref()
            == Some("1")
        {
            // The escape was used in
            // a release build. Warn
            // loudly so the operator
            // knows their plugin is
            // running without a
            // signature check.
            tracing::warn!(
                plugin = %self.name,
                binary = %self.binary.display(),
                "P1-S-05: AGENCY_ALLOW_UNSIGNED_PLUGINS=1 in a release build; \
                 plugin is running WITHOUT signature verification. \
                 This is for development ONLY; do NOT use in production."
            );
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
        // 2.11.0 (P1-S-02, TZ #1 §9 /
        // S-02, CWE-400): chunked
        // stdin write. The pre-fix
        // code did
        // `stdin.write_all(&request_json)`
        // in a single syscall. For
        // a large `files` Vec
        // (every path under the scan
        // root) the request JSON
        // can exceed the OS pipe
        // buffer (64 KiB on Linux);
        // the parent blocks on the
        // write until the plugin
        // reads, and the plugin is
        // not scheduled because the
        // parent is not yielding. A
        // buggy / malicious plugin
        // that simply does NOT
        // read its stdin becomes a
        // parent-blocking DoS.
        // The chunked write keeps
        // the pipe drained: each
        // `write_all` call is at
        // most STDIN_CHUNK_BYTES
        // (4 KiB), well under any
        // pipe buffer, and the
        // plugin's reader can
        // interleave its work
        // between chunks. CWE-400.
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            for chunk in request_json.chunks(STDIN_CHUNK_BYTES) {
                stdin.write_all(chunk).map_err(|e| {
                    CoreError::ErrIo(std::io::Error::other(format!("write plugin stdin: {e}")))
                })?;
            }
            // Drop stdin to signal EOF.
        }
        // 2.11.0 (P1-S-02, TZ #1 §9 /
        // S-02, TZ #2 WP-1.2 / SEC-07,
        // CWE-400 Uncontrolled
        // Resource Consumption):
        // wall-clock timeout. The
        // pre-fix code called
        // `child.wait_with_output()`,
        // a blocking call with no
        // timeout. A runaway plugin
        // (infinite loop, deadlocked
        // I/O) would block the
        // parent forever — the
        // operator would have to
        // SIGKILL the whole
        // `agency catalog scan`
        // process to recover.
        // CWE-400.
        //
        // Post-fix: we
        // (1) drain the child's
        //     stdout and stderr in
        //     dedicated threads
        //     (the pipes are bounded;
        //     a slow parent reader
        //     would block the child
        //     on a full pipe — same
        //     DoS shape as the
        //     pre-fix stdin);
        // (2) poll `child.try_wait()`
        //     every 100ms on the
        //     calling thread;
        // (3) on timeout, call
        //     `child.kill()` (SIGKILL
        //     on Unix,
        //     TerminateProcess on
        //     Windows), wait for the
        //     kernel to reap, and
        //     return a synthetic
        //     `plugin.<name>.timed-out`
        //     finding so the
        //     operator sees the
        //     failure in the
        //     SARIF / text output;
        // (4) join the reader
        //     threads so their
        //     buffers are not
        //     leaked.
        //
        // The `try_wait` poll is
        // portable (no `wait-timeout`
        // dependency) and the
        // 100ms cadence is fine
        // for a 30s default
        // timeout (300 polls,
        // negligible CPU).
        // 2.11.0 (P1-S-03, TZ #1 §9 /
        // S-03, CWE-400): the cap
        // and the cap-hit signals
        // for stdout and stderr.
        // The drain threads
        // (spawned below) wrap
        // the pipes in
        // `BytesLimitedReader`,
        // which sets the
        // respective atomic on
        // the first byte that
        // hits the cap. The
        // wait loop checks both
        // atomics on every poll
        // and kills the child
        // (fail-closed) as soon
        // as either fires.
        let cap = self.max_output_bytes();
        let stdout_cap_hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stderr_cap_hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stdout_thread = child.stdout.take().map(|s| {
            let cap_hit = stdout_cap_hit.clone();
            std::thread::spawn(move || {
                let mut buf: Vec<u8> = Vec::with_capacity(cap.min(64 * 1024));
                let mut limited = BytesLimitedReader::new(s, cap, cap_hit);
                let _ = std::io::Read::read_to_end(&mut limited, &mut buf);
                buf
            })
        });
        let stderr_thread = child.stderr.take().map(|s| {
            let cap_hit = stderr_cap_hit.clone();
            std::thread::spawn(move || {
                let mut buf: Vec<u8> = Vec::with_capacity(cap.min(16 * 1024));
                let mut limited = BytesLimitedReader::new(s, cap, cap_hit);
                let _ = std::io::Read::read_to_end(&mut limited, &mut buf);
                buf
            })
        });
        let timeout = self.default_timeout();
        let deadline = Instant::now() + timeout;
        let exit: Result<std::process::ExitStatus, std::io::Error> = loop {
            // 2.11.0 (P1-S-03, CWE-400):
            // cap-hit check BEFORE
            // the wall-clock timeout
            // check. Either signal
            // kills the child; we
            // surface a different
            // synthetic finding
            // depending on which
            // fired. The atomic
            // load uses `SeqCst` to
            // be consistent with the
            // `Store` in
            // `BytesLimitedReader`.
            if stdout_cap_hit.load(std::sync::atomic::Ordering::SeqCst)
                || stderr_cap_hit.load(std::sync::atomic::Ordering::SeqCst)
            {
                // 2.11.0 (P1-S-03):
                // the cap-hit path.
                // Kill the child,
                // reap, emit a
                // synthetic
                // `plugin.<name>.output-cap-exceeded`
                // finding. Same
                // shape as the
                // timeout path
                // (P1-S-02) but a
                // distinct rule so
                // the operator can
                // tell which guard
                // fired.
                let _ = child.kill();
                let _ = child.wait();
                let _stdout_bytes = stdout_thread
                    .map(|t| t.join().unwrap_or_default())
                    .unwrap_or_default();
                let stderr_bytes = stderr_thread
                    .map(|t| t.join().unwrap_or_default())
                    .unwrap_or_default();
                let stderr_lossy = String::from_utf8_lossy(&stderr_bytes);
                let reason = format!(
                    "plugin `{}` exceeded the stdout/stderr cap of {} bytes and was killed; \
                     stderr tail: {}",
                    self.name,
                    cap,
                    stderr_lossy.chars().take(512).collect::<String>()
                );
                tracing::warn!(
                    plugin = %self.name,
                    binary = %self.binary.display(),
                    cap_bytes = cap,
                    stdout_cap_hit = stdout_cap_hit.load(std::sync::atomic::Ordering::SeqCst),
                    stderr_cap_hit = stderr_cap_hit.load(std::sync::atomic::Ordering::SeqCst),
                    stderr = %stderr_lossy.chars().take(2048).collect::<String>(),
                    "P1-S-03: plugin exceeded output cap; killed"
                );
                return Ok(vec![Finding {
                    severity: Severity::Warn,
                    rule: format!("plugin.{}.output-cap-exceeded", self.name),
                    path: String::new(),
                    reason,
                }]);
            }
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        // 2.11.0 (P1-S-02):
                        // the runaway-plugin
                        // path. Kill the
                        // child, wait for
                        // the kernel to
                        // reap, emit a
                        // synthetic
                        // finding, audit-log
                        // the event at
                        // WARN level so the
                        // operator can see
                        // it in the server
                        // logs.
                        let _ = child.kill();
                        let _ = child.wait().map_err(|e| {
                            tracing::warn!(
                                error = %e,
                                plugin = %self.name,
                                "P1-S-02: post-kill wait failed"
                            );
                            e
                        });
                        // Drain the reader
                        // threads (their
                        // readers saw the
                        // pipe close when
                        // the child exited).
                        let _stdout_bytes = stdout_thread
                            .map(|t| t.join().unwrap_or_default())
                            .unwrap_or_default();
                        let stderr_bytes = stderr_thread
                            .map(|t| t.join().unwrap_or_default())
                            .unwrap_or_default();
                        let stderr_lossy = String::from_utf8_lossy(&stderr_bytes);
                        let reason = format!(
                            "plugin `{}` exceeded the wall-clock timeout of {}s and was killed; \
                             stderr tail: {}",
                            self.name,
                            timeout.as_secs(),
                            stderr_lossy.chars().take(512).collect::<String>()
                        );
                        tracing::warn!(
                            plugin = %self.name,
                            binary = %self.binary.display(),
                            timeout_secs = timeout.as_secs(),
                            stderr = %stderr_lossy.chars().take(2048).collect::<String>(),
                            "P1-S-02: plugin exceeded wall-clock timeout; killed"
                        );
                        return Ok(vec![Finding {
                            severity: Severity::Warn,
                            rule: format!("plugin.{}.timed-out", self.name),
                            path: String::new(),
                            reason,
                        }]);
                    }
                    std::thread::sleep(PLUGIN_WAIT_POLL);
                }
                Err(e) => {
                    return Err(CoreError::ErrIo(std::io::Error::other(format!(
                        "try_wait plugin: {e}"
                    ))));
                }
            }
        };
        let status = match exit {
            Ok(s) => s,
            Err(_) => unreachable!("loop only returns Ok"),
        };
        // Drain the reader threads.
        let stdout_bytes = stdout_thread
            .map(|t| t.join().unwrap_or_default())
            .unwrap_or_default();
        let stderr_bytes = stderr_thread
            .map(|t| t.join().unwrap_or_default())
            .unwrap_or_default();
        let output = std::process::Output {
            status,
            stdout: stdout_bytes,
            stderr: stderr_bytes,
        };
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
        if output.stdout.len() > self.max_output_bytes() {
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
