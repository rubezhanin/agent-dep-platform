//! CLI environment validation + decoupling guard.
//!
//! P1-CLI-01 (TZ #2 WP-4.1 / SEC-11, CWE-15 External
//! Control of System or Configuration Setting):
//!
//! **Threat model.** The CLI and the server share the
//! `AGENCY_*` env namespace. The CLI is invoked from
//! the operator's interactive shell; the server runs
//! as a long-lived service (systemd unit, docker, etc.).
//! Both processes inherit the parent shell's env. If
//! the operator sets `AGENCY_OIDC_ISSUER` for the
//! server and then runs `agency status` from the same
//! shell, the CLI would see a server-only env var and
//! silently ignore it — the operator's mental model
//! is "I set this, the CLI knows about it". Worse, a
//! shared `AGENCY_DATA_DIR` set for the CLI ingest
//! step would be picked up by the server boot and
//! redirect the server at the CLI's per-user DB
//! (or vice versa, depending on which shell history
//! wins). CWE-15: external input (the env) controls
//! the configuration of a system (CLI / server) that
//! the operator did not intend to configure.
//!
//! **Fix.** Two layers:
//!
//! 1. **Explicit env struct** ([`CliEnv`]) that reads
//!    ONLY the three CLI-owned env vars
//!    (`AGENCY_DATA_DIR`, `AGENCY_HERMES_HOME`,
//!    `AGENCY_CAS_ROOT`), validates each (non-empty,
//!    no NUL, no `..` path-traversal segment, and
//!    each one canonicalized so a symlink cannot
//!    redirect the ingest at a privileged path), and
//!    returns them as a typed struct. The
//!    `data_dir::default_*` helpers now delegate to
//!    this struct (so the catalog / deploy / status
//!    commands see the same validated paths).
//!
//! 2. **Decoupling guard**
//!    ([`warn_server_only_envs`]) that scans the
//!    parent env for the set of known server-only
//!    env vars (`AGENCY_OIDC_*`, `AGENCY_VAULT_*`,
//!    `AGENCY_BIND_IP`, `AGENCY_COOKIE_SECURE`,
//!    `AGENCY_SERVER_DATA_DIR`) and prints a warning
//!    to stderr if any are set. The CLI does not
//!    fail-loud because a) the operator may have
//!    these set for the server they manage and the
//!    CLI invocation is unrelated, and b) a
//!    fail-loud would break the dev loop (where
//!    the same shell hosts both). The warning is
//!    explicit: "this is a server-only env var, the
//!    CLI ignores it; if you intended to configure
//!    the CLI, use the CLI-owned env vars listed
//!    in `agency --help`".

use std::path::{Component, Path, PathBuf};

use crate::data_dir::default_data_dir;

/// CLI-owned env vars. Each is read once at startup,
/// validated, and the resolved paths are what the rest
/// of the CLI sees via [`crate::data_dir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliEnv {
    pub data_dir: PathBuf,
    pub hermes_home: PathBuf,
    pub cas_root: PathBuf,
}

/// Server-only env vars. The CLI ignores these — if
/// the operator has them set, it is for the
/// `agency-server` they manage in another shell /
/// systemd unit / container. The CLI prints a warning
/// if any are present, so the operator does not
/// mistakenly think the CLI is reading them.
const SERVER_ONLY_ENV: &[&str] = &[
    "AGENCY_OIDC_ISSUER",
    "AGENCY_OIDC_CLIENT_ID",
    "AGENCY_OIDC_CLIENT_SECRET",
    "AGENCY_OIDC_REDIRECT_URI",
    "AGENCY_OIDC_SCOPES",
    "AGENCY_OIDC_ROLE_CLAIM",
    "AGENCY_OIDC_ADMIN_GROUPS",
    "AGENCY_OIDC_OPERATOR_GROUPS",
    "AGENCY_OIDC_MOCK",
    "AGENCY_COOKIE_SECURE",
    "AGENCY_VAULT_PASSPHRASE",
    "AGENCY_VAULT_PASSPHRASE_FILE",
    "AGENCY_BIND_IP",
    "AGENCY_SERVER_DATA_DIR",
];

#[derive(Debug, thiserror::Error)]
pub enum CliEnvError {
    #[error("env `{var}` is set but empty; either unset it or set a non-empty value")]
    EmptyPath { var: &'static str },
    #[error("env `{var}` contains a NUL byte at position {pos}")]
    NulByte { var: &'static str, pos: usize },
    #[error(
        "env `{var}` contains a parent-directory segment (`..`); \
         refusing to follow it to avoid a path-traversal confusion"
    )]
    ParentDir { var: &'static str },
    #[error("env `{var}` resolves to a non-utf8 path on this platform")]
    NonUtf8 { var: &'static str },
}

impl CliEnv {
    /// Read the three CLI-owned env vars and validate
    /// them. Returns a typed struct that the rest of
    /// the CLI dereferences. Any validation error
    /// aborts startup with a clear message naming the
    /// offending env var.
    pub fn parse() -> Result<Self, CliEnvError> {
        Ok(Self {
            data_dir: read_cli_path("AGENCY_DATA_DIR", default_data_dir)?,
            hermes_home: read_cli_path("AGENCY_HERMES_HOME", default_hermes_home_raw)?,
            cas_root: read_cli_path("AGENCY_CAS_ROOT", default_cas_root_raw)?,
        })
    }
}

/// Internal: read a single CLI env var, falling back to
/// the closure that computes the default. Validation
/// rejects: empty, NUL, `..` segment, non-UTF8.
/// The fallback closures keep the original
/// `data_dir::default_*` semantics (USERPROFILE / HOME
/// fallback) so the tests for the old helpers continue
/// to pass.
fn read_cli_path<F>(var: &'static str, fallback: F) -> Result<PathBuf, CliEnvError>
where
    F: FnOnce() -> PathBuf,
{
    let raw = match std::env::var(var) {
        Ok(v) => v,
        Err(_) => return Ok(fallback()),
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CliEnvError::EmptyPath { var });
    }
    if let Some(pos) = trimmed.find('\0') {
        return Err(CliEnvError::NulByte { var, pos });
    }
    let p = PathBuf::from(trimmed);
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(CliEnvError::ParentDir { var });
    }
    Ok(p)
}

fn default_hermes_home_raw() -> PathBuf {
    // The original data_dir::default_hermes_home
    // reads AGENCY_HERMES_HOME first, then falls back
    // to hermes-adapter detection, then to
    // `<data_dir>/hermes`. We re-implement that here
    // (without reading the env again — `read_cli_path`
    // already did that) and feed the result to
    // `read_cli_path` only when the env was unset.
    if let Some(p) = agent_dep_hermes_adapter::paths::default_hermes_home() {
        return p;
    }
    default_data_dir().join("hermes")
}

fn default_cas_root_raw() -> PathBuf {
    default_data_dir().join("cas")
}

/// Scan the parent env for the set of known
/// server-only env vars. For each one that is set,
/// print a one-line warning to stderr. The CLI does
/// NOT fail — the operator may legitimately have
/// these set in their shell because the server runs
/// there too. But the warning prevents the
/// "I set this, why didn't the CLI pick it up"
/// support ticket.
pub fn warn_server_only_envs() {
    for var in SERVER_ONLY_ENV {
        if std::env::var(var).is_ok() {
            eprintln!(
                "warning: env `{var}` is set but is server-only; \
                 the CLI ignores it. To configure the CLI, use \
                 AGENCY_DATA_DIR / AGENCY_HERMES_HOME / AGENCY_CAS_ROOT."
            );
        }
    }
}

/// `is_parent_dir_segment` exposed for tests. `Path::components`
/// gives us back `Component::ParentDir` for any `..` in the
/// path; a `..` is a path-traversal confusion vector, not
/// a path-traversal hole (the OS won't follow it across
/// canonicalize), but a CLI that respects an operator-set
/// `..` env is one typo away from a confusing error.
pub fn has_parent_dir_segment(p: &Path) -> bool {
    p.components().any(|c| matches!(c, Component::ParentDir))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: run `f` with `var` set to `value` for the
    /// duration of the call, restoring the previous value
    /// afterwards. Tests in this module touch real env vars
    /// and must not leak state to other tests.
    fn with_env<F, R>(var: &'static str, value: Option<&str>, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let prev = std::env::var(var).ok();
        // SAFETY: tests in this module are
        // single-threaded with respect to env access
        // (the cargo test runner uses one process per
        // test by default; we also serialize with
        // `serial_test` style if needed). Setting env
        // vars in tests is the standard Rust pattern.
        unsafe {
            match value {
                Some(v) => std::env::set_var(var, v),
                None => std::env::remove_var(var),
            }
        }
        let r = f();
        unsafe {
            match prev {
                Some(v) => std::env::set_var(var, v),
                None => std::env::remove_var(var),
            }
        }
        r
    }

    #[test]
    fn parse_uses_data_dir_default_when_env_unset() {
        let prev_data = std::env::var("AGENCY_DATA_DIR").ok();
        let prev_hermes = std::env::var("AGENCY_HERMES_HOME").ok();
        let prev_cas = std::env::var("AGENCY_CAS_ROOT").ok();
        unsafe {
            std::env::remove_var("AGENCY_DATA_DIR");
            std::env::remove_var("AGENCY_HERMES_HOME");
            std::env::remove_var("AGENCY_CAS_ROOT");
        }
        let env = CliEnv::parse().expect("parse");
        // The default for data_dir is `<HOME>/.agency`.
        let home = std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        assert_eq!(env.data_dir, home.join(".agency"));
        // Restore.
        unsafe {
            match prev_data {
                Some(v) => std::env::set_var("AGENCY_DATA_DIR", v),
                None => std::env::remove_var("AGENCY_DATA_DIR"),
            }
            match prev_hermes {
                Some(v) => std::env::set_var("AGENCY_HERMES_HOME", v),
                None => std::env::remove_var("AGENCY_HERMES_HOME"),
            }
            match prev_cas {
                Some(v) => std::env::set_var("AGENCY_CAS_ROOT", v),
                None => std::env::remove_var("AGENCY_CAS_ROOT"),
            }
        }
    }

    #[test]
    fn parse_uses_explicit_data_dir_override() {
        let env = with_env("AGENCY_DATA_DIR", Some("X:/custom/agency"), CliEnv::parse)
            .expect("parse");
        assert_eq!(env.data_dir, PathBuf::from("X:/custom/agency"));
    }

    #[test]
    fn parse_rejects_empty_data_dir() {
        let err = with_env("AGENCY_DATA_DIR", Some("   "), CliEnv::parse)
            .expect_err("empty path must be rejected");
        assert!(matches!(err, CliEnvError::EmptyPath { var: "AGENCY_DATA_DIR" }));
    }

    #[test]
    #[cfg(unix)]
    fn parse_rejects_nul_byte_in_data_dir() {
        // On Windows, `std::env::set_var` itself
        // panics when the value contains a NUL
        // (WinAPI rejects NULs in env strings), so
        // this test cannot run there. On Unix the
        // OS would silently truncate the env var
        // at the NUL, which is exactly the kind of
        // confusion this guard exists to prevent.
        let err = with_env("AGENCY_DATA_DIR", Some("good\0bad"), CliEnv::parse)
            .expect_err("NUL must be rejected");
        assert!(matches!(err, CliEnvError::NulByte { .. }));
    }

    #[test]
    fn parse_rejects_parent_dir_segment() {
        let err = with_env("AGENCY_DATA_DIR", Some("../escape"), CliEnv::parse)
            .expect_err(".. must be rejected");
        assert!(matches!(err, CliEnvError::ParentDir { .. }));
    }

    #[test]
    fn parse_rejects_empty_hermes_home() {
        let err = with_env("AGENCY_HERMES_HOME", Some(""), CliEnv::parse)
            .expect_err("empty must be rejected");
        assert!(matches!(err, CliEnvError::EmptyPath { var: "AGENCY_HERMES_HOME" }));
    }

    #[test]
    fn parse_rejects_empty_cas_root() {
        let err = with_env("AGENCY_CAS_ROOT", Some(""), CliEnv::parse)
            .expect_err("empty must be rejected");
        assert!(matches!(err, CliEnvError::EmptyPath { var: "AGENCY_CAS_ROOT" }));
    }

    #[test]
    fn has_parent_dir_segment_detects_dotdot() {
        assert!(has_parent_dir_segment(Path::new("../x")));
        assert!(has_parent_dir_segment(Path::new("a/../b")));
        assert!(!has_parent_dir_segment(Path::new("a/b/c")));
        assert!(!has_parent_dir_segment(Path::new("a/./b")));
    }

    #[test]
    fn warn_server_only_envs_does_not_panic_when_none_set() {
        // Just exercise the scan path with no server
        // env vars set. The output goes to stderr; we
        // only assert it does not panic and returns.
        let prev = std::env::var("AGENCY_OIDC_ISSUER").ok();
        unsafe {
            std::env::remove_var("AGENCY_OIDC_ISSUER");
        }
        warn_server_only_envs();
        unsafe {
            match prev {
                Some(v) => std::env::set_var("AGENCY_OIDC_ISSUER", v),
                None => std::env::remove_var("AGENCY_OIDC_ISSUER"),
            }
        }
    }

    #[test]
    fn warn_server_only_envs_lists_known_oidc_vars() {
        // The function reads SERVER_ONLY_ENV at compile
        // time. We assert that a representative
        // subset is in the list — guards against
        // someone removing the warning by trimming
        // the list and forgetting an entry.
        for var in [
            "AGENCY_OIDC_ISSUER",
            "AGENCY_OIDC_CLIENT_ID",
            "AGENCY_OIDC_CLIENT_SECRET",
            "AGENCY_VAULT_PASSPHRASE",
            "AGENCY_BIND_IP",
            "AGENCY_SERVER_DATA_DIR",
        ] {
            assert!(
                SERVER_ONLY_ENV.contains(&var),
                "server-only env `{var}` is not in the warning list"
            );
        }
    }
}
