//! Server environment decoupling guard.
//!
//! P1-CLI-01 (TZ #2 WP-4.1 / SEC-11, CWE-15 External
//! Control of System or Configuration Setting):
//! the symmetric counterpart of
//! `agent_dep_cli::env_validate`. The CLI prints a
//! warning when it sees server-only env vars; the
//! server prints a warning when it sees CLI-only
//! env vars.
//!
//! The CLI-only env vars are the three that the CLI
//! reads for its per-user data / Hermes / CAS
//! locations: `AGENCY_DATA_DIR`, `AGENCY_HERMES_HOME`,
//! `AGENCY_CAS_ROOT`. If any of these are set when
//! the server boots, it usually means the operator
//! has them in their interactive shell and the
//! server (which is supposed to have its own
//! `AGENCY_SERVER_DATA_DIR`) is inheriting the
//! wrong value. The server keeps using its own
//! `AGENCY_SERVER_DATA_DIR` (so it does not
//! misroute at startup), but emits a warning so
//! the operator knows their CLI config is leaking
//! into the server's process env.

/// CLI-only env vars. The server does NOT read these
/// for its own config — if they are set, the operator
/// has them in their shell and the server inherited
/// them. Warn at boot.
const CLI_ONLY_ENV: &[&str] = &[
    "AGENCY_DATA_DIR",
    "AGENCY_HERMES_HOME",
    "AGENCY_CAS_ROOT",
];

/// Scan the parent env for the set of known CLI-only
/// env vars. For each one that is set, print a
/// one-line warning to stderr. The server does NOT
/// fail — systemd units / docker runs frequently
/// inherit the operator's interactive shell, and
/// a fail-loud would brick production deploys.
/// The warning is explicit: "this is a CLI-only
/// env var, the server ignores it; configure the
/// server with AGENCY_SERVER_DATA_DIR (and the
/// AGENCY_OIDC_* / AGENCY_VAULT_* / AGENCY_BIND_*
/// set for the server)".
pub fn warn_cli_only_envs() {
    for var in CLI_ONLY_ENV {
        if std::env::var(var).is_ok() {
            eprintln!(
                "warning: env `{var}` is set but is CLI-only; \
                 the server ignores it. To configure the \
                 server, use AGENCY_SERVER_DATA_DIR (or the \
                 AGENCY_BIND_IP / AGENCY_OIDC_* / \
                 AGENCY_VAULT_* envs documented in the \
                 server README)."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warn_cli_only_envs_does_not_panic_when_none_set() {
        let prev = std::env::var("AGENCY_DATA_DIR").ok();
        unsafe {
            std::env::remove_var("AGENCY_DATA_DIR");
        }
        warn_cli_only_envs();
        unsafe {
            match prev {
                Some(v) => std::env::set_var("AGENCY_DATA_DIR", v),
                None => std::env::remove_var("AGENCY_DATA_DIR"),
            }
        }
    }

    #[test]
    fn cli_only_env_list_includes_all_three() {
        for var in ["AGENCY_DATA_DIR", "AGENCY_HERMES_HOME", "AGENCY_CAS_ROOT"] {
            assert!(
                CLI_ONLY_ENV.contains(&var),
                "CLI-only env `{var}` is not in the warning list"
            );
        }
    }
}
