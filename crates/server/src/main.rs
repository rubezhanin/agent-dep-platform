//! `agency-server` — 2.0.0 enterprise server (ADR-0017, ADR-0018).
//!
//! Thin binary wrapper around `agent_dep_server::run`.
//! The library surface is what the integration tests
//! link against.
//!
//! 2.10.0 (A6, audit): the CLI
//! argument parser was rewritten
//! with `clap::Parser` (was a
//! hand-rolled argv walker in
//! `lib.rs::parse_bind` /
//! `parse_port` that didn't support
//! `--bind=ip` syntax, had no
//! `--help`, and silently ignored
//! invalid input). The
//! `ServerArgs` struct is `pub` so
//! integration tests can
//! `ServerArgs::parse_from(&[...])`
//! directly without going through
//! the binary's `std::env::args`.

use std::net::SocketAddr;

use clap::Parser;

use agent_dep_server::{run, ServerArgs};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    // P1-CLI-01 (TZ #2 WP-4.1 / SEC-11, CWE-15):
    // warn if the operator has set CLI-only env
    // vars (AGENCY_DATA_DIR / AGENCY_HERMES_HOME
    // / AGENCY_CAS_ROOT) in the same shell that
    // runs the server. The server ignores them
    // (it has its own AGENCY_SERVER_DATA_DIR) but
    // the warning prevents a silent inheritance
    // misconfiguration.
    agent_dep_server::env_validate::warn_cli_only_envs();
    let args = ServerArgs::parse();
    let addr: SocketAddr = SocketAddr::new(args.bind, args.port);
    run(addr).await
}

fn init_tracing() {
    use tracing_subscriber::{prelude::*, EnvFilter};
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn"));
    let layer = tracing_subscriber::fmt::layer().with_target(false);
    tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .init();
}
