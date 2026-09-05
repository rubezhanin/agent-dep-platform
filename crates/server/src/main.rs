//! `agency-server` — 2.0.0 enterprise server (ADR-0017, ADR-0018).
//!
//! Thin binary wrapper around `agent_dep_server::run`.
//! The library surface is what the integration tests
//! link against.
//!
//! 2.9.0 (VPS deploy): the bind address is
//! configurable. The CLI flag `--bind` and
//! the `AGENCY_BIND` env var both accept
//! `<ip>:<port>`. Default is `0.0.0.0:8080` —
//! the integration tests (and the 2.x dev
//! loop) override this with `--bind 127.0.0.1:0`
//! to keep the kernel-port collision surface
//! small. Production deployments behind a
//! reverse proxy should leave the default and
//! let caddy/nginx do the TLS termination on
//! the public side.

use std::net::SocketAddr;

use agent_dep_server::{parse_bind, parse_port};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let args: Vec<String> = std::env::args().collect();
    let bind = parse_bind(&args);
    let port = parse_port(&args);
    let addr: SocketAddr = format!("{bind}:{port}")
        .parse()
        .map_err(|e| anyhow::anyhow!("parse {bind}:{port}: {e}"))?;
    agent_dep_server::run(addr).await
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
