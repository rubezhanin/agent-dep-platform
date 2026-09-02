//! `agency-server` — 2.0.0 enterprise server (ADR-0017, ADR-0018).
//!
//! Thin binary wrapper around `agent_dep_server::run`.
//! The library surface is what the integration tests
//! link against.

use std::net::SocketAddr;

use agent_dep_server::parse_port;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let args: Vec<String> = std::env::args().collect();
    let port = parse_port(&args);
    let addr: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .map_err(|e| anyhow::anyhow!("parse 127.0.0.1:{port}: {e}"))?;
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
