//! `agency serve` — 2.0.0 enterprise server bootstrap.
//!
//! The binary lives in the `agent_dep_server` crate; this
//! module is a thin shim that defers to it. Keeping the
//! subcommand under `agent_dep_cli` means the existing CLI
//! dispatch works unchanged and the server inherits the
//! same `agency` UX (version, help, --port).

use std::path::PathBuf;

pub async fn run(port: u16) -> anyhow::Result<()> {
    // The `agency-server` binary is a separate cargo
    // package. From the CLI we shell out so the operator
    // can run `agency serve --port 7878` instead of
    // `agency-server --port 7878` and the user-visible
    // UX stays under one binary.
    let exe = current_exe()?;
    let sibling = exe.with_file_name("agency-server.exe");
    let sibling = if sibling.is_file() {
        sibling
    } else {
        exe.with_file_name("agency-server")
    };
    if !sibling.is_file() {
        anyhow::bail!(
            "`agency-server` not found next to `{}`. Build it with `cargo build -p agent_dep_server --release` and try again.",
            exe.display()
        );
    }
    let status = std::process::Command::new(&sibling)
        .arg("--port")
        .arg(port.to_string())
        .status()
        .map_err(|e| anyhow::anyhow!("spawn {}: {e}", sibling.display()))?;
    if !status.success() {
        anyhow::bail!("agency-server exited with {:?}", status.code());
    }
    Ok(())
}

fn current_exe() -> anyhow::Result<PathBuf> {
    std::env::current_exe().map_err(|e| anyhow::anyhow!("current_exe: {e}"))
}
