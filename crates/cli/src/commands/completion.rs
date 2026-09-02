//! `agency completion <shell>` — generate a shell
//! completion script to stdout (1.6.0, ADR-0015).
//!
//! The user is expected to redirect the output to a
//! shell-specific location. We do not write to disk
//! ourselves; that would require per-platform path
//! detection which is out of scope.

use anyhow::Result;
use clap::CommandFactory;
use clap_complete::{generate, Shell};
use std::str::FromStr;

use crate::cli_def::Cli;

/// CLI entry point. Validates the shell name and
/// writes the script to stdout. Returns an error if
/// the shell is not one of the supported values.
pub fn run(shell_name: &str) -> Result<()> {
    let shell = Shell::from_str(shell_name).map_err(|_| {
        anyhow::anyhow!(
            "unsupported shell `{shell_name}`; expected one of: bash, zsh, fish, elvish, powershell"
        )
    })?;
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    generate(shell, &mut cmd, name, &mut std::io::stdout());
    Ok(())
}
