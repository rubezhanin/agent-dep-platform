mod commands;
mod output;

#[cfg(test)]
mod cli_tests;

use clap::{Parser, Subcommand};
use commands::{deploy, status};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(name = "agency", version, about = "Agent Deployment Platform CLI", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Deploy a system to a runtime.
    Deploy {
        /// System identifier (e.g. "saas-platform").
        system: String,
    },
    /// Show current deployment status.
    Status,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Deploy { system } => deploy::run(&system).await,
        Command::Status => status::run().await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}
