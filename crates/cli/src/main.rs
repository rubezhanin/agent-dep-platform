mod commands;
mod output;

#[cfg(test)]
mod cli_tests;

use clap::{Parser, Subcommand};
use commands::{catalog, deploy, status};
use std::path::PathBuf;
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
    /// Ingest and inspect a local catalog (MVP-3).
    Catalog {
        #[command(subcommand)]
        action: CatalogAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum CatalogAction {
    /// Walk a local directory, parse + validate + scan, return the
    /// immutable snapshot identity and counts. (Persistence is a
    /// separate task; this command prints the result.)
    Update {
        /// Path to the catalog root (must contain `divisions.json`
        /// and an `agents/<division>/*.md` subtree).
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result: Result<(), Box<dyn std::error::Error>> = match cli.command {
        Command::Deploy { system } => deploy::run(&system).await.map_err(Into::into),
        Command::Status => status::run().await.map_err(Into::into),
        Command::Catalog { action } => match action {
            CatalogAction::Update { path } => catalog::update(path),
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}
