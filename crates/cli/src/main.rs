mod commands;
mod data_dir;
mod output;

#[cfg(test)]
mod cli_tests;

use clap::{Parser, Subcommand};
use commands::{catalog, deploy, status, system};
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
    /// Compose + plan a system from a `system.yaml` (MVP-3).
    System {
        #[command(subcommand)]
        action: SystemAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum CatalogAction {
    /// Walk a local directory, parse + validate + scan, persist the
    /// snapshot to the default SQLite DB, and print a summary.
    Update {
        /// Path to the catalog root (must contain `divisions.json`
        /// and an `agents/<division>/*.md` subtree).
        path: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum SystemAction {
    /// Compose a system.yaml against a local catalog and print the
    /// resulting deployment plan. For MVP-3 every resolved agent
    /// becomes one ADD operation; the diff against an existing
    /// deployment state lands in 1.x.
    Plan {
        /// Path to the system definition (a `system.yaml`).
        file: PathBuf,
        /// Path to the local catalog root (must contain
        /// `divisions.json` and `agents/<division>/*.md`). The
        /// catalog is re-ingested in-memory; nothing is written to
        /// the DB by this command.
        #[arg(long)]
        catalog: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result: Result<(), Box<dyn std::error::Error>> = match cli.command {
        Command::Deploy { system } => deploy::run(&system).await.map_err(Into::into),
        Command::Status => status::run().await.map_err(Into::into),
        Command::Catalog { action } => match action {
            CatalogAction::Update { path } => catalog::update(path).await.map_err(Into::into),
        },
        Command::System { action } => match action {
            SystemAction::Plan { file, catalog } => {
                system::plan(&file, &catalog).await.map_err(Into::into)
            }
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
