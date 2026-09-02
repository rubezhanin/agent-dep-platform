mod commands;
mod data_dir;
mod output;

#[cfg(test)]
mod cli_tests;

use clap::{Parser, Subcommand};
use commands::{catalog, deploy, lock, rollback, status, system};
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
    /// Apply a `system.yaml` to a target directory through the
    /// journal-backed `DeploymentService`. The journal records the
    /// operation so a crash mid-flight leaves a non-terminal row
    /// that `gc_stale` will force-fail on next startup.
    Deploy {
        #[command(subcommand)]
        action: DeployAction,
    },
    /// Generate or inspect an `agency.lock` next to a system file.
    Lock {
        #[command(subcommand)]
        action: LockAction,
    },
    /// Roll back a previous deploy by operation id.
    Rollback {
        /// Journal operation id (UUID) to roll back.
        operation_id: String,
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
    /// Clone a Git repository (HTTPS or SSH) and ingest it as a
    /// new catalog source. The working copy is cached at
    /// `<data>/sources/<source_id>/` so subsequent
    /// `agency catalog update <url>` calls only re-fetch
    /// (1.1.0, ADR-0009).
    Add {
        /// URL of the Git repository. Accepts `https://…`,
        /// `http://…`, `git@host:path`, or `host:path`
        /// (SCP-style SSH). `file://…` is also accepted for
        /// local testing.
        url: String,
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

#[derive(Subcommand, Debug)]
pub enum LockAction {
    /// Generate `agency.lock` next to a `system.yaml` from
    /// the resolved snapshot. Re-ingests the catalog; does
    /// not write to the DB.
    Generate {
        /// Path to the system definition (a `system.yaml`).
        file: PathBuf,
        /// Path to the local catalog root.
        #[arg(long)]
        catalog: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum DeployAction {
    /// Apply a composed `system.yaml` to a target directory. Agent
    /// files are written to `<target>/agents/<id>@<version>/<id>.md`
    /// with backup-before-overwrite and atomic temp+rename.
    Apply {
        /// Path to the system definition (a `system.yaml`).
        file: PathBuf,
        /// Path to the local catalog root.
        #[arg(long)]
        catalog: PathBuf,
        /// Directory to write the deployed agent files into.
        #[arg(long)]
        target: PathBuf,
    },
    /// Install a router plugin into Hermes home. Writes
    /// `manifest.yaml` + `SKILL.md` + `skills/<slug>.md` under
    /// `<HERMES_HOME>/plugins/<plugin-id>/` (per ADR-0008). Does
    /// NOT call `hermes mcp configure` — enable the plugin in
    /// Hermes separately (e.g. via the Hermes UI or
    /// `hermes plugin enable <id>` when available in your build).
    Install {
        /// Path to the system definition (a `system.yaml`).
        file: PathBuf,
        /// Path to the local catalog root.
        #[arg(long)]
        catalog: PathBuf,
        /// Plugin slug under `<HERMES_HOME>/plugins/`.
        #[arg(long, default_value = deploy::DEFAULT_PLUGIN_ID)]
        plugin_id: String,
        /// Optional policy file (`policy.yaml`).
        #[arg(long)]
        policy: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result: Result<(), Box<dyn std::error::Error>> = match cli.command {
        Command::Status => status::run().await.map_err(Into::into),
        Command::Catalog { action } => match action {
            CatalogAction::Update { path } => catalog::update(path).await.map_err(Into::into),
            CatalogAction::Add { url } => catalog::add(url).await.map_err(Into::into),
        },
        Command::System { action } => match action {
            SystemAction::Plan { file, catalog } => {
                system::plan(&file, &catalog).await.map_err(Into::into)
            }
        },
        Command::Deploy { action } => match action {
            DeployAction::Apply { file, catalog, target } => {
                deploy::deploy(&file, &catalog, &target)
                    .await
                    .map_err(Into::into)
            }
            DeployAction::Install { file, catalog, plugin_id, policy } => {
                deploy::install(&file, &catalog, &plugin_id, policy.as_deref())
                    .await
                    .map_err(Into::into)
            }
        },
        Command::Lock { action } => match action {
            LockAction::Generate { file, catalog } => {
                lock::generate(&file, &catalog).await.map_err(Into::into)
            }
        },
        Command::Rollback { operation_id } => match uuid::Uuid::parse_str(&operation_id) {
            Ok(id) => rollback::rollback(id).await.map_err(Into::into),
            Err(e) => {
                let err: Box<dyn std::error::Error> =
                    anyhow::anyhow!("invalid operation id `{operation_id}`: {e}").into();
                Err(err)
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
