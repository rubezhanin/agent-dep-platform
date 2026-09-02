//! `agency` CLI binary — 2.0.0 thin wrapper.
//!
//! The `Cli` / `Command` definition and the per-subcommand
//! dispatch live in `agent_dep_cli::cli_def` and the
//! `agent_dep_cli::commands` module. The binary here
//! parses the argv, dispatches into the same code, and
//! exits with `ExitCode` per the platform convention.

use agent_dep_cli::cli_def::{Cli, Command};
use agent_dep_cli::commands::{
    catalog, completion, deploy, hermes, lock, mcp, rollback, serve, status, system,
};
use clap::Parser;
use std::process::ExitCode;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // clap errors (help, version, bad args) print to
            // stdout/stderr themselves; exit with the
            // user-error code clap suggests.
            e.exit();
        }
    };
    match dispatch(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Status => status::run().await.map_err(Into::into),
        Command::Catalog { action } => match action {
            agent_dep_cli::cli_def::CatalogAction::Update { path } => catalog::update(path).await,
            agent_dep_cli::cli_def::CatalogAction::Add { url } => catalog::add(url).await,
        },
        Command::System { action } => match action {
            agent_dep_cli::cli_def::SystemAction::Plan {
                file,
                catalog,
                drift,
                target,
                db,
            } => {
                if drift {
                    let target = target.expect("--target is required with --drift");
                    let db = db.expect("--db is required with --drift");
                    match system::plan_at_drift(&file, &catalog, &target, &db).await {
                        Ok(summary) => {
                            system::print_summary(&summary);
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                } else {
                    system::plan(&file, &catalog).await
                }
            }
        },
        Command::Deploy { action } => match action {
            agent_dep_cli::cli_def::DeployAction::Apply {
                file,
                catalog,
                target,
                db,
            } => {
                let db_path = match db {
                    Some(p) => p.clone(),
                    None => agent_dep_cli::data_dir::default_db_path(),
                };
                deploy::deploy(&file, &catalog, &target, &db_path).await
            }
            agent_dep_cli::cli_def::DeployAction::Install {
                file,
                catalog,
                plugin_id,
                policy,
            } => deploy::install(&file, &catalog, &plugin_id, policy.as_deref()).await,
        },
        Command::Lock { action } => match action {
            agent_dep_cli::cli_def::LockAction::Generate {
                file,
                catalog,
                range,
            } => lock::generate(&file, &catalog, range.as_deref()).await,
        },
        Command::Mcp { action } => match action {
            agent_dep_cli::cli_def::McpAction::Add { name, spec } => mcp::add(name, &spec).await,
            agent_dep_cli::cli_def::McpAction::List => mcp::list(),
            agent_dep_cli::cli_def::McpAction::Remove { name } => mcp::remove(&name),
        },
        Command::Hermes { action } => match action {
            agent_dep_cli::cli_def::HermesAction::Probe { plugin_id } => {
                hermes::probe(plugin_id).await
            }
        },
        Command::Completion { shell } => completion::run(&shell),
        Command::Rollback { operation_id } => {
            let id = uuid::Uuid::parse_str(&operation_id)
                .map_err(|e| anyhow::anyhow!("operation id is not a UUID: {e}"))?;
            rollback::rollback(id).await
        }
        Command::Serve { port } => serve::run(port).await,
        Command::Paths => {
            println!(
                "data dir  : {}",
                agent_dep_cli::data_dir::default_data_dir().display()
            );
            println!(
                "db path   : {}",
                agent_dep_cli::data_dir::default_db_path().display()
            );
            println!(
                "cas root  : {}",
                agent_dep_cli::data_dir::default_cas_root().display()
            );
            println!(
                "hermes home: {}",
                agent_dep_cli::data_dir::default_hermes_home().display()
            );
            Ok(())
        }
    }
}
