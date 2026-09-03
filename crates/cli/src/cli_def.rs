//! `clap` definition for the `agency` binary.
//!
//! Lives in the library (not in `main.rs`) so that
//! 2.0.0 server tests can construct the parser and
//! inspect the surface without spinning up a process.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
    /// Install / remove Hermes 0.19+ Flow B MCP server
    /// manifests under `<hermes_home>/optional-mcps/<name>/`
    /// (1.3.0, ADR-0011).
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },
    /// Probe a Flow A router plugin under `<hermes_home>/plugins/`
    /// (1.4.0, ADR-0012). Currently static-structural only; the
    /// dynamic LLM probe lands in 2.x with Hermes 0.19+ Flow B.
    Hermes {
        #[command(subcommand)]
        action: HermesAction,
    },
    /// Generate a shell completion script to stdout (1.6.0,
    /// ADR-0015). Redirect the output to the shell-specific
    /// completion directory.
    Completion { shell: String },
    /// Roll back a previous deploy by operation id.
    Rollback {
        /// UUID printed by `agency deploy apply` (or the
        /// `operation_id` field of the deploy summary).
        operation_id: String,
    },
    /// Start the 2.0.0 enterprise HTTP server (ADR-0017) in
    /// the foreground. The server is intended for headless
    /// installs; the desktop Tauri app does not host it.
    Serve {
        /// Bind port. `0` picks an ephemeral port.
        #[arg(long, default_value_t = 0)]
        port: u16,
    },
    /// Print the resolved paths to stdout (data dir, db,
    /// CAS root, hermes home). 1.x admin helper.
    Paths,
}

#[derive(Subcommand, Debug)]
pub enum CatalogAction {
    /// Ingest a local catalog directory and write the
    /// snapshot to the SQLite DB.
    Update {
        /// Path to the local catalog root (must contain
        /// `divisions.json` and `agents/<division>/*.md`).
        path: PathBuf,
    },
    /// Add a remote Git source to the catalog. 1.1.0+.
    Add {
        /// HTTPS or SSH URL of the Git repository.
        url: String,
    },
    /// 2.6.4 (ADR-0027): run the scanner over a
    /// local directory without ingesting.
    /// Supports `--format text|json|sarif` for
    /// piping into CI / IDE viewers.
    Scan {
        /// Path to the local directory to scan.
        path: PathBuf,
        /// Output format. `text` is the
        /// human-readable default; `json` is a
        /// flat array of findings; `sarif` is
        /// the SARIF 2.1.0 log.
        #[arg(long, value_name = "FORMAT", default_value = "text")]
        format: String,
        /// 2.7.0 (ADR-0028): register an external
        /// scanner plugin (absolute path to a
        /// binary). May be repeated. The plugin
        /// receives a JSON envelope on stdin and
        /// writes a JSON envelope on stdout.
        #[arg(long, value_name = "NAME:PATH")]
        plugin: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum SystemAction {
    Plan {
        file: PathBuf,
        #[arg(long, value_name = "CATALOG")]
        catalog: PathBuf,
        /// 1.5.0+ (ADR-0013): when set, the plan includes
        /// drift-detection ops (`Verify` and `Backup`).
        #[arg(long)]
        drift: bool,
        /// Required with `--drift`: the previously-deployed
        /// target tree.
        #[arg(long, value_name = "PATH")]
        target: Option<PathBuf>,
        /// Required with `--drift`: the SQLite DB holding
        /// the `deployed_artifacts` rows.
        #[arg(long, value_name = "PATH")]
        db: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum DeployAction {
    /// Apply a `system.yaml` to a target directory.
    Apply {
        file: PathBuf,
        #[arg(long, value_name = "CATALOG")]
        catalog: PathBuf,
        #[arg(long, value_name = "PATH")]
        target: PathBuf,
        /// Override the default SQLite path. By default the
        /// CLI uses `<data>/data/agency.db`.
        #[arg(long, value_name = "PATH")]
        db: Option<PathBuf>,
    },
    /// Materialize a Hermes router plugin under
    /// `<hermes_home>/plugins/<plugin_id>/`.
    Install {
        file: PathBuf,
        #[arg(long, value_name = "CATALOG")]
        catalog: PathBuf,
        #[arg(long, value_name = "PLUGIN_ID")]
        plugin_id: Option<String>,
        /// Optional path to a `policy.yaml` (TZ §24).
        #[arg(long, value_name = "PATH")]
        policy: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum LockAction {
    /// Generate an `agency.lock` next to a `system.yaml`.
    Generate {
        file: PathBuf,
        #[arg(long, value_name = "CATALOG")]
        catalog: PathBuf,
        /// 1.2.0+ (ADR-0010): SemVer range template applied
        /// to every resolved agent version. Supports
        /// `{major}`, `{minor}`, `{patch}` placeholders.
        #[arg(long, value_name = "TEMPLATE")]
        range: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum McpAction {
    /// Materialize a `manifest.yaml` for a remote MCP server
    /// under `<hermes_home>/optional-mcps/<name>/`.
    Add {
        name: String,
        /// Path to a JSON file describing the MCP server
        /// (name, transport, auth, …).
        #[arg(long, value_name = "PATH")]
        spec: PathBuf,
    },
    /// List every MCP server currently installed under
    /// `<hermes_home>/optional-mcps/`.
    List,
    /// Remove an installed MCP server. Deletes
    /// `<hermes_home>/optional-mcps/<name>/` recursively.
    Remove { name: String },
}

#[derive(Subcommand, Debug)]
pub enum HermesAction {
    /// Run the static-structural health probe on a
    /// Flow A router plugin (1.4.0, ADR-0012).
    /// 2.7.4 (ADR-0032) adds `--llm` to extend
    /// the structural probe with an LLM-based
    /// semantic review.
    Probe {
        plugin_id: String,
        /// 2.7.4 (ADR-0032): also run the
        /// LLM-based semantic review. Requires
        /// `AGENCY_LLM_ENDPOINT` /
        /// `AGENCY_LLM_MODEL` /
        /// `AGENCY_LLM_API_KEY` env vars.
        #[arg(long)]
        llm: bool,
    },
}
