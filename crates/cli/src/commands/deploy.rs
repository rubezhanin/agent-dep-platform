//! `agency deploy ...` — apply a `system.yaml` to a target
//! directory through the journal-backed `DeploymentService`,
//! or install a router plugin into Hermes home through the
//! `HermesAdapter` (per ADR-0008).

use std::path::{Path, PathBuf};

use agent_dep_core::application::compose::CompositionService;
use agent_dep_core::application::deploy::DeploymentService;
use agent_dep_core::application::ingest::IngestService;
use agent_dep_core::application::journal::JournalService;
use agent_dep_core::domain::source::{Source, SourceKind};
use agent_dep_core::domain::system::parse_system_file;
use agent_dep_core::infrastructure::sqlite::{connect, Db};
use agent_dep_hermes_adapter::paths::default_hermes_home;
use agent_dep_hermes_adapter::router_plugin::{AgentFile, RouterPluginInputs};
use agent_dep_hermes_adapter::{HermesAdapter, RuntimeAdapter};
use anyhow::{Context, Result};
use tokio::fs;

use crate::output;

/// Default plugin id used by `agency deploy install` when
/// the caller does not pass `--plugin-id`. Matches the
/// `agency-agents-router` slug from the upstream catalog
/// template at
/// `C:\projects\agency-agents\templates\hermes-kit-manifest.json`.
pub const DEFAULT_PLUGIN_ID: &str = "agency-agents-router";

const ROUTER_TOOLS: &[&str] = &[
    "agency_agents_search",
    "agency_agents_inspect",
    "agency_agents_load",
    "agency_agents_delegate",
];

/// Summary returned from `deploy_at` so tests can assert without
/// re-parsing stdout.
#[derive(Debug, Clone)]
pub struct DeploySummary {
    pub system_id: String,
    pub operation_id: uuid::Uuid,
    pub wrote: usize,
    pub skipped: usize,
    pub backed_up: usize,
    pub target: PathBuf,
    pub db_path: PathBuf,
}

/// Summary returned from `install_at`.
#[derive(Debug, Clone)]
pub struct InstallSummary {
    pub system_id: String,
    pub plugin_id: String,
    pub plugin_dir: PathBuf,
    pub manifest_sha256: String,
    pub skills_sha256: String,
    pub skill_count: usize,
    pub hermes_home: PathBuf,
}

/// CLI entry point for the file-materialization flow.
pub async fn deploy(system_file: &Path, catalog_path: &Path, target: &Path) -> Result<()> {
    let db_path = crate::data_dir::default_db_path();
    let summary = deploy_at(system_file, catalog_path, target, &db_path).await?;
    print_summary(&summary);
    Ok(())
}

/// CLI entry point for the Hermes-router-plugin flow.
pub async fn install(
    system_file: &Path,
    catalog_path: &Path,
    plugin_id: &str,
) -> Result<()> {
    let summary = install_at(system_file, catalog_path, plugin_id, &default_hermes_home_safe()).await?;
    print_install_summary(&summary);
    Ok(())
}

/// Pure orchestration: read the system file, re-ingest the
/// catalog, compose, then run `DeploymentService` against the
/// journal. No source-side state is mutated.
pub async fn deploy_at(
    system_file: &Path,
    catalog_path: &Path,
    target: &Path,
    db_path: &Path,
) -> Result<DeploySummary> {
    if !system_file.is_file() {
        anyhow::bail!("not a file: {}", system_file.display());
    }
    if !catalog_path.is_dir() {
        anyhow::bail!("not a directory: {}", catalog_path.display());
    }
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create_dir_all {}", parent.display()))?;
    }

    let text = std::fs::read_to_string(system_file)
        .with_context(|| format!("read {}", system_file.display()))?;
    let file = parse_system_file(&text)
        .map_err(|e| anyhow::anyhow!("parse {} (expected a `system.yaml`): {e}", system_file.display()))?;

    let source = Source::new(SourceKind::local(catalog_path.to_path_buf()));
    let (result, _report) = IngestService::new().ingest_local(&source).map_err(|e| {
        anyhow::anyhow!("ingest {}: {e}", catalog_path.display())
    })?;

    let placeholder_source_id = uuid::Uuid::new_v4();
    let composed = CompositionService::new()
        .compose(
            placeholder_source_id,
            result.snapshot.id,
            &result.agents,
            &[],
            &file,
        )
        .map_err(|e| anyhow::anyhow!("compose: {e}"))?;

    let db = open_and_migrate(db_path).await?;
    let journal = JournalService::new(db.pool().clone());

    let outcome = DeploymentService::new()
        .apply(target, &composed, &journal)
        .await
        .map_err(|e| anyhow::anyhow!("deploy: {e}"))?;

    Ok(DeploySummary {
        system_id: composed.metadata.id.clone(),
        operation_id: outcome.operation_id,
        wrote: outcome.wrote,
        skipped: outcome.skipped,
        backed_up: outcome.backed_up,
        target: target.to_path_buf(),
        db_path: db_path.to_path_buf(),
    })
}

/// Pure orchestration for the Hermes-router-plugin flow.
/// Re-ingests the catalog, composes, builds the
/// `RouterPluginInputs`, and materializes the plugin tree
/// under `<hermes_home>/plugins/<plugin_id>/`. The
/// resulting `RouterPluginLayout` is returned so tests
/// can assert on the on-disk paths.
pub async fn install_at(
    system_file: &Path,
    catalog_path: &Path,
    plugin_id: &str,
    hermes_home: &Path,
) -> Result<InstallSummary> {
    if !system_file.is_file() {
        anyhow::bail!("not a file: {}", system_file.display());
    }
    if !catalog_path.is_dir() {
        anyhow::bail!("not a directory: {}", catalog_path.display());
    }
    let text = std::fs::read_to_string(system_file)
        .with_context(|| format!("read {}", system_file.display()))?;
    let file = parse_system_file(&text)
        .map_err(|e| anyhow::anyhow!("parse {} (expected a `system.yaml`): {e}", system_file.display()))?;

    let source = Source::new(SourceKind::local(catalog_path.to_path_buf()));
    let (result, _report) = IngestService::new().ingest_local(&source).map_err(|e| {
        anyhow::anyhow!("ingest {}: {e}", catalog_path.display())
    })?;

    let placeholder_source_id = uuid::Uuid::new_v4();
    let composed = CompositionService::new()
        .compose(
            placeholder_source_id,
            result.snapshot.id,
            &result.agents,
            &[],
            &file,
        )
        .map_err(|e| anyhow::anyhow!("compose: {e}"))?;

    let inputs = build_router_plugin_inputs(plugin_id, &composed, &result.snapshot.commit_sha);
    let adapter = HermesAdapter::new(hermes_home.to_path_buf());
    let layout = adapter
        .deploy(&inputs)
        .map_err(|e| anyhow::anyhow!("hermes deploy: {e}"))?;

    Ok(InstallSummary {
        system_id: composed.metadata.id.clone(),
        plugin_id: plugin_id.to_string(),
        plugin_dir: layout.plugin_dir,
        manifest_sha256: layout.manifest_sha256,
        skills_sha256: layout.skills_sha256,
        skill_count: layout.skill_paths.len(),
        hermes_home: hermes_home.to_path_buf(),
    })
}

/// Convert a composed `System` into the value object the
/// Hermes adapter consumes. The catalog source URL is a
/// stable hint (the CLI infers it from the catalog path);
/// MVP-1.0 does not yet round-trip a real Git URL.
pub fn build_router_plugin_inputs(
    plugin_id: &str,
    composed: &agent_dep_core::domain::system::System,
    catalog_commit_sha: &str,
) -> RouterPluginInputs {
    let agent_files: Vec<AgentFile> = composed
        .resolved
        .iter()
        .map(|r| AgentFile {
            slug: r.agent.id.clone(),
            body: r.agent.body.clone(),
        })
        .collect();
    RouterPluginInputs {
        plugin_id: plugin_id.to_string(),
        display_name: format!(
            "{} router",
            composed.metadata.name
        ),
        description: composed
            .metadata
            .description
            .clone()
            .unwrap_or_else(|| {
                format!(
                    "Routes the agency-agents catalog for system `{}`.",
                    composed.metadata.id
                )
            }),
        catalog_source: format!(
            "local:{}",
            composed.source_id
        ),
        catalog_commit_sha: catalog_commit_sha.to_string(),
        router_skills: ROUTER_TOOLS.iter().map(|s| s.to_string()).collect(),
        agent_files,
    }
}

fn default_hermes_home_safe() -> PathBuf {
    default_hermes_home().unwrap_or_else(|| PathBuf::from("."))
}

async fn open_and_migrate(db_path: &Path) -> Result<Db> {
    let db = connect(db_path)
        .await
        .with_context(|| format!("connect {}", db_path.display()))?;
    db.migrate()
        .await
        .with_context(|| format!("migrate {}", db_path.display()))?;
    Ok(db)
}

fn print_summary(s: &DeploySummary) {
    let i = agent_dep_core::i18n::I18n::from_env();
    output::header(&i.tr("cli.deploy.apply.header", &[("id", &s.system_id)]));
    output::kv(&i.t("cli.deploy.kv.operation_id"), &s.operation_id.to_string());
    output::kv(&i.t("cli.deploy.kv.target"), &s.target.display().to_string());
    output::kv(&i.t("cli.deploy.kv.wrote"), &s.wrote.to_string());
    output::kv(&i.t("cli.deploy.kv.skipped"), &s.skipped.to_string());
    output::kv(&i.t("cli.deploy.kv.backed_up"), &s.backed_up.to_string());
    output::kv(
        &i.t("cli.deploy.kv.journaled_to"),
        &s.db_path.display().to_string(),
    );
}

fn print_install_summary(s: &InstallSummary) {
    let i = agent_dep_core::i18n::I18n::from_env();
    output::header(&i.tr("cli.deploy.install.header", &[("id", &s.system_id)]));
    output::kv(&i.t("cli.deploy.kv.plugin_id"), &s.plugin_id);
    output::kv(&i.t("cli.deploy.kv.plugin_dir"), &s.plugin_dir.display().to_string());
    output::kv(
        &i.t("cli.deploy.kv.hermes_home"),
        &s.hermes_home.display().to_string(),
    );
    output::kv(&i.t("cli.deploy.kv.skill_count"), &s.skill_count.to_string());
    output::kv(
        &i.t("cli.deploy.kv.manifest_sha256"),
        &s.manifest_sha256,
    );
    output::kv(&i.t("cli.deploy.kv.skills_sha256"), &s.skills_sha256);
}
