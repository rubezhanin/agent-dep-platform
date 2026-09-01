//! `agency deploy ...` — apply a `system.yaml` to a target
//! directory through the journal-backed `DeploymentService`.

use std::path::{Path, PathBuf};

use agent_dep_core::application::compose::CompositionService;
use agent_dep_core::application::deploy::DeploymentService;
use agent_dep_core::application::ingest::IngestService;
use agent_dep_core::application::journal::JournalService;
use agent_dep_core::domain::source::{Source, SourceKind};
use agent_dep_core::domain::system::SystemFile;
use agent_dep_core::infrastructure::sqlite::{connect, Db};
use anyhow::{Context, Result};
use tokio::fs;

use crate::output;

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

/// CLI entry point.
pub async fn deploy(system_file: &Path, catalog_path: &Path, target: &Path) -> Result<()> {
    let db_path = crate::data_dir::default_db_path();
    let summary = deploy_at(system_file, catalog_path, target, &db_path).await?;
    print_summary(&summary);
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
    let file: SystemFile = serde_yaml::from_str(&text).with_context(|| {
        format!("parse {} (expected a `system.yaml`)", system_file.display())
    })?;

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
    output::header(&format!("Deployed system: {}", s.system_id));
    output::kv("operation_id", &s.operation_id.to_string());
    output::kv("target", &s.target.display().to_string());
    output::kv("wrote", &s.wrote.to_string());
    output::kv("skipped", &s.skipped.to_string());
    output::kv("backed_up", &s.backed_up.to_string());
    output::kv("journaled_to", &s.db_path.display().to_string());
}
