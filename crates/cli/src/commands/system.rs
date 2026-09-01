//! `agency system ...` — compose a `system.yaml` against a local
//! catalog and print the deployment plan.

use std::path::{Path, PathBuf};

use agent_dep_core::application::compose::CompositionService;
use agent_dep_core::application::ingest::IngestService;
use agent_dep_core::application::plan::PlanService;
use agent_dep_core::domain::plan::PlanOperationKind;
use agent_dep_core::domain::source::{Source, SourceKind};
use agent_dep_core::domain::system::parse_system_file;
use anyhow::{Context, Result};
use uuid::Uuid;

use crate::output;

/// Summary returned from `plan_at` so tests can assert without
/// re-parsing stdout.
#[derive(Debug, Clone)]
pub struct PlanSummary {
    pub system_id: String,
    pub risk: String,
    pub operations: Vec<PlanOpSummary>,
    pub catalog_path: PathBuf,
    pub system_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct PlanOpSummary {
    pub kind: String,
    pub target: String,
    pub reason: String,
}

/// CLI entry point: re-ingests the catalog in-memory, composes the
/// system, computes the plan, and prints a human-readable summary.
pub async fn plan(system_file: &Path, catalog_path: &Path) -> Result<()> {
    let summary = plan_at(system_file, catalog_path).await?;
    print_summary(&summary);
    Ok(())
}

/// Pure orchestration: read the system file, re-ingest the
/// catalog, compose, plan, return a typed summary. No DB writes.
pub async fn plan_at(system_file: &Path, catalog_path: &Path) -> Result<PlanSummary> {
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
    let (result, _report) = IngestService::new()
        .ingest_local(&source)
        .map_err(|e| anyhow::anyhow!("ingest {}: {e}", catalog_path.display()))?;

    // For MVP-3 we always work against the just-ingested snapshot
    // (1 UUID for both source and snapshot is a deliberate MVP
    // simplification; a later "use latest committed snapshot"
    // would pull from the DB).
    let placeholder_source_id = Uuid::new_v4();
    let placeholder_snapshot_id = result.snapshot.id;
    let composed = CompositionService::new()
        .compose(
            placeholder_source_id,
            placeholder_snapshot_id,
            &result.agents,
            &[],
            &file,
        )
        .map_err(|e| anyhow::anyhow!("compose: {e}"))?;

    let plan = PlanService::new().plan_for(&composed);

    Ok(PlanSummary {
        system_id: plan.system_id.clone(),
        risk: plan.risk.as_str().to_string(),
        operations: plan
            .operations
            .iter()
            .map(|o| PlanOpSummary {
                kind: o.kind.as_str().to_string(),
                target: o.target.clone(),
                reason: o.reason.clone(),
            })
            .collect(),
        catalog_path: catalog_path.to_path_buf(),
        system_file: system_file.to_path_buf(),
    })
}

fn print_summary(s: &PlanSummary) {
    output::header(&format!("Plan for system: {}", s.system_id));
    output::kv("system_file", &s.system_file.display().to_string());
    output::kv("catalog", &s.catalog_path.display().to_string());
    output::kv("risk", &s.risk);
    output::kv("operations", &s.operations.len().to_string());

    for op in &s.operations {
        let kind_lower = op.kind.to_ascii_lowercase();
        let kind_marker = match op.kind.as_str() {
            x if x == PlanOperationKind::Add.as_str() => "[ADD]",
            x if x == PlanOperationKind::Update.as_str() => "[UPDATE]",
            x if x == PlanOperationKind::Delete.as_str() => "[DELETE]",
            x if x == PlanOperationKind::Noop.as_str() => "[NOOP]",
            x if x == PlanOperationKind::Backup.as_str() => "[BACKUP]",
            x if x == PlanOperationKind::Verify.as_str() => "[VERIFY]",
            _ => "[?]",
        };
        println!("  {kind_marker} {} — {}", op.target, op.reason);
        let _ = kind_lower;
    }
}
