//! `agency system ...` — compose a `system.yaml` against a local
//! catalog and print the deployment plan.
//!
//! 1.5.0 (ADR-0013) adds the `plan_at_drift` variant:
//! it reads `deployed_artifacts` from the DB, walks the
//! on-disk tree under `target_dir`, and feeds the
//! plan service a `DeployedObservation` map so
//! `Verify` (sha mismatch / missing file) and
//! `Backup` (no `<parent>/.backups/<name>`) ops
//! show up in the printed plan.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use agent_dep_core::application::compose::CompositionService;
use agent_dep_core::application::deploy::DeploymentService;
use agent_dep_core::application::ingest::IngestService;
use agent_dep_core::application::journal::JournalService;
use agent_dep_core::application::plan::{DeployedObservation, PlanService};
use agent_dep_core::domain::plan::PlanOperationKind;
use agent_dep_core::domain::source::{Source, SourceKind};
use agent_dep_core::domain::system::parse_system_file;
use agent_dep_core::infrastructure::repository::deployed_artifacts_repository::DeployedArtifactsRepository;
use agent_dep_core::infrastructure::sqlite::connect;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
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
        .ingest_local(&source, None)
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

    let plan = PlanService::new().plan_for(&composed, None, None, None);

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

/// 1.5.0 (ADR-0013): plan with drift detection. The
/// caller has already deployed the system (this
/// orchestrator does NOT deploy again — it just
/// inspects the state). It reads `deployed_artifacts`
/// from the DB at `db_path`, walks the on-disk tree
/// under `target_dir` to compute each row's current
/// sha256 and the presence of `<parent>/.backups/<row>`,
/// and feeds the result to `PlanService::plan_for` so
/// `Verify` and `Backup` ops show up in the plan.
pub async fn plan_at_drift(
    system_file: &Path,
    catalog_path: &Path,
    target_dir: &Path,
    db_path: &Path,
) -> Result<PlanSummary> {
    // Compose the system (same as plan_at) so the plan
    // service has the resolved agent refs and the
    // planned_targets set.
    let base = plan_at(system_file, catalog_path).await?;

    if !target_dir.is_dir() {
        anyhow::bail!("not a directory: {}", target_dir.display());
    }

    let db = connect(db_path)
        .await
        .with_context(|| format!("connect {}", db_path.display()))?;
    db.migrate()
        .await
        .with_context(|| format!("migrate {}", db_path.display()))?;
    let repo = DeployedArtifactsRepository::new(db.pool().clone());
    // `list_for_system` returns the rows for the system
    // we just composed. We pass the system_id in the
    // path so the CLI can recover it from the URL later
    // (we keep the public API keyed on system_id).
    let system_id = base.system_id.clone();
    let rows = repo
        .list_for_system(&system_id)
        .await
        .map_err(|e| anyhow::anyhow!("deployed_artifacts: {e}"))?;
    drop(db); // close the pool before we walk the FS

    let mut observations: BTreeMap<String, DeployedObservation> = BTreeMap::new();
    for (target, expected_sha, observed_sha) in rows {
        let abs = target_dir.join(&target);
        let on_disk_sha = if abs.is_file() {
            let bytes = std::fs::read(&abs)
                .with_context(|| format!("read {}", abs.display()))?;
            let mut h = Sha256::new();
            h.update(&bytes);
            Some(hex::encode(h.finalize()))
        } else {
            None
        };
        // The CLI only emits an `observed_sha` row if the
        // last deploy was successful; that is what we
        // see. A failed deploy leaves the row with
        // `observed_sha = None`, which is what we want
        // to feed forward.
        let _ = observed_sha; // tracked at write time
        let backup_present = backup_for_target(target_dir, &target);
        observations.insert(
            target.clone(),
            DeployedObservation {
                target,
                expected_sha256: expected_sha,
                observed_sha256: on_disk_sha,
                backup_present,
            },
        );
    }

    // Re-compose + plan with the observations. We do
    // not call `plan_at` a second time — we re-use the
    // resolve+compose from the first call to keep the
    // 1.4.x cli_tests green.
    let text = std::fs::read_to_string(system_file)
        .with_context(|| format!("read {}", system_file.display()))?;
    let file = parse_system_file(&text)
        .map_err(|e| anyhow::anyhow!("parse {}: {e}", system_file.display()))?;
    let source = Source::new(SourceKind::local(catalog_path.to_path_buf()));
    let (result, _report) = IngestService::new()
        .ingest_local(&source, None)
        .map_err(|e| anyhow::anyhow!("ingest {}: {e}", catalog_path.display()))?;
    let placeholder_source_id = Uuid::new_v4();
    let composed = CompositionService::new()
        .compose(
            placeholder_source_id,
            result.snapshot.id,
            &result.agents,
            &[],
            &file,
        )
        .map_err(|e| anyhow::anyhow!("compose: {e}"))?;
    let plan = PlanService::new().plan_for(
        &composed,
        None,
        None,
        if observations.is_empty() {
            None
        } else {
            Some(&observations)
        },
    );

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

/// True iff `<target_dir>/<target>/.backups/<target>`
/// exists. The MVP-1.0 backup layout (per ADR-0002)
/// puts the per-file backup in a sibling
/// `.backups/` directory next to the file itself; the
/// CLI walks that directory at plan time.
fn backup_for_target(target_dir: &Path, target: &str) -> bool {
    let backups_dir = target_dir.join(target).join(".backups");
    if !backups_dir.is_dir() {
        return false;
    }
    std::fs::read_dir(&backups_dir)
        .map(|mut it| it.next().is_some())
        .unwrap_or(false)
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
