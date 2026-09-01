//! `agency rollback <operation-id>` — undo a deploy.
//!
//! MVP-1.0 scope: a `rollback` operates on a single
//! `operation_id` from the journal. The previous
//! deployment's `effect_json` (per
//! `agent_dep_core::application::deploy::DeployEffect`)
//! holds the per-file target paths; the rollback writes
//! the pre-deploy body back to each path from a content
//! store snapshot. The store path lands in Phase 5
//! (CAS integration); for now rollback is wired end-to-
//! end against the journal and the in-process `DeployEffect`
//! data, with a TODO marker for the actual file revert.

use std::path::PathBuf;

use agent_dep_core::application::deploy::DeployEffect;
use agent_dep_core::application::journal::JournalService;
use agent_dep_core::infrastructure::sqlite::connect;
use anyhow::{Context, Result};
use uuid::Uuid;

use crate::output;

#[derive(Debug, Clone)]
pub struct RollbackSummary {
    pub operation_id: Uuid,
    pub target_root: PathBuf,
    pub files_to_revert: usize,
}

/// CLI entry point. The DB is opened at the default path.
pub async fn rollback(operation_id: Uuid) -> Result<()> {
    let db_path = crate::data_dir::default_db_path();
    let summary = rollback_at(operation_id, &db_path).await?;
    print_summary(&summary);
    Ok(())
}

/// Pure orchestration: open the journal, fetch the
/// operation, parse its `effect_json` as a
/// `DeployEffect`, and (Phase 5) write the previous
/// bytes back. The actual restore is a follow-up — for
/// now we return the summary so the CLI can print it
/// and tests can assert the journal round-trip.
pub async fn rollback_at(
    operation_id: Uuid,
    db_path: &std::path::Path,
) -> Result<RollbackSummary> {
    let db = connect(db_path)
        .await
        .with_context(|| format!("connect {}", db_path.display()))?;
    db.migrate()
        .await
        .with_context(|| format!("migrate {}", db_path.display()))?;
    let journal = JournalService::new(db.pool().clone());

    let op = journal
        .get(operation_id)
        .await
        .with_context(|| format!("journal.get({operation_id})"))?
        .ok_or_else(|| anyhow::anyhow!("operation not found: {operation_id}"))?;

    let effect: DeployEffect = serde_json::from_value(op.effect.clone())
        .with_context(|| "operation.effect is not a DeployEffect")?;

    Ok(RollbackSummary {
        operation_id,
        target_root: effect.target,
        files_to_revert: effect.writes.len(),
    })
}

fn print_summary(s: &RollbackSummary) {
    let i = agent_dep_core::i18n::I18n::from_env();
    output::header(&i.tr("cli.rollback.header", &[("id", &s.operation_id.to_string())]));
    output::kv(
        &i.t("cli.rollback.kv.target_root"),
        &s.target_root.display().to_string(),
    );
    output::kv(
        &i.t("cli.rollback.kv.files_to_revert"),
        &s.files_to_revert.to_string(),
    );
    println!("{}", i.t("cli.rollback.todo_cas"));
}
