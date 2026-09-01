//! `agency rollback <operation-id>` — undo a deploy.
//!
//! MVP-1.0 scope: a `rollback` operates on a single
//! `operation_id` from the journal. The previous
//! deployment's `effect_json` (per
//! `agent_dep_core::application::deploy::DeployEffect`)
//! holds the per-file target paths and the sha256 of the
//! body that the deploy wrote. For each write:
//!
//! 1. If the on-disk file is already at `expected_sha256`
//!    (i.e. nothing has been modified since the deploy),
//!    the entry is a no-op.
//! 2. Otherwise, look for a backup under
//!    `<parent>/.backups/`. The most recent backup whose
//!    name starts with `<file_name>.` is copied back to
//!    the target, atomically (temp+rename).
//! 3. If no backup exists for a write that was modified
//!    after the deploy, the entry is reported as failed
//!    and the operation is left in `committed` state so
//!    the user can intervene.
//!
//! The journal row is flipped to `rolled_back` at the end
//! of a successful (or fully no-op) rollback. `deployed_artifacts`
//! rows are NOT deleted: the next `agency deploy apply` will
//! upsert them with the new state, so a stale `current`
//! row is at worst a single extra row until then.

use std::path::{Path, PathBuf};

use agent_dep_core::application::deploy::{DeployEffect, DeployWrite};
use agent_dep_core::application::journal::JournalService;
use agent_dep_core::infrastructure::sqlite::connect;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::output;

#[derive(Debug, Clone)]
pub struct RollbackSummary {
    pub operation_id: Uuid,
    pub target_root: PathBuf,
    pub files_to_revert: usize,
    pub restored: usize,
    pub kept_current: usize,
    pub failed: Vec<FailedRevert>,
}

#[derive(Debug, Clone)]
pub struct FailedRevert {
    pub relative: String,
    pub reason: String,
}

/// CLI entry point. The DB is opened at the default path.
pub async fn rollback(operation_id: Uuid) -> Result<()> {
    let db_path = crate::data_dir::default_db_path();
    let summary = rollback_at(operation_id, &db_path).await?;
    print_summary(&summary);
    Ok(())
}

/// Pure orchestration: open the journal, fetch the
/// operation, parse its `effect_json` as a `DeployEffect`,
/// restore each file from `.backups/`, then flip the
/// journal row to `rolled_back`.
pub async fn rollback_at(
    operation_id: Uuid,
    db_path: &Path,
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

    let mut summary = RollbackSummary {
        operation_id,
        target_root: effect.target.clone(),
        files_to_revert: effect.writes.len(),
        restored: 0,
        kept_current: 0,
        failed: Vec::new(),
    };

    for w in &effect.writes {
        let target_path = effect.target.join(&w.relative);
        match restore_one(&target_path, w) {
            Ok(RestoreOutcome::KeptCurrent) => summary.kept_current += 1,
            Ok(RestoreOutcome::Restored) => summary.restored += 1,
            Err(e) => summary.failed.push(FailedRevert {
                relative: w.relative.clone(),
                reason: format!("{e}"),
            }),
        }
    }

    // Only flip the journal row if every entry succeeded
    // (either restored or was already current). If any
    // entry failed, leave the operation in `committed` so
    // the user can retry or intervene manually.
    if summary.failed.is_empty() {
        journal
            .rollback(operation_id)
            .await
            .with_context(|| format!("journal.rollback({operation_id})"))?;
    }

    Ok(summary)
}

enum RestoreOutcome {
    Restored,
    KeptCurrent,
}

fn restore_one(target_path: &Path, write: &DeployWrite) -> Result<RestoreOutcome> {
    // If the file is present and matches expected_sha256,
    // nothing to undo.
    if target_path.is_file() {
        let bytes = std::fs::read(target_path)
            .with_context(|| format!("read {}", target_path.display()))?;
        if sha256_hex(&bytes) == write.expected_sha256 {
            return Ok(RestoreOutcome::KeptCurrent);
        }
    }

    // Otherwise, look for a backup. Backup file names start
    // with the original file's name (e.g. `be.md.<ts>.<rand>`).
    let file_name = target_path
        .file_name()
        .ok_or_else(|| {
            anyhow::anyhow!("target has no file name: {}", target_path.display())
        })?
        .to_string_lossy()
        .to_string();
    let parent = target_path.parent().ok_or_else(|| {
        anyhow::anyhow!("target has no parent: {}", target_path.display())
    })?;
    let backups_dir = parent.join(".backups");
    if !backups_dir.is_dir() {
        anyhow::bail!(
            "no .backups/ for {} (was the file modified after deploy without a prior apply?)",
            target_path.display()
        );
    }

    let prefix = format!("{file_name}.");
    let mut candidates: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(&backups_dir)
        .with_context(|| format!("read_dir {}", backups_dir.display()))?
    {
        let entry = entry.with_context(|| {
            format!("read_dir entry in {}", backups_dir.display())
        })?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(&prefix) {
            continue;
        }
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        candidates.push((mtime, entry.path()));
    }
    if candidates.is_empty() {
        anyhow::bail!(
            "no backup starting with `{}` under {}",
            prefix,
            backups_dir.display()
        );
    }
    // Newest first.
    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    let backup = &candidates[0].1;
    let bytes = std::fs::read(backup)
        .with_context(|| format!("read backup {}", backup.display()))?;
    // Make sure the parent of the target exists (it should,
    // but a stray delete could have removed it).
    if !parent.is_dir() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create_dir_all {}", parent.display()))?;
    }
    // Atomic write to the target via temp+rename so a crash
    // mid-rollback does not leave a half-restored file.
    let tmp = parent.join(format!(".{file_name}.rollback-tmp.{}", Uuid::new_v4()));
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("create temp {}", tmp.display()))?;
        f.write_all(&bytes)
            .with_context(|| format!("write temp {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("sync temp {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, target_path).with_context(|| {
        format!(
            "rename {} -> {}",
            tmp.display(),
            target_path.display()
        )
    })?;
    Ok(RestoreOutcome::Restored)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
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
    output::kv(
        &i.t("cli.rollback.kv.restored"),
        &s.restored.to_string(),
    );
    output::kv(
        &i.t("cli.rollback.kv.kept_current"),
        &s.kept_current.to_string(),
    );
    if !s.failed.is_empty() {
        output::kv(
            &i.t("cli.rollback.kv.failed"),
            &s.failed.len().to_string(),
        );
        for f in &s.failed {
            eprintln!("  - {}: {}", f.relative, f.reason);
        }
    }
}
