//! Deployment service (TZ §16, ADR-0002, ADR-0006).
//!
//! Closes the MVP-3 read→plan→write loop. Given a `System` (already
//! composed against an ingested snapshot) and a target directory,
//! write each resolved agent's body to
//! `<target>/agents/<id>@<version>/<id>.md` using the file-level
//! atomic temp+rename rules from ADR-0002. The whole operation is
//! journaled via `JournalService` so a crash mid-flight leaves a
//! non-terminal row that `gc_stale` will force-fail on next startup.
//!
//! MVP-3 does not yet call out to Hermes (`hermes mcp add` per
//! ADR-0001); it only materializes the agent files in a target
//! directory. 1.x adds the actual Hermes wiring.

use crate::application::journal::{JournalService, OperationType};
use crate::domain::system::System;
use crate::error::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Plan + per-file target for one operation, snapshotted at
/// `prepare` time so recovery can finish or roll back without
/// re-reading external state (per ADR-0006).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployEffect {
    pub target: PathBuf,
    pub writes: Vec<DeployWrite>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployWrite {
    pub agent_ref: String, // e.g. "be@1.0.0"
    pub relative: String,  // POSIX, relative to target root
    pub expected_sha256: String,
    pub body_sha256: String, // hash of the body bytes
}

#[derive(Debug, Clone)]
pub struct DeployOutcome {
    pub operation_id: Uuid,
    pub wrote: usize,
    pub skipped: usize,
    pub backed_up: usize,
    pub failed: Vec<FailedWrite>,
}

#[derive(Debug, Clone)]
pub struct FailedWrite {
    pub agent_ref: String,
    pub reason: String,
}

pub struct DeploymentService;

impl Default for DeploymentService {
    fn default() -> Self {
        Self::new()
    }
}

impl DeploymentService {
    pub fn new() -> Self {
        Self
    }

    /// Apply a `System` to `target`, journaled end-to-end. The
    /// returned `DeployOutcome` reports counts of writes, skips,
    /// and backups so the CLI can print a useful summary.
    pub async fn apply(
        &self,
        target: &Path,
        system: &System,
        journal: &JournalService,
    ) -> CoreResult<DeployOutcome> {
        if !target.exists() {
            std::fs::create_dir_all(target).map_err(|e| CoreError::ErrIo(e))?;
        }
        if !target.is_dir() {
            return Err(CoreError::ErrPathOutsideRoot {
                path: target.display().to_string(),
                root: String::new(),
            });
        }

        // 1. Build the per-file effect.
        let writes: Vec<DeployWrite> = system
            .resolved
            .iter()
            .map(|r| {
                let rel = format!("agents/{}/{}.md", r.from_ref, r.agent.id);
                let body_sha = sha256_hex(r.agent.body.as_bytes());
                DeployWrite {
                    agent_ref: r.from_ref.to_string(),
                    relative: rel,
                    expected_sha256: body_sha.clone(),
                    body_sha256: body_sha,
                }
            })
            .collect();
        let effect = DeployEffect {
            target: target.to_path_buf(),
            writes: writes.clone(),
        };
        let effect_json = serde_json::to_value(&effect).map_err(|e| CoreError::ErrSchemaInvalid {
            path: "operations.effect_json".to_string(),
            reason: format!("effect is not serializable: {e}"),
        })?;

        // 2. Plan hash: sha256 of the system metadata.id + resolved ids
        //    (stable across runs that target the same system).
        let plan_hash = compute_plan_hash(system);

        // 3. Prepare + begin_writing.
        let op = journal
            .prepare(OperationType::Deploy, &plan_hash, effect_json)
            .await?;
        let op_id = op.id;
        journal.begin_writing(op_id).await?;

        // 4. Write each file. We do NOT roll back partial writes on
        //    failure — the journal row is left in `Writing` so the
        //    next startup's `gc_stale` can force-fail it, and the
        //    user can inspect the half-done target manually.
        let mut wrote = 0usize;
        let mut skipped = 0usize;
        let mut backed_up = 0usize;
        let mut failed: Vec<FailedWrite> = Vec::new();
        for w in &writes {
            // Find the agent body by ref.
            let resolved = system
                .resolved
                .iter()
                .find(|r| r.from_ref.to_string() == w.agent_ref);
            let Some(ra) = resolved else {
                failed.push(FailedWrite {
                    agent_ref: w.agent_ref.clone(),
                    reason: "agent not in system.resolved".to_string(),
                });
                continue;
            };
            let target_path = target.join(&w.relative);
            match write_one(&target_path, ra.agent.body.as_bytes(), &w.body_sha256) {
                Ok(WriteOutcome::Wrote) => wrote += 1,
                Ok(WriteOutcome::Skipped) => skipped += 1,
                Ok(WriteOutcome::BackedUp) => {
                    backed_up += 1;
                    wrote += 1;
                }
                Err(e) => failed.push(FailedWrite {
                    agent_ref: w.agent_ref.clone(),
                    reason: format!("{e}"),
                }),
            }
        }

        // 5. Begin committing + verify all writes are in place.
        journal.begin_committing(op_id).await?;
        for w in &writes {
            let target_path = target.join(&w.relative);
            if !target_path.exists() {
                journal
                    .fail(op_id, &format!("verification: {} missing", w.relative))
                    .await?;
                return Err(CoreError::ErrVerificationFailed {
                    target: w.relative.clone(),
                    reason: "expected file missing after write".to_string(),
                });
            }
        }
        journal.complete(op_id).await?;

        Ok(DeployOutcome {
            operation_id: op_id,
            wrote,
            skipped,
            backed_up,
            failed,
        })
    }
}

enum WriteOutcome {
    Wrote,
    Skipped,
    BackedUp,
}

/// Write `content` to `target_path` atomically (temp file in the
/// same directory, then rename). If the target already exists with
/// different content, copy the old content to `<target>/.backups/`
/// first. If the target exists with the same content, no-op.
fn write_one(target_path: &Path, content: &[u8], expected_sha: &str) -> CoreResult<WriteOutcome> {
    let parent = target_path.parent().ok_or_else(|| CoreError::ErrPathOutsideRoot {
        path: target_path.display().to_string(),
        root: String::new(),
    })?;
    if !parent.exists() {
        std::fs::create_dir_all(parent).map_err(CoreError::ErrIo)?;
    }

    if target_path.exists() {
        let existing = std::fs::read(target_path).map_err(CoreError::ErrIo)?;
        let existing_sha = sha256_hex(&existing);
        if existing_sha == expected_sha {
            return Ok(WriteOutcome::Skipped);
        }
        // Backup the old file under .backups/<name>.<unix_ts>.<rand>.
        let backup_path = make_backup_path(target_path)?;
        std::fs::copy(target_path, &backup_path).map_err(CoreError::ErrIo)?;
        // Fall through to overwrite.
    }

    // Atomic write: temp file in the same directory, then rename.
    let tmp = parent.join(format!(
        ".{}.tmp.{}",
        target_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("write"),
        Uuid::new_v4()
    ));
    {
        let mut f = std::fs::File::create(&tmp).map_err(CoreError::ErrIo)?;
        use std::io::Write;
        f.write_all(content).map_err(CoreError::ErrIo)?;
        f.sync_all().map_err(CoreError::ErrIo)?;
    }
    std::fs::rename(&tmp, target_path).map_err(CoreError::ErrIo)?;
    Ok(if target_path
        .parent()
        .map(|p| p.join(".backups").exists())
        .unwrap_or(false)
    {
        WriteOutcome::BackedUp
    } else {
        WriteOutcome::Wrote
    })
}

fn make_backup_path(target_path: &Path) -> CoreResult<PathBuf> {
    let parent = target_path.parent().ok_or_else(|| CoreError::ErrPathOutsideRoot {
        path: target_path.display().to_string(),
        root: String::new(),
    })?;
    let backups_dir = parent.join(".backups");
    std::fs::create_dir_all(&backups_dir).map_err(CoreError::ErrIo)?;
    let stem = target_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let suffix: String = Uuid::new_v4().to_string().chars().take(8).collect();
    Ok(backups_dir.join(format!("{stem}.{ts}.{suffix}")))
}

fn compute_plan_hash(system: &System) -> String {
    let mut hasher = Sha256::new();
    hasher.update(system.metadata.id.as_bytes());
    hasher.update(b"\n");
    let mut refs: Vec<String> = system
        .resolved
        .iter()
        .map(|r| r.from_ref.to_string())
        .collect();
    refs.sort();
    for r in refs {
        hasher.update(r.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[cfg(test)]
#[path = "deploy_tests.rs"]
mod tests;
