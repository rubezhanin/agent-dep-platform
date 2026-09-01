//! `agency lock ...` — generate / inspect `agency.lock`.
//!
//! MVP-1.0: only `generate` ships. It re-ingests the
//! catalog, composes the system, and writes a
//! deterministic `agency.lock` next to the system file.

use std::path::{Path, PathBuf};

use agent_dep_core::application::compose::CompositionService;
use agent_dep_core::application::ingest::IngestService;
use agent_dep_core::domain::lock::LockFile;
use agent_dep_core::domain::source::{Source, SourceKind};
use agent_dep_core::domain::system::parse_system_file;
use anyhow::{Context, Result};

use crate::output;

/// Summary returned from `generate_at` so tests can assert
/// without re-parsing stdout.
#[derive(Debug, Clone)]
pub struct LockSummary {
    pub system_id: String,
    pub lock_path: PathBuf,
    pub agent_count: usize,
    pub skill_count: usize,
    pub commit_sha: String,
}

/// CLI entry point.
pub async fn generate(system_file: &Path, catalog_path: &Path) -> Result<()> {
    let summary = generate_at(system_file, catalog_path).await?;
    print_summary(&summary);
    Ok(())
}

/// Pure orchestration: read the system file, re-ingest
/// the catalog, compose, build the `LockFile`, and
/// write it next to the system file as `agency.lock`.
pub async fn generate_at(
    system_file: &Path,
    catalog_path: &Path,
) -> Result<LockSummary> {
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

    let agent_pins: Vec<(String, _)> = composed
        .resolved
        .iter()
        .map(|r| (r.agent.id.clone(), r.agent.version.clone()))
        .collect();
    let skill_pins: Vec<(String, _)> = composed
        .resolved_skills
        .iter()
        .map(|s| (s.skill.id.clone(), s.skill.version.clone()))
        .collect();

    // The repository "URL" is opaque in MVP-1.0 because the
    // catalog root is a local path. We carry the resolved
    // path so a future Git source can replace this with a
    // real URL without changing the lock-file shape.
    let repo = catalog_path.to_string_lossy().to_string();
    let lock = LockFile::from_resolved(&repo, &result.snapshot.commit_sha, &agent_pins, &skill_pins);

    let lock_path = lock_path_for(system_file);
    let yaml = lock
        .to_yaml()
        .map_err(|e| anyhow::anyhow!("serialize lock: {e}"))?;
    std::fs::write(&lock_path, yaml)
        .with_context(|| format!("write {}", lock_path.display()))?;

    Ok(LockSummary {
        system_id: composed.metadata.id.clone(),
        lock_path,
        agent_count: lock.agents.len(),
        skill_count: lock.skills.len(),
        commit_sha: lock.source.commit.clone(),
    })
}

fn lock_path_for(system_file: &Path) -> PathBuf {
    let parent = system_file
        .parent()
        .unwrap_or_else(|| Path::new("."));
    parent.join("agency.lock")
}

fn print_summary(s: &LockSummary) {
    output::header(&format!("Lock file for system: {}", s.system_id));
    output::kv("lock_path", &s.lock_path.display().to_string());
    output::kv("agent_count", &s.agent_count.to_string());
    output::kv("skill_count", &s.skill_count.to_string());
    output::kv("catalog_commit", &s.commit_sha);
}
