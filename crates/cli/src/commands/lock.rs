//! `agency lock ...` — generate / inspect `agency.lock`.
//!
//! MVP-1.0: only `generate` ships. It re-ingests the
//! catalog, composes the system, and writes a
//! deterministic `agency.lock` next to the system file.
//! 1.2.0 (ADR-0010) adds `--range <expr>` which rewrites
//! the resolved agent versions into SemVer ranges
//! (caret, tilde, compound) before writing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use agent_dep_core::application::compose::CompositionService;
use agent_dep_core::application::ingest::IngestService;
use agent_dep_core::domain::lock::LockFile;
use agent_dep_core::domain::source::{Source, SourceKind};
use agent_dep_core::domain::system::parse_system_file;
use agent_dep_core::domain::version::Version;
use anyhow::{Context, Result};
use semver::VersionReq;

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
#[allow(dead_code)] // retained for future 1.x caller; today the CLI uses generate_with_range
pub async fn generate(system_file: &Path, catalog_path: &Path) -> Result<()> {
    let summary = generate_at(system_file, catalog_path).await?;
    print_summary(&summary);
    Ok(())
}

/// CLI entry point with optional SemVer range expression
/// (1.2.0+, ADR-0010). When `range` is `Some`, every
/// agent's resolved version is rewritten as
/// `range_template(current_version)` — e.g. `^1.0.0` on
/// `1.0.5` becomes `^1.0.5`. The template supports the
/// placeholders `{major}`, `{minor}`, `{patch}` so
/// `--range '^1.{minor}.0'` is also valid.
pub async fn generate_with_range(
    system_file: &Path,
    catalog_path: &Path,
    range: Option<&str>,
) -> Result<LockSummary> {
    let summary = generate_at_with_range(system_file, catalog_path, range).await?;
    print_summary(&summary);
    Ok(summary)
}

/// Pure orchestration: read the system file, re-ingest
/// the catalog, compose, build the `LockFile`, and
/// write it next to the system file as `agency.lock`.
#[allow(dead_code)] // retained for future 1.x caller; today the CLI uses generate_at_with_range
pub async fn generate_at(system_file: &Path, catalog_path: &Path) -> Result<LockSummary> {
    generate_at_with_range(system_file, catalog_path, None).await
}

/// Range-aware variant (1.2.0+). `range` is the
/// SemVer range template to apply to every resolved
/// agent version.
pub async fn generate_at_with_range(
    system_file: &Path,
    catalog_path: &Path,
    range: Option<&str>,
) -> Result<LockSummary> {
    if !system_file.is_file() {
        anyhow::bail!("not a file: {}", system_file.display());
    }
    if !catalog_path.is_dir() {
        anyhow::bail!("not a directory: {}", catalog_path.display());
    }
    let text = std::fs::read_to_string(system_file)
        .with_context(|| format!("read {}", system_file.display()))?;
    let file = parse_system_file(&text).map_err(|e| {
        anyhow::anyhow!(
            "parse {} (expected a `system.yaml`): {e}",
            system_file.display()
        )
    })?;

    let source = Source::new(SourceKind::local(catalog_path.to_path_buf()));
    let (result, _report) = IngestService::new()
        .ingest_local(&source, None)
        .map_err(|e| anyhow::anyhow!("ingest {}: {e}", catalog_path.display()))?;

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

    let agent_pins: Vec<(String, Version)> = composed
        .resolved
        .iter()
        .map(|r| (r.agent.id.clone(), r.agent.version.clone()))
        .collect();
    let skill_pins: Vec<(String, Version)> = composed
        .resolved_skills
        .iter()
        .map(|s| (s.skill.id.clone(), s.skill.version.clone()))
        .collect();

    // If a range template is given, validate it once and
    // rewrite every agent pin to the rendered range. We
    // store the rendered range as the lockfile value
    // (e.g. `^1.0.5`); the resolver handles the math on
    // the next `agency system plan` call.
    let agent_lock_entries: BTreeMap<String, String> = match range {
        Some(tmpl) => {
            // Sanity-check the template by rendering it for
            // the first resolved agent, if any.
            if let Some((_, v)) = agent_pins.first() {
                let _ = render_range_template(tmpl, v)
                    .map_err(|e| anyhow::anyhow!("invalid range template `{tmpl}`: {e}"))?;
            }
            agent_pins
                .iter()
                .map(|(id, v)| {
                    let rendered = render_range_template(tmpl, v).unwrap_or_else(|_| v.to_string());
                    (id.clone(), rendered)
                })
                .collect()
        }
        None => agent_pins
            .iter()
            .map(|(id, v)| (id.clone(), format!("={v}")))
            .collect(),
    };
    let skill_lock_entries: BTreeMap<String, String> = skill_pins
        .iter()
        .map(|(id, v)| (id.clone(), format!("={v}")))
        .collect();

    // Build the LockFile directly (rather than going
    // through `from_resolved`) so we can mix exact pins
    // and ranges in the same map. The map values are
    // already shaped correctly (each value is a
    // `VersionReq` string).
    let mut lock = LockFile::new_for_test(
        catalog_path.to_string_lossy().as_ref(),
        &result.snapshot.commit_sha,
    );
    for (id, val) in &agent_lock_entries {
        lock.agents.insert(id.clone(), val.clone());
    }
    for (id, val) in &skill_lock_entries {
        lock.skills.insert(id.clone(), val.clone());
    }

    let lock_path = lock_path_for(system_file);
    let yaml = lock
        .to_yaml()
        .map_err(|e| anyhow::anyhow!("serialize lock: {e}"))?;
    std::fs::write(&lock_path, yaml).with_context(|| format!("write {}", lock_path.display()))?;

    Ok(LockSummary {
        system_id: composed.metadata.id.clone(),
        lock_path,
        agent_count: lock.agents.len(),
        skill_count: lock.skills.len(),
        commit_sha: lock.source.commit.clone(),
    })
}

/// Render a SemVer range template like `^1.{minor}.0` or
/// `~{major}.{minor}.{patch}` against a concrete
/// `Version`. Placeholders are `{major}`, `{minor}`,
/// `{patch}`. The output is validated through
/// `VersionReq::parse` so the caller catches typos.
fn render_range_template(tmpl: &str, v: &Version) -> Result<String, String> {
    let rendered = tmpl
        .replace("{major}", &v.major.to_string())
        .replace("{minor}", &v.minor.to_string())
        .replace("{patch}", &v.patch.to_string());
    // Sanity-check that the result is a valid VersionReq.
    VersionReq::parse(&rendered).map_err(|e| format!("{e}"))?;
    Ok(rendered)
}

fn lock_path_for(system_file: &Path) -> PathBuf {
    let parent = system_file.parent().unwrap_or_else(|| Path::new("."));
    parent.join("agency.lock")
}

fn print_summary(s: &LockSummary) {
    let i = agent_dep_core::i18n::I18n::from_env();
    output::header(&i.tr("cli.lock.header", &[("id", &s.system_id)]));
    output::kv(
        &i.t("cli.lock.kv.lock_path"),
        &s.lock_path.display().to_string(),
    );
    output::kv(&i.t("cli.lock.kv.agent_count"), &s.agent_count.to_string());
    output::kv(&i.t("cli.lock.kv.skill_count"), &s.skill_count.to_string());
    output::kv(&i.t("cli.lock.kv.catalog_commit"), &s.commit_sha);
}
