//! `agency catalog ...` — ingest/inspect local or (1.x) git catalogs.

use std::path::{Path, PathBuf};

use agent_dep_core::application::ingest::IngestService;
use agent_dep_core::domain::source::{Source, SourceKind};
use agent_dep_core::infrastructure::repository::IngestRepository;
use agent_dep_core::infrastructure::sqlite::{connect, Db};
use anyhow::{Context, Result};
use tokio::fs;
use uuid::Uuid;

use crate::output;

/// Summary returned from `update_at` so tests can assert without
/// re-parsing stdout.
#[derive(Debug, Clone)]
pub struct UpdateSummary {
    pub snapshot_id: Uuid,
    pub commit_sha: String,
    pub agent_count: usize,
    pub division_count: usize,
    pub files_scanned: u32,
    pub total_bytes: u64,
    pub rejected: usize,
    pub findings_block: u32,
    pub findings_warn: u32,
    pub findings_pass: u32,
    pub snapshot_status: String,
    pub top_findings: Vec<TopFinding>,
    pub db_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct TopFinding {
    pub severity: String,
    pub rule: String,
    pub path: String,
    pub reason: String,
}

/// CLI entry point: resolves the default data dir, persists to the
/// default SQLite location, and prints a human-readable summary.
pub async fn update(path: PathBuf) -> Result<()> {
    let db_path = crate::data_dir::default_db_path();
    let summary = update_at(&path, &db_path).await?;
    print_summary(&path, &summary);
    Ok(())
}

/// Ingest a local catalog and persist the resulting snapshot to the
/// SQLite DB at `db_path`. Pure orchestration: parse+validate+scan
/// via `IngestService`, then write via `IngestRepository`. The DB is
/// opened, created if missing, and migrated on first use.
pub async fn update_at(path: &Path, db_path: &Path) -> Result<UpdateSummary> {
    if !path.is_dir() {
        anyhow::bail!("not a directory: {}", path.display());
    }
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create_dir_all {}", parent.display()))?;
    }

    let db = open_and_migrate(db_path).await?;
    let repo = IngestRepository::new(db.pool().clone());

    let source = Source::new(SourceKind::local(path.to_path_buf()));
    let svc = IngestService::new();
    let (result, report) = svc
        .ingest_local(&source)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Upsert source (no-op if same (kind, location) already exists)
    // and record the snapshot in a single transaction.
    let source_id = repo
        .upsert_source(&source, false)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    repo.record_snapshot(source_id, &result, &report)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Keep the DB connection alive for the duration of the call so
    // any background task is shut down before we return.
    drop(db);

    Ok(UpdateSummary {
        snapshot_id: result.snapshot.id,
        commit_sha: result.snapshot.commit_sha,
        agent_count: result.agents.len(),
        division_count: result.divisions.len(),
        files_scanned: report.files_scanned,
        total_bytes: report.total_bytes,
        rejected: report.agents_rejected.len(),
        findings_block: report.findings_block,
        findings_warn: report.findings_warn,
        findings_pass: report.findings_pass,
        snapshot_status: format!("{:?}", result.snapshot.status),
        top_findings: result
            .findings
            .iter()
            .take(5)
            .map(|f| TopFinding {
                severity: f.severity.as_str().to_string(),
                rule: f.rule.clone(),
                path: f.path.clone(),
                reason: f.reason.clone(),
            })
            .collect(),
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

fn print_summary(path: &Path, s: &UpdateSummary) {
    output::header(&format!("Ingested catalog: {}", path.display()));
    output::kv("snapshot_id", &s.snapshot_id.to_string());
    output::kv("status", &s.snapshot_status);
    output::kv("commit", &s.commit_sha);
    output::kv("agents", &s.agent_count.to_string());
    output::kv("divisions", &s.division_count.to_string());
    output::kv("files", &s.files_scanned.to_string());
    output::kv("total_bytes", &s.total_bytes.to_string());
    output::kv("rejected", &s.rejected.to_string());
    output::kv(
        "findings",
        &format!(
            "{} BLOCK, {} WARN, {} PASS",
            s.findings_block, s.findings_warn, s.findings_pass
        ),
    );
    output::kv("persisted_to", &s.db_path.display().to_string());

    if s.findings_block > 0 {
        output::warn(&format!(
            "{} BLOCK finding(s); snapshot status is Blocked. Top {}:",
            s.findings_block,
            s.top_findings.len()
        ));
        for f in &s.top_findings {
            eprintln!("  [{}] {} on {}: {}", f.severity, f.rule, f.path, f.reason);
        }
    } else if s.findings_warn > 0 {
        output::warn(&format!(
            "{} WARN finding(s) (see DB for details)",
            s.findings_warn
        ));
    }

    if s.rejected > 0 {
        output::warn(&format!(
            "{} agent(s) rejected (see DB for details)",
            s.rejected
        ));
    }
}
