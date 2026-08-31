//! `agency catalog ...` — ingest/inspect local or (1.x) git catalogs.

use agent_dep_core::application::ingest::IngestService;
use agent_dep_core::domain::source::{Source, SourceKind};
use std::path::PathBuf;

use crate::output;

pub fn update(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if !path.is_dir() {
        return Err(format!("not a directory: {}", path.display()).into());
    }
    let source = Source::new(SourceKind::local(path.clone()));
    let svc = IngestService::new();
    let (result, report) = svc.ingest_local(&source)?;

    output::header(&format!("Ingested catalog: {}", path.display()));
    output::kv("snapshot_id", &result.snapshot.id.to_string());
    output::kv("commit", &result.snapshot.commit_sha);
    output::kv("status", format!("{:?}", result.snapshot.status).as_str());
    output::kv("agents", &result.agents.len().to_string());
    output::kv("divisions", &result.divisions.len().to_string());
    output::kv("files", &report.files_scanned.to_string());
    output::kv("total_bytes", &report.total_bytes.to_string());

    if !report.agents_rejected.is_empty() {
        output::warn(&format!(
            "{} agent(s) rejected:",
            report.agents_rejected.len()
        ));
        for r in &report.agents_rejected {
            eprintln!("  {} — {}", r.relative_path, r.reason);
        }
    }

    Ok(())
}
