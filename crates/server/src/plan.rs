//! Pure plan-computation used by `POST /v1/systems/plan`.
//!
//! Mirrors `agent_dep_cli::commands::system::plan_at` but
//! without the journal / artifacts / DB dependency. The
//! 2.0.0 server treats the plan as a read-only operation
//! that the operator inspects before issuing a deploy.

use anyhow::Result;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct PlanSummary {
    pub system_id: String,
    pub writes: Vec<PlanWrite>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanWrite {
    pub agent_ref: String,
    pub relative: String,
    pub sha256: String,
}

pub async fn compute_plan(catalog_root: &str, system_yaml: &str) -> Result<PlanSummary> {
    let cat = Path::new(catalog_root);
    if !cat.is_dir() {
        anyhow::bail!("catalog path is not a directory: {catalog_root}");
    }
    let file = agent_dep_core::domain::system::parse_system_file(system_yaml)
        .map_err(|e| anyhow::anyhow!("parse system_yaml: {e}"))?;
    let source = agent_dep_core::domain::source::Source::new(
        agent_dep_core::domain::source::SourceKind::local(cat.to_path_buf()),
    );
    let (result, _report) = agent_dep_core::application::ingest::IngestService::new()
        .ingest_local(&source, None)
        .map_err(|e| anyhow::anyhow!("ingest {}: {e}", cat.display()))?;
    let placeholder_source_id = Uuid::new_v4();
    let composed = agent_dep_core::application::compose::CompositionService::new()
        .compose(
            placeholder_source_id,
            result.snapshot.id,
            &result.agents,
            &[],
            &file,
        )
        .map_err(|e| anyhow::anyhow!("compose: {e}"))?;
    let writes = composed
        .resolved
        .iter()
        .map(|r| {
            let rel = format!("agents/{}/{}.md", r.from_ref, r.agent.id);
            let sha = sha256_hex(r.agent.body.as_bytes());
            PlanWrite {
                agent_ref: r.from_ref.to_string(),
                relative: rel,
                sha256: sha,
            }
        })
        .collect();
    Ok(PlanSummary {
        system_id: composed.metadata.id,
        writes,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

use uuid::Uuid;
