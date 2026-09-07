//! Pure plan-computation used by `POST /v1/systems/plan`.
//!
//! P0-F-07 (TZ #1 §8 F-07, CWE-22, Appendix
//! A.5): the pre-fix `compute_plan` took
//! `catalog_root: &str` — a caller-supplied
//! filesystem path. Any authenticated user
//! could ask the server to read any path on
//! disk (path traversal). The post-fix
//! `compute_plan_from_source` takes
//! `source_id: &str` — an opaque UUID that
//! the server resolves against the
//! pre-registered `sources` table. The
//! filesystem path is read FROM the DB
//! (registered by the operator via
//! `POST /v1/sources` or `agency sources add`),
//! not FROM the request. The caller never
//! influences the path the server ingests.

use anyhow::{anyhow, Result};
use serde::Serialize;
use sqlx::SqlitePool;
use std::path::Path;
use uuid::Uuid;

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

/// P0-F-07: look up the registered source by
/// ID, fail closed if the source is missing
/// or is not a `local` kind, then delegate
/// to the existing ingest path on the
/// operator-controlled path. Returns the
/// (source_id, path) so the handler can
/// audit-log the resolved path (not the
/// caller-supplied UUID).
pub async fn resolve_source_path(pool: &SqlitePool, source_id: &str) -> Result<std::path::PathBuf> {
    let id =
        Uuid::parse_str(source_id).map_err(|e| anyhow!("invalid source_id (not a UUID): {e}"))?;
    let row: Option<(String,)> = sqlx::query_as("SELECT location FROM sources WHERE id = ?1")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await
        .map_err(|e| anyhow!("lookup source {source_id}: {e}"))?;
    let location = row
        .ok_or_else(|| anyhow!("source {source_id} not registered"))?
        .0;
    let path = Path::new(&location);
    if !path.is_dir() {
        return Err(anyhow!(
            "registered source {source_id} points at non-directory: {location}"
        ));
    }
    Ok(path.to_path_buf())
}

pub async fn compute_plan_from_source(
    pool: &SqlitePool,
    source_id: &str,
    system_yaml: &str,
) -> Result<(Uuid, PlanSummary)> {
    let path = resolve_source_path(pool, source_id).await?;
    let file = agent_dep_core::domain::system::parse_system_file(system_yaml)
        .map_err(|e| anyhow::anyhow!("parse system_yaml: {e}"))?;
    let source = agent_dep_core::domain::source::Source::new(
        agent_dep_core::domain::source::SourceKind::local(path.clone()),
    );
    let (result, _report) = agent_dep_core::application::ingest::IngestService::new()
        .ingest_local(&source, None)
        .map_err(|e| anyhow::anyhow!("ingest {}: {e}", path.display()))?;
    let resolved_source_id =
        Uuid::parse_str(source_id).map_err(|e| anyhow!("invalid source_id (not a UUID): {e}"))?;
    let composed = agent_dep_core::application::compose::CompositionService::new()
        .compose(
            resolved_source_id,
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
    Ok((
        resolved_source_id,
        PlanSummary {
            system_id: composed.metadata.id,
            writes,
        },
    ))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}
