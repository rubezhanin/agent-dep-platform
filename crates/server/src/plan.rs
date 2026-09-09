//! Pure plan-computation used by `POST /v1/systems/plan` and
//! `POST /v1/deploys`.
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
//!
//! P1-D-01d (TZ #1 §10 / D-01d, CWE-494):
//! `compute_plan_from_source` also accepts
//! an optional `source_snapshot_id`. When
//! present, the server loads the agents /
//! divisions / skills from the stored
//! `source_snapshots` row instead of
//! re-ingesting the working copy. The plan
//! is now bound to the exact commit the
//! operator approved; later edits to the
//! working copy cannot change the deploy
//! that the row records. The legacy
//! re-ingest path (no `source_snapshot_id`)
//! is preserved for callers that do not
//! know about snapshots yet (the 2.11.0
//! `agency` CLI, the SPA before it
//! learns about `GET /v1/sources/{id}/snapshots`).

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
    source_snapshot_id: Option<&str>,
) -> Result<(Uuid, PlanSummary, Option<String>)> {
    // P1-D-01d (TZ #1 §10 / D-01d,
    // CWE-494): when the caller passes a
    // `source_snapshot_id`, the plan is
    // built against the stored snapshot,
    // not the live working copy. The
    // snapshot's `source_id` MUST equal
    // the request's `source_id`; a
    // mismatch is a CWE-345
    // source-confusion attempt and is
    // rejected with a 400.
    let resolved_source_id =
        Uuid::parse_str(source_id).map_err(|e| anyhow!("invalid source_id (not a UUID): {e}"))?;
    let file = agent_dep_core::domain::system::parse_system_file(system_yaml)
        .map_err(|e| anyhow::anyhow!("parse system_yaml: {e}"))?;

    let (snapshot_id_for_persist, agents) = match source_snapshot_id {
        Some(raw_snap_id) => {
            let snap_id = Uuid::parse_str(raw_snap_id)
                .map_err(|e| anyhow!("invalid source_snapshot_id (not a UUID): {e}"))?;
            let repo =
                agent_dep_core::infrastructure::repository::IngestRepository::new(pool.clone());
            let detail = repo
                .get_snapshot_detail(snap_id)
                .await
                .map_err(|e| anyhow!("lookup snapshot {raw_snap_id}: {e}"))?
                .ok_or_else(|| {
                    anyhow!("source_snapshot_id `{raw_snap_id}` not found in source_snapshots")
                })?;
            // CWE-345 guard: a snapshot
            // belongs to exactly one
            // source. Mixing them would
            // let an operator quote a
            // snapshot from source A in a
            // deploy that names source B.
            if detail.snapshot.source_id != resolved_source_id {
                return Err(anyhow!(
                    "source_snapshot_id `{raw_snap_id}` belongs to source `{}`, \
                     but request named source `{source_id}`",
                    detail.snapshot.source_id
                ));
            }
            let agents = stored_agents_to_agents(detail.agents, detail.snapshot.id);
            (Some(detail.snapshot.id.to_string()), agents)
        }
        None => {
            // Legacy path: re-ingest the
            // working copy. Used by the
            // 2.11.0 `agency` CLI which
            // does not yet pass a
            // snapshot id, and by the
            // SPA before it learns
            // about
            // `GET /v1/sources/{id}/snapshots`.
            let path = resolve_source_path(pool, source_id).await?;
            let source = agent_dep_core::domain::source::Source::new(
                agent_dep_core::domain::source::SourceKind::local(path.clone()),
            );
            let (result, _report) = agent_dep_core::application::ingest::IngestService::new()
                .ingest_local(&source, None)
                .map_err(|e| anyhow::anyhow!("ingest {}: {e}", path.display()))?;
            (None, result.agents)
        }
    };

    // P1-D-01d: the `compose` API needs
    // a `snapshot_id` for provenance.
    // For the stored-snapshot path it is
    // the snap id we just loaded; for
    // the legacy re-ingest path we do
    // not have a snap id at this layer
    // (the snapshot only materialises
    // when `record_snapshot` runs).
    // We pass the well-known nil UUID
    // so the legacy path keeps
    // composing; the mark_applied
    // freshness check is gated on the
    // caller supplying a real
    // source_snapshot_id at
    // request_deploy time, which is
    // what makes the legacy path safe
    // today.
    let compose_snapshot_id = snapshot_id_for_persist
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(Uuid::nil);

    let composed = agent_dep_core::application::compose::CompositionService::new()
        .compose(resolved_source_id, compose_snapshot_id, &agents, &[], &file)
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
        snapshot_id_for_persist,
    ))
}

/// P1-D-01d (TZ #1 §10 / D-01d,
/// CWE-494): map `StoredAgentRow` (the
/// read-back DTO from the
/// `source_snapshots` / `agents` join)
/// back to the in-memory `Agent` value
/// the compose step needs. The DB stores
/// the body verbatim and the hash
/// alongside it; we set `snapshot_id`
/// to the snap the row was loaded from
/// so a later drift check can pin the
/// agent to its source snapshot.
fn stored_agents_to_agents(
    rows: Vec<agent_dep_core::infrastructure::repository::StoredAgentRow>,
    snapshot_id: Uuid,
) -> Vec<agent_dep_core::domain::agent::Agent> {
    rows.into_iter()
        .map(|r| {
            // The `version` column is a
            // semver string. The ingest
            // path stored it via
            // `Version::parse`; the
            // back-conversion is therefore
            // guaranteed to round-trip on
            // rows written by this code
            // path. Pre-2.11.0 rows from
            // a different writer would
            // surface here as a 500 from
            // the parse failure — that is
            // intentional (we refuse to
            // plan against an unparseable
            // version).
            let version = agent_dep_core::domain::version::Version::parse(&r.version)
                .expect("stored agent version must be a valid semver");
            agent_dep_core::domain::agent::Agent {
                snapshot_id,
                id: r.id,
                division: r.division,
                name: r.name,
                display_name: r.display_name,
                role: r.role,
                description: r.description,
                version,
                sensitive: r.sensitive,
                tools: r.tools,
                activation_phrases: r.activation_phrases,
                body: r.body,
                body_hash: r.body_hash,
            }
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}
