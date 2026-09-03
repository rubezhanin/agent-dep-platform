//! Persistence layer for catalog snapshots (TZ §11.1).
//!
//! `IngestRepository` is the only writer for the `sources` /
//! `source_snapshots` / `divisions` / `agents` / link tables. It owns
//! the transactional boundary: a snapshot and all its child rows are
//! written in a single transaction so partial failures never leak.
//!
//! `SkillRepository` (Phase 1B) owns the parallel `skills` /
//! `skill_tags` / `skill_dependencies` / `skill_permissions` tables
//! for the v2 catalog shape.
//!
//! Per ADR-0004: this DB is metadata only. The on-disk system YAML
//! remains the source of truth; a snapshot row is a derived view.
//! Per ADR-0006: re-ingestion produces a new snapshot row; the
//! previous Active row is flipped to `Superseded` in the same
//! transaction.

pub mod audit_log_repository;
pub mod deployed_artifacts_repository;
pub mod pending_deploys_repository;
pub mod secrets_repository;
pub mod oidc_pending_repository;
pub mod skill_repository;
pub mod targets_repository;
pub mod users_repository;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::application::ingest::{IngestReport, IngestResult, RejectedAgent};
use crate::application::scanner::Severity;
use crate::domain::source::{SnapshotStatus, Source, SourceKind, SourceSnapshot};
use crate::error::{CoreError, CoreResult};

// ---------------------------------------------------------------------------
// Row type aliases (keep sqlx `query_as` types readable)
// ---------------------------------------------------------------------------

type SourceRow = (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
);

type SnapshotRow = (
    String,
    String,
    String,
    String,
    i64,
    i64,
    String,
    Option<String>,
    Option<String>,
);

type DivisionRow = (String, i64, String, Option<String>);

type AgentRow = (
    String,
    String,
    String,
    Option<String>,
    String,
    String,
    String,
    i64,
    String,
    String,
);

// ---------------------------------------------------------------------------
// Read-back DTOs (kept in the repository module because they're
// 1:1 with SQL row shapes; not domain types).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct StoredSnapshotSummary {
    pub snapshot: SourceSnapshot,
    pub source_id: Uuid,
    pub finding_count: u32,
}

#[derive(Debug, Clone)]
pub struct StoredAgentRow {
    pub id: String,
    pub division: String,
    pub name: String,
    pub display_name: Option<String>,
    pub role: String,
    pub description: String,
    pub version: String,
    pub sensitive: bool,
    pub body: String,
    pub body_hash: String,
    pub tools: Vec<String>,
    pub activation_phrases: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct StoredSnapshotDetail {
    pub snapshot: SourceSnapshot,
    pub divisions: Vec<StoredDivisionRow>,
    pub agents: Vec<StoredAgentRow>,
    pub rejected: Vec<RejectedAgent>,
    pub findings: Vec<StoredFinding>,
}

/// One persisted finding. Carries the scanner's severity verbatim;
/// the snapshot's `status` already reflects the rollup.
#[derive(Debug, Clone)]
pub struct StoredFinding {
    pub position: u32,
    pub severity: crate::application::scanner::Severity,
    pub rule: String,
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct StoredDivisionRow {
    pub id: String,
    pub display_order: u32,
    pub label: String,
    pub description: Option<String>,
}

/// Minimal agent row for list views (TZ §51). Returned by
/// `IngestRepository::list_agents_in_latest_snapshot`.
#[derive(Debug, Clone, Serialize)]
pub struct StoredAgentListEntry {
    pub id: String,
    pub name: String,
    pub version: String,
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

pub struct IngestRepository {
    pool: SqlitePool,
}

impl IngestRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert or update a `Source` row keyed by `(kind, location)`.
    /// Returns the persisted source's UUID. If a row already exists
    /// for the same kind+location, the existing UUID is preserved and
    /// the metadata fields are refreshed; `last_indexed_at` is set to
    /// `now` only when `touch_last_indexed = true`.
    pub async fn upsert_source(
        &self,
        source: &Source,
        touch_last_indexed: bool,
    ) -> CoreResult<Uuid> {
        let kind = source_kind_str(&source.kind);
        let location = source_location_str(&source.kind);
        let pinned_ref = source.pinned_ref.clone();
        let display_name = source.display_name.clone();
        let created_at = source.created_at;
        let last_indexed_at = if touch_last_indexed {
            Some(Utc::now())
        } else {
            source.last_indexed_at
        };

        // Look up an existing row first so we can preserve the UUID.
        let existing: Option<(String,)> =
            sqlx::query_as("SELECT id FROM sources WHERE kind = ?1 AND location = ?2")
                .bind(kind)
                .bind(&location)
                .fetch_optional(&self.pool)
                .await?;

        let id = match existing {
            Some((id,)) => {
                let id_uuid = Uuid::parse_str(&id).map_err(|e| CoreError::ErrSchemaInvalid {
                    path: "sources.id".to_string(),
                    reason: format!("bad UUID in DB: {e}"),
                })?;
                sqlx::query(
                    "UPDATE sources SET pinned_ref = ?1, display_name = ?2, \
                     last_indexed_at = ?3 WHERE id = ?4",
                )
                .bind(&pinned_ref)
                .bind(&display_name)
                .bind(last_indexed_at.map(iso8601))
                .bind(&id)
                .execute(&self.pool)
                .await?;
                id_uuid
            }
            None => {
                let id = source.id;
                sqlx::query(
                    "INSERT INTO sources (id, kind, location, pinned_ref, display_name, \
                     created_at, last_indexed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                )
                .bind(id.to_string())
                .bind(kind)
                .bind(&location)
                .bind(&pinned_ref)
                .bind(&display_name)
                .bind(iso8601(created_at))
                .bind(last_indexed_at.map(iso8601))
                .execute(&self.pool)
                .await?;
                id
            }
        };
        Ok(id)
    }

    /// Find a source by `(kind, location)`. Returns `None` if no row.
    pub async fn find_source_by_location(
        &self,
        kind: &str,
        location: &str,
    ) -> CoreResult<Option<Source>> {
        let row: Option<SourceRow> = sqlx::query_as(
            "SELECT id, kind, location, pinned_ref, display_name, created_at, \
             last_indexed_at FROM sources WHERE kind = ?1 AND location = ?2",
        )
        .bind(kind)
        .bind(location)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            None => Ok(None),
            Some((id, kind, location, pinned_ref, display_name, created_at, last_indexed_at)) => {
                let id = Uuid::parse_str(&id).map_err(|e| CoreError::ErrSchemaInvalid {
                    path: "sources.id".to_string(),
                    reason: format!("bad UUID in DB: {e}"),
                })?;
                let created_at = parse_iso8601(&created_at)?;
                let last_indexed_at = match last_indexed_at {
                    Some(s) => Some(parse_iso8601(&s)?),
                    None => None,
                };
                let kind = parse_source_kind(&kind, &location)?;
                Ok(Some(Source {
                    id,
                    kind,
                    pinned_ref,
                    display_name,
                    created_at,
                    last_indexed_at,
                }))
            }
        }
    }

    /// Atomically record a snapshot:
    /// 1. Flip any currently-`active` snapshot for `source_id` to `superseded`.
    /// 2. Insert the new snapshot row with status `active` (or whatever the
    ///    caller passed in `IngestResult::snapshot`).
    /// 3. Insert all divisions, agents, tools, activation_phrases, files, and
    ///    rejected-agent rows.
    /// 4. Update `sources.last_indexed_at`.
    pub async fn record_snapshot(
        &self,
        source_id: Uuid,
        result: &IngestResult,
        report: &IngestReport,
    ) -> CoreResult<()> {
        let mut tx = self.pool.begin().await?;

        // Step 1: supersede any current Active snapshot for this source.
        if result.snapshot.status == SnapshotStatus::Active {
            sqlx::query(
                "UPDATE source_snapshots SET status = 'superseded' \
                 WHERE source_id = ?1 AND status = 'active'",
            )
            .bind(source_id.to_string())
            .execute(&mut *tx)
            .await?;
        }

        // Step 2: insert the new snapshot row.
        let snapshot = &result.snapshot;
        sqlx::query(
            "INSERT INTO source_snapshots (id, source_id, commit_sha, status, \
             agent_count, division_count, created_at, upstream_template_version, \
             scan_note) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(snapshot.id.to_string())
        .bind(source_id.to_string())
        .bind(&snapshot.commit_sha)
        .bind(snapshot_status_str(snapshot.status))
        .bind(snapshot.agent_count as i64)
        .bind(snapshot.division_count as i64)
        .bind(iso8601(snapshot.created_at))
        .bind(
            snapshot
                .upstream_template_version
                .as_ref()
                .map(|v| v.to_string()),
        )
        .bind(&snapshot.scan_note)
        .execute(&mut *tx)
        .await?;

        let snapshot_id = snapshot.id;

        // Step 3a: insert divisions.
        for (_, d) in result.divisions.iter() {
            sqlx::query(
                "INSERT INTO divisions (id, snapshot_id, display_order, label, \
                 description) VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .bind(&d.id)
            .bind(snapshot_id.to_string())
            .bind(d.display_order as i64)
            .bind(&d.label)
            .bind(&d.description)
            .execute(&mut *tx)
            .await?;
        }

        // Step 3b: insert agents + their tools + activation_phrases.
        for a in &result.agents {
            sqlx::query(
                "INSERT INTO agents (id, snapshot_id, division, name, display_name, \
                 role, description, version, sensitive, body, body_hash) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )
            .bind(&a.id)
            .bind(snapshot_id.to_string())
            .bind(&a.division)
            .bind(&a.name)
            .bind(&a.display_name)
            .bind(&a.role)
            .bind(&a.description)
            .bind(a.version.to_string())
            .bind(a.sensitive as i64)
            .bind(&a.body)
            .bind(&a.body_hash)
            .execute(&mut *tx)
            .await?;
            for (i, t) in a.tools.iter().enumerate() {
                sqlx::query(
                    "INSERT INTO agent_tools (snapshot_id, agent_id, position, tool) \
                     VALUES (?1, ?2, ?3, ?4)",
                )
                .bind(snapshot_id.to_string())
                .bind(&a.id)
                .bind(i as i64)
                .bind(t)
                .execute(&mut *tx)
                .await?;
            }
            for (i, p) in a.activation_phrases.iter().enumerate() {
                sqlx::query(
                    "INSERT INTO agent_activation_phrases (snapshot_id, agent_id, \
                     position, phrase) VALUES (?1, ?2, ?3, ?4)",
                )
                .bind(snapshot_id.to_string())
                .bind(&a.id)
                .bind(i as i64)
                .bind(p)
                .execute(&mut *tx)
                .await?;
            }
        }

        // Step 3c: insert observed files.
        for f in &result.files {
            sqlx::query(
                "INSERT INTO snapshot_files (snapshot_id, relative, sha256, \
                 size_bytes) VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(snapshot_id.to_string())
            .bind(&f.relative)
            .bind(&f.sha256)
            .bind(f.size_bytes as i64)
            .execute(&mut *tx)
            .await?;
        }

        // Step 3d: insert rejected agents.
        for r in &report.agents_rejected {
            sqlx::query(
                "INSERT INTO snapshot_rejected_agents (snapshot_id, relative_path, \
                 reason) VALUES (?1, ?2, ?3)",
            )
            .bind(snapshot_id.to_string())
            .bind(&r.relative_path)
            .bind(&r.reason)
            .execute(&mut *tx)
            .await?;
        }

        // Step 3e: insert scanner findings.
        for (i, f) in result.findings.iter().enumerate() {
            sqlx::query(
                "INSERT INTO snapshot_findings (snapshot_id, position, severity, \
                 rule, path, reason) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(snapshot_id.to_string())
            .bind(i as i64)
            .bind(f.severity.as_str())
            .bind(&f.rule)
            .bind(&f.path)
            .bind(&f.reason)
            .execute(&mut *tx)
            .await?;
        }

        // Step 4: update source last_indexed_at.
        sqlx::query("UPDATE sources SET last_indexed_at = ?1 WHERE id = ?2")
            .bind(iso8601(Utc::now()))
            .bind(source_id.to_string())
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Read all snapshots for a source, newest first.
    pub async fn list_snapshots(&self, source_id: Uuid) -> CoreResult<Vec<StoredSnapshotSummary>> {
        let rows: Vec<SnapshotRow> = sqlx::query_as(
            "SELECT id, source_id, commit_sha, status, agent_count, division_count, \
             created_at, upstream_template_version, scan_note FROM source_snapshots \
             WHERE source_id = ?1 ORDER BY created_at DESC",
        )
        .bind(source_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for (
            id,
            sid,
            commit,
            status_str,
            agent_count,
            division_count,
            created_at,
            upstream,
            scan_note,
        ) in rows
        {
            let id = Uuid::parse_str(&id).map_err(|e| CoreError::ErrSchemaInvalid {
                path: "source_snapshots.id".to_string(),
                reason: format!("bad UUID in DB: {e}"),
            })?;
            let source_id = Uuid::parse_str(&sid).map_err(|e| CoreError::ErrSchemaInvalid {
                path: "source_snapshots.source_id".to_string(),
                reason: format!("bad UUID in DB: {e}"),
            })?;
            let status = parse_snapshot_status(&status_str)?;
            let created_at = parse_iso8601(&created_at)?;
            let upstream_template_version = match upstream {
                Some(s) => Some(crate::domain::version::Version::parse(&s).map_err(|e| {
                    CoreError::ErrSchemaInvalid {
                        path: "source_snapshots.upstream_template_version".to_string(),
                        reason: format!("bad version: {e}"),
                    }
                })?),
                None => None,
            };
            out.push(StoredSnapshotSummary {
                source_id,
                finding_count: 0, // hydrated below
                snapshot: SourceSnapshot {
                    id,
                    source_id,
                    commit_sha: commit,
                    status,
                    agent_count: agent_count as u32,
                    division_count: division_count as u32,
                    created_at,
                    upstream_template_version,
                    scan_note,
                },
            });
        }
        // Hydrate finding counts in a single follow-up query.
        for s in &mut out {
            let row: (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM snapshot_findings WHERE snapshot_id = ?1")
                    .bind(s.snapshot.id.to_string())
                    .fetch_one(&self.pool)
                    .await?;
            s.finding_count = row.0 as u32;
        }
        Ok(out)
    }

    /// Read full snapshot detail (divisions + agents + rejected).
    pub async fn get_snapshot_detail(
        &self,
        snapshot_id: Uuid,
    ) -> CoreResult<Option<StoredSnapshotDetail>> {
        let snap_row: Option<SnapshotRow> = sqlx::query_as(
            "SELECT id, source_id, commit_sha, status, agent_count, division_count, \
             created_at, upstream_template_version, scan_note FROM source_snapshots \
             WHERE id = ?1",
        )
        .bind(snapshot_id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        let snap = match snap_row {
            None => return Ok(None),
            Some((
                id,
                source_id,
                commit_sha,
                status_str,
                agent_count,
                division_count,
                created_at,
                upstream,
                scan_note,
            )) => {
                let id = Uuid::parse_str(&id).map_err(|e| CoreError::ErrSchemaInvalid {
                    path: "source_snapshots.id".to_string(),
                    reason: format!("bad UUID in DB: {e}"),
                })?;
                let source_id =
                    Uuid::parse_str(&source_id).map_err(|e| CoreError::ErrSchemaInvalid {
                        path: "source_snapshots.source_id".to_string(),
                        reason: format!("bad UUID in DB: {e}"),
                    })?;
                let status = parse_snapshot_status(&status_str)?;
                let created_at = parse_iso8601(&created_at)?;
                let upstream_template_version = match upstream {
                    Some(s) => Some(crate::domain::version::Version::parse(&s).map_err(|e| {
                        CoreError::ErrSchemaInvalid {
                            path: "source_snapshots.upstream_template_version".to_string(),
                            reason: format!("bad version: {e}"),
                        }
                    })?),
                    None => None,
                };
                SourceSnapshot {
                    id,
                    source_id,
                    commit_sha,
                    status,
                    agent_count: agent_count as u32,
                    division_count: division_count as u32,
                    created_at,
                    upstream_template_version,
                    scan_note,
                }
            }
        };

        let div_rows: Vec<DivisionRow> = sqlx::query_as(
            "SELECT id, display_order, label, description FROM divisions \
             WHERE snapshot_id = ?1 ORDER BY display_order",
        )
        .bind(snapshot_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        let divisions = div_rows
            .into_iter()
            .map(|(id, order, label, description)| StoredDivisionRow {
                id,
                display_order: order as u32,
                label,
                description,
            })
            .collect();

        let agent_rows: Vec<AgentRow> = sqlx::query_as(
            "SELECT id, division, name, display_name, role, description, version, \
             sensitive, body, body_hash FROM agents WHERE snapshot_id = ?1 \
             ORDER BY id",
        )
        .bind(snapshot_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        let mut agents = Vec::with_capacity(agent_rows.len());
        for (
            id,
            division,
            name,
            display_name,
            role,
            description,
            version,
            sensitive,
            body,
            body_hash,
        ) in agent_rows
        {
            let tool_rows: Vec<(String,)> = sqlx::query_as(
                "SELECT tool FROM agent_tools WHERE snapshot_id = ?1 AND agent_id = ?2 \
                 ORDER BY position",
            )
            .bind(snapshot_id.to_string())
            .bind(&id)
            .fetch_all(&self.pool)
            .await?;
            let phrase_rows: Vec<(String,)> = sqlx::query_as(
                "SELECT phrase FROM agent_activation_phrases WHERE snapshot_id = ?1 \
                 AND agent_id = ?2 ORDER BY position",
            )
            .bind(snapshot_id.to_string())
            .bind(&id)
            .fetch_all(&self.pool)
            .await?;
            agents.push(StoredAgentRow {
                id,
                division,
                name,
                display_name,
                role,
                description,
                version,
                sensitive: sensitive != 0,
                body,
                body_hash,
                tools: tool_rows.into_iter().map(|(t,)| t).collect(),
                activation_phrases: phrase_rows.into_iter().map(|(p,)| p).collect(),
            });
        }

        let rej_rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT relative_path, reason FROM snapshot_rejected_agents \
             WHERE snapshot_id = ?1 ORDER BY relative_path",
        )
        .bind(snapshot_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        let rejected = rej_rows
            .into_iter()
            .map(|(relative_path, reason)| RejectedAgent {
                relative_path,
                reason,
            })
            .collect();

        let finding_rows: Vec<(i64, String, String, String, String)> = sqlx::query_as(
            "SELECT position, severity, rule, path, reason FROM snapshot_findings \
             WHERE snapshot_id = ?1 ORDER BY position",
        )
        .bind(snapshot_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        let findings = finding_rows
            .into_iter()
            .map(
                |(position, severity_str, rule, path, reason)| -> CoreResult<StoredFinding> {
                    let severity = Severity::parse(&severity_str).map_err(|e| {
                        CoreError::ErrSchemaInvalid {
                            path: "snapshot_findings.severity".to_string(),
                            reason: format!("{e}"),
                        }
                    })?;
                    Ok(StoredFinding {
                        position: position as u32,
                        severity,
                        rule,
                        path,
                        reason,
                    })
                },
            )
            .collect::<CoreResult<Vec<_>>>()?;

        Ok(Some(StoredSnapshotDetail {
            snapshot: snap,
            divisions,
            agents,
            rejected,
            findings,
        }))
    }

    /// All sources, newest first (last_indexed_at DESC NULLS LAST,
    /// then created_at DESC). Used by the Svelte sources route.
    pub async fn list_sources(&self) -> CoreResult<Vec<Source>> {
        let rows: Vec<SourceRow> = sqlx::query_as(
            "SELECT id, kind, location, pinned_ref, display_name, created_at, \
             last_indexed_at FROM sources \
             ORDER BY (last_indexed_at IS NULL), last_indexed_at DESC, created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for (id, kind, location, pinned_ref, display_name, created_at, last_indexed_at) in rows {
            let id = Uuid::parse_str(&id).map_err(|e| CoreError::ErrSchemaInvalid {
                path: "sources.id".to_string(),
                reason: format!("bad UUID: {e}"),
            })?;
            let created_at = parse_iso8601(&created_at)?;
            let last_indexed_at = match last_indexed_at {
                Some(s) => Some(parse_iso8601(&s)?),
                None => None,
            };
            let kind = parse_source_kind(&kind, &location)?;
            out.push(Source {
                id,
                kind,
                pinned_ref,
                display_name,
                created_at,
                last_indexed_at,
            });
        }
        Ok(out)
    }

    /// Agents in the most-recent `active` snapshot across all
    /// sources. Returns an empty Vec when no active snapshot
    /// exists (e.g. fresh install, no `agency catalog update`
    /// run yet). Used by the Svelte catalog route.
    pub async fn list_agents_in_latest_snapshot(&self) -> CoreResult<Vec<StoredAgentListEntry>> {
        let latest: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM source_snapshots WHERE status = 'active' \
             ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        let Some((snap_id,)) = latest else {
            return Ok(Vec::new());
        };
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT id, name, version FROM agents \
             WHERE snapshot_id = ?1 ORDER BY division, id",
        )
        .bind(&snap_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, name, version)| StoredAgentListEntry { id, name, version })
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn iso8601(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn parse_iso8601(s: &str) -> CoreResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| CoreError::ErrSchemaInvalid {
            path: "timestamp".to_string(),
            reason: format!("bad ISO 8601: {e}"),
        })
}

fn source_kind_str(k: &SourceKind) -> &'static str {
    match k {
        SourceKind::Local { .. } => "local",
        SourceKind::GitHttps { .. } => "git_https",
        SourceKind::GitSsh { .. } => "git_ssh",
    }
}

fn source_location_str(k: &SourceKind) -> String {
    match k {
        SourceKind::Local { path } => path.to_string_lossy().to_string(),
        SourceKind::GitHttps { url } | SourceKind::GitSsh { url } => url.clone(),
    }
}

fn parse_source_kind(kind: &str, location: &str) -> CoreResult<SourceKind> {
    let l = location.to_string();
    Ok(match kind {
        "local" => SourceKind::Local {
            path: std::path::PathBuf::from(l),
        },
        "git_https" => SourceKind::GitHttps { url: l },
        "git_ssh" => SourceKind::GitSsh { url: l },
        other => {
            return Err(CoreError::ErrSchemaInvalid {
                path: "sources.kind".to_string(),
                reason: format!("unknown kind: {other}"),
            })
        }
    })
}

fn snapshot_status_str(s: SnapshotStatus) -> &'static str {
    match s {
        SnapshotStatus::Active => "active",
        SnapshotStatus::Superseded => "superseded",
        SnapshotStatus::Blocked => "blocked",
        SnapshotStatus::Failed => "failed",
    }
}

fn parse_snapshot_status(s: &str) -> CoreResult<SnapshotStatus> {
    Ok(match s {
        "active" => SnapshotStatus::Active,
        "superseded" => SnapshotStatus::Superseded,
        "blocked" => SnapshotStatus::Blocked,
        "failed" => SnapshotStatus::Failed,
        other => {
            return Err(CoreError::ErrSchemaInvalid {
                path: "source_snapshots.status".to_string(),
                reason: format!("unknown status: {other}"),
            })
        }
    })
}

#[cfg(test)]
#[path = "repository_tests.rs"]
mod repository_tests;
