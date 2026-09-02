//! V2 catalog ingest (TZ Enterprise v2 §5, §6, §7).
//!
//! Walks the v2 directory layout:
//!
//! ```text
//! repo/
//! ├── divisions.json
//! ├── agents/
//! │   └── <id>/
//! │       ├── agent.yaml
//! │       └── instructions.md
//! └── skills/
//!     └── <id>/
//!         ├── skill.yaml
//!         └── SKILL.md
//! ```
//!
//! Each `agent.yaml` is parsed with the strict v2 parser
//! (`parse_agent_yaml`); each `skill.yaml` is parsed with
//! `parse_skill_yaml`. The `instructions.md` / `SKILL.md` body
//! file is read and its sha256 becomes `body_hash`. The result
//! is an `IngestResult` with both `agents` and `skills` filled
//! in; the snapshot identity is the content-derived sha256 of
//! the sorted `<rel-path>\0<file-sha256>` lines, identical to
//! the v1 IngestService so the SQLite persistence layer can
//! store v1 and v2 snapshots in the same tables.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::application::ingest::{IngestReport, IngestResult, ObservedFile, RejectedAgent};
use crate::application::scanner::{Finding, RegexScanner, ScanPolicy, Scanner};
use crate::domain::agent::Agent;
use crate::domain::agent_yaml::parse_agent_yaml;
use crate::domain::division::DivisionIndex;
use crate::domain::skill::Skill;
use crate::domain::skill_yaml::parse_skill_yaml;
use crate::domain::source::{SnapshotStatus, Source, SourceSnapshot};
use crate::domain::version::Version;
use crate::error::{CoreError, CoreResult};
use uuid::Uuid;

pub struct IngestV2Service;

impl IngestV2Service {
    pub fn new() -> Self {
        Self
    }

    /// Ingest a v2 catalog from a local directory. Mirrors the
    /// shape of `IngestService::ingest_local` but walks the v2
    /// layout.
    pub fn ingest_v2(
        &self,
        source: &Source,
        policy: &ScanPolicy,
    ) -> CoreResult<(IngestResult, IngestReport)> {
        let root = match &source.kind {
            crate::domain::source::SourceKind::Local { path } => path.clone(),
            other => {
                return Err(CoreError::ErrUntrustedSource {
                    source_id: format!("{other:?}"),
                    reason: "IngestV2Service only supports Local sources in MVP".to_string(),
                });
            }
        };
        if !root.is_dir() {
            return Err(CoreError::ErrSourceNotFound {
                source_id: root.display().to_string(),
            });
        }

        let divisions = read_divisions_v2(&root).map_err(|e| CoreError::ErrSchemaInvalid {
            path: "divisions.json".to_string(),
            reason: e,
        })?;
        let mut agents: Vec<Agent> = Vec::new();
        let mut rejected_agents: Vec<RejectedAgent> = Vec::new();
        let mut skills: Vec<Skill> = Vec::new();
        let mut files: Vec<ObservedFile> = Vec::new();
        let mut findings: Vec<Finding> = Vec::new();
        let mut total_bytes: u64 = 0;

        // Snapshot id is the content-derived sha256 of the sorted
        // `<rel>\0<sha256>` lines. We hash files in two passes:
        // first record entries, then sort and finalize.
        let mut snapshot = SourceSnapshot {
            id: Uuid::new_v4(),
            source_id: source.id,
            commit_sha: String::new(),
            status: SnapshotStatus::Active,
            agent_count: 0,
            division_count: divisions.len() as u32,
            created_at: now_utc(),
            upstream_template_version: None,
            scan_note: None,
        };

        // ---- agents/<id>/agent.yaml + instructions.md ----
        let agents_dir = root.join("agents");
        if agents_dir.is_dir() {
            for entry in collect_subdirs(&agents_dir)? {
                let id = entry
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_string();
                let manifest_path = entry.join("agent.yaml");
                let body_path = entry.join("instructions.md");
                if !manifest_path.is_file() {
                    rejected_agents.push(RejectedAgent {
                        relative_path: rel(&root, &manifest_path),
                        reason: "missing agent.yaml in agents/<id>/".to_string(),
                    });
                    continue;
                }
                let manifest_text = match fs::read_to_string(&manifest_path) {
                    Ok(t) => t,
                    Err(e) => {
                        rejected_agents.push(RejectedAgent {
                            relative_path: rel(&root, &manifest_path),
                            reason: format!("read: {e}"),
                        });
                        continue;
                    }
                };
                let yaml = match parse_agent_yaml(&manifest_text) {
                    Ok(y) => y,
                    Err(e) => {
                        rejected_agents.push(RejectedAgent {
                            relative_path: rel(&root, &manifest_path),
                            reason: format!("agent.yaml invalid: {e}"),
                        });
                        continue;
                    }
                };
                if yaml.metadata.id != id {
                    rejected_agents.push(RejectedAgent {
                        relative_path: rel(&root, &manifest_path),
                        reason: format!(
                            "agent.yaml id `{}` does not match directory `{}`",
                            yaml.metadata.id, id
                        ),
                    });
                    continue;
                }
                if !body_path.is_file() {
                    rejected_agents.push(RejectedAgent {
                        relative_path: rel(&root, &manifest_path),
                        reason: format!(
                            "spec.instructions `{}` is not a file",
                            yaml.spec.instructions
                        ),
                    });
                    continue;
                }
                let body_text = match fs::read_to_string(&body_path) {
                    Ok(t) => t,
                    Err(e) => {
                        rejected_agents.push(RejectedAgent {
                            relative_path: rel(&root, &body_path),
                            reason: format!("read body: {e}"),
                        });
                        continue;
                    }
                };
                let body_hash = Skill::sha256_hex(body_text.as_bytes());

                // Scan the body for secret/exec patterns. The
                // MVP `RegexScanner` exposes a directory-level
                // `scan`; for per-file scanning we filter by
                // `path` after the walk. For the v2 reader the
                // body and manifest are small, so scanning the
                // whole root for every body is cheap.
                let all_findings =
                    RegexScanner
                        .scan(&root, policy)
                        .map_err(|e| CoreError::ErrSchemaInvalid {
                            path: "scanner".to_string(),
                            reason: format!("{e}"),
                        })?;
                let body_rel = rel(&root, &body_path);
                let body_findings: Vec<Finding> = all_findings
                    .into_iter()
                    .filter(|f| f.path == body_rel)
                    .collect();
                if body_findings
                    .iter()
                    .any(|f| matches!(f.severity, crate::application::scanner::Severity::Block))
                {
                    rejected_agents.push(RejectedAgent {
                        relative_path: rel(&root, &manifest_path),
                        reason: "blocked by security scanner".to_string(),
                    });
                    findings.extend(body_findings);
                    continue;
                }
                findings.extend(body_findings);

                let version = Version::parse(&yaml.metadata.version).map_err(|e| {
                    CoreError::ErrSchemaInvalid {
                        path: "metadata.version".to_string(),
                        reason: format!("{e}"),
                    }
                })?;

                let agent = Agent {
                    snapshot_id: snapshot.id,
                    id: yaml.metadata.id.clone(),
                    division: "v2".to_string(),
                    name: yaml.metadata.name.clone(),
                    display_name: None,
                    role: "agent".to_string(),
                    description: yaml.metadata.description.clone(),
                    version,
                    sensitive: false,
                    tools: vec![],
                    activation_phrases: vec![],
                    body: body_text.clone(),
                    body_hash: body_hash.clone(),
                };
                record_file(
                    &mut files,
                    &root,
                    &manifest_path,
                    &mut total_bytes,
                    &Skill::sha256_hex(manifest_text.as_bytes()),
                );
                record_file(&mut files, &root, &body_path, &mut total_bytes, &body_hash);
                agents.push(agent);
            }
        }

        // ---- skills/<id>/skill.yaml + SKILL.md ----
        let skills_dir = root.join("skills");
        if skills_dir.is_dir() {
            for entry in collect_subdirs(&skills_dir)? {
                let id = entry
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_string();
                let manifest_path = entry.join("skill.yaml");
                let body_path = entry.join("SKILL.md");
                if !manifest_path.is_file() {
                    rejected_agents.push(RejectedAgent {
                        relative_path: rel(&root, &manifest_path),
                        reason: "missing skill.yaml in skills/<id>/".to_string(),
                    });
                    continue;
                }
                let manifest_text = match fs::read_to_string(&manifest_path) {
                    Ok(t) => t,
                    Err(e) => {
                        rejected_agents.push(RejectedAgent {
                            relative_path: rel(&root, &manifest_path),
                            reason: format!("read: {e}"),
                        });
                        continue;
                    }
                };
                let yaml = match parse_skill_yaml(&manifest_text) {
                    Ok(y) => y,
                    Err(e) => {
                        rejected_agents.push(RejectedAgent {
                            relative_path: rel(&root, &manifest_path),
                            reason: format!("skill.yaml invalid: {e}"),
                        });
                        continue;
                    }
                };
                if yaml.metadata.id != id {
                    rejected_agents.push(RejectedAgent {
                        relative_path: rel(&root, &manifest_path),
                        reason: format!(
                            "skill.yaml id `{}` does not match directory `{}`",
                            yaml.metadata.id, id
                        ),
                    });
                    continue;
                }
                if !body_path.is_file() {
                    rejected_agents.push(RejectedAgent {
                        relative_path: rel(&root, &manifest_path),
                        reason: format!("spec.body `{}` is not a file", yaml.spec.body),
                    });
                    continue;
                }
                let body_text = match fs::read_to_string(&body_path) {
                    Ok(t) => t,
                    Err(e) => {
                        rejected_agents.push(RejectedAgent {
                            relative_path: rel(&root, &body_path),
                            reason: format!("read body: {e}"),
                        });
                        continue;
                    }
                };
                let body_hash = Skill::sha256_hex(body_text.as_bytes());

                let body_findings_root =
                    RegexScanner
                        .scan(&root, policy)
                        .map_err(|e| CoreError::ErrSchemaInvalid {
                            path: "scanner".to_string(),
                            reason: format!("{e}"),
                        })?;
                let body_findings: Vec<Finding> = body_findings_root
                    .into_iter()
                    .filter(|f| f.path == rel(&root, &body_path))
                    .collect();
                findings.extend(body_findings);

                let version = Version::parse(&yaml.metadata.version).map_err(|e| {
                    CoreError::ErrSchemaInvalid {
                        path: "metadata.version".to_string(),
                        reason: format!("{e}"),
                    }
                })?;

                let skill = Skill {
                    snapshot_id: snapshot.id,
                    id: yaml.metadata.id.clone(),
                    name: yaml.metadata.name.clone(),
                    version,
                    description: yaml.metadata.description.clone(),
                    tags: yaml.metadata.tags.clone(),
                    body: body_text.clone(),
                    body_hash: body_hash.clone(),
                    dependencies: yaml
                        .spec
                        .dependencies
                        .iter()
                        .map(|d| {
                            Ok(crate::domain::skill::SkillDependency {
                                id: d.id.clone(),
                                version: Version::parse(&d.version).map_err(|e| {
                                    CoreError::ErrSchemaInvalid {
                                        path: format!("spec.dependencies[{}].version", d.id),
                                        reason: format!("{e}"),
                                    }
                                })?,
                            })
                        })
                        .collect::<CoreResult<Vec<_>>>()?,
                    permissions: yaml
                        .spec
                        .permissions
                        .iter()
                        .map(|p| crate::domain::skill::SkillPermission::from(p.clone()))
                        .collect(),
                };
                record_file(
                    &mut files,
                    &root,
                    &manifest_path,
                    &mut total_bytes,
                    &Skill::sha256_hex(manifest_text.as_bytes()),
                );
                record_file(&mut files, &root, &body_path, &mut total_bytes, &body_hash);
                skills.push(skill);
            }
        }

        // ---- finalize snapshot identity ----
        files.sort_by(|a, b| a.relative.cmp(&b.relative));
        let mut hasher = Sha256::new();
        for f in &files {
            hasher.update(f.relative.as_bytes());
            hasher.update(b"\0");
            hasher.update(f.sha256.as_bytes());
            hasher.update(b"\n");
        }
        snapshot.commit_sha = hex::encode(hasher.finalize());
        snapshot.agent_count = agents.len() as u32;

        // Apply scan policy verdict to the snapshot.
        let findings_block = findings
            .iter()
            .filter(|f| matches!(f.severity, crate::application::scanner::Severity::Block))
            .count() as u32;
        let findings_warn = findings
            .iter()
            .filter(|f| matches!(f.severity, crate::application::scanner::Severity::Warn))
            .count() as u32;
        let findings_pass = findings
            .iter()
            .filter(|f| matches!(f.severity, crate::application::scanner::Severity::Pass))
            .count() as u32;
        if findings_block > 0 {
            snapshot.status = SnapshotStatus::Blocked;
            snapshot.scan_note = Some(format!(
                "{findings_block} BLOCK finding(s) in scanned bodies"
            ));
        }

        let report = IngestReport {
            agents_parsed: agents.len() as u32,
            agents_rejected: rejected_agents,
            divisions_loaded: divisions.len() as u32,
            files_scanned: files.len() as u32,
            total_bytes,
            findings_block,
            findings_warn,
            findings_pass,
        };

        Ok((
            IngestResult {
                snapshot,
                divisions,
                agents,
                skills,
                files,
                findings,
            },
            report,
        ))
    }
}

impl Default for IngestV2Service {
    fn default() -> Self {
        Self::new()
    }
}

// ---------- helpers (file walking, scanning, time) ----------

fn collect_subdirs(dir: &Path) -> CoreResult<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir).map_err(CoreError::ErrIo)? {
        let entry = entry.map_err(CoreError::ErrIo)?;
        let p = entry.path();
        if p.is_dir() {
            out.push(p);
        }
    }
    out.sort();
    Ok(out)
}

fn record_file(
    files: &mut Vec<ObservedFile>,
    root: &Path,
    p: &Path,
    total: &mut u64,
    sha256: &str,
) {
    let meta = match fs::metadata(p) {
        Ok(m) => m,
        Err(_) => return,
    };
    let size = meta.len();
    *total += size;
    files.push(ObservedFile {
        relative: rel(root, p),
        sha256: sha256.to_string(),
        size_bytes: size,
    });
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .components()
        .map(|c| {
            let s = c.as_os_str().to_string_lossy().to_string();
            s.replace('\\', "/")
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn read_divisions_v2(root: &Path) -> Result<DivisionIndex, String> {
    let p = root.join("divisions.json");
    if !p.exists() {
        // v2 catalogs may omit divisions.json if no divisions are
        // used. The v1 reader required the file; v2 allows an empty
        // default.
        return Ok(DivisionIndex::new());
    }
    let text = fs::read_to_string(&p).map_err(|e| format!("read: {e}"))?;
    let parsed: crate::domain::division::UpstreamDivisionsFile =
        serde_json::from_str(&text).map_err(|e| format!("parse: {e}"))?;
    Ok(DivisionIndex::from_upstream(&parsed))
}

fn now_utc() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

#[cfg(test)]
#[path = "ingest_v2_tests.rs"]
mod tests;
