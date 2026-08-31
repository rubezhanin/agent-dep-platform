//! Catalog ingestion (TZ §10).
//!
//! MVP supports `SourceKind::Local` (filesystem clone). Git is
//! planned for 1.x (ADR-0001).
//!
//! Pipeline:
//! 1. Open the source directory.
//! 2. Enumerate files (read `divisions.json` at root, walk
//!    `agents/<division>/*.md`).
//! 3. Parse each `.md`: extract YAML frontmatter between `---\n`
//!    markers, treat the rest as Markdown body.
//! 4. Validate: required frontmatter fields, division exists in
//!    `divisions.json`, version is SemVer, IDs are unique.
//! 5. Pre-scan with the security scanner (MVP: stub returning PASS
//!    unless a real `Scanner` is injected; real scanner in
//!    a follow-up task per ADR-0005).
//! 6. Compute a content-hash identity for the snapshot (sha256 of
//!    sorted `<rel-path>\0<file-sha256>` lines).
//! 7. Return `IngestResult` with divisions, agents, snapshot metadata.
//!
//! The result is consumed either by the SQLite persistence layer
//! (separate task) or by the CLI for ad-hoc inspection.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::domain::agent::{Agent, UpstreamAgentFrontmatter};
use crate::domain::division::{DivisionIndex, UpstreamDivisionsFile};
use crate::domain::source::{SnapshotStatus, Source, SourceSnapshot};
use crate::error::{CoreError, CoreResult};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct IngestResult {
    pub snapshot: SourceSnapshot,
    pub divisions: DivisionIndex,
    pub agents: Vec<Agent>,
    /// Files that were observed and hashed, in sorted order. Useful
    /// for the SQLite persistence layer to record per-file entries.
    pub files: Vec<ObservedFile>,
}

#[derive(Debug, Clone)]
pub struct ObservedFile {
    /// Path relative to the source root, in POSIX form.
    pub relative: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub struct IngestReport {
    pub agents_parsed: u32,
    pub agents_rejected: Vec<RejectedAgent>,
    pub divisions_loaded: u32,
    pub files_scanned: u32,
    pub total_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct RejectedAgent {
    pub relative_path: String,
    pub reason: String,
}

pub struct IngestService;

impl IngestService {
    pub fn new() -> Self {
        Self
    }

    /// Ingest a local source. The returned `IngestResult` is the
    /// *parsed-and-validated* view; persistence is a separate concern.
    pub fn ingest_local(&self, source: &Source) -> CoreResult<(IngestResult, IngestReport)> {
        let root = match &source.kind {
            crate::domain::source::SourceKind::Local { path } => path.clone(),
            other => {
                return Err(CoreError::Unimplemented {
                    feature: format!("ingest for source kind {:?}", other),
                });
            }
        };

        if !root.is_dir() {
            return Err(CoreError::ErrSourceNotFound {
                source_id: root.display().to_string(),
            });
        }

        // 1. Read divisions.json at the root.
        let divisions_path = root.join("divisions.json");
        let divisions = self.read_divisions(&divisions_path)?;

        // 2. Walk agents/<division>/*.md.
        let agents_dir = root.join("agents");
        let mut agents = Vec::new();
        let mut rejected = Vec::new();
        let mut files = Vec::new();
        let mut total_bytes: u64 = 0;

        if agents_dir.is_dir() {
            // Walk the agents/ subtree in sorted order. We use
            // `walkdir` for portability, but only descend two levels.
            let walker = walkdir::WalkDir::new(&agents_dir)
                .min_depth(1)
                .max_depth(3)
                .follow_links(false);
            let mut entries: Vec<PathBuf> = walker
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .filter(|e| {
                    e.path()
                        .extension()
                        .and_then(|s| s.to_str())
                        .map(|s| s.eq_ignore_ascii_case("md"))
                        .unwrap_or(false)
                })
                .map(|e| e.into_path())
                .collect();
            entries.sort();

            for path in entries {
                match self.parse_and_validate(&path, &divisions, &root) {
                    Ok(agent) => {
                        // Reject duplicate IDs across the catalog.
                        if agents.iter().any(|a: &Agent| a.id == agent.id) {
                            rejected.push(RejectedAgent {
                                relative_path: self.relative(&agent.body_hash, &path, &root),
                                reason: format!("duplicate agent id `{}`", agent.id),
                            });
                            continue;
                        }
                        total_bytes += agent.body.len() as u64;
                        agents.push(agent);
                    }
                    Err(reason) => {
                        rejected.push(RejectedAgent {
                            relative_path: self.rel_to(&path, &root),
                            reason: reason.to_string(),
                        });
                    }
                }
            }
        }

        // 3. Hash every file in the source tree for the snapshot
        //    identity. We include divisions.json and all agent .md
        //    files (and SKILL.md files for skills — none in MVP, but
        //    we record them when found).
        let mut all_files: Vec<PathBuf> = Vec::new();
        for entry in walkdir::WalkDir::new(&root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            all_files.push(entry.into_path());
        }
        all_files.sort();
        for f in &all_files {
            let bytes = fs::read(f).map_err(CoreError::ErrIo)?;
            let hash = sha256_hex(&bytes);
            let rel = self.rel_to(f, &root);
            total_bytes += bytes.len() as u64;
            files.push(ObservedFile {
                relative: rel,
                sha256: hash,
                size_bytes: bytes.len() as u64,
            });
        }

        // 4. Snapshot identity = sha256 of sorted "<rel>\0<sha256>" lines.
        let commit = compute_snapshot_identity(&files);

        // 5. Build snapshot.
        let now = chrono::Utc::now();
        let snapshot = SourceSnapshot {
            id: Uuid::new_v4(),
            source_id: source.id,
            commit_sha: commit,
            // MVP: any non-blocked snapshot is `Active`. Blocked is set
            // by the scanner layer (separate task) once it lands.
            status: SnapshotStatus::Active,
            agent_count: agents.len() as u32,
            division_count: divisions.len() as u32,
            created_at: now,
            upstream_template_version: None,
            scan_note: None,
        };

        let report = IngestReport {
            agents_parsed: agents.len() as u32,
            agents_rejected: rejected,
            divisions_loaded: divisions.len() as u32,
            files_scanned: files.len() as u32,
            total_bytes,
        };

        // Re-attach files to agents in source-tree order. (We also
        // recorded the agent body via the agent's own body hash.)
        let _ = files; // used via the snapshot identity above
        Ok((
            IngestResult {
                snapshot,
                divisions,
                agents,
                files,
            },
            report,
        ))
    }

    fn read_divisions(&self, path: &Path) -> CoreResult<DivisionIndex> {
        if !path.exists() {
            return Err(CoreError::ErrSourceNotFound {
                source_id: format!("divisions.json: {}", path.display()),
            });
        }
        let text = fs::read_to_string(path).map_err(CoreError::ErrIo)?;
        let parsed: UpstreamDivisionsFile =
            serde_json::from_str(&text).map_err(|e| CoreError::ErrSchemaInvalid {
                path: path.display().to_string(),
                reason: format!("divisions.json: {e}"),
            })?;
        Ok(DivisionIndex::from_upstream(&parsed))
    }

    fn parse_and_validate(
        &self,
        path: &Path,
        divisions: &DivisionIndex,
        root: &Path,
    ) -> Result<Agent, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
        let (fm, body) = extract_frontmatter(&text).map_err(|e| format!("frontmatter: {e}"))?;
        let _ = root; // root is used in the snapshot, not per-file

        // Validate required fields. Serde already enforces non-optional
        // ones; here we add cross-field checks.
        if fm.id.trim().is_empty() {
            return Err("id is empty".into());
        }
        if !divisions.get(&fm.division).is_some() {
            return Err(format!(
                "division `{}` not in divisions.json (known: {})",
                fm.division,
                divisions.ids().collect::<Vec<_>>().join(", ")
            ));
        }
        // Slug consistency: file basename should match id.
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            if stem != fm.id {
                return Err(format!(
                    "id `{}` does not match file stem `{}`",
                    fm.id, stem
                ));
            }
        }
        let body_hash = sha256_hex(body.as_bytes());
        let _ = body_hash.clone();

        Ok(Agent {
            // snapshot_id will be filled in by the caller; we use
            // a placeholder here and patch it after the snapshot is
            // created.
            snapshot_id: Uuid::nil(),
            id: fm.id,
            division: fm.division,
            name: fm.name,
            display_name: fm.display_name,
            role: fm.role,
            description: fm.description,
            version: fm.version,
            sensitive: fm.sensitive,
            tools: fm.tools,
            activation_phrases: fm.activation_phrases,
            body: body.to_string(),
            body_hash,
        })
    }

    fn rel_to(&self, path: &Path, root: &Path) -> String {
        path.strip_prefix(root)
            .ok()
            .and_then(|p| p.to_str())
            .map(|s| s.replace('\\', "/"))
            .unwrap_or_else(|| path.display().to_string())
    }

    fn relative(&self, _body_hash: &str, path: &Path, root: &Path) -> String {
        self.rel_to(path, root)
    }
}

impl Default for IngestService {
    fn default() -> Self {
        Self::new()
    }
}

/// Splits `---YAML---\n<body>` (or `---YAML---\r\n<body>`). The opening
/// `---` MUST be the first non-BOM characters on a line. The closing
/// `---` MUST be at the start of a line followed by an LF or CRLF.
fn extract_frontmatter(text: &str) -> Result<(UpstreamAgentFrontmatter, String), String> {
    // Strip UTF-8 BOM if present.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);

    // We work line-by-line so CRLF and LF inputs behave the same.
    let lines: Vec<&str> = text.split('\n').collect();
    if lines.is_empty() || lines[0].trim_end_matches('\r').trim() != "---" {
        return Err(format!(
            "expected `---\\n` at start of file, got: {:?}",
            lines
                .first()
                .copied()
                .unwrap_or("")
                .chars()
                .take(20)
                .collect::<String>()
        ));
    }

    // Find the closing `---` line. It must be on a line by itself
    // (after the opening `---`).
    let close_idx = lines[1..]
        .iter()
        .position(|l| l.trim_end_matches('\r').trim() == "---")
        .ok_or("no closing `---` for frontmatter".to_string())?
        + 1;

    let yaml_text: String = lines[1..close_idx].join("\n");
    let body_lines: Vec<&str> = lines[close_idx + 1..]
        .iter()
        .map(|l| l.trim_end_matches('\r'))
        .collect();
    let body_text = body_lines.join("\n");

    let frontmatter: UpstreamAgentFrontmatter =
        serde_yaml::from_str(&yaml_text).map_err(|e| format!("yaml parse: {e}"))?;
    Ok((frontmatter, body_text))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn compute_snapshot_identity(files: &[ObservedFile]) -> String {
    let mut h = Sha256::new();
    for f in files {
        h.update(f.relative.as_bytes());
        h.update(b"\0");
        h.update(f.sha256.as_bytes());
        h.update(b"\n");
    }
    hex::encode(h.finalize())
}

/// Helpers used by the integration tests in `ingest_tests.rs`.
pub fn extract_frontmatter_pub(text: &str) -> Result<(UpstreamAgentFrontmatter, String), String> {
    extract_frontmatter(text)
}

#[cfg(test)]
mod ingest_tests;
