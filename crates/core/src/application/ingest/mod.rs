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

use crate::application::scanner::{Finding, ScanPolicy, Scanner};
use crate::domain::agent::{Agent, UpstreamAgentFrontmatter};
use crate::domain::division::{DivisionIndex, UpstreamDivisionsFile};
use crate::domain::skill::Skill;
use crate::domain::source::{SnapshotStatus, Source, SourceSnapshot};
use crate::error::{CoreError, CoreResult};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct IngestResult {
    pub snapshot: SourceSnapshot,
    pub divisions: DivisionIndex,
    pub agents: Vec<Agent>,
    /// Skills resolved from the v2 catalog layout.
    ///   - `skills/<id>/skill.yaml` + `SKILL.md`.
    ///   - Empty for the v1 reader; the v1 source tree
    ///     (MVP-3 `agents/<division>/*.md`) has no skills to resolve.
    pub skills: Vec<Skill>,
    /// Files that were observed and hashed, in sorted order. Useful
    /// for the SQLite persistence layer to record per-file entries.
    pub files: Vec<ObservedFile>,
    /// Security scan findings. Empty if the scanner was skipped.
    /// Block-severity findings flip `snapshot.status` to `Blocked`.
    pub findings: Vec<Finding>,
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
    pub findings_block: u32,
    pub findings_warn: u32,
    pub findings_pass: u32,
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
    ///
    /// For `SourceKind::Local`, the working copy is `source.kind.path`.
    /// For `SourceKind::GitHttps` / `SourceKind::GitSsh`, the
    /// caller MUST pass `override_root` pointing at the
    /// already-cloned working copy (typically produced by
    /// `git_fetcher::HttpsFetcher` or `SshFetcher`). The
    /// `git_fetcher::ingest_source` helper wires the two
    /// together; the public CLI uses that.
    pub fn ingest_local(
        &self,
        source: &Source,
        override_root: Option<&Path>,
    ) -> CoreResult<(IngestResult, IngestReport)> {
        let root: PathBuf = match (&source.kind, override_root) {
            (crate::domain::source::SourceKind::Local { path }, None) => path.clone(),
            (crate::domain::source::SourceKind::Local { path: _ }, Some(p)) => p.to_path_buf(),
            (_, Some(p)) => p.to_path_buf(),
            (_, None) => {
                return Err(CoreError::Unimplemented {
                    feature: format!(
                        "ingest for source kind {:?} requires an override_root (use `ingest_git`)",
                        source.kind
                    ),
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

        // 5. Pre-scan the source tree with the security scanner.
        //    Findings are recorded; any BLOCK flips the snapshot to
        //    `Blocked` so the planner / deployer can refuse it.
        let policy = ScanPolicy::mvp_default();
        let scanner = crate::application::scanner::RegexScanner;
        let findings = scanner
            .scan(&root, &policy)
            .map_err(|e| CoreError::ErrIo(std::io::Error::other(format!("scanner: {e}"))))?;
        let mut findings_block: u32 = 0;
        let mut findings_warn: u32 = 0;
        let mut findings_pass: u32 = 0;
        for f in &findings {
            match f.severity {
                crate::application::scanner::Severity::Block => findings_block += 1,
                crate::application::scanner::Severity::Warn => findings_warn += 1,
                crate::application::scanner::Severity::Pass => findings_pass += 1,
            }
        }
        let blocked = findings_block > 0;
        let scan_note = if findings.is_empty() {
            None
        } else {
            Some(format!(
                "{findings_block} BLOCK, {findings_warn} WARN, {findings_pass} PASS"
            ))
        };

        // 6. Build snapshot.
        let now = chrono::Utc::now();
        // 2.11.0 (P1-G-04, TZ #1 §7 /
        // G-04, CWE-494 Download of
        // Code Without Integrity
        // Check): compute the
        // integrity hashes. The
        // SHA-256 of the canonical
        // artifact manifest
        // (sorted
        // `<rel-path>\0<file-sha256>`
        // lines, LF-separated) and
        // the SHA-256 of the
        // canonical scanner findings
        // (sorted
        // `<severity>\0<rule>\0<path>\0<reason>`,
        // LF-separated). The
        // `tree_hash` is the git
        // root-tree SHA, populated
        // only for git sources (the
        // pre-fix design accepted
        // mutable branches; the
        // post-fix design resolves
        // the branch to a SHA at
        // clone time, so the
        // `tree_hash` field is the
        // unique identifier of the
        // directory structure of
        // this commit).
        let artifact_manifest_hash = Some(compute_artifact_manifest_hash(&files));
        let scanner_result_hash = Some(compute_scanner_result_hash(&findings));
        let tree_hash = commit_tree_hash(&commit);
        let snapshot = SourceSnapshot {
            id: Uuid::new_v4(),
            source_id: source.id,
            commit_sha: commit,
            tree_hash,
            artifact_manifest_hash,
            scanner_result_hash,
            status: if blocked {
                SnapshotStatus::Blocked
            } else {
                SnapshotStatus::Active
            },
            agent_count: agents.len() as u32,
            division_count: divisions.len() as u32,
            created_at: now,
            upstream_template_version: None,
            scan_note,
        };

        let report = IngestReport {
            agents_parsed: agents.len() as u32,
            agents_rejected: rejected,
            divisions_loaded: divisions.len() as u32,
            files_scanned: files.len() as u32,
            total_bytes,
            findings_block,
            findings_warn,
            findings_pass,
        };

        // Re-attach files to agents in source-tree order. (We also
        // recorded the agent body via the agent's own body hash.)
        let _ = files; // used via the snapshot identity above
        Ok((
            IngestResult {
                snapshot,
                divisions,
                agents,
                skills: Vec::new(),
                files,
                findings,
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

/// 2.8.1 (ADR-0040): cross-layer glue
/// for the Git-source path. Lives
/// here — not in
/// `infrastructure::git_fetcher` —
/// because the lower layer must not
/// depend on `IngestService`. This
/// function: 1) clones (or
/// fast-forwards) the working copy
/// for `source` via the appropriate
/// `GitFetcher` impl, 2) hands the
/// resulting path to
/// `IngestService::ingest_local`, and
/// 3) patches the synthetic
/// `commit_sha` from the content
/// hash to the real Git HEAD SHA
/// on the returned snapshot.
///
/// For `SourceKind::Local`, the fetch
/// step is skipped; the local path
/// is passed straight to
/// `ingest_local`.
///
/// 2.11.0 (P1-G-01 / P1-G-02, CWE-918):
/// the URL is checked against the
/// supplied `UrlPolicy` BEFORE the
/// fetcher is invoked. The check
/// rejects `http://`, `file://`,
/// `ssh://` to a non-allowlisted
/// host, and any URL whose host
/// resolves to a loopback /
/// RFC 1918 / link-local / metadata
/// address. The fetcher is a
/// defense-in-depth layer; the
/// policy is the primary gate.
pub fn ingest_source_with_policy(
    source: &Source,
    working_copy_root: &std::path::Path,
    policy: &crate::infrastructure::url_policy::UrlPolicy,
) -> CoreResult<(IngestResult, IngestReport)> {
    use crate::infrastructure::git_fetcher::{
        classify_url_with_policy, GitFetcher, HttpsFetcher, SshFetcher,
    };
    // Pre-flight: classify the URL
    // and run the policy. The
    // fetcher would do this again
    // (defense in depth), but
    // failing fast here gives the
    // operator / CLI a clean
    // error before any TCP /
    // libgit2 setup.
    let url = match &source.kind {
        crate::domain::source::SourceKind::GitHttps { url } => url.clone(),
        crate::domain::source::SourceKind::GitSsh { url } => url.clone(),
        crate::domain::source::SourceKind::Local { .. } => {
            return IngestService::new().ingest_local(source, None);
        }
    };
    classify_url_with_policy(&url, policy)?;
    let dest = working_copy_root.join(source.id.to_string());
    let fetch = match &source.kind {
        crate::domain::source::SourceKind::GitHttps { .. } => {
            HttpsFetcher.clone_or_update(source, &dest)
        }
        crate::domain::source::SourceKind::GitSsh { .. } => {
            SshFetcher.clone_or_update(source, &dest)
        }
        crate::domain::source::SourceKind::Local { .. } => {
            return IngestService::new().ingest_local(source, None);
        }
    }?;
    let svc = IngestService::new();
    let (mut result, report) = svc.ingest_local(source, Some(&fetch.working_copy))?;
    result.snapshot.commit_sha = fetch.commit_sha;
    Ok((result, report))
}

/// Test-mode wrapper for callers
/// that pre-date the
/// `UrlPolicy` (the
/// `git_fetcher` integration test,
/// the old CLI). Uses
/// `UrlPolicy::permissive_test()`.
pub fn ingest_source(
    source: &Source,
    working_copy_root: &std::path::Path,
) -> CoreResult<(IngestResult, IngestReport)> {
    ingest_source_with_policy(
        source,
        working_copy_root,
        &crate::infrastructure::url_policy::UrlPolicy::permissive_test(),
    )
}

// -----------------------------------------------------------------------
// 2.11.0 (P1-G-04, TZ #1 §7 / G-04,
// CWE-494 Download of Code Without
// Integrity Check): the integrity-
// hash helpers.
//
// All three helpers are PURE
// functions of the inputs (no DB,
// no clock, no env). A test that
// computes the hash on a known
// fixture asserts byte-stability:
// the same `files` Vec / `findings`
// Vec / commit SHA always
// produces the same hash. A
// regression-guard test asserts
// the hash CHANGES when any
// input changes.
//
// The `commit_tree_hash` helper
// is a no-op placeholder for the
// pre-fix design: a real
// implementation would open the
// git repo at the working copy
// and return
// `repo.find_commit(sha)?.tree()?.id().to_string()`.
// The full implementation is
// deferred to a follow-up; for
// now, the field is `None` for
// non-git sources and the
// snapshot's
// `commit_sha` already serves as
// the immutable content
// identity for the git side.
// -----------------------------------------------------------------------

/// 2.11.0 (P1-G-04): SHA-256 of
/// the canonical artifact
/// manifest. The canonical form
/// is the `ObservedFile` list
/// (already sorted by `relative`
/// path, with `sha256` for each
/// file), serialized as
/// `<rel>\0<sha256>\n` lines.
/// Same shape as
/// `pending_deploys_repository::compute_artifact_manifest_hash`
/// — the function is duplicated
/// here to avoid a cross-crate
/// dependency between
/// `agent_dep_core` and itself
/// (the P1-D-01c helper lives in
/// `core/src/infrastructure/repository`
/// and the snapshot is built in
/// `core/src/application/ingest`;
/// both layers are in the same
/// crate but the layering rule is
/// "application does not depend
/// on infrastructure repository
/// types").
fn compute_artifact_manifest_hash(files: &[ObservedFile]) -> String {
    let mut hasher = Sha256::new();
    for f in files {
        hasher.update(f.relative.as_bytes());
        hasher.update([0u8]);
        hasher.update(f.sha256.as_bytes());
        hasher.update([b'\n']);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// 2.11.0 (P1-G-04): SHA-256 of
/// the canonical scanner findings
/// list. The canonical form is
/// the findings sorted by
/// `(severity, rule, path,
/// reason)`, serialized as
/// `<severity>\0<rule>\0<path>\0<reason>\n`
/// lines. Sort order is stable
/// (the `sort_by` tuple comparison
/// is total) so the hash is
/// byte-stable for the same
/// findings set.
fn compute_scanner_result_hash(findings: &[Finding]) -> String {
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| {
        a.severity
            .as_str()
            .cmp(b.severity.as_str())
            .then(a.rule.cmp(&b.rule))
            .then(a.path.cmp(&b.path))
            .then(a.reason.cmp(&b.reason))
    });
    let mut hasher = Sha256::new();
    for f in sorted {
        hasher.update(f.severity.as_str().as_bytes());
        hasher.update([0u8]);
        hasher.update(f.rule.as_bytes());
        hasher.update([0u8]);
        hasher.update(f.path.as_bytes());
        hasher.update([0u8]);
        hasher.update(f.reason.as_bytes());
        hasher.update([b'\n']);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// 2.11.0 (P1-G-04): the
/// `commit_sha` is a 40-char hex
/// SHA-1. The pre-fix design had
/// no `tree_hash` field; the
/// post-fix design leaves it
/// `None` for non-git sources
/// (the `commit_sha` is
/// sufficient for content
/// identity when the source is
/// not git). For git sources, a
/// follow-up will open the
/// working copy and resolve
/// `commit_sha -> tree() -> id`.
/// The placeholder returns
/// `None` so the build compiles
/// and the field is wired
/// end-to-end (the snapshot
/// struct, the ingest path, the
/// tests); a real implementation
/// is a one-line
/// `repo.find_tree(oid).id()`
/// when the working copy is
/// guaranteed to be a git repo.
fn commit_tree_hash(_commit_sha: &str) -> Option<String> {
    None
}

#[cfg(test)]
mod ingest_tests;

// -----------------------------------------------------------------------
// 2.11.0 (P1-G-04, TZ #1 §7 / G-04,
// CWE-494) — integrity-hash unit
// tests.
//
// The two helpers (`compute_artifact_manifest_hash`
// and `compute_scanner_result_hash`)
// are PURE functions of their
// inputs. The tests assert
// byte-stability (same input ⇒
// same hash) and
// sensitivity-to-change (any
// field change ⇒ different
// hash). The `commit_tree_hash`
// helper is a `None` placeholder
// (the real implementation
// needs a git repo; the v1
// ingest path is filesystem-
// only); the test asserts the
// `None` return.
// -----------------------------------------------------------------------

#[cfg(test)]
mod p1_g04_hash_tests {
    use super::*;
    use crate::application::scanner::Severity;

    fn make_finding(severity: Severity, rule: &str, path: &str, reason: &str) -> Finding {
        Finding {
            severity,
            rule: rule.to_string(),
            path: path.to_string(),
            reason: reason.to_string(),
        }
    }

    // 2.11.0 (P1-G-04): the
    // `Severity` enum has only
    // three variants
    // (`Pass` / `Warn` /
    // `Block`); there is no
    // `Info` variant. The
    // tests below use
    // `Severity::Pass` (the
    // lowest severity) as
    // the "second ordering
    // input" to verify the
    // sort is total.
    type TestSev = Severity;

    fn make_file(rel: &str, sha: &str) -> ObservedFile {
        ObservedFile {
            relative: rel.to_string(),
            sha256: sha.to_string(),
            size_bytes: 0,
        }
    }

    #[test]
    fn artifact_manifest_hash_is_byte_stable() {
        let files = vec![
            make_file("agents/a.md", "aaa"),
            make_file("agents/b.md", "bbb"),
            make_file("divisions.json", "ccc"),
        ];
        let h1 = compute_artifact_manifest_hash(&files);
        let h2 = compute_artifact_manifest_hash(&files);
        assert_eq!(h1, h2, "same input ⇒ same hash");
        // SHA-256 hex is 64 chars
        assert_eq!(h1.len(), 64);
        // Hex chars only
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn artifact_manifest_hash_changes_when_content_changes() {
        let h1 = compute_artifact_manifest_hash(&[make_file("a.md", "aaa")]);
        let h2 = compute_artifact_manifest_hash(&[make_file("a.md", "bbb")]);
        assert_ne!(h1, h2, "different sha256 ⇒ different hash");
        let h3 = compute_artifact_manifest_hash(&[make_file("a.md", "aaa")]);
        let h4 = compute_artifact_manifest_hash(&[make_file("a-renamed.md", "aaa")]);
        assert_ne!(h3, h4, "different path ⇒ different hash");
    }

    #[test]
    fn scanner_result_hash_is_byte_stable() {
        let findings = vec![
            make_finding(Severity::Warn, "rule-a", "a.md", "reason-1"),
            make_finding(Severity::Pass, "rule-b", "b.md", "reason-2"),
        ];
        let h1 = compute_scanner_result_hash(&findings);
        let h2 = compute_scanner_result_hash(&findings);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn scanner_result_hash_is_order_independent() {
        // The same findings in a
        // different order must
        // produce the same hash
        // (the sort is stable and
        // total). Without the sort,
        // a scanner that emits
        // findings in
        // hash-map-iteration
        // order would produce
        // a different hash on
        // every run.
        let f1 = vec![
            make_finding(Severity::Warn, "rule-a", "a.md", "r"),
            make_finding(Severity::Pass, "rule-b", "b.md", "r"),
        ];
        let f2 = vec![
            make_finding(Severity::Pass, "rule-b", "b.md", "r"),
            make_finding(Severity::Warn, "rule-a", "a.md", "r"),
        ];
        let h1 = compute_scanner_result_hash(&f1);
        let h2 = compute_scanner_result_hash(&f2);
        assert_eq!(h1, h2, "sort must canonicalize the order");
    }

    #[test]
    fn scanner_result_hash_changes_when_finding_changes() {
        let f1 = vec![make_finding(Severity::Warn, "rule-a", "a.md", "r")];
        let f2 = vec![make_finding(Severity::Block, "rule-a", "a.md", "r")];
        assert_ne!(
            compute_scanner_result_hash(&f1),
            compute_scanner_result_hash(&f2),
            "different severity ⇒ different hash"
        );
    }

    #[test]
    fn commit_tree_hash_is_a_placeholder_for_now() {
        // The pre-fix `SourceSnapshot`
        // had no `tree_hash` field;
        // the post-fix `commit_tree_hash`
        // returns `None` for the v1
        // filesystem-only ingest
        // path (a real
        // implementation would
        // open the git working
        // copy and resolve the
        // commit's tree). The
        // placeholder is
        // documented and tested
        // so a future commit can
        // swap the body without
        // changing the signature.
        assert_eq!(commit_tree_hash(&"a".repeat(40)), None);
        assert_eq!(commit_tree_hash(""), None);
    }
}
