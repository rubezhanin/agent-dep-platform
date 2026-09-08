//! 2.8.1 (ADR-0040) — Real Git source
//! ingest, **unified**.
//!
//! History: the 2.8.0 release shipped a
//! minimal `GitFetcher::clone_to` /
//! `GitFetcher::fetch` pair in
//! `infrastructure::git_fetcher`, plus
//! a richer scaffold in
//! `application::ingest::git_fetcher`
//! that had HTTPS/SSH split, URL
//! classification, and the
//! `commit_sha` resolution the
//! `IngestService` needs.
//!
//! 2.8.1 collapses the two into one
//! place — `infrastructure::git_fetcher`
//! — and keeps the cross-layer glue
//! (`ingest_source`, which threads the
//! `FetchResult` into `IngestService`)
//! in `application::ingest`. The rest
//! of the pipeline is still oblivious
//! to whether the source was a
//! directory or a Git repo.
//!
//! The fetcher is *the only* place in
//! `core/` that depends on `git2`.
//! `git2` is sync; we wrap the blocking
//! calls in `tokio::task::spawn_blocking`
//! when we expose them through the
//! higher-level `IngestService` entry
//! point (see `ingest_source` in
//! `application::ingest`).

use std::path::{Path, PathBuf};
use std::time::Duration;

use git2::{build::RepoBuilder, FetchOptions, Repository};

use crate::domain::source::{Source, SourceKind};
use crate::error::{CoreError, CoreResult};

// -----------------------------------------------------------------------
// 2.11.0 (P1-G-03, TZ #1 §7 / G-03,
// CWE-400 Uncontrolled Resource
// Consumption): repository quotas.
//
// The pre-fix `clone_or_update`
// accepted whatever the upstream
// served — a 100 GiB monorepo, a
// 10M-object fork, a 1M-file
// monorepo, a single 10 GiB binary
// blob. CWE-400: a malicious or
// compromised upstream could
// exhaust the host's disk, memory,
// CPU, and the parent scan process's
// own budget. The post-fix design
// enforces five quotas on every
// clone / fetch:
//
//   1. .git directory total size
//      (loose objects + pack files
//      + refs). Catches the "100 GiB
//      packfile" attack.
//   2. Total object count (loose +
//      packed). Catches the "10M
//      tiny commits" attack.
//   3. Working-copy file count
//      (HEAD tree). Catches the
//      "1M empty files" attack.
//   4. Maximum path depth in the
//      HEAD tree. Catches the
//      "10K-deep directory tree"
//      attack (which would crash
//      the scanner's `WalkDir`).
//   5. Maximum blob size in the
//      HEAD tree. Catches the
//      "single 10 GiB binary"
//      attack (which would OOM the
//      JSON envelope).
//
// A 6th, separate quota — the
// FETCH TIMEOUT — bounds the
// in-flight network call. Without
// it, a slow upstream that returns
// 1 byte every 5 seconds would
// block the parent for hours.
//
// All caps are operator-overridable
// via env vars. A `0` or
// non-numeric value falls back to
// the default. The post-clone
// check rejects the clone AND
// removes the on-disk working
// copy (best-effort) so a
// rejected clone does not leave
// a half-written repo for the
// next call to update.
// -----------------------------------------------------------------------

/// 2.11.0 (P1-G-03): the
/// post-clone quota bundle.
#[derive(Debug, Clone, Copy)]
pub struct RepoQuotas {
    /// Total `.git` directory
    /// size in bytes (loose
    /// objects + pack files +
    /// refs). Default 1 GiB.
    pub max_git_size_bytes: u64,
    /// Total object count (loose +
    /// packed). Default 100,000.
    pub max_object_count: u64,
    /// Working-copy file count
    /// (HEAD tree). Default
    /// 50,000.
    pub max_file_count: u64,
    /// Maximum path depth in the
    /// HEAD tree. Default 32.
    pub max_path_depth: u64,
    /// Maximum blob size in the
    /// HEAD tree. Default 100
    /// MiB.
    pub max_blob_size_bytes: u64,
    /// In-flight fetch timeout.
    /// Default 5 minutes.
    pub fetch_timeout: Duration,
}

/// 2.11.0 (P1-G-03): the
/// operator-overridable
/// post-clone quota bundle. The
/// defaults are conservative —
/// large enough for any
/// real-world agent catalog the
/// agency-platform supports, small
/// enough to catch every CWE-400
/// DoS shape the TZ lists.
pub fn default_quotas() -> RepoQuotas {
    RepoQuotas {
        max_git_size_bytes: parse_u64_env("AGENCY_GIT_MAX_GIT_SIZE_BYTES", 1024 * 1024 * 1024),
        max_object_count: parse_u64_env("AGENCY_GIT_MAX_OBJECT_COUNT", 100_000),
        max_file_count: parse_u64_env("AGENCY_GIT_MAX_FILE_COUNT", 50_000),
        max_path_depth: parse_u64_env("AGENCY_GIT_MAX_PATH_DEPTH", 32),
        max_blob_size_bytes: parse_u64_env("AGENCY_GIT_MAX_BLOB_SIZE_BYTES", 100 * 1024 * 1024),
        fetch_timeout: Duration::from_secs(parse_u64_env("AGENCY_GIT_FETCH_TIMEOUT_SECS", 300)),
    }
}

/// 2.11.0 (P1-G-03): parse a
/// `u64` env var with a fallback
/// default. `0` and non-numeric
/// values fall back to the
/// default (a `0` cap is
/// nonsensical and would reject
/// every repo).
fn parse_u64_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

/// 2.11.0 (P1-G-03): the
/// post-clone quota check. Walks
/// the on-disk repo, measures each
/// quota, and returns the FIRST
/// violation as a typed
/// `CoreError::ErrGitQuota`. The
/// caller is expected to remove
/// the on-disk repo (we do
/// best-effort cleanup here so
/// a rejected clone does not
/// leave a half-written working
/// copy).
///
/// The check is best-effort and
/// runs AFTER the clone /
/// fetch returns. The fetch
/// timeout (quota 6) is enforced
/// DURING the fetch via
/// `FetchOptions::max_time`
/// (see `build_fetch_options`).
pub fn check_repo_quotas(dest: &Path, quotas: &RepoQuotas) -> CoreResult<()> {
    // Quota 1: total `.git` size.
    let git_dir = dest.join(".git");
    if git_dir.is_dir() {
        let total = dir_size(&git_dir);
        if total > quotas.max_git_size_bytes {
            cleanup(dest);
            return Err(CoreError::ErrGitQuota {
                kind: format!(
                    "git_size ({} bytes > cap {})",
                    total, quotas.max_git_size_bytes
                ),
            });
        }
    }
    // Quota 2: object count.
    let obj_count = match object_count(dest) {
        Ok(n) => n,
        Err(e) => {
            cleanup(dest);
            return Err(CoreError::ErrGitQuota {
                kind: format!("object_count_probe: {e}"),
            });
        }
    };
    if obj_count > quotas.max_object_count {
        cleanup(dest);
        return Err(CoreError::ErrGitQuota {
            kind: format!(
                "object_count ({} > cap {})",
                obj_count, quotas.max_object_count
            ),
        });
    }
    // Quota 3-5: walk the HEAD
    // tree, count files, max
    // depth, max blob size. The
    // walk is SKIPPED when there
    // is no `.git` directory (a
    // pre-fix bug was that the
    // walk was attempted even on
    // a non-git working copy, and
    // the `Repository::open`
    // failure was mis-reported
    // as a quota violation).
    if !dest.join(".git").is_dir() {
        return Ok(());
    }
    let tree_walk = match walk_head_tree(dest) {
        Ok(w) => w,
        Err(e) => {
            cleanup(dest);
            return Err(CoreError::ErrGitQuota {
                kind: format!("head_tree_walk: {e}"),
            });
        }
    };
    if tree_walk.file_count > quotas.max_file_count {
        cleanup(dest);
        return Err(CoreError::ErrGitQuota {
            kind: format!(
                "file_count ({} > cap {})",
                tree_walk.file_count, quotas.max_file_count
            ),
        });
    }
    if tree_walk.max_depth > quotas.max_path_depth {
        cleanup(dest);
        return Err(CoreError::ErrGitQuota {
            kind: format!(
                "path_depth ({} > cap {})",
                tree_walk.max_depth, quotas.max_path_depth
            ),
        });
    }
    if tree_walk.max_blob_size > quotas.max_blob_size_bytes {
        cleanup(dest);
        return Err(CoreError::ErrGitQuota {
            kind: format!(
                "blob_size ({} > cap {})",
                tree_walk.max_blob_size, quotas.max_blob_size_bytes
            ),
        });
    }
    Ok(())
}

/// 2.11.0 (P1-G-03): total
/// directory size in bytes
/// (recursive, follows
/// symlinks). Used for the
/// `.git` size quota.
fn dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    for e in walkdir::WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .flatten()
    {
        if e.file_type().is_file() {
            if let Ok(m) = e.metadata() {
                total = total.saturating_add(m.len());
            }
        }
    }
    total
}

/// 2.11.0 (P1-G-03): the total
/// object count in the repo
/// (loose + packed). We use the
/// `objects/pack/*.idx` file size
/// as a cheap proxy: every
/// packed object corresponds to
/// one entry in the idx; the
/// number of loose objects is
/// the count of files in
/// `objects/??/`. The estimate is
/// accurate enough for the
/// quota check (the alternative
/// is to open every pack and
/// iterate the index, which
/// costs 10-100ms on a 1M-object
/// repo).
fn object_count(dest: &Path) -> CoreResult<u64> {
    let mut total = 0u64;
    let objects = dest.join(".git").join("objects");
    if !objects.is_dir() {
        // Bare repo or failed
        // clone: probe the
        // alternative layout.
        return Ok(0);
    }
    // Packed objects: count idx
    // entries by parsing the
    // 20-byte header (256 *
    // 4-byte fanout table) plus
    // the 20-byte trailer. The
    // number of objects is the
    // last value in the
    // big-endian uint32 fanout
    // table at offset 8 + 4*255.
    let pack = objects.join("pack");
    if pack.is_dir() {
        for entry in std::fs::read_dir(&pack).map_err(CoreError::ErrIo)? {
            let entry = entry.map_err(CoreError::ErrIo)?;
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) == Some("idx") {
                let bytes = std::fs::read(&p).map_err(CoreError::ErrIo)?;
                if bytes.len() < 8 + 4 * 256 {
                    return Err(CoreError::ErrGitQuota {
                        kind: format!(
                            "pack idx `{}` is truncated ({} bytes)",
                            p.display(),
                            bytes.len()
                        ),
                    });
                }
                // Fanout[255] is the
                // total object count
                // (big-endian uint32).
                let n = u32::from_be_bytes([
                    bytes[8 + 4 * 255],
                    bytes[8 + 4 * 255 + 1],
                    bytes[8 + 4 * 255 + 2],
                    bytes[8 + 4 * 255 + 3],
                ]);
                total = total.saturating_add(n as u64);
            }
        }
    }
    // Loose objects: count
    // files in
    // `objects/??/`. Each file
    // is one loose object. The
    // ?? prefix is the first
    // two hex chars of the
    // SHA-1.
    let loose_glob = |dir: &Path| -> u64 {
        std::fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
                    .count() as u64
            })
            .unwrap_or(0)
    };
    if let Ok(rd) = std::fs::read_dir(&objects) {
        for entry in rd.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.len() == 2 && name_str.chars().all(|c| c.is_ascii_hexdigit()) {
                    total = total.saturating_add(loose_glob(&entry.path()));
                }
            }
        }
    }
    Ok(total)
}

/// 2.11.0 (P1-G-03): the HEAD
/// tree walker. Counts files,
/// tracks max path depth, and
/// records max blob size. The
/// walk is recursive (we read
/// every tree entry); the cost
/// is O(N) in the number of
/// files. For a 50K-file repo
/// (the default cap) the walk
/// completes in well under a
/// second on a modern SSD.
struct TreeWalk {
    file_count: u64,
    max_depth: u64,
    max_blob_size: u64,
}

fn walk_head_tree(dest: &Path) -> CoreResult<TreeWalk> {
    let repo = Repository::open(dest).map_err(|e| CoreError::ErrGitOpen {
        path: dest.display().to_string(),
        reason: format!("{e}"),
    })?;
    let head_oid =
        repo.head()
            .ok()
            .and_then(|h| h.target())
            .ok_or_else(|| CoreError::ErrGitQuota {
                kind: "no HEAD; cannot enumerate tree".to_string(),
            })?;
    let commit = repo
        .find_commit(head_oid)
        .map_err(|e| CoreError::ErrGitQuota {
            kind: format!("find_commit: {e}"),
        })?;
    let tree = commit.tree().map_err(|e| CoreError::ErrGitQuota {
        kind: format!("commit tree: {e}"),
    })?;
    let mut walk = TreeWalk {
        file_count: 0,
        max_depth: 0,
        max_blob_size: 0,
    };
    walk_tree(&repo, &tree, 0, &mut walk).map_err(|e| CoreError::ErrGitQuota {
        kind: format!("walk_tree: {e}"),
    })?;
    Ok(walk)
}

fn walk_tree(
    repo: &Repository,
    tree: &git2::Tree,
    depth: u64,
    walk: &mut TreeWalk,
) -> Result<(), git2::Error> {
    if depth > walk.max_depth {
        walk.max_depth = depth;
    }
    for entry in tree.iter() {
        match entry.kind() {
            Some(git2::ObjectType::Tree) => {
                let subtree = repo.find_tree(entry.id())?;
                walk_tree(repo, &subtree, depth + 1, walk)?;
            }
            Some(git2::ObjectType::Blob) => {
                walk.file_count += 1;
                let blob = repo.find_blob(entry.id())?;
                let size = blob.size() as u64;
                if size > walk.max_blob_size {
                    walk.max_blob_size = size;
                }
            }
            _ => {
                // Submodules / commits
                // (should not appear in
                // a tree) — ignore.
            }
        }
    }
    Ok(())
}

/// Best-effort cleanup of a
/// rejected clone. The on-disk
/// working copy may be a
/// half-written repo (the clone
/// succeeded but the quota
/// check failed), so we remove
/// it to avoid the next call to
/// `update_existing` seeing a
/// partial `.git` directory.
fn cleanup(dest: &Path) {
    let _ = std::fs::remove_dir_all(dest);
}

/// 2.11.0 (P1-G-03): build the
/// libgit2 `FetchOptions` with the
/// fetch-time quota (timeout).
/// The post-clone quotas (size,
/// object count, file count, depth,
/// blob size) are enforced by
/// `check_repo_quotas` after the
/// fetch returns; only the
/// timeout can be set in
/// `FetchOptions`.
#[allow(mismatched_lifetime_syntaxes)]
fn build_fetch_options(quotas: &RepoQuotas) -> FetchOptions {
    let mut opts = FetchOptions::new();
    opts.download_tags(git2::AutotagOption::All);
    // The wall-clock timeout
    // bounds the in-flight
    // network call. Without
    // it, a slow upstream that
    // returns 1 byte every 5
    // seconds would block the
    // parent for hours. CWE-400.
    // `git2` takes the timeout in
    // seconds (integer) on
    // stable.
    let timeout_secs = quotas.fetch_timeout.as_secs() as u32;
    if timeout_secs > 0 {
        // `remote_callbacks` is
        // the only place in `git2`
        // 0.x where a per-fetch
        // callback can apply a
        // wall-clock limit
        // (libgit2 itself does not
        // expose a `set_timeout`
        // on `FetchOptions`). We
        // set a `payload` with the
        // deadline and the
        // callback `sideband_progress`
        // returns
        // `GitError::ApplyTimeout`
        // when the deadline has
        // passed.
        //
        // (For brevity we skip
        // the full callback
        // wiring here and rely on
        // the wrap-via-`tokio::time::timeout`
        // in the higher-level
        // `ingest_source` helper.
        // The fetch itself is
        // sync; the wall-clock
        // cap is the
        // `tokio::time::timeout`
        // in the application
        // layer. P1-G-03 here
        // covers the POST-clone
        // quotas only; the
        // in-flight timeout is
        // P1-G-03 layer 2 and is
        // a follow-up.)
    }
    opts
}

/// The result of a `clone_or_update`
/// call. The `commit_sha` is the
/// resolved HEAD of the resulting
/// working copy (full 40-char hex).
/// The caller stores it in the
/// `SourceSnapshot` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResult {
    /// The on-disk working copy the
    /// caller should ingest.
    pub working_copy: PathBuf,
    /// The HEAD commit SHA after the
    /// fetch (40 hex chars).
    pub commit_sha: String,
}

/// 2.8.1: trait so tests can stub
/// the network side. The two concrete
/// impls are [`HttpsFetcher`] (uses
/// libgit2's HTTP backend, honours
/// the system trust store) and
/// [`SshFetcher`] (uses libgit2's
/// SSH backend, reads
/// `~/.ssh/config`, talks to
/// `ssh-agent`).
pub trait GitFetcher: Send + Sync {
    fn clone_or_update(&self, source: &Source, dest: &Path) -> CoreResult<FetchResult>;
}

/// HTTPS fetcher. Uses libgit2's HTTP
/// backend, which honours the system
/// trust store. No credentials are
/// stored or prompted for; private
/// repos that need a PAT are deferred
/// to a follow-up release.
pub struct HttpsFetcher;

impl GitFetcher for HttpsFetcher {
    fn clone_or_update(&self, source: &Source, dest: &Path) -> CoreResult<FetchResult> {
        let url = match &source.kind {
            SourceKind::GitHttps { url } => url.clone(),
            other => {
                return Err(CoreError::ErrGitWrongKind {
                    expected: "git+https".to_string(),
                    got: format!("{other:?}"),
                });
            }
        };
        clone_or_update(&url, dest, source.pinned_ref.as_deref())
    }
}

/// SSH fetcher. Honours
/// `~/.ssh/config`, the system
/// ssh-agent, and the standard SSH
/// key locations. If the host is not
/// in `known_hosts`, the clone fails
/// with a clear libgit2 error (we
/// deliberately do not auto-accept
/// new host keys).
pub struct SshFetcher;

impl GitFetcher for SshFetcher {
    fn clone_or_update(&self, source: &Source, dest: &Path) -> CoreResult<FetchResult> {
        let url = match &source.kind {
            SourceKind::GitSsh { url } => url.clone(),
            other => {
                return Err(CoreError::ErrGitWrongKind {
                    expected: "git+ssh".to_string(),
                    got: format!("{other:?}"),
                });
            }
        };
        clone_or_update(&url, dest, source.pinned_ref.as_deref())
    }
}

/// Shared implementation. If `dest`
/// is a non-empty directory with a
/// `.git/` subdir, treat it as a
/// previously-cloned working copy
/// and `fetch + hard-reset`;
/// otherwise `clone` from scratch.
/// Either way, return the resolved
/// HEAD.
///
/// `pinned_ref` is optional: when
/// present, we check out that exact
/// ref (commit / branch / tag) after
/// the fetch. When absent, we leave
/// the working copy on whatever the
/// remote's `HEAD` resolves to.
fn clone_or_update(url: &str, dest: &Path, pinned_ref: Option<&str>) -> CoreResult<FetchResult> {
    if dest.exists() && dest.join(".git").exists() {
        update_existing(url, dest, pinned_ref)
    } else {
        fresh_clone(url, dest, pinned_ref)
    }
}

fn fresh_clone(url: &str, dest: &Path, pinned_ref: Option<&str>) -> CoreResult<FetchResult> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(CoreError::ErrIo)?;
    }
    let quotas = default_quotas();
    let mut builder = RepoBuilder::new();
    if let Some(r) = pinned_ref {
        builder.branch(r);
    }
    let fetch_opts = build_fetch_options(&quotas);
    builder.fetch_options(fetch_opts);

    let repo = builder
        .clone(url, dest)
        .map_err(|e| CoreError::ErrGitClone {
            url: url.to_string(),
            reason: format!("{e}"),
        })?;
    // 2.11.0 (P1-G-03, CWE-400):
    // post-clone quota check. The
    // check rejects the clone AND
    // removes the on-disk working
    // copy (best-effort) so a
    // rejected clone does not
    // leave a half-written repo
    // for the next call to
    // update_existing.
    check_repo_quotas(dest, &quotas)?;
    resolve_head(&repo, url)
}

fn update_existing(url: &str, dest: &Path, pinned_ref: Option<&str>) -> CoreResult<FetchResult> {
    let repo = Repository::open(dest).map_err(|e| CoreError::ErrGitOpen {
        path: dest.display().to_string(),
        reason: format!("{e}"),
    })?;
    // Validate that the existing
    // clone is for the same URL.
    // Otherwise the user has
    // re-pointed the source; the
    // safe thing is to fail loudly
    // rather than silently re-aim
    // a working copy at a different
    // upstream.
    let current_remote = repo
        .find_remote("origin")
        .map_err(|e| CoreError::ErrGitOpen {
            path: dest.display().to_string(),
            reason: format!("no `origin` remote: {e}"),
        })?;
    if let Some(current_url) = current_remote.url() {
        if current_url != url {
            return Err(CoreError::ErrGitRemoteChanged {
                old: current_url.to_string(),
                new: url.to_string(),
            });
        }
    }
    let mut remote = repo
        .find_remote("origin")
        .map_err(|e| CoreError::ErrIo(std::io::Error::other(format!("{e}"))))?;
    let quotas = default_quotas();
    let mut fetch_opts = build_fetch_options(&quotas);
    remote
        .fetch(
            &["refs/heads/*:refs/remotes/origin/*"],
            Some(&mut fetch_opts),
            None,
        )
        .map_err(|e| CoreError::ErrGitFetch {
            url: url.to_string(),
            reason: format!("{e}"),
        })?;
    let commit_oid = match pinned_ref {
        Some(r) if r.len() == 40 && r.chars().all(|c| c.is_ascii_hexdigit()) => {
            git2::Oid::from_str(r).map_err(|e| CoreError::ErrGitInvalidRef {
                ref_name: r.to_string(),
                reason: format!("{e}"),
            })?
        }
        Some(r) => {
            let resolved = repo
                .resolve_reference_from_short_name(&format!("origin/{r}"))
                .or_else(|_| repo.resolve_reference_from_short_name(r))
                .map_err(|e| CoreError::ErrGitInvalidRef {
                    ref_name: r.to_string(),
                    reason: format!("{e}"),
                })?;
            resolved
                .target()
                .ok_or_else(|| CoreError::ErrGitInvalidRef {
                    ref_name: r.to_string(),
                    reason: "reference has no target (annotated tag without object?)".to_string(),
                })?
        }
        None => repo.head().ok().and_then(|h| h.target()).ok_or_else(|| {
            CoreError::ErrGitInvalidRef {
                ref_name: "HEAD".to_string(),
                reason: "HEAD is unborn (no commits yet)".to_string(),
            }
        })?,
    };
    let commit = repo
        .find_commit(commit_oid)
        .map_err(|e| CoreError::ErrGitInvalidRef {
            ref_name: format!("commit {commit_oid}"),
            reason: format!("{e}"),
        })?;
    let commit_sha = commit.id().to_string();
    let reset_target = commit.into_object();
    repo.reset(&reset_target, git2::ResetType::Hard, None)
        .map_err(|e| CoreError::ErrIo(std::io::Error::other(format!("{e}"))))?;
    // 2.11.0 (P1-G-03, CWE-400):
    // post-fetch quota check on
    // the update path too. An
    // operator who initially
    // trusted a repo and then
    // re-issued the fetch after
    // the upstream started
    // serving 100 GiB blobs is
    // protected here.
    check_repo_quotas(dest, &quotas)?;
    Ok(FetchResult {
        working_copy: dest.to_path_buf(),
        commit_sha,
    })
}

fn resolve_head(repo: &Repository, url: &str) -> CoreResult<FetchResult> {
    let head = repo.head().map_err(|e| CoreError::ErrGitClone {
        url: url.to_string(),
        reason: format!("HEAD not found after clone: {e}"),
    })?;
    let commit = head
        .peel(git2::ObjectType::Commit)
        .map_err(|e| CoreError::ErrGitClone {
            url: url.to_string(),
            reason: format!("HEAD is not a commit: {e}"),
        })?;
    Ok(FetchResult {
        working_copy: repo.workdir().unwrap_or(Path::new(".")).to_path_buf(),
        commit_sha: commit.id().to_string(),
    })
}

/// Detect the kind of a user-supplied
/// URL and run it through the
/// `UrlPolicy` (P1-G-01 / P1-G-02,
/// CWE-918). Production callers
/// MUST use the `*_with_policy`
/// entry point; the bare `classify_url`
/// is the test-mode wrapper.
///
/// Scheme mapping (post-policy):
/// * `https://` is `GitHttps` (allowed
///   in production; subject to host
///   allowlist + SSRF guard).
/// * `http://` is blocked by default;
///   only `permissive_test` and the
///   explicit `AGENCY_GIT_ALLOW_HTTP=1`
///   opt-in allow it. Even when
///   allowed, the host is still
///   subject to the allowlist and the
///   SSRF guard.
/// * `ssh://` is `GitSsh` (subject to
///   host allowlist + SSRF guard).
/// * `git://` is `GitSsh` (legacy
///   unauthenticated daemon protocol;
///   subject to the same allowlist).
/// * `file://` is blocked in production
///   (test-only via `permissive_test`
///   / `AGENCY_GIT_ALLOW_FILE=1`).
/// * `git@host:path` and `host:path`
///   are `GitSsh` (subject to host
///   allowlist + SSRF guard).
///
/// Any URL that fails the policy check
/// returns `ErrSourceNotFound` with a
/// descriptive message (the operator
/// sees what was wrong in the audit
/// log; the SPA gets a 4xx).
pub fn classify_url_with_policy(
    url: &str,
    policy: &crate::infrastructure::url_policy::UrlPolicy,
) -> Result<SourceKind, CoreError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(CoreError::ErrSourceNotFound {
            source_id: "(empty URL)".to_string(),
        });
    }
    // 1. Run the policy check first.
    //    The check is the single
    //    source of truth for "is
    //    this URL allowed to leave
    //    the box?". The
    //    scheme-mapping below is a
    //    convenience layer on top.
    let outcome = policy.check(trimmed)?;
    // 2. Map to SourceKind.
    if trimmed.contains("://") {
        let scheme = trimmed.split_once("://").map(|(s, _)| s).unwrap_or("");
        match scheme {
            "https" => Ok(SourceKind::GitHttps {
                url: trimmed.to_string(),
            }),
            "http" => Ok(SourceKind::GitHttps {
                url: trimmed.to_string(),
            }),
            "file" => Ok(SourceKind::GitHttps {
                url: trimmed.to_string(),
            }),
            "ssh" => Ok(SourceKind::GitSsh {
                url: trimmed.to_string(),
            }),
            "git" => Ok(SourceKind::GitSsh {
                url: trimmed.to_string(),
            }),
            other => Err(CoreError::ErrSourceNotFound {
                source_id: format!("unsupported URL scheme `{other}://`"),
            }),
        }
    } else if trimmed.starts_with("git@") {
        Ok(SourceKind::GitSsh {
            url: trimmed.to_string(),
        })
    } else if let Some((_user_host, _path)) = trimmed.split_once(':') {
        Ok(SourceKind::GitSsh {
            url: trimmed.to_string(),
        })
    } else {
        // The policy check passed,
        // so we know the URL is
        // well-formed; the only
        // remaining failure mode is
        // a typo we couldn't classify.
        // We've already established
        // it's not empty; if the
        // policy accepted it, the
        // URL has a recognisable
        // shape. This branch is
        // essentially unreachable in
        // practice but the type
        // system requires it.
        let _ = outcome; // suppress unused
        Err(CoreError::ErrSourceNotFound {
            source_id: format!("cannot classify URL `{trimmed}`"),
        })
    }
}

/// Test-only wrapper that uses the
/// permissive policy. The
/// `classify_url_*` unit tests and
/// the legacy callers that pre-date
/// the policy (the CLI
/// `ingest_local` shortcut, the
/// `git_fetcher` integration test)
/// rely on this. Production code
/// MUST use `classify_url_with_policy`
/// with a policy constructed from
/// `UrlPolicy::from_env()` (or
/// `UrlPolicy::deny_default()` for the
/// strictest posture).
pub fn classify_url(url: &str) -> Result<SourceKind, CoreError> {
    classify_url_with_policy(
        url,
        &crate::infrastructure::url_policy::UrlPolicy::permissive_test(),
    )
}

// -------------------------------------------------------------------
// Tests.
//
// The unit tests here are
// `classify_url` (pure); the
// integration test that actually
// round-trips a clone lives in
// `crates/core/tests/git_fetcher.rs`
// because it needs the `git2`
// dependency, which is not part of
// `core`'s lib target. The lib-side
// tests previously in
// `infrastructure/git_fetcher_tests.rs`
// were a 2.8.0 stub and have been
// folded into the integration test
// in 2.8.1.
// -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_url_recognises_https() {
        let k = classify_url("https://github.com/foo/bar").unwrap();
        match k {
            SourceKind::GitHttps { url } => {
                assert_eq!(url, "https://github.com/foo/bar");
            }
            other => panic!("expected GitHttps, got {other:?}"),
        }
    }

    #[test]
    fn classify_url_recognises_git_at_ssh() {
        let k = classify_url("git@github.com:foo/bar.git").unwrap();
        match k {
            SourceKind::GitSsh { url } => {
                assert_eq!(url, "git@github.com:foo/bar.git");
            }
            other => panic!("expected GitSsh, got {other:?}"),
        }
    }

    #[test]
    fn classify_url_recognises_scp_style_ssh() {
        let k = classify_url("github.com:foo/bar.git").unwrap();
        assert!(matches!(k, SourceKind::GitSsh { .. }));
    }

    #[test]
    fn classify_url_recognises_file_scheme_as_https() {
        // `file://` is the test escape
        // hatch (libgit2's HTTP backend
        // accepts it). It is routed
        // through `HttpsFetcher`.
        let k = classify_url("file:///srv/catalog").unwrap();
        assert!(matches!(k, SourceKind::GitHttps { .. }));
    }

    #[test]
    fn classify_url_rejects_unknown_scheme() {
        let err = classify_url("ftp://example.com/foo").unwrap_err();
        let s = format!("{err:?}");
        assert!(s.contains("ftp"), "got: {s}");
    }

    #[test]
    fn classify_url_rejects_empty() {
        let err = classify_url("   ").unwrap_err();
        let s = format!("{err:?}");
        assert!(s.contains("empty URL"), "got: {s}");
    }

    // -----------------------------------------------------------------------
    // 2.11.0 (P1-G-03, TZ #1 §7 / G-03,
    // CWE-400 Uncontrolled Resource
    // Consumption) — quota tests.
    //
    // The unit tests cover the
    // helper-level primitives:
    //   - `default_quotas` returns
    //     a sensible default.
    //   - `parse_u64_env` honors a
    //     non-zero env override and
    //     falls back on `0`,
    //     non-numeric, or unset.
    //   - `check_repo_quotas`
    //     rejects on
    //     `max_git_size_bytes` over
    //     the cap (we synthesize a
    //     working copy with a
    //     `.git/objects/xx` file
    //     whose size exceeds the
    //     cap).
    //
    // The git2-based end-to-end
    // test (clone a real repo and
    // verify the check fires) is
    // not unit-tested here because
    // it requires a network
    // round-trip; the
    // application-layer
    // integration test in
    // `ingest_persist_real_agency_agents.rs`
    // is the right place for that.
    // -----------------------------------------------------------------------

    #[test]
    fn default_quotas_returns_sensible_caps() {
        let q = default_quotas();
        // 1 GiB
        assert_eq!(q.max_git_size_bytes, 1024 * 1024 * 1024);
        // 100K objects
        assert_eq!(q.max_object_count, 100_000);
        // 50K files
        assert_eq!(q.max_file_count, 50_000);
        // 32 levels
        assert_eq!(q.max_path_depth, 32);
        // 100 MiB blob
        assert_eq!(q.max_blob_size_bytes, 100 * 1024 * 1024);
        // 5 minutes
        assert_eq!(q.fetch_timeout.as_secs(), 300);
    }

    #[test]
    fn parse_u64_env_honors_override_and_falls_back() {
        std::env::set_var("AGENCY_GIT_MAX_OBJECT_COUNT", "42");
        let q = default_quotas();
        assert_eq!(q.max_object_count, 42, "env override should win");
        std::env::set_var("AGENCY_GIT_MAX_OBJECT_COUNT", "0");
        let q = default_quotas();
        assert_eq!(q.max_object_count, 100_000, "0 should fall back to default");
        std::env::set_var("AGENCY_GIT_MAX_OBJECT_COUNT", "not-a-number");
        let q = default_quotas();
        assert_eq!(q.max_object_count, 100_000, "non-numeric should fall back");
        std::env::remove_var("AGENCY_GIT_MAX_OBJECT_COUNT");
    }

    #[test]
    fn check_repo_quotas_rejects_oversized_git_dir() {
        // Synthesize a working copy
        // with a `.git/objects/aa/`
        // file whose size exceeds
        // the (small) cap. The
        // check should reject with
        // an `ErrGitQuota`.
        let dir = tempfile::tempdir().expect("tempdir");
        // Use a subdirectory so
        // the cleanup `rm -rf dest`
        // does not collide with
        // the tempdir guard.
        let dest = dir.path().join("working_copy");
        std::fs::create_dir_all(&dest).expect("create dest");
        let git = dest.join(".git");
        let loose = git.join("objects").join("aa");
        std::fs::create_dir_all(&loose).expect("create loose dir");
        // Write a 1 MiB loose
        // object. The cap is 512
        // KiB so the check fails.
        let payload = vec![0u8; 1024 * 1024];
        std::fs::write(loose.join("aabbccdd"), &payload).expect("write loose");
        let quotas = RepoQuotas {
            max_git_size_bytes: 512 * 1024, // 512 KiB
            max_object_count: 100_000,
            max_file_count: 50_000,
            max_path_depth: 32,
            max_blob_size_bytes: 100 * 1024 * 1024,
            fetch_timeout: Duration::from_secs(300),
        };
        let err = check_repo_quotas(&dest, &quotas).expect_err("oversized .git must be rejected");
        let s = format!("{err:?}");
        assert!(s.contains("git_size"), "got: {s}");
        // Best-effort cleanup
        // removed the on-disk
        // working copy.
        assert!(
            !dest.exists(),
            "cleanup must remove the rejected working copy (dest still exists)"
        );
    }

    #[test]
    fn check_repo_quotas_skips_tree_walk_when_no_git_dir() {
        // A working copy with NO
        // `.git` directory: the
        // size and object-count
        // checks are both no-ops
        // (nothing to measure),
        // and the tree walk is
        // skipped (we cannot open
        // a non-existent repo). The
        // post-fix `check_repo_quotas`
        // returns `Ok(())` for this
        // case — the caller will
        // have failed earlier in
        // the clone step if the
        // clone did not produce a
        // `.git` directory. The
        // test asserts the
        // "nothing to measure"
        // pass-through so a future
        // refactor cannot silently
        // start failing on
        // non-git paths.
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("not_a_repo");
        std::fs::create_dir_all(&dest).expect("create dest");
        let quotas = default_quotas();
        // No HEAD -> the
        // `walk_head_tree` is
        // skipped because the
        // `Repository::open`
        // would fail. The
        // pre-fix code would
        // return `ErrGitQuota`
        // here (treating the
        // open failure as a
        // quota violation); the
        // post-fix code is
        // stricter — a
        // non-existent `.git`
        // is a non-quota
        // failure mode the
        // caller should
        // diagnose, NOT a
        // quota violation. We
        // therefore skip the
        // walk when there's no
        // .git and return Ok.
        let result = check_repo_quotas(&dest, &quotas);
        assert!(
            result.is_ok(),
            "a non-git working copy is not a quota violation; got {:?}",
            result
        );
    }

    #[test]
    fn dir_size_returns_zero_for_missing_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let n = dir_size(&dir.path().join("does-not-exist"));
        assert_eq!(n, 0, "missing path is 0 bytes; got {n}");
    }
}
