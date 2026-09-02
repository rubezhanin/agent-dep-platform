//! Git source fetcher (TZ §10, ADR-0009).
//!
//! Wraps `libgit2` via the `git2` crate to provide a single
//! `GitFetcher` trait that the rest of the ingest pipeline
//! talks to. Two concrete impls exist today: HTTPS (uses
//! libgit2's HTTP backend, which honours the system trust
//! store) and SSH (uses libgit2's SSH backend, which reads
//! `~/.ssh/config` and talks to `ssh-agent`).
//!
//! The fetcher is *the only* place in `core/` that depends
//! on `git2`. `IngestService::ingest` calls
//! `clone_or_update` and then runs the existing
//! `ingest_local` against the resulting working copy, so
//! the rest of the pipeline is oblivious to whether the
//! source was a directory or a Git repo.

use crate::domain::source::Source;
use crate::error::{CoreError, CoreResult};
use git2::{build::RepoBuilder, FetchOptions, Repository};
use std::path::{Path, PathBuf};

/// The result of a `clone_or_update` call. The
/// `commit_sha` is the resolved HEAD of the resulting
/// working copy (full 40-char hex). The caller stores
/// it in the `SourceSnapshot` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResult {
    /// The on-disk working copy the caller should ingest.
    pub working_copy: PathBuf,
    /// The HEAD commit SHA after the fetch (40 hex chars).
    pub commit_sha: String,
}

/// Trait so tests can stub out the network side. The
/// default impls are `HttpsFetcher` and `SshFetcher`.
pub trait GitFetcher: Send + Sync {
    fn clone_or_update(&self, source: &Source, dest: &Path) -> CoreResult<FetchResult>;
}

/// HTTPS fetcher. Uses libgit2's HTTP backend, which
/// honours the system trust store. No credentials are
/// stored or prompted for; private repos that need a
/// PAT are an open question deferred to 1.1.1.
pub struct HttpsFetcher;

impl GitFetcher for HttpsFetcher {
    fn clone_or_update(&self, source: &Source, dest: &Path) -> CoreResult<FetchResult> {
        let url = match &source.kind {
            crate::domain::source::SourceKind::GitHttps { url } => url.clone(),
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

/// SSH fetcher. Honours `~/.ssh/config`, the system
/// ssh-agent, and the standard SSH key locations. If
/// the host is not in `known_hosts`, the clone fails
/// with a clear libgit2 error (we deliberately do not
/// auto-accept new host keys).
pub struct SshFetcher;

impl GitFetcher for SshFetcher {
    fn clone_or_update(&self, source: &Source, dest: &Path) -> CoreResult<FetchResult> {
        let url = match &source.kind {
            crate::domain::source::SourceKind::GitSsh { url } => url.clone(),
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

/// Shared implementation. If `dest` is a non-empty
/// directory, treat it as a previously-cloned working
/// copy and `fetch + hard-reset`; otherwise `clone`
/// from scratch. Either way, return the resolved HEAD.
///
/// `pinned_ref` is optional: when present, we check
/// out that exact ref (commit / branch / tag) after
/// the fetch. When absent, we leave the working copy
/// on whatever the remote's `HEAD` resolves to.
fn clone_or_update(url: &str, dest: &Path, pinned_ref: Option<&str>) -> CoreResult<FetchResult> {
    if dest.exists() && dest.join(".git").exists() {
        update_existing(url, dest, pinned_ref)
    } else {
        fresh_clone(url, dest, pinned_ref)
    }
}

fn fresh_clone(url: &str, dest: &Path, pinned_ref: Option<&str>) -> CoreResult<FetchResult> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CoreError::ErrIo(e))?;
    }
    let mut builder = RepoBuilder::new();
    if let Some(r) = pinned_ref {
        builder.branch(r);
    }
    let mut fetch_opts = FetchOptions::new();
    fetch_opts.download_tags(git2::AutotagOption::All);
    builder.fetch_options(fetch_opts);

    let repo = builder
        .clone(url, dest)
        .map_err(|e| CoreError::ErrGitClone {
            url: url.to_string(),
            reason: format!("{e}"),
        })?;
    resolve_head(&repo, url)
}

fn update_existing(url: &str, dest: &Path, pinned_ref: Option<&str>) -> CoreResult<FetchResult> {
    let repo = Repository::open(dest).map_err(|e| CoreError::ErrGitOpen {
        path: dest.display().to_string(),
        reason: format!("{e}"),
    })?;
    // Validate that the existing clone is for the same URL.
    // (Otherwise the user has re-pointed the source; the
    // safe thing is to fail loudly rather than silently
    // re-aim a working copy at a different upstream.)
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
    let mut fetch_opts = FetchOptions::new();
    fetch_opts.download_tags(git2::AutotagOption::All);
    remote
        .fetch(&["refs/heads/*:refs/remotes/origin/*"], Some(&mut fetch_opts), None)
        .map_err(|e| CoreError::ErrGitFetch {
            url: url.to_string(),
            reason: format!("{e}"),
        })?;
    // Resolve to a concrete commit oid. We return the
    // `Oid` so the three match arms have a uniform type.
    let commit_oid = match pinned_ref {
        Some(r) if r.len() == 40 && r.chars().all(|c| c.is_ascii_hexdigit()) => {
            // Looks like a SHA — resolve directly.
            git2::Oid::from_str(r).map_err(|e| CoreError::ErrGitInvalidRef {
                ref_name: r.to_string(),
                reason: format!("{e}"),
            })?
        }
        Some(r) => {
            // Branch or tag. Try `origin/<r>` first, then
            // fall back to a local ref of the same name.
            let resolved = repo
                .resolve_reference_from_short_name(&format!("origin/{r}"))
                .or_else(|_| repo.resolve_reference_from_short_name(r))
                .map_err(|e| CoreError::ErrGitInvalidRef {
                    ref_name: r.to_string(),
                    reason: format!("{e}"),
                })?;
            resolved.target().ok_or_else(|| CoreError::ErrGitInvalidRef {
                ref_name: r.to_string(),
                reason: "reference has no target (annotated tag without object?)".to_string(),
            })?
        }
        None => {
            // Default: the current HEAD. After a fetch
            // this is whatever we resolved at fetch time.
            repo.head()
                .ok()
                .and_then(|h| h.target())
                .ok_or_else(|| CoreError::ErrGitInvalidRef {
                    ref_name: "HEAD".to_string(),
                    reason: "HEAD is unborn (no commits yet)".to_string(),
                })?
        }
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
    Ok(FetchResult {
        working_copy: dest.to_path_buf(),
        commit_sha,
    })
}

fn resolve_head(repo: &Repository, url: &str) -> CoreResult<FetchResult> {
    let head = repo
        .head()
        .map_err(|e| CoreError::ErrGitClone {
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

/// Detect the kind of a user-supplied URL. Returns
/// `GitSsh` for `git@host:path` and `[user@]host:path`;
/// `GitHttps` for everything that starts with `http://`,
/// `https://`, or `file://` (the last is the test escape
/// hatch); and an `ErrSourceNotFound` for anything else.
pub fn classify_url(url: &str) -> Result<crate::domain::source::SourceKind, CoreError> {
    use crate::domain::source::SourceKind;
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(CoreError::ErrSourceNotFound {
            source_id: "(empty URL)".to_string(),
        });
    }
    if trimmed.contains("://") {
        let scheme = trimmed.split_once("://").map(|(s, _)| s).unwrap_or("");
        match scheme {
            "https" => Ok(SourceKind::GitHttps { url: trimmed.to_string() }),
            "http" => Ok(SourceKind::GitHttps { url: trimmed.to_string() }),
            "file" => Ok(SourceKind::GitHttps { url: trimmed.to_string() }),
            "ssh" => Ok(SourceKind::GitSsh { url: trimmed.to_string() }),
            "git" => Ok(SourceKind::GitSsh { url: trimmed.to_string() }),
            other => Err(CoreError::ErrSourceNotFound {
                source_id: format!("unsupported URL scheme `{other}://`"),
            }),
        }
    } else if trimmed.starts_with("git@") {
        // `git@github.com:org/repo.git`
        Ok(SourceKind::GitSsh { url: trimmed.to_string() })
    } else if let Some((_user_host, _path)) = trimmed.split_once(':') {
        // `host:path` without `git@` prefix — SCP-style SSH.
        Ok(SourceKind::GitSsh { url: trimmed.to_string() })
    } else {
        Err(CoreError::ErrSourceNotFound {
            source_id: format!("cannot classify URL `{trimmed}`"),
        })
    }
}

/// High-level helper: clone-or-update the working copy
/// for `source` into `<working_copy_root>/<source_id>/`,
/// then run the existing `IngestService::ingest_local`
/// against the resulting path. Returns the
/// `(IngestResult, IngestReport)` from the inner
/// ingest. The caller is responsible for the
/// `Source` row (it was either newly created via
/// `IngestRepository::upsert_source` or fetched
/// from the DB by URL).
pub fn ingest_source(
    source: &Source,
    working_copy_root: &Path,
) -> CoreResult<(crate::application::ingest::IngestResult, crate::application::ingest::IngestReport)>
{
    let dest = working_copy_root.join(source.id.to_string());
    let fetch = match &source.kind {
        crate::domain::source::SourceKind::GitHttps { .. } => {
            HttpsFetcher.clone_or_update(source, &dest)
        }
        crate::domain::source::SourceKind::GitSsh { .. } => {
            SshFetcher.clone_or_update(source, &dest)
        }
        crate::domain::source::SourceKind::Local { .. } => {
            // No fetch step; caller passes the local path
            // directly. Return a synthetic FetchResult so
            // the rest of the flow is uniform.
            return crate::application::ingest::IngestService::new()
                .ingest_local(source, None);
        }
    }?;
    let svc = crate::application::ingest::IngestService::new();
    let (mut result, report) = svc.ingest_local(source, Some(&fetch.working_copy))?;
    // Override the synthetic commit_sha with the real one
    // for Git sources. For Local sources the snapshot's
    // commit_sha is already a content-derived hash set by
    // `ingest_local`.
    result.snapshot.commit_sha = fetch.commit_sha;
    Ok((result, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_url_recognises_https() {
        let k = classify_url("https://github.com/foo/bar").unwrap();
        match k {
            crate::domain::source::SourceKind::GitHttps { url } => {
                assert_eq!(url, "https://github.com/foo/bar");
            }
            other => panic!("expected GitHttps, got {other:?}"),
        }
    }

    #[test]
    fn classify_url_recognises_git_at_ssh() {
        let k = classify_url("git@github.com:foo/bar.git").unwrap();
        match k {
            crate::domain::source::SourceKind::GitSsh { url } => {
                assert_eq!(url, "git@github.com:foo/bar.git");
            }
            other => panic!("expected GitSsh, got {other:?}"),
        }
    }

    #[test]
    fn classify_url_recognises_scp_style_ssh() {
        let k = classify_url("github.com:foo/bar.git").unwrap();
        assert!(matches!(
            k,
            crate::domain::source::SourceKind::GitSsh { .. }
        ));
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
}
