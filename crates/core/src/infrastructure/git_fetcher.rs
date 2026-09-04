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

use git2::{build::RepoBuilder, FetchOptions, Repository};

use crate::domain::source::{Source, SourceKind};
use crate::error::{CoreError, CoreResult};

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
    fn clone_or_update(
        &self,
        source: &Source,
        dest: &Path,
    ) -> CoreResult<FetchResult>;
}

/// HTTPS fetcher. Uses libgit2's HTTP
/// backend, which honours the system
/// trust store. No credentials are
/// stored or prompted for; private
/// repos that need a PAT are deferred
/// to a follow-up release.
pub struct HttpsFetcher;

impl GitFetcher for HttpsFetcher {
    fn clone_or_update(
        &self,
        source: &Source,
        dest: &Path,
    ) -> CoreResult<FetchResult> {
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
    fn clone_or_update(
        &self,
        source: &Source,
        dest: &Path,
    ) -> CoreResult<FetchResult> {
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
fn clone_or_update(
    url: &str,
    dest: &Path,
    pinned_ref: Option<&str>,
) -> CoreResult<FetchResult> {
    if dest.exists() && dest.join(".git").exists() {
        update_existing(url, dest, pinned_ref)
    } else {
        fresh_clone(url, dest, pinned_ref)
    }
}

fn fresh_clone(
    url: &str,
    dest: &Path,
    pinned_ref: Option<&str>,
) -> CoreResult<FetchResult> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(CoreError::ErrIo)?;
    }
    let mut builder = RepoBuilder::new();
    if let Some(r) = pinned_ref {
        builder.branch(r);
    }
    let mut fetch_opts = FetchOptions::new();
    fetch_opts.download_tags(git2::AutotagOption::All);
    builder.fetch_options(fetch_opts);

    let repo = builder.clone(url, dest).map_err(|e| {
        CoreError::ErrGitClone {
            url: url.to_string(),
            reason: format!("{e}"),
        }
    })?;
    resolve_head(&repo, url)
}

fn update_existing(
    url: &str,
    dest: &Path,
    pinned_ref: Option<&str>,
) -> CoreResult<FetchResult> {
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
    let current_remote =
        repo.find_remote("origin").map_err(|e| CoreError::ErrGitOpen {
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
            resolved.target().ok_or_else(|| CoreError::ErrGitInvalidRef {
                ref_name: r.to_string(),
                reason: "reference has no target (annotated tag without object?)"
                    .to_string(),
            })?
        }
        None => repo
            .head()
            .ok()
            .and_then(|h| h.target())
            .ok_or_else(|| CoreError::ErrGitInvalidRef {
                ref_name: "HEAD".to_string(),
                reason: "HEAD is unborn (no commits yet)".to_string(),
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
    Ok(FetchResult {
        working_copy: dest.to_path_buf(),
        commit_sha,
    })
}

fn resolve_head(
    repo: &Repository,
    url: &str,
) -> CoreResult<FetchResult> {
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
/// URL. Returns `GitSsh` for
/// `git@host:path` and
/// `[user@]host:path`; `GitHttps` for
/// everything that starts with
/// `http://`, `https://`, or `file://`
/// (the last is the test escape
/// hatch); and an `ErrSourceNotFound`
/// for anything else.
pub fn classify_url(
    url: &str,
) -> Result<SourceKind, CoreError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(CoreError::ErrSourceNotFound {
            source_id: "(empty URL)".to_string(),
        });
    }
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
        Err(CoreError::ErrSourceNotFound {
            source_id: format!("cannot classify URL `{trimmed}`"),
        })
    }
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
}
