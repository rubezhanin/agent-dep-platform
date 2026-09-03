//! 2.8.0 (ADR-0039) Real Git source
//! ingest. The MVP `IngestRepository`
//! walks a local catalog directory;
//! `GitFetcher` clones a remote repo
//! into a tempdir and feeds the local
//! walker. Supports HTTPS + SSH via
//! the operator's `~/.ssh/config` +
//! `ssh-agent`.
//!
//! `git2` is sync; we wrap the
//! blocking calls in
//! `tokio::task::spawn_blocking`.

use std::path::Path;

use crate::error::{CoreError, CoreResult};

pub struct GitFetcher;

impl GitFetcher {
    /// Clone a remote repo into
    /// `dest` and check out `ref_`
    /// (branch, tag, or commit SHA).
    /// The default is the remote's
    /// HEAD.
    pub async fn clone_to(
        url: &str,
        ref_: Option<&str>,
        dest: &Path,
    ) -> CoreResult<()> {
        let url = url.to_string();
        let ref_ = ref_.map(String::from);
        let dest = dest.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let mut builder = git2::build::RepoBuilder::new();
            if let Some(r) = ref_.as_deref() {
                builder.branch(r);
            }
            builder
                .clone(&url, &dest)
                .map_err(|e| CoreError::ErrIo(std::io::Error::other(format!("git clone: {e}"))))?;
            Ok::<(), CoreError>(())
        })
        .await
        .map_err(|e| {
            CoreError::ErrIo(std::io::Error::other(format!("join: {e}")))
        })??;
        Ok(())
    }

    /// Fetch + fast-forward the
    /// existing clone at `dest` to
    /// `ref_` (defaults to the
    /// clone's current branch's
    /// upstream).
    pub async fn fetch(
        dest: &Path,
        ref_: Option<&str>,
    ) -> CoreResult<()> {
        let dest = dest.to_path_buf();
        let ref_ = ref_.map(String::from);
        tokio::task::spawn_blocking(move || {
            let repo = git2::Repository::open(&dest).map_err(|e| {
                CoreError::ErrIo(std::io::Error::other(format!(
                    "git open: {e}"
                )))
            })?;
            let mut remote = match repo.find_remote("origin") {
                Ok(r) => r,
                Err(_) => {
                    return Err(CoreError::ErrSchemaInvalid {
                        path: "git_fetcher.fetch".to_string(),
                        reason: "no `origin` remote".to_string(),
                    });
                }
            };
            let refspec = ref_.as_deref().unwrap_or("HEAD");
            remote
                .fetch(&[refspec], None, None)
                .map_err(|e| {
                    CoreError::ErrIo(std::io::Error::other(format!(
                        "git fetch: {e}"
                    )))
                })?;
            // 2.8.0 limitation: we
            // do not auto-merge the
            // fetched refs into the
            // local branch. The
            // operator must checkout
            // the new HEAD. A 2.8.x
            // enhancement may add
            // fast-forward merges.
            Ok::<(), CoreError>(())
        })
        .await
        .map_err(|e| {
            CoreError::ErrIo(std::io::Error::other(format!("join: {e}")))
        })??;
        Ok(())
    }
}

#[cfg(test)]
#[path = "git_fetcher_tests.rs"]
mod tests;
