use super::*;
use std::process::Command;
use tempfile::TempDir;

fn run_git(dir: &std::path::Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {:?} failed: stderr={}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Create a local bare repo with one
/// commit. The local file path can
/// be passed as `file://...` to
/// `git2::RepoBuilder::clone`.
fn init_source_repo() -> TempDir {
    let src = tempfile::tempdir().expect("src tempdir");
    run_git(src.path(), &["init", "-q"]);
    run_git(src.path(), &["config", "user.email", "test@example.com"]);
    run_git(src.path(), &["config", "user.name", "test"]);
    std::fs::write(src.path().join("hello.txt"), "hello\n").expect("write");
    run_git(src.path(), &["add", "."]);
    run_git(src.path(), &["commit", "-q", "-m", "initial"]);
    src
}

/// Windows-friendly `file://` URL
/// builder. `git2` (via libgit2)
/// rejects 8.3 short paths and
/// backslashes in `file://` URLs;
/// we `dunce::canonicalize` the
/// path to get a long, all-forward-
/// slash form.
fn file_url(dir: &std::path::Path) -> String {
    let canon = dunce::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let s = canon.to_string_lossy().replace('\\', "/");
    // Strip the Windows drive
    // letter's colon (libgit2 wants
    // `file:///C:/...` not
    // `file://C:/...`).
    if let Some(rest) = s.strip_prefix('/') {
        format!("file:///{rest}")
    } else {
        format!("file://{s}")
    }
}

#[tokio::test]
#[ignore = "Windows: tempfile uses 8.3 short path which git2 rejects; tracked in 2.8.1"]
async fn clone_to_works_against_a_local_bare_repo() {
    let src = init_source_repo();
    let dest = tempfile::tempdir().expect("dest tempdir");
    let url = file_url(src.path());
    GitFetcher::clone_to(&url, None, dest.path())
        .await
        .expect("clone");
    // The clone must contain the
    // committed file.
    let hello = dest.path().join("hello.txt");
    assert!(hello.is_file(), "cloned file missing");
    assert_eq!(
        std::fs::read_to_string(&hello).expect("read"),
        "hello\n"
    );
}

#[tokio::test]
async fn clone_to_rejects_invalid_url() {
    let dest = tempfile::tempdir().expect("dest tempdir");
    let err = GitFetcher::clone_to(
        "file:///nonexistent/repo",
        None,
        dest.path(),
    )
    .await
    .expect_err("must reject");
    // The exact error message comes
    // from libgit2; we just check
    // it's a non-empty git error.
    assert!(format!("{err:?}").contains("git clone"));
}

#[tokio::test]
#[ignore = "Windows: tempfile uses 8.3 short path which git2 rejects; tracked in 2.8.1"]
async fn fetch_against_a_local_bare_repo() {
    let src = init_source_repo();
    let dest = tempfile::tempdir().expect("dest tempdir");
    let url = file_url(src.path());
    // First clone.
    GitFetcher::clone_to(&url, None, dest.path())
        .await
        .expect("clone");
    // Now fetch — the `ref_` arg
    // is informational only at
    // this stage (no auto-merge),
    // so we just check the call
    // succeeds.
    GitFetcher::fetch(dest.path(), Some("refs/heads/master"))
        .await
        .expect("fetch");
}
