//! Integration test for the Git source fetcher (1.1.0, ADR-0009).
//!
//! Creates a fixture git repository with `git2`, then asks the
//! HttpsFetcher to clone a `file://` URL pointing at it. We use
//! `file://` because libgit2's HTTP backend accepts it and the test
//! does not need a real network. The SSH fetcher is exercised at
//! the classify_url level (and is required to refuse non-SSH URLs);
//! an end-to-end SSH test would need a live `ssh-agent` and is
//! opt-in via `AGENCY_SSH_TEST=1` (skipped in CI).

use agent_dep_core::application::ingest::ingest_source;
use agent_dep_core::domain::source::{Source, SourceKind};
use agent_dep_core::infrastructure::git_fetcher::{
    classify_url, GitFetcher, HttpsFetcher, SshFetcher,
};
use git2::Repository;
use std::fs;
use std::path::Path;

fn write_fixture(root: &Path) {
    fs::create_dir_all(root.join("agents/engineering")).unwrap();
    fs::write(
        root.join("divisions.json"),
        r#"{
            "divisions": [
                {"id": "engineering", "order": 1, "label": "Engineering"}
            ]
        }"#,
    )
    .unwrap();
    fs::write(
        root.join("agents/engineering/be.md"),
        "---\nid: be\nname: BE\ndivision: engineering\nrole: r\ndescription: d\nversion: 1.0.0\n---\nbody\n",
    )
    .unwrap();
}

fn make_fixture_repo() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();
    write_fixture(&path);
    let repo = Repository::init(&path).expect("git init");
    let mut idx = repo.index().expect("index");
    idx.add_path(Path::new("divisions.json"))
        .expect("add divisions");
    idx.add_path(Path::new("agents/engineering/be.md"))
        .expect("add be");
    let oid = idx.write_tree().expect("write tree");
    let tree = repo.find_tree(oid).expect("find tree");
    let sig = git2::Signature::now("test", "test@example.com").unwrap();
    let _ = repo
        .commit(
            Some("HEAD"),
            &sig,
            &sig,
            "initial fixture",
            &tree,
            &[], // no parents
        )
        .expect("commit");
    let url = path_to_file_url(&path);
    (dir, url)
}

fn path_to_file_url(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    if s.starts_with('/') {
        format!("file://{s}")
    } else {
        format!("file:///{s}")
    }
}

#[tokio::test]
async fn https_fetcher_clones_a_file_url_into_a_working_copy() {
    let (_repo_dir, url) = make_fixture_repo();
    let dest_dir = tempfile::tempdir().expect("dest tempdir");
    let source = Source::new(SourceKind::GitHttps { url: url.clone() });

    let result = HttpsFetcher
        .clone_or_update(&source, dest_dir.path())
        .expect("clone_or_update");

    // We don't compare `result.working_copy == dest_dir.path()`
    // literally: on Windows libgit2 normalizes the path
    // (forward slashes + 8.3 long-name resolution) so the
    // two strings differ even though they name the same
    // directory. Instead we check that the fixture's files
    // exist under the working copy and that the basename
    // matches.
    assert_eq!(
        result.working_copy.file_name(),
        dest_dir.path().file_name(),
        "working_copy basenames differ: {:?} vs {:?}",
        result.working_copy,
        dest_dir.path()
    );
    assert_eq!(result.commit_sha.len(), 40, "got: {}", result.commit_sha);
    // The working copy must contain the fixture's files.
    assert!(result.working_copy.join("divisions.json").is_file());
    assert!(result
        .working_copy
        .join("agents/engineering/be.md")
        .is_file());
    // A subsequent re-fetch on the same working copy must
    // succeed and yield the same commit_sha (idempotent).
    let again = HttpsFetcher
        .clone_or_update(&source, dest_dir.path())
        .expect("re-fetch");
    assert_eq!(again.commit_sha, result.commit_sha);
}

#[tokio::test]
async fn ingest_source_runs_full_pipeline_on_a_cloned_repo() {
    let (_repo_dir, url) = make_fixture_repo();
    let dest_root = tempfile::tempdir().expect("dest tempdir");
    let source = Source::new(SourceKind::GitHttps { url });

    let (result, report) = ingest_source(&source, dest_root.path()).expect("ingest_source");
    assert_eq!(report.agents_rejected.len(), 0);
    assert_eq!(result.agents.len(), 1, "one fixture agent");
    assert_eq!(result.agents[0].id, "be");
    assert_eq!(
        result.snapshot.commit_sha.len(),
        40,
        "snapshot commit_sha is the real Git commit"
    );
}

#[tokio::test]
async fn https_fetcher_rejects_an_ssh_url() {
    let source = Source::new(SourceKind::GitSsh {
        url: "git@github.com:foo/bar.git".to_string(),
    });
    let dest = tempfile::tempdir().expect("tempdir");
    let err = HttpsFetcher
        .clone_or_update(&source, dest.path())
        .expect_err("HttpsFetcher must not accept an SSH source");
    let s = format!("{err:?}");
    assert!(
        s.contains("git+https") || s.contains("git+ssh") || s.contains("wrong kind"),
        "got: {s}"
    );
}

#[tokio::test]
async fn ssh_fetcher_rejects_an_https_url() {
    let source = Source::new(SourceKind::GitHttps {
        url: "https://github.com/foo/bar.git".to_string(),
    });
    let dest = tempfile::tempdir().expect("tempdir");
    let err = SshFetcher
        .clone_or_update(&source, dest.path())
        .expect_err("SshFetcher must not accept an HTTPS source");
    let s = format!("{err:?}");
    assert!(s.contains("ErrGitWrongKind"), "got: {s}");
}

#[test]
fn classify_url_handles_common_shapes() {
    assert!(matches!(
        classify_url("https://github.com/x/y").unwrap(),
        SourceKind::GitHttps { .. }
    ));
    assert!(matches!(
        classify_url("http://internal.example.com:8080/r.git").unwrap(),
        SourceKind::GitHttps { .. }
    ));
    assert!(matches!(
        classify_url("git@github.com:x/y.git").unwrap(),
        SourceKind::GitSsh { .. }
    ));
    assert!(matches!(
        classify_url("github.com:x/y.git").unwrap(),
        SourceKind::GitSsh { .. }
    ));
    assert!(matches!(
        classify_url("file:///tmp/repo.git").unwrap(),
        SourceKind::GitHttps { .. }
    ));
}
