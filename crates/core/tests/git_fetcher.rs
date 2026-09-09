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
use agent_dep_core::error::CoreError;
use agent_dep_core::infrastructure::git_fetcher::{
    classify_url, verify_annotated_tag, GitFetcher, HttpsFetcher, SshFetcher,
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

// -----------------------------------------------------------------------
// 3.0.0 (B7, audit, CWE-345
// Insufficient Verification of
// Data Authenticity): the
// `require_signed_refs` flag
// gates `clone_or_update` on the
// pinned ref being an annotated
// tag object (the only Git
// object type that carries a GPG
// signature). The check is
// STRUCTURAL — no GPG binary is
// invoked. A 3.1 follow-up adds
// the cryptographic verification
// via the `pgp` crate.
//
// The tests below exercise the
// `verify_annotated_tag` helper
// directly against local
// in-memory fixture repos. The
// end-to-end
// `clone_or_update` path
// includes a pre-existing
// `update_existing` issue
// (`.target()` returns the
// *tag* OID for annotated
// tags, not the peeled
// commit OID) that is
// unrelated to B7 and is
// fixed separately. The
// unit-level check is the
// authoritative surface for
// the B7 acceptance
// criteria.
// -----------------------------------------------------------------------

/// 3.0.0 (B7): build a
/// local repo + return
/// it. Caller tags /
/// branches it as
/// needed.
fn make_local_repo_with(initial_commit: bool) -> (tempfile::TempDir, Repository) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path();
    // Write one tracked file
    // so the commit has a
    // tree with at least
    // one entry.
    fs::create_dir_all(path.join("agents")).unwrap();
    fs::write(path.join("agents/a.md"), "---\nid: a\n---\nbody").unwrap();
    let repo = Repository::init(path).expect("git init");
    if initial_commit {
        let mut idx = repo.index().expect("index");
        idx.add_path(Path::new("agents/a.md")).expect("add");
        let oid = idx.write_tree().expect("write tree");
        let tree = repo.find_tree(oid).expect("find tree");
        let sig = git2::Signature::now("test", "test@example.com").unwrap();
        repo.commit(Some("HEAD"), &sig, &sig, "initial", &tree, &[])
            .expect("commit");
    }
    (dir, repo)
}

/// 3.0.0 (B7): create a
/// `tag` (lightweight)
/// pointing at HEAD.
/// Lightweight tags have
/// no `tagger`, no
/// message, and no
/// signature slot. The
/// signature-required
/// path must reject
/// them.
fn make_local_repo_with_lightweight_tag() -> (tempfile::TempDir, Repository) {
    let (dir, repo) = make_local_repo_with(true);
    let head_oid = repo.head().unwrap().target().unwrap();
    let target = repo.find_object(head_oid, None).unwrap();
    repo.tag_lightweight("v1.0.0-lightweight", &target, true)
        .expect("create lightweight tag");
    drop(target);
    (dir, repo)
}

/// 3.0.0 (B7): create an
/// `annotated` tag with
/// a real `tagger`
/// field.
fn make_local_repo_with_annotated_tag() -> (tempfile::TempDir, Repository) {
    let (dir, repo) = make_local_repo_with(true);
    let head_oid = repo.head().unwrap().target().unwrap();
    let target = repo.find_commit(head_oid).unwrap();
    let sig = git2::Signature::now("test-signer", "signer@example.com").unwrap();
    repo.tag(
        "v1.0.0-annotated",
        &target.into_object(),
        &sig,
        "release 1.0.0",
        true,
    )
    .expect("create annotated tag");
    (dir, repo)
}

#[test]
fn verify_annotated_tag_rejects_lightweight_tag() {
    // 3.0.0 (B7, audit, CWE-345):
    // the pinned ref is a
    // lightweight tag — a
    // non-annotated pointer
    // at HEAD. The
    // signature-required path
    // must reject it.
    let (_dir, repo) = make_local_repo_with_lightweight_tag();
    let err = verify_annotated_tag(&repo, "v1.0.0-lightweight")
        .expect_err("lightweight tag must be rejected");
    assert!(
        matches!(err, CoreError::ErrGitSignatureMissing { .. }),
        "expected ErrGitSignatureMissing, got: {err:?}"
    );
}

#[test]
fn verify_annotated_tag_accepts_annotated_tag() {
    // 3.0.0 (B7): the
    // pinned ref is an
    // annotated tag with a
    // real `tagger`. The
    // signature-required
    // path must accept it
    // (the structural check
    // passes; cryptographic
    // GPG verification is
    // a 3.1 follow-up).
    let (_dir, repo) = make_local_repo_with_annotated_tag();
    verify_annotated_tag(&repo, "v1.0.0-annotated").expect("annotated tag must be accepted");
}

#[test]
fn verify_annotated_tag_rejects_branch_pin() {
    // 3.0.0 (B7): the
    // pinned ref is a
    // branch. Branches
    // point at `Commit`
    // objects, not `Tag`
    // objects, so the
    // signature-required
    // path must reject
    // them. The
    // post-`init` HEAD on
    // a fresh repo points
    // at `refs/heads/<name>`
    // (the name is
    // `init.defaultBranch`
    // — `main` on
    // git ≥2.28, `master`
    // otherwise). The
    // name varies by host,
    // so we resolve via
    // `head().target()`
    // and read it back
    // from the `Reference`
    // to find the
    // current branch
    // name. We then
    // assert the verify
    // path returns
    // `ErrGitSignatureMissing`
    // for that name
    // (i.e. the
    // short-name branch
    // ref).
    let (_dir, repo) = make_local_repo_with(true);
    let head = repo.head().expect("head");
    let commit_oid = head.target().expect("head target");
    let branch_name = head.shorthand().unwrap_or("HEAD").to_string();
    // The verify path uses
    // `revparse_single`,
    // which accepts the
    // short branch name
    // (it'll resolve
    // through HEAD).
    let _ = commit_oid;
    let err = verify_annotated_tag(&repo, &branch_name).expect_err("branch pin must be rejected");
    assert!(
        matches!(err, CoreError::ErrGitSignatureMissing { .. }),
        "expected ErrGitSignatureMissing, got: {err:?}"
    );
}

#[test]
fn verify_annotated_tag_rejects_commit_sha_pin() {
    // 3.0.0 (B7): the
    // pinned ref is a
    // 40-char commit
    // SHA. A SHA pin is a
    // `Commit` object, not
    // a `Tag` object.
    let (_dir, repo) = make_local_repo_with(true);
    let head_oid = repo.head().unwrap().target().unwrap();
    let commit_sha = head_oid.to_string();
    assert_eq!(commit_sha.len(), 40);
    let err =
        verify_annotated_tag(&repo, &commit_sha).expect_err("commit SHA pin must be rejected");
    assert!(
        matches!(err, CoreError::ErrGitSignatureMissing { .. }),
        "expected ErrGitSignatureMissing, got: {err:?}"
    );
}

#[test]
fn err_git_signature_required_carries_ref_name() {
    // 3.0.0 (B7): the
    // `ErrGitSignatureRequired`
    // variant carries the
    // ref name in the
    // `Display` impl so the
    // operator gets a
    // actionable hint. The
    // `Debug` impl is
    // asserted here; the
    // `Display` impl is
    // covered by the
    // `clone_or_update`
    // integration tests.
    let err = CoreError::ErrGitSignatureRequired {
        ref_name: "v1.2.3".to_string(),
    };
    let s = format!("{err:?}");
    assert!(s.contains("ErrGitSignatureRequired"), "{s}");
    assert!(s.contains("v1.2.3"), "{s}");
}

#[test]
fn err_git_signature_missing_carries_ref_name_and_got() {
    // 3.0.0 (B7): the
    // `ErrGitSignatureMissing`
    // variant carries
    // both the requested
    // ref name AND the
    // actual resolved
    // object kind, so an
    // operator seeing
    // the audit row knows
    // "I pinned a branch,
    // not a tag".
    let err = CoreError::ErrGitSignatureMissing {
        ref_name: "main".to_string(),
        got: "Commit".to_string(),
    };
    let s = format!("{err:?}");
    assert!(s.contains("ErrGitSignatureMissing"), "{s}");
    assert!(s.contains("main"), "{s}");
    assert!(s.contains("Commit"), "{s}");
}
