use crate::application::ingest::{extract_frontmatter_pub, IngestService};
use crate::domain::source::{Source, SourceKind};
use std::fs;
use std::path::PathBuf;

fn write_file(path: &std::path::Path, content: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

#[test]
fn extract_frontmatter_simple() {
    let text =
        "---\nid: a\nname: A\ndivision: eng\nrole: r\ndescription: d\nversion: 1.0.0\n---\nbody\n";
    let (fm, body) = extract_frontmatter_pub(text).unwrap();
    assert_eq!(fm.id, "a");
    assert_eq!(fm.name, "A");
    assert_eq!(fm.division, "eng");
    assert_eq!(fm.role, "r");
    assert_eq!(fm.description, "d");
    // The body preserves the line after the closing `---`, including
    // its trailing newline (it is the actual file content).
    assert_eq!(body, "body\n");
}

#[test]
fn extract_frontmatter_with_crlf() {
    let text = "---\r\nid: a\r\nname: A\r\ndivision: eng\r\nrole: r\r\ndescription: d\r\nversion: 1.0.0\r\n---\r\nbody line 1\r\nbody line 2\r\n";
    let (fm, body) = extract_frontmatter_pub(text).unwrap();
    assert_eq!(fm.id, "a");
    assert!(body.contains("body line 1"));
    assert!(body.contains("body line 2"));
}

#[test]
fn extract_frontmatter_rejects_missing_open() {
    let text = "id: a\n---\nbody\n";
    let result = extract_frontmatter_pub(text);
    assert!(result.is_err());
}

#[test]
fn extract_frontmatter_rejects_missing_close() {
    let text = "---\nid: a\nbody without close\n";
    let result = extract_frontmatter_pub(text);
    assert!(result.is_err());
}

#[test]
fn extract_frontmatter_rejects_missing_required() {
    let text = "---\nid: a\nname: A\n---\nbody\n";
    let result = extract_frontmatter_pub(text);
    assert!(
        result.is_err(),
        "missing division/role/description/version should fail"
    );
}

#[test]
fn ingest_local_agency_agents_shape() {
    // Mimic the upstream `agency-agents` layout in a temp dir.
    let dir = tempfile::tempdir().unwrap();
    let root: PathBuf = dir.path().to_path_buf();

    write_file(
        &root.join("divisions.json"),
        r#"{
            "divisions": [
                {"id": "engineering", "order": 1, "label": "Engineering"}
            ]
        }"#,
    );

    write_file(
        &root.join("agents/engineering/backend-engineer.md"),
        "---\nid: backend-engineer\nname: Backend Engineer\ndivision: engineering\nrole: API\ndescription: backend\nversion: 1.0.0\n---\nBody of backend.\n",
    );
    write_file(
        &root.join("agents/engineering/devops.md"),
        "---\nid: devops\nname: DevOps\ndivision: engineering\nrole: ops\ndescription: devops\nversion: 0.5.0\n---\nBody of devops.\n",
    );
    write_file(
        &root.join("agents/engineering/bad-id.md"),
        "---\nid: mismatch\nname: ID Mismatch\ndivision: engineering\nrole: r\ndescription: d\nversion: 1.0.0\n---\nBody.\n",
    );
    write_file(
        &root.join("agents/engineering/orphan-division.md"),
        "---\nid: orphan\nname: Orphan\ndivision: ghost\nrole: r\ndescription: d\nversion: 1.0.0\n---\nBody.\n",
    );

    let source = Source::new(SourceKind::local(root.clone()));
    let svc = IngestService::new();
    let (result, report) = svc.ingest_local(&source).expect("ingest");

    // 2 good agents; 2 rejected (id mismatch + unknown division).
    assert_eq!(result.agents.len(), 2, "expected 2 valid agents");
    assert_eq!(report.agents_parsed, 2);
    assert_eq!(report.agents_rejected.len(), 2);

    let ids: Vec<&str> = result.agents.iter().map(|a| a.id.as_str()).collect();
    assert!(ids.contains(&"backend-engineer"));
    assert!(ids.contains(&"devops"));

    // Snapshot identity is stable: re-ingesting yields the same commit.
    let (_again, _) = svc.ingest_local(&source).expect("ingest 2");
    assert_eq!(
        result.snapshot.commit_sha, _again.snapshot.commit_sha,
        "snapshot identity must be stable across re-ingest"
    );
}

#[test]
fn ingest_local_missing_divisions_errors() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    // No divisions.json
    let source = Source::new(SourceKind::local(root));
    let svc = IngestService::new();
    let result = svc.ingest_local(&source);
    assert!(result.is_err(), "missing divisions.json should fail ingest");
}
