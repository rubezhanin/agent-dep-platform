//! Tests for `IngestV2Service`.

use super::*;
use crate::application::scanner::ScanPolicy;
use crate::domain::source::{Source, SourceKind};

fn write_v2_catalog(root: &Path) {
    fs::write(
        root.join("divisions.json"),
        r#"{
            "_note": "v2 test",
            "divisions": [
                {"id": "engineering", "order": 1, "label": "Engineering"}
            ]
        }"#,
    )
    .unwrap();

    let agents = root.join("agents");
    fs::create_dir_all(agents.join("backend-architect")).unwrap();
    fs::write(
        agents.join("backend-architect/agent.yaml"),
        r#"$schema: "https://schemas.agent-dep.platform/agent/v1.json"
apiVersion: agency/v1
kind: Agent
metadata:
  id: backend-architect
  name: Backend Architect
  version: 2.4.0
  description: Designs backend architectures.
spec:
  instructions: instructions.md
  skills: []
  runtime:
    hermes:
      supported: true
"#,
    )
    .unwrap();
    fs::write(
        agents.join("backend-architect/instructions.md"),
        "# Backend Architect\n\nYou design backend systems.\n",
    )
    .unwrap();

    let skills = root.join("skills");
    fs::create_dir_all(skills.join("postgres")).unwrap();
    fs::write(
        skills.join("postgres/skill.yaml"),
        r#"$schema: "https://schemas.agent-dep.platform/skill/v1.json"
apiVersion: agency/v1
kind: Skill
metadata:
  id: postgres
  name: PostgreSQL
  version: 3.1.0
  description: PostgreSQL design, migrations and diagnostics.
spec:
  body: SKILL.md
"#,
    )
    .unwrap();
    fs::write(
        skills.join("postgres/SKILL.md"),
        "# PostgreSQL\n\nUse indexes wisely.\n",
    )
    .unwrap();
}

#[test]
fn ingest_v2_parses_agents_and_skills() {
    let dir = tempfile::tempdir().unwrap();
    write_v2_catalog(dir.path());

    let source = Source::new(SourceKind::local(dir.path().to_path_buf()));
    let policy = ScanPolicy::mvp_default();
    let (result, report) =
        IngestV2Service::new().ingest_v2(&source, &policy).expect("ingest v2");

    assert_eq!(result.agents.len(), 1);
    assert_eq!(result.agents[0].id, "backend-architect");
    assert_eq!(result.agents[0].version, Version::parse("2.4.0").unwrap());

    assert_eq!(result.skills.len(), 1);
    assert_eq!(result.skills[0].id, "postgres");
    assert_eq!(result.skills[0].version, Version::parse("3.1.0").unwrap());
    assert!(result.skills[0].body.contains("Use indexes wisely"));

    assert_eq!(result.snapshot.status, SnapshotStatus::Active);
    assert_eq!(result.snapshot.agent_count, 1);
    assert!(!result.snapshot.commit_sha.is_empty());
    assert_eq!(report.agents_parsed, 1);
    assert_eq!(report.divisions_loaded, 1);
}

#[test]
fn ingest_v2_rejects_agent_with_id_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("divisions.json"),
        r#"{"divisions": []}"#,
    )
    .unwrap();
    let agents = dir.path().join("agents");
    fs::create_dir_all(agents.join("real-id")).unwrap();
    fs::write(
        agents.join("real-id/agent.yaml"),
        r#"$schema: "https://schemas.agent-dep.platform/agent/v1.json"
apiVersion: agency/v1
kind: Agent
metadata:
  id: different-id
  name: Mismatch
  version: 1.0.0
  description: d
spec:
  instructions: instructions.md
  skills: []
  runtime:
    hermes:
      supported: true
"#,
    )
    .unwrap();
    fs::write(agents.join("real-id/instructions.md"), "body\n").unwrap();

    let source = Source::new(SourceKind::local(dir.path().to_path_buf()));
    let (result, report) = IngestV2Service::new()
        .ingest_v2(&source, &ScanPolicy::mvp_default())
        .expect("ingest v2");
    assert_eq!(result.agents.len(), 0);
    assert_eq!(report.agents_rejected.len(), 1);
    assert!(report.agents_rejected[0]
        .reason
        .contains("does not match directory"));
}

#[test]
fn ingest_v2_rejects_missing_instructions_md() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("divisions.json"),
        r#"{"divisions": []}"#,
    )
    .unwrap();
    let agents = dir.path().join("agents");
    fs::create_dir_all(agents.join("lonely")).unwrap();
    fs::write(
        agents.join("lonely/agent.yaml"),
        r#"$schema: "https://schemas.agent-dep.platform/agent/v1.json"
apiVersion: agency/v1
kind: Agent
metadata:
  id: lonely
  name: Lonely
  version: 1.0.0
  description: d
spec:
  instructions: instructions.md
  skills: []
  runtime:
    hermes:
      supported: true
"#,
    )
    .unwrap();
    // intentionally no instructions.md

    let source = Source::new(SourceKind::local(dir.path().to_path_buf()));
    let (result, report) = IngestV2Service::new()
        .ingest_v2(&source, &ScanPolicy::mvp_default())
        .expect("ingest v2");
    assert_eq!(result.agents.len(), 0);
    assert!(report
        .agents_rejected
        .iter()
        .any(|r| r.reason.contains("is not a file")));
}

#[test]
fn ingest_v2_without_divisions_json_still_parses() {
    let dir = tempfile::tempdir().unwrap();
    let agents = dir.path().join("agents");
    fs::create_dir_all(agents.join("a")).unwrap();
    fs::write(
        agents.join("a/agent.yaml"),
        r#"$schema: "https://schemas.agent-dep.platform/agent/v1.json"
apiVersion: agency/v1
kind: Agent
metadata:
  id: a
  name: A
  version: 1.0.0
  description: d
spec:
  instructions: instructions.md
  skills: []
  runtime:
    hermes:
      supported: true
"#,
    )
    .unwrap();
    fs::write(agents.join("a/instructions.md"), "body\n").unwrap();

    let source = Source::new(SourceKind::local(dir.path().to_path_buf()));
    let (result, _) = IngestV2Service::new()
        .ingest_v2(&source, &ScanPolicy::mvp_default())
        .expect("ingest v2");
    assert_eq!(result.agents.len(), 1);
    assert_eq!(result.snapshot.division_count, 0);
}
