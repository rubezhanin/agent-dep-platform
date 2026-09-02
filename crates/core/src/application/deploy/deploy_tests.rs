//! Tests for `DeploymentService` — the journal-backed `apply` step
//! that closes the MVP-3 read→plan→write loop.

use super::*;
use crate::application::journal::JournalService;
use crate::domain::agent::Agent;
use crate::domain::system::{
    AgentRef, ResolvedAgent, System, SystemAgentRef, SystemMetadata, SystemSpec,
};
use crate::domain::version::Version;
use crate::infrastructure::repository::deployed_artifacts_repository::DeployedArtifactsRepository;
use crate::infrastructure::sqlite::connect;
use uuid::Uuid;

fn make_agent(id: &str, version: &str, body: &str) -> Agent {
    Agent {
        snapshot_id: Uuid::nil(),
        id: id.to_string(),
        division: "engineering".to_string(),
        name: format!("{id} display"),
        display_name: None,
        role: "role".to_string(),
        description: "desc".to_string(),
        version: Version::parse(version).unwrap(),
        sensitive: false,
        tools: vec![],
        activation_phrases: vec![],
        body: body.to_string(),
        body_hash: "deadbeef".to_string(),
    }
}

fn make_system(agents: Vec<(&str, &str)>) -> System {
    let resolved: Vec<ResolvedAgent> = agents
        .iter()
        .map(|(id, v)| ResolvedAgent {
            agent: make_agent(id, v, &format!("You are {id}.\n")),
            from_ref: AgentRef {
                id: (*id).to_string(),
                version: Version::parse(v).unwrap(),
            },
            applied_override: None,
        })
        .collect();
    System {
        metadata: SystemMetadata {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: None,
        },
        spec: SystemSpec {
            runtime_type: "hermes".to_string(),
            source: "x".to_string(),
            agents: resolved
                .iter()
                .map(|r| SystemAgentRef {
                    agent_ref: r.from_ref.clone(),
                    r#override: None,
                })
                .collect(),
            skills: vec![],
            project_root: None,
        },
        source_id: Uuid::nil(),
        snapshot_id: Uuid::nil(),
        resolved,
        resolved_skills: vec![],
    }
}

async fn make_journal() -> (
    tempfile::TempDir,
    JournalService,
    DeployedArtifactsRepository,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("journal.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    (
        dir,
        JournalService::new(db.pool().clone()),
        DeployedArtifactsRepository::new(db.pool().clone()),
    )
}

#[tokio::test]
async fn apply_writes_each_resolved_agent_file() {
    let (_dir, journal, artifacts) = make_journal().await;
    let target = tempfile::tempdir().expect("target tempdir");
    let system = make_system(vec![("be", "1.0.0"), ("fe", "1.0.0")]);
    let svc = DeploymentService;
    let outcome = svc
        .apply(target.path(), &system, &journal, &artifacts)
        .await
        .expect("apply");

    assert_eq!(outcome.wrote, 2);
    assert_eq!(outcome.skipped, 0);
    assert_eq!(outcome.backed_up, 0);

    let be_path = target.path().join("agents/be@1.0.0/be.md");
    let fe_path = target.path().join("agents/fe@1.0.0/fe.md");
    assert!(be_path.exists(), "be.md should exist at {be_path:?}");
    assert!(fe_path.exists(), "fe.md should exist at {fe_path:?}");

    let be_content = std::fs::read_to_string(&be_path).expect("read be.md");
    assert!(
        be_content.contains("You are be."),
        "be content: {be_content}"
    );
    let fe_content = std::fs::read_to_string(&fe_path).expect("read fe.md");
    assert!(
        fe_content.contains("You are fe."),
        "fe content: {fe_content}"
    );
}

#[tokio::test]
async fn apply_is_idempotent_second_run_with_same_content() {
    let (_dir, journal, artifacts) = make_journal().await;
    let target = tempfile::tempdir().expect("target tempdir");
    let system = make_system(vec![("be", "1.0.0")]);
    let svc = DeploymentService;

    let first = svc
        .apply(target.path(), &system, &journal, &artifacts)
        .await
        .expect("first");
    assert_eq!(first.wrote, 1);
    assert_eq!(first.skipped, 0);

    let second = svc
        .apply(target.path(), &system, &journal, &artifacts)
        .await
        .expect("second");
    assert_eq!(second.wrote, 0, "no new writes on idempotent re-deploy");
    assert_eq!(second.skipped, 1, "second run should skip identical file");
    assert_eq!(second.backed_up, 0);
}

#[tokio::test]
async fn apply_creates_backup_when_content_changes() {
    let (_dir, journal, artifacts) = make_journal().await;
    let target = tempfile::tempdir().expect("target tempdir");
    let system_v1 = make_system(vec![("be", "1.0.0")]);
    let svc = DeploymentService;

    svc.apply(target.path(), &system_v1, &journal, &artifacts)
        .await
        .expect("v1");

    // Change the body and re-deploy.
    let system_v1_changed = System {
        resolved: vec![ResolvedAgent {
            agent: make_agent("be", "1.0.0", "You are be. v2 content.\n"),
            from_ref: AgentRef {
                id: "be".to_string(),
                version: Version::new(1, 0, 0),
            },
            applied_override: None,
        }],
        ..system_v1.clone()
    };
    let second = svc
        .apply(target.path(), &system_v1_changed, &journal, &artifacts)
        .await
        .expect("v1 changed");
    assert_eq!(second.wrote, 1);
    assert_eq!(
        second.backed_up, 1,
        "old content backed up before overwrite"
    );

    // The new file has v2 content.
    let new_content =
        std::fs::read_to_string(target.path().join("agents/be@1.0.0/be.md")).expect("read new");
    assert!(new_content.contains("v2 content"));

    // A backup file exists under .backups/, which lives next to the
    // overwritten file (i.e. `<target>/agents/be@1.0.0/.backups/`).
    let backups_dir = target.path().join("agents/be@1.0.0/.backups");
    let backups: Vec<_> = std::fs::read_dir(&backups_dir)
        .expect("read .backups")
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(backups.len(), 1, "exactly one backup should exist");
    let backup_content = std::fs::read_to_string(backups[0].path()).expect("read backup");
    assert!(
        !backup_content.contains("v2"),
        "backup should contain the v1 body (no v2), got: {backup_content:?}"
    );
    assert!(
        backup_content.contains("You are be"),
        "backup should contain the v1 body marker, got: {backup_content:?}"
    );
}

#[tokio::test]
async fn apply_records_operation_in_journal() {
    let (_dir, journal, artifacts) = make_journal().await;
    let target = tempfile::tempdir().expect("target tempdir");
    let system = make_system(vec![("be", "1.0.0")]);
    let svc = DeploymentService;
    let outcome = svc
        .apply(target.path(), &system, &journal, &artifacts)
        .await
        .expect("apply");
    let op = journal
        .get(outcome.operation_id)
        .await
        .expect("get")
        .expect("some");
    assert_eq!(
        op.status,
        crate::application::journal::OperationStatus::Committed
    );
    assert!(op.error.is_none());
    assert!(op.finished_at.is_some());
    let ops = journal.list_non_terminal().await.expect("list");
    assert!(ops.is_empty(), "no non-terminal ops left after success");
}

#[tokio::test]
async fn apply_rejects_when_target_is_not_a_directory() {
    let (_dir, journal, artifacts) = make_journal().await;
    let target = tempfile::tempdir().expect("target tempdir");
    // Create a regular file where a directory is expected.
    let not_a_dir = target.path().join("not-a-dir");
    std::fs::write(&not_a_dir, b"x").expect("write file");
    let system = make_system(vec![("be", "1.0.0")]);
    let svc = DeploymentService;
    let err = svc
        .apply(&not_a_dir, &system, &journal, &artifacts)
        .await
        .expect_err("apply on a file should error");
    let _ = err;
}

#[tokio::test]
async fn apply_writes_one_deployed_artifacts_row_per_file() {
    let (_dir, journal, artifacts) = make_journal().await;
    let target = tempfile::tempdir().expect("target tempdir");
    let system = make_system(vec![("be", "1.0.0"), ("fe", "1.0.0")]);
    let svc = DeploymentService;
    let outcome = svc
        .apply(target.path(), &system, &journal, &artifacts)
        .await
        .expect("apply");
    assert_eq!(outcome.wrote, 2);

    let rows = artifacts
        .list_for_system("test")
        .await
        .expect("list_for_system");
    assert_eq!(rows.len(), 2, "one row per agent file");

    // Each row has state="current" and actual==expected.
    for (target_rel, expected, actual) in &rows {
        assert!(
            actual.is_some(),
            "{target_rel} should have actual_sha256 set after a successful write"
        );
        assert_eq!(
            actual.as_deref(),
            Some(expected.as_str()),
            "{target_rel}: actual_sha must equal expected_sha after write"
        );
        let row = artifacts
            .get("test", target_rel)
            .await
            .expect("get")
            .expect("row exists");
        assert_eq!(row.state, "current");
        assert!(row.last_verified_at.is_some());
    }
}

#[tokio::test]
async fn apply_re_records_actual_sha_after_content_change() {
    let (_dir, journal, artifacts) = make_journal().await;
    let target = tempfile::tempdir().expect("target tempdir");
    let system_v1 = make_system(vec![("be", "1.0.0")]);
    let svc = DeploymentService;

    svc.apply(target.path(), &system_v1, &journal, &artifacts)
        .await
        .expect("v1");
    let first = artifacts
        .get("test", "agents/be@1.0.0/be.md")
        .await
        .expect("get")
        .expect("row");
    let first_expected = first.expected_sha256.clone();
    let first_deployed = first.deployed_at.clone();

    // Change the body, redeploy.
    let system_v2 = System {
        resolved: vec![ResolvedAgent {
            agent: make_agent("be", "1.0.0", "You are be. v2 content.\n"),
            from_ref: AgentRef {
                id: "be".to_string(),
                version: Version::new(1, 0, 0),
            },
            applied_override: None,
        }],
        ..system_v1.clone()
    };
    svc.apply(target.path(), &system_v2, &journal, &artifacts)
        .await
        .expect("v2");

    let rows = artifacts.list_for_system("test").await.expect("list");
    assert_eq!(rows.len(), 1, "upsert keeps a single row per target");
    let second = artifacts
        .get("test", "agents/be@1.0.0/be.md")
        .await
        .expect("get")
        .expect("row");
    assert_ne!(
        second.expected_sha256, first_expected,
        "expected_sha must change when body changes"
    );
    assert_eq!(
        second.actual_sha256.as_deref(),
        Some(second.expected_sha256.as_str()),
        "actual_sha must equal new expected_sha after rewrite"
    );
    assert_eq!(second.state, "current");
    assert_ne!(
        second.deployed_at, first_deployed,
        "deployed_at must advance to reflect the latest apply"
    );
}

#[tokio::test]
async fn apply_idempotent_run_does_not_grow_deployed_artifacts() {
    let (_dir, journal, artifacts) = make_journal().await;
    let target = tempfile::tempdir().expect("target tempdir");
    let system = make_system(vec![("be", "1.0.0")]);
    let svc = DeploymentService;

    svc.apply(target.path(), &system, &journal, &artifacts)
        .await
        .expect("first");
    svc.apply(target.path(), &system, &journal, &artifacts)
        .await
        .expect("second");

    let rows = artifacts.list_for_system("test").await.expect("list");
    assert_eq!(
        rows.len(),
        1,
        "idempotent re-deploy upserts the same row, not a new one"
    );
}
