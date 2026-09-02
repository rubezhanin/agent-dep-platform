//! Tests for `IngestRepository` (sources / source_snapshots / divisions / agents).
//!
//! All tests use a file-backed SQLite DB in a tempdir (not `:memory:`) so
//! the migration, the writes, and the read-backs share the same database
//! across pool acquires. The fixture builder creates a tiny catalog
//! (one division, two valid agents, one broken agent) so `IngestService`
//! can produce a realistic `IngestResult` we can persist.

use std::fs;
use std::path::{Path, PathBuf};

use agent_dep_hermes_adapter as _; // keep dev-dep alive

use crate::application::ingest::IngestService;
use crate::domain::source::{Source, SourceKind};
use crate::infrastructure::repository::IngestRepository;
use crate::infrastructure::sqlite::{connect, schema_version, Db};

// -----------------------------------------------------------------------
// Fixture builder
// -----------------------------------------------------------------------

struct Fixture {
    /// Keep alive for the duration of the test.
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_path_buf();
        fs::write(
            root.join("divisions.json"),
            r#"{
                "_note": "fixture",
                "divisions": [
                    {"id": "engineering", "order": 1, "label": "Engineering", "description": "Eng"}
                ]
            }"#,
        )
        .expect("write divisions");
        fs::create_dir_all(root.join("agents/engineering")).expect("mkdir agents");
        fs::write(
            root.join("agents/engineering/be.md"),
            "---\n\
             id: be\n\
             name: Backend Engineer\n\
             division: engineering\n\
             role: builds APIs\n\
             description: backend\n\
             tools: [claude-code, hermes]\n\
             activation_phrases: [design an api, write a service]\n\
             version: 1.0.0\n\
             ---\n\
             You are a backend engineer.\n",
        )
        .expect("write be.md");
        fs::write(
            root.join("agents/engineering/fe.md"),
            "---\n\
             id: fe\n\
             name: Frontend Engineer\n\
             division: engineering\n\
             role: builds UIs\n\
             description: frontend\n\
             sensitive: true\n\
             version: 0.2.0\n\
             ---\n\
             You are a frontend engineer.\n",
        )
        .expect("write fe.md");
        // Bad agent: id mismatches file stem.
        fs::write(
            root.join("agents/engineering/broken.md"),
            "---\n\
             id: actually-something-else\n\
             name: Broken\n\
             division: engineering\n\
             role: x\n\
             description: x\n\
             version: 1.0.0\n\
             ---\n\
             body\n",
        )
        .expect("write broken.md");
        Self { _dir: dir, root }
    }
}

fn make_source(path: &Path) -> Source {
    Source::new(SourceKind::local(path.to_path_buf()))
}

async fn make_db() -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("repo.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    (dir, db)
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[tokio::test]
async fn migration_advances_schema_version() {
    let (_dir, db) = make_db().await;
    let v = schema_version(&db).await.expect("version");
    // The exact value depends on the latest applied migration. As of
    // the MVP-3 journal (migrations 001/002/003/004), it should be at
    // least 4. This test guards against a missing or duplicate
    // migration. Update the bound when adding more migrations.
    assert!(
        v >= 4,
        "schema_version should be at least 4 after migrations run"
    );
}

#[tokio::test]
async fn upsert_source_inserts_new_row() {
    let (_dir, db) = make_db().await;
    let repo = IngestRepository::new(db.pool().clone());
    let fx = Fixture::new();
    let src = make_source(&fx.root);
    let id = repo.upsert_source(&src, false).await.expect("upsert");
    assert_eq!(id, src.id);
    let round = repo
        .find_source_by_location("local", &fx.root.to_string_lossy())
        .await
        .expect("find")
        .expect("row");
    assert_eq!(round.id, src.id);
    assert!(round.last_indexed_at.is_none());
}

#[tokio::test]
async fn upsert_source_is_idempotent_and_preserves_id() {
    let (_dir, db) = make_db().await;
    let repo = IngestRepository::new(db.pool().clone());
    let fx = Fixture::new();
    let first = make_source(&fx.root);
    let first_id = first.id;
    let id1 = repo.upsert_source(&first, false).await.expect("upsert 1");
    let id2 = repo.upsert_source(&first, true).await.expect("upsert 2");
    assert_eq!(id1, id2, "same physical source should keep its UUID");
    assert_eq!(id1, first_id);
    let round = repo
        .find_source_by_location("local", &fx.root.to_string_lossy())
        .await
        .expect("find")
        .expect("row");
    assert!(
        round.last_indexed_at.is_some(),
        "touch_last_indexed sets it"
    );
}

#[tokio::test]
async fn upsert_source_touch_false_keeps_last_indexed_none() {
    let (_dir, db) = make_db().await;
    let repo = IngestRepository::new(db.pool().clone());
    let fx = Fixture::new();
    let src = make_source(&fx.root);
    repo.upsert_source(&src, false).await.expect("upsert");
    let round = repo
        .find_source_by_location("local", &fx.root.to_string_lossy())
        .await
        .expect("find")
        .expect("row");
    assert!(round.last_indexed_at.is_none());
}

#[tokio::test]
async fn record_snapshot_persists_divisions_agents_and_files() {
    let (_dir, db) = make_db().await;
    let repo = IngestRepository::new(db.pool().clone());
    let fx = Fixture::new();
    let src = make_source(&fx.root);
    let source_id = repo.upsert_source(&src, false).await.expect("upsert");
    let (result, report) = IngestService::new().ingest_local(&src, None).expect("ingest");
    repo.record_snapshot(source_id, &result, &report)
        .await
        .expect("record");

    let detail = repo
        .get_snapshot_detail(result.snapshot.id)
        .await
        .expect("get")
        .expect("some");
    assert_eq!(detail.snapshot.commit_sha, result.snapshot.commit_sha);
    assert_eq!(detail.divisions.len(), 1);
    assert_eq!(detail.divisions[0].id, "engineering");
    assert_eq!(detail.agents.len(), 2, "broken.md should be rejected");
    let ids: Vec<&str> = detail.agents.iter().map(|a| a.id.as_str()).collect();
    assert!(ids.contains(&"be"));
    assert!(ids.contains(&"fe"));
    let be = detail.agents.iter().find(|a| a.id == "be").expect("be");
    assert_eq!(be.tools, vec!["claude-code", "hermes"]);
    assert_eq!(
        be.activation_phrases,
        vec!["design an api", "write a service"]
    );
    let fe = detail.agents.iter().find(|a| a.id == "fe").expect("fe");
    assert!(fe.sensitive);
    assert_eq!(fe.version, "0.2.0");
    assert_eq!(detail.rejected.len(), 1);
    assert!(detail.rejected[0].reason.contains("does not match"));
}

#[tokio::test]
async fn record_snapshot_supersedes_previous_active() {
    let (_dir, db) = make_db().await;
    let repo = IngestRepository::new(db.pool().clone());
    let fx = Fixture::new();
    let src = make_source(&fx.root);
    let source_id = repo.upsert_source(&src, false).await.expect("upsert");

    // First ingest.
    let (r1, rep1) = IngestService::new().ingest_local(&src, None).expect("ingest 1");
    repo.record_snapshot(source_id, &r1, &rep1)
        .await
        .expect("record 1");

    // Touch the file so the content hash differs.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    fs::write(
        fx.root.join("agents/engineering/be.md"),
        "---\n\
         id: be\n\
         name: Backend Engineer\n\
         division: engineering\n\
         role: builds APIs\n\
         description: backend updated\n\
         tools: [claude-code, hermes]\n\
         version: 1.0.1\n\
         ---\n\
         You are a backend engineer. v2\n",
    )
    .expect("rewrite be.md");

    let (r2, rep2) = IngestService::new().ingest_local(&src, None).expect("ingest 2");
    assert_ne!(r1.snapshot.commit_sha, r2.snapshot.commit_sha);
    repo.record_snapshot(source_id, &r2, &rep2)
        .await
        .expect("record 2");

    let snaps = repo.list_snapshots(source_id).await.expect("list");
    assert_eq!(snaps.len(), 2);
    let active: Vec<&_> = snaps
        .iter()
        .filter(|s| s.snapshot.status == crate::domain::source::SnapshotStatus::Active)
        .collect();
    let superseded: Vec<&_> = snaps
        .iter()
        .filter(|s| s.snapshot.status == crate::domain::source::SnapshotStatus::Superseded)
        .collect();
    assert_eq!(active.len(), 1, "exactly one Active per source");
    assert_eq!(superseded.len(), 1, "previous Active flipped to Superseded");
    assert_eq!(active[0].snapshot.commit_sha, r2.snapshot.commit_sha);
    assert_eq!(superseded[0].snapshot.commit_sha, r1.snapshot.commit_sha);
}

#[tokio::test]
async fn record_snapshot_does_not_supersede_when_status_not_active() {
    let (_dir, db) = make_db().await;
    let repo = IngestRepository::new(db.pool().clone());
    let fx = Fixture::new();
    let src = make_source(&fx.root);
    let source_id = repo.upsert_source(&src, false).await.expect("upsert");

    let (mut r, rep) = IngestService::new().ingest_local(&src, None).expect("ingest");
    r.snapshot.status = crate::domain::source::SnapshotStatus::Blocked;
    repo.record_snapshot(source_id, &r, &rep)
        .await
        .expect("record blocked");

    // Now record a real Active — the Blocked one should stay Blocked.
    let (r2, rep2) = IngestService::new().ingest_local(&src, None).expect("ingest 2");
    repo.record_snapshot(source_id, &r2, &rep2)
        .await
        .expect("record active");

    let snaps = repo.list_snapshots(source_id).await.expect("list");
    let active: Vec<&_> = snaps
        .iter()
        .filter(|s| s.snapshot.status == crate::domain::source::SnapshotStatus::Active)
        .collect();
    let blocked: Vec<&_> = snaps
        .iter()
        .filter(|s| s.snapshot.status == crate::domain::source::SnapshotStatus::Blocked)
        .collect();
    assert_eq!(active.len(), 1);
    assert_eq!(blocked.len(), 1, "Blocked snapshot was not flipped");
}

#[tokio::test]
async fn list_snapshots_empty_for_unknown_source() {
    let (_dir, db) = make_db().await;
    let repo = IngestRepository::new(db.pool().clone());
    let snaps = repo
        .list_snapshots(uuid::Uuid::new_v4())
        .await
        .expect("list");
    assert!(snaps.is_empty());
}
