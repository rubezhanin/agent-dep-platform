//! Integration test: full path against the real upstream
//! `agency-agents` catalog at `C:\projects\agency-agents`.
//!
//! Ingest -> persist to a tempdir SQLite DB -> read back -> verify
//! counts and that the snapshot identity round-trips. Gated on the
//! catalog existing; skips gracefully when not present (CI may not
//! have it).

use std::path::PathBuf;

use agent_dep_core::application::ingest::IngestService;
use agent_dep_core::domain::source::{SnapshotStatus, Source, SourceKind};
use agent_dep_core::infrastructure::repository::IngestRepository;
use agent_dep_core::infrastructure::sqlite::{connect, schema_version};

fn real_agency_agents_path() -> Option<PathBuf> {
    let candidates = [
        r"C:\projects\agency-agents",
        r"C:/projects/agency-agents",
        "/projects/agency-agents",
    ];
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|p| p.join("divisions.json").exists() && p.join("agents").is_dir())
}

#[tokio::test]
async fn ingest_persist_real_agency_agents_round_trips() {
    let Some(root) = real_agency_agents_path() else {
        eprintln!("skip: upstream `agency-agents` catalog not present in any known location");
        return;
    };

    // Set up a tempdir DB and migrate.
    let db_dir = tempfile::tempdir().expect("tempdir");
    let db_path = db_dir.path().join("agency.db");
    let db = connect(&db_path).await.expect("connect");
    db.migrate().await.expect("migrate");
    assert_eq!(schema_version(&db).await.unwrap(), 4);

    // Ingest the real catalog.
    let source = Source::new(SourceKind::local(root.clone()));
    let (result, report) = IngestService::new()
        .ingest_local(&source)
        .expect("ingest real catalog");

    // Persist.
    let repo = IngestRepository::new(db.pool().clone());
    let source_id = repo.upsert_source(&source, false).await.expect("upsert");
    repo.record_snapshot(source_id, &result, &report)
        .await
        .expect("record");

    // Read back the snapshot list and the detail.
    let snaps = repo.list_snapshots(source_id).await.expect("list");
    assert_eq!(snaps.len(), 1, "first run, one snapshot row");
    let only = &snaps[0];
    assert_eq!(only.snapshot.commit_sha, result.snapshot.commit_sha);
    // The real upstream catalog is clean as of 2026-08-31, so we
    // expect zero findings and an Active snapshot. If the catalog
    // ever picks up a pattern match, the snapshot would be Blocked
    // and this assertion would catch it (and tell us to update the
    // catalog, not the test).
    assert_eq!(only.snapshot.status, SnapshotStatus::Active);
    assert_eq!(only.finding_count, 0);
    assert!(only.snapshot.agent_count >= 3);

    let detail = repo
        .get_snapshot_detail(only.snapshot.id)
        .await
        .expect("detail")
        .expect("some");
    assert_eq!(detail.snapshot.commit_sha, result.snapshot.commit_sha);
    assert_eq!(detail.divisions.len(), 1);
    assert!(detail.divisions.iter().any(|d| d.id == "engineering"));
    assert!(detail.agents.len() >= 3);
    let ids: Vec<&str> = detail.agents.iter().map(|a| a.id.as_str()).collect();
    for expected in [
        "backend-engineer",
        "frontend-architect",
        "devops-specialist",
    ] {
        assert!(
            ids.contains(&expected),
            "missing expected agent id `{expected}`; got {ids:?}"
        );
    }
    // Body is persisted intact.
    let be = detail.agents.iter().find(|a| a.id == "backend-engineer");
    if let Some(be) = be {
        assert!(!be.body.is_empty());
        assert_eq!(be.body_hash.len(), 64);
    }

    // Re-ingest -> new snapshot row, old flips to Superseded.
    let (r2, rep2) = IngestService::new()
        .ingest_local(&source)
        .expect("re-ingest");
    assert_eq!(r2.snapshot.commit_sha, result.snapshot.commit_sha);
    repo.record_snapshot(source_id, &r2, &rep2)
        .await
        .expect("record 2");

    let snaps2 = repo.list_snapshots(source_id).await.expect("list 2");
    assert_eq!(snaps2.len(), 2);
    let active: Vec<&_> = snaps2
        .iter()
        .filter(|s| s.snapshot.status == SnapshotStatus::Active)
        .collect();
    let superseded: Vec<&_> = snaps2
        .iter()
        .filter(|s| s.snapshot.status == SnapshotStatus::Superseded)
        .collect();
    assert_eq!(active.len(), 1, "exactly one Active per source");
    assert_eq!(superseded.len(), 1, "previous Active flipped to Superseded");

    // Source row was upserted (same UUID across both runs).
    let source_again = repo
        .find_source_by_location("local", &root.to_string_lossy())
        .await
        .expect("find")
        .expect("row");
    assert_eq!(source_again.id, source_id);
}
