//! Tests for `JournalService` and the operations state machine.

use super::*;
use crate::infrastructure::sqlite::{connect, schema_version};
use serde_json::json;

async fn make_service() -> (tempfile::TempDir, JournalService) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("journal.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    assert_eq!(schema_version(&db).await.unwrap(), 16);
    (dir, JournalService::new(db.pool().clone()))
}

fn small_effect() -> serde_json::Value {
    json!({ "writes": [], "deletes": [] })
}

fn plan_hash(s: &str) -> &str {
    // Simple helper; in real use, callers pass a sha256 hex.
    if s.is_empty() {
        "deadbeef"
    } else {
        s
    }
}

// -----------------------------------------------------------------------
// prepare / get / list_non_terminal
// -----------------------------------------------------------------------

#[tokio::test]
async fn prepare_creates_row_in_prepared_status() {
    let (_dir, svc) = make_service().await;
    let op = svc
        .prepare(OperationType::Deploy, plan_hash("a"), small_effect())
        .await
        .expect("prepare");
    assert_eq!(op.status, OperationStatus::Prepared);
    assert_eq!(op.op_type, OperationType::Deploy);
    assert!(op.finished_at.is_none());
    assert!(op.error.is_none());

    let fetched = svc.get(op.id).await.expect("get").expect("some");
    assert_eq!(fetched.id, op.id);
    assert_eq!(fetched.status, OperationStatus::Prepared);
    assert_eq!(fetched.plan_hash, "a");
}

#[tokio::test]
async fn get_returns_none_for_unknown_id() {
    let (_dir, svc) = make_service().await;
    let got = svc.get(uuid::Uuid::new_v4()).await.expect("get");
    assert!(got.is_none());
}

#[tokio::test]
async fn list_non_terminal_returns_only_open_ops() {
    let (_dir, svc) = make_service().await;
    let a = svc
        .prepare(OperationType::Deploy, plan_hash("a"), small_effect())
        .await
        .unwrap();
    let _b = svc
        .prepare(OperationType::Plan, plan_hash("b"), small_effect())
        .await
        .unwrap();
    // Complete `a` so it leaves the non-terminal set.
    svc.begin_writing(a.id).await.unwrap();
    svc.begin_committing(a.id).await.unwrap();
    svc.complete(a.id).await.unwrap();

    let non_terminal = svc.list_non_terminal().await.unwrap();
    assert_eq!(non_terminal.len(), 1);
    assert_eq!(non_terminal[0].id, _b.id);
    assert_eq!(non_terminal[0].status, OperationStatus::Prepared);
}

#[tokio::test]
async fn empty_plan_hash_is_rejected() {
    let (_dir, svc) = make_service().await;
    let err = svc
        .prepare(OperationType::Deploy, "", small_effect())
        .await
        .expect_err("empty plan_hash");
    assert!(err.to_string().contains("plan_hash"));
}

#[tokio::test]
async fn effect_larger_than_cap_is_rejected() {
    let (_dir, svc) = make_service().await;
    // Build a 1.1 MiB string of 'x'.
    let huge = "x".repeat(MAX_EFFECT_BYTES + 1000);
    let effect = json!({ "blob": huge });
    let err = svc
        .prepare(OperationType::Deploy, plan_hash("a"), effect)
        .await
        .expect_err("huge effect");
    assert!(err.to_string().contains("effect too large"));
}

#[tokio::test]
async fn effect_round_trips_through_json() {
    let (_dir, svc) = make_service().await;
    let effect = json!({
        "writes": [
            { "path": "/tmp/a", "expected_sha256": "deadbeef" },
            { "path": "/tmp/b", "expected_sha256": "cafebabe" }
        ],
        "deletes": ["/tmp/c"]
    });
    let op = svc
        .prepare(OperationType::Deploy, plan_hash("a"), effect.clone())
        .await
        .unwrap();
    let back = svc.get(op.id).await.unwrap().unwrap();
    assert_eq!(back.effect, effect);
}

// -----------------------------------------------------------------------
// State machine
// -----------------------------------------------------------------------

#[tokio::test]
async fn happy_path_prepared_to_committed() {
    let (_dir, svc) = make_service().await;
    let op = svc
        .prepare(OperationType::Deploy, plan_hash("a"), small_effect())
        .await
        .unwrap();
    svc.begin_writing(op.id).await.unwrap();
    let mid = svc.get(op.id).await.unwrap().unwrap();
    assert_eq!(mid.status, OperationStatus::Writing);
    assert!(mid.finished_at.is_none());

    svc.begin_committing(op.id).await.unwrap();
    let mid = svc.get(op.id).await.unwrap().unwrap();
    assert_eq!(mid.status, OperationStatus::Committing);

    svc.complete(op.id).await.unwrap();
    let done = svc.get(op.id).await.unwrap().unwrap();
    assert_eq!(done.status, OperationStatus::Committed);
    assert!(done.finished_at.is_some());
}

#[tokio::test]
async fn fail_from_writing() {
    let (_dir, svc) = make_service().await;
    let op = svc
        .prepare(OperationType::Deploy, plan_hash("a"), small_effect())
        .await
        .unwrap();
    svc.begin_writing(op.id).await.unwrap();
    svc.fail(op.id, "boom").await.unwrap();
    let got = svc.get(op.id).await.unwrap().unwrap();
    assert_eq!(got.status, OperationStatus::Failed);
    assert_eq!(got.error.as_deref(), Some("boom"));
    assert!(got.finished_at.is_some());
}

#[tokio::test]
async fn fail_from_prepared() {
    let (_dir, svc) = make_service().await;
    let op = svc
        .prepare(OperationType::Deploy, plan_hash("a"), small_effect())
        .await
        .unwrap();
    svc.fail(op.id, "rejected at prepare-time").await.unwrap();
    let got = svc.get(op.id).await.unwrap().unwrap();
    assert_eq!(got.status, OperationStatus::Failed);
    assert_eq!(got.error.as_deref(), Some("rejected at prepare-time"));
}

#[tokio::test]
async fn rollback_from_committed() {
    let (_dir, svc) = make_service().await;
    let op = svc
        .prepare(OperationType::Rollback, plan_hash("a"), small_effect())
        .await
        .unwrap();
    svc.begin_writing(op.id).await.unwrap();
    svc.begin_committing(op.id).await.unwrap();
    svc.complete(op.id).await.unwrap();
    svc.rollback(op.id).await.unwrap();
    let got = svc.get(op.id).await.unwrap().unwrap();
    assert_eq!(got.status, OperationStatus::RolledBack);
}

#[tokio::test]
async fn rollback_from_writing_is_recovery_path() {
    let (_dir, svc) = make_service().await;
    let op = svc
        .prepare(OperationType::Deploy, plan_hash("a"), small_effect())
        .await
        .unwrap();
    svc.begin_writing(op.id).await.unwrap();
    // App died mid-write; recovery rolls back.
    svc.rollback(op.id).await.unwrap();
    let got = svc.get(op.id).await.unwrap().unwrap();
    assert_eq!(got.status, OperationStatus::RolledBack);
}

#[tokio::test]
async fn rollback_from_prepared_is_recovery_path() {
    let (_dir, svc) = make_service().await;
    let op = svc
        .prepare(OperationType::Deploy, plan_hash("a"), small_effect())
        .await
        .unwrap();
    // App died before any write; recovery rolls back.
    svc.rollback(op.id).await.unwrap();
    let got = svc.get(op.id).await.unwrap().unwrap();
    assert_eq!(got.status, OperationStatus::RolledBack);
}

// -----------------------------------------------------------------------
// Invalid transitions
// -----------------------------------------------------------------------

#[tokio::test]
async fn cannot_skip_writing_state() {
    let (_dir, svc) = make_service().await;
    let op = svc
        .prepare(OperationType::Deploy, plan_hash("a"), small_effect())
        .await
        .unwrap();
    // prepared -> committing is illegal; must go via writing.
    let err = svc
        .begin_committing(op.id)
        .await
        .expect_err("skipping writing should be rejected");
    assert!(err.to_string().contains("invalid transition"));
}

#[tokio::test]
async fn cannot_complete_from_prepared() {
    let (_dir, svc) = make_service().await;
    let op = svc
        .prepare(OperationType::Deploy, plan_hash("a"), small_effect())
        .await
        .unwrap();
    let err = svc
        .complete(op.id)
        .await
        .expect_err("complete from prepared is illegal");
    assert!(err.to_string().contains("invalid transition"));
}

#[tokio::test]
async fn cannot_advance_terminal_ops() {
    let (_dir, svc) = make_service().await;
    let op = svc
        .prepare(OperationType::Deploy, plan_hash("a"), small_effect())
        .await
        .unwrap();
    svc.begin_writing(op.id).await.unwrap();
    svc.begin_committing(op.id).await.unwrap();
    svc.complete(op.id).await.unwrap();
    // Already committed; any further transition is illegal.
    assert!(svc.begin_writing(op.id).await.is_err());
    assert!(svc.complete(op.id).await.is_err());
    assert!(svc.fail(op.id, "x").await.is_err());
    // rollback from committed is the one legal exit.
    svc.rollback(op.id).await.unwrap();
    // Now rolled_back; nothing more.
    assert!(svc.rollback(op.id).await.is_err());
    assert!(svc.fail(op.id, "x").await.is_err());
}

#[tokio::test]
async fn transition_on_unknown_op_is_rejected() {
    let (_dir, svc) = make_service().await;
    let err = svc
        .begin_writing(uuid::Uuid::new_v4())
        .await
        .expect_err("unknown op");
    assert!(err.to_string().contains("not found"));
}

// -----------------------------------------------------------------------
// Bounded retention (gc_stale)
// -----------------------------------------------------------------------

#[tokio::test]
async fn gc_stale_force_fails_old_non_terminal_ops() {
    let (_dir, svc) = make_service().await;
    // Create 5 non-terminal ops.
    let mut ids = Vec::new();
    for i in 0..5 {
        let op = svc
            .prepare(
                OperationType::Deploy,
                plan_hash(&format!("p{i}")),
                small_effect(),
            )
            .await
            .unwrap();
        ids.push(op.id);
        // Spread out started_at slightly so DESC ordering is stable.
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    // keep=2 means the 3 oldest non-terminal rows get force-failed.
    let n = svc.gc_stale(2).await.unwrap();
    assert_eq!(n, 3);
    // ids[0..3] should now be failed; ids[3..5] still non-terminal.
    for id in &ids[..3] {
        let got = svc.get(*id).await.unwrap().unwrap();
        assert_eq!(got.status, OperationStatus::Failed);
        assert!(got
            .error
            .as_deref()
            .unwrap_or("")
            .contains("stale operation aborted"));
    }
    for id in &ids[3..] {
        let got = svc.get(*id).await.unwrap().unwrap();
        assert_eq!(got.status, OperationStatus::Prepared);
    }
}

#[tokio::test]
async fn gc_stale_does_not_touch_terminal_ops() {
    let (_dir, svc) = make_service().await;
    let op = svc
        .prepare(OperationType::Deploy, plan_hash("a"), small_effect())
        .await
        .unwrap();
    svc.begin_writing(op.id).await.unwrap();
    svc.begin_committing(op.id).await.unwrap();
    svc.complete(op.id).await.unwrap();
    let n = svc.gc_stale(0).await.unwrap();
    assert_eq!(n, 0, "no non-terminal ops to force-fail");
    let got = svc.get(op.id).await.unwrap().unwrap();
    assert_eq!(got.status, OperationStatus::Committed);
}

#[tokio::test]
async fn gc_stale_with_zero_keep_force_fails_everything_non_terminal() {
    let (_dir, svc) = make_service().await;
    for i in 0..3 {
        svc.prepare(
            OperationType::Plan,
            plan_hash(&format!("p{i}")),
            small_effect(),
        )
        .await
        .unwrap();
    }
    let n = svc.gc_stale(0).await.unwrap();
    assert_eq!(n, 3);
    let remaining = svc.list_non_terminal().await.unwrap();
    assert!(remaining.is_empty());
}

// -----------------------------------------------------------------------
// Type / status string round-trip
// -----------------------------------------------------------------------

#[test]
fn operation_type_round_trip() {
    for t in [
        OperationType::Deploy,
        OperationType::Rollback,
        OperationType::Plan,
        OperationType::Audit,
    ] {
        let s = t.as_str();
        let back = OperationType::parse(s).expect("parse");
        assert_eq!(t, back);
    }
    assert!(OperationType::parse("nope").is_err());
}

#[test]
fn operation_status_round_trip_and_terminal_flags() {
    for s in [
        OperationStatus::Prepared,
        OperationStatus::Writing,
        OperationStatus::Committing,
        OperationStatus::Committed,
        OperationStatus::RolledBack,
        OperationStatus::Failed,
    ] {
        let back = OperationStatus::parse(s.as_str()).expect("parse");
        assert_eq!(s, back);
    }
    assert!(OperationStatus::parse("nope").is_err());

    assert!(OperationStatus::Prepared.is_non_terminal());
    assert!(OperationStatus::Writing.is_non_terminal());
    assert!(OperationStatus::Committing.is_non_terminal());
    assert!(!OperationStatus::Committed.is_non_terminal());
    assert!(!OperationStatus::RolledBack.is_non_terminal());
    assert!(!OperationStatus::Failed.is_non_terminal());
    assert!(OperationStatus::Committed.is_terminal());
    assert!(OperationStatus::RolledBack.is_terminal());
    assert!(OperationStatus::Failed.is_terminal());
}

// Sanity: silence unused warnings for items used in trait/derive paths.
#[allow(dead_code)]
fn _op_marker(_: Operation) {}
