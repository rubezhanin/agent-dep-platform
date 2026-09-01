//! Crash-recovery integration test (TZ §17.3 + ADR-0006).
//!
//! Simulates a deploy that crashes mid-flight: the journal
//! row is left in `Writing` (the migration for the
//! `Writing -> Committing` transition never happened because
//! the process died). On the next startup `gc_stale` must
//! force-fail the row.
//!
//! MVP-1.0 uses the same `JournalService` for the `Deploy`,
//! `Rollback`, `Plan`, and `Audit` operation types, so the
//! test exercises a `Deploy` op but the recovery contract
//! is identical for all four.

use agent_dep_core::application::journal::{
    JournalService, OperationStatus, OperationType,
};
use agent_dep_core::infrastructure::sqlite::connect;
use serde_json::json;

async fn fresh_journal() -> (tempfile::TempDir, JournalService) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("journal.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    (dir, JournalService::new(db.pool().clone()))
}

#[tokio::test]
async fn stale_writing_operation_is_force_failed_by_gc_stale() {
    let (_dir, journal) = fresh_journal().await;

    // 1. A deploy operation is prepared and moved to Writing.
    let op = journal
        .prepare(OperationType::Deploy, "plan-hash-abc", json!({"target": "/tmp"}))
        .await
        .expect("prepare");
    journal.begin_writing(op.id).await.expect("begin_writing");

    // 2. Verify the row is in Writing (non-terminal) and that
    //    `list_non_terminal` sees it.
    let non_terminal = journal.list_non_terminal().await.expect("list");
    assert_eq!(non_terminal.len(), 1, "Writing op is non-terminal");
    assert_eq!(non_terminal[0].status, OperationStatus::Writing);

    // 3. `gc_stale(keep=0)` is the call the startup hook
    //    makes (with the default 100-keep window this single
    //    row would already be force-failed; passing 0 forces
    //    immediate GC for the test).
    let failed = journal.gc_stale(0).await.expect("gc_stale");
    assert_eq!(failed, 1, "exactly one row was force-failed");

    // 4. The row is now `failed` with a synthetic error,
    //    terminal, and visible to the regular journal reader.
    let after = journal.get(op.id).await.expect("get").expect("row");
    assert_eq!(after.status, OperationStatus::Failed);
    assert!(
        after
            .error
            .as_deref()
            .unwrap_or("")
            .contains("stale operation aborted"),
        "error must mark it as stale, got: {:?}",
        after.error
    );
    assert!(after.finished_at.is_some(), "finished_at must be set");

    // 5. The row no longer appears in `list_non_terminal`.
    let non_terminal = journal.list_non_terminal().await.expect("list");
    assert!(non_terminal.is_empty(), "no non-terminal rows remain");
}

#[tokio::test]
async fn gc_stale_keeps_recent_operations_intact() {
    // A deployment in Writing that the operator is actively
    // working on must NOT be force-failed by `gc_stale`
    // unless it falls outside the `keep` window. The
    // default keep is 100 (per ADR-0006); we pass 5 to
    // exercise the same logic with a tighter window.
    let (_dir, journal) = fresh_journal().await;

    let mut ids = Vec::new();
    for i in 0..3 {
        let op = journal
            .prepare(
                OperationType::Deploy,
                &format!("plan-hash-{i}"),
                json!({"target": "/tmp"}),
            )
            .await
            .expect("prepare");
        journal.begin_writing(op.id).await.expect("begin_writing");
        ids.push(op.id);
    }

    // GC with keep=5 must leave all 3 rows intact.
    let failed = journal.gc_stale(5).await.expect("gc_stale");
    assert_eq!(failed, 0, "no rows beyond the keep window");

    for id in &ids {
        let row = journal.get(*id).await.expect("get").expect("row");
        assert_eq!(
            row.status,
            OperationStatus::Writing,
            "row {id} should still be Writing"
        );
    }
}

#[tokio::test]
async fn completed_operation_is_never_force_failed() {
    // A `committed` row is terminal. `gc_stale` must not
    // touch it under any keep value, even zero.
    let (_dir, journal) = fresh_journal().await;
    let op = journal
        .prepare(OperationType::Deploy, "plan-hash-ok", json!({"target": "/tmp"}))
        .await
        .expect("prepare");
    journal.begin_writing(op.id).await.expect("begin_writing");
    journal.begin_committing(op.id).await.expect("begin_committing");
    journal.complete(op.id).await.expect("complete");

    let failed = journal.gc_stale(0).await.expect("gc_stale");
    assert_eq!(failed, 0, "committed rows are never stale");

    let after = journal.get(op.id).await.expect("get").expect("row");
    assert_eq!(after.status, OperationStatus::Committed);
}

#[tokio::test]
async fn rolled_back_operation_is_never_force_failed() {
    // A `rolled_back` row is also terminal.
    let (_dir, journal) = fresh_journal().await;
    let op = journal
        .prepare(OperationType::Rollback, "plan-hash-rb", json!({"target": "/tmp"}))
        .await
        .expect("prepare");
    journal.rollback(op.id).await.expect("rollback");

    let failed = journal.gc_stale(0).await.expect("gc_stale");
    assert_eq!(failed, 0);

    let after = journal.get(op.id).await.expect("get").expect("row");
    assert_eq!(after.status, OperationStatus::RolledBack);
}
