use super::*;
use crate::infrastructure::sqlite::connect;

async fn fresh_repo() -> (tempfile::TempDir, IdempotencyRepository) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("idempotency.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    (dir, IdempotencyRepository::new(db.pool().clone()))
}

#[tokio::test]
async fn record_in_flight_creates_a_row_with_null_response() {
    let (_dir, repo) = fresh_repo().await;
    let created = repo
        .record_in_flight("key-1", "POST /v1/deploys", "hash-a", DEFAULT_TTL_SECONDS)
        .await
        .expect("record");
    assert!(created, "first caller creates the row");
    let stored = repo
        .lookup("key-1", "POST /v1/deploys")
        .await
        .expect("lookup")
        .expect("present");
    assert!(stored.in_flight, "row must be marked in-flight");
    assert_eq!(stored.request_hash, "hash-a");
    assert_eq!(stored.status, 0);
    assert_eq!(stored.body, "");
}

#[tokio::test]
async fn record_in_flight_second_caller_returns_false() {
    let (_dir, repo) = fresh_repo().await;
    repo.record_in_flight("k", "R", "h", 60)
        .await
        .expect("first");
    let created = repo
        .record_in_flight("k", "R", "h", 60)
        .await
        .expect("second");
    assert!(!created, "second caller does NOT create a row");
}

#[tokio::test]
async fn finalize_promotes_an_in_flight_row_to_replayable() {
    let (_dir, repo) = fresh_repo().await;
    repo.record_in_flight("k", "R", "h", 60).await.expect("rec");
    repo.finalize("k", "R", 201, r#"{"deploy":1}"#)
        .await
        .expect("fin");
    let stored = repo
        .lookup("k", "R")
        .await
        .expect("lookup")
        .expect("present");
    assert!(!stored.in_flight);
    assert_eq!(stored.status, 201);
    assert_eq!(stored.body, r#"{"deploy":1}"#);
}

#[tokio::test]
async fn lookup_returns_none_for_unknown_key() {
    let (_dir, repo) = fresh_repo().await;
    let stored = repo
        .lookup("nope", "POST /v1/deploys")
        .await
        .expect("lookup");
    assert!(stored.is_none());
}

#[tokio::test]
async fn same_key_different_route_is_a_separate_row() {
    let (_dir, repo) = fresh_repo().await;
    repo.record_in_flight("k", "POST /v1/deploys", "h1", 60)
        .await
        .expect("rec a");
    let created = repo
        .record_in_flight("k", "POST /v1/targets", "h2", 60)
        .await
        .expect("rec b");
    assert!(created, "different route => different row");
    let a = repo
        .lookup("k", "POST /v1/deploys")
        .await
        .expect("a")
        .expect("present");
    let b = repo
        .lookup("k", "POST /v1/targets")
        .await
        .expect("b")
        .expect("present");
    assert_eq!(a.request_hash, "h1");
    assert_eq!(b.request_hash, "h2");
}

#[tokio::test]
async fn gc_expired_removes_only_expired_rows() {
    let (_dir, repo) = fresh_repo().await;
    // A row with a 1s TTL.
    repo.record_in_flight("exp", "R", "h", 1)
        .await
        .expect("rec exp");
    // A row with a long TTL.
    repo.record_in_flight("keep", "R", "h", DEFAULT_TTL_SECONDS)
        .await
        .expect("rec keep");
    // Wait 1.5s for the first to expire.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let n = repo.gc_expired().await.expect("gc");
    assert!(n >= 1, "must reap at least 1 row, got {n}");
    let exp = repo.lookup("exp", "R").await.expect("exp");
    assert!(exp.is_none(), "expired row must be gone");
    let keep = repo.lookup("keep", "R").await.expect("keep");
    assert!(keep.is_some(), "non-expired row must survive");
}
