use super::*;
use crate::infrastructure::sqlite::connect;

async fn fresh_db() -> (tempfile::TempDir, OidcPendingRepository) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("oidc.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let repo = OidcPendingRepository::new(db.pool().clone());
    (dir, repo)
}

#[tokio::test]
async fn insert_then_take_round_trip() {
    let (_dir, repo) = fresh_db().await;
    let now = chrono::Utc::now().timestamp();
    repo.insert("state-1", "verifier-1", "nonce-1", now)
        .await
        .expect("insert");
    let taken = repo
        .take("state-1", 600)
        .await
        .expect("take")
        .expect("present");
    assert_eq!(taken.pkce_verifier, "verifier-1");
    assert_eq!(taken.nonce, "nonce-1");
    assert_eq!(taken.created_at_secs, now);
}

#[tokio::test]
async fn take_is_atomic_no_double_consume() {
    let (_dir, repo) = fresh_db().await;
    let now = chrono::Utc::now().timestamp();
    repo.insert("state-2", "v", "n", now)
        .await
        .expect("insert");
    let first = repo.take("state-2", 600).await.expect("first");
    assert!(first.is_some());
    let second = repo.take("state-2", 600).await.expect("second");
    assert!(second.is_none(), "second take must be None");
}

#[tokio::test]
async fn take_rejects_expired() {
    let (_dir, repo) = fresh_db().await;
    let ancient = chrono::Utc::now().timestamp() - 1000;
    repo.insert("state-3", "v", "n", ancient)
        .await
        .expect("insert");
    let out = repo.take("state-3", 600).await.expect("take");
    assert!(out.is_none(), "expired state must be rejected");
}

#[tokio::test]
async fn gc_expired_removes_old_rows() {
    let (_dir, repo) = fresh_db().await;
    let now = chrono::Utc::now().timestamp();
    repo.insert("old", "v", "n", now - 1000)
        .await
        .expect("insert");
    repo.insert("new", "v", "n", now)
        .await
        .expect("insert");
    let n = repo.gc_expired(600).await.expect("gc");
    assert_eq!(n, 1, "must remove exactly the old row");
    let old = repo.take("old", 600).await.expect("take old");
    assert!(old.is_none());
    let new = repo
        .take("new", 600)
        .await
        .expect("take new")
        .expect("present");
    assert_eq!(new.pkce_verifier, "v");
}
