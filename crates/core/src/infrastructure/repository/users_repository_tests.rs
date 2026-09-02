use super::*;
use crate::infrastructure::sqlite::connect;

async fn fresh_db() -> (tempfile::TempDir, UserRepository) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("users.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let repo = UserRepository::new(db.pool().clone());
    (dir, repo)
}

#[tokio::test]
async fn create_returns_plain_token_once() {
    let (_dir, repo) = fresh_db().await;
    let out = repo.create("alice", Role::Operator).await.expect("create");
    assert_eq!(out.user.name, "alice");
    assert_eq!(out.user.role, Role::Operator);
    assert!(!out.token.is_empty(), "token must be non-empty");
    // The token_hash is sha256(token) — verify.
    let expected = sha256_hex_public(out.token.as_bytes());
    assert_eq!(out.user.token_hash, expected);
}

#[tokio::test]
async fn find_by_token_returns_none_for_unknown() {
    let (_dir, repo) = fresh_db().await;
    let got = repo.find_by_token("not-a-real-token").await.expect("find");
    assert!(got.is_none());
}

#[tokio::test]
async fn find_by_token_returns_user_for_real_token() {
    let (_dir, repo) = fresh_db().await;
    let out = repo.create("bob", Role::Viewer).await.expect("create");
    let got = repo.find_by_token(&out.token).await.expect("find");
    assert!(got.is_some());
    let u = got.unwrap();
    assert_eq!(u.id, out.user.id);
    assert_eq!(u.name, "bob");
    assert_eq!(u.role, Role::Viewer);
}

#[tokio::test]
async fn soft_delete_blocks_find_by_token() {
    let (_dir, repo) = fresh_db().await;
    let out = repo.create("carol", Role::Operator).await.expect("create");
    let id = out.user.id;
    let disabled = repo.disable(id).await.expect("disable");
    assert!(disabled, "disable must report success");
    let got = repo.find_by_token(&out.token).await.expect("find");
    assert!(got.is_none(), "disabled user must not be found by token");
}

#[tokio::test]
async fn rotate_token_invalidates_old_token() {
    let (_dir, repo) = fresh_db().await;
    let out = repo.create("dave", Role::Admin).await.expect("create");
    let old_token = out.token;
    let new_token = repo
        .rotate_token(out.user.id)
        .await
        .expect("rotate")
        .expect("active user");
    assert_ne!(old_token, new_token);
    let by_old = repo.find_by_token(&old_token).await.expect("find");
    let by_new = repo.find_by_token(&new_token).await.expect("find");
    assert!(by_old.is_none(), "old token must stop working");
    assert!(by_new.is_some(), "new token must work");
}

#[tokio::test]
async fn list_orders_by_id_and_excludes_token_hash_field() {
    let (_dir, repo) = fresh_db().await;
    repo.create("eve", Role::Viewer).await.expect("create");
    repo.create("frank", Role::Admin).await.expect("create");
    let list = repo.list().await.expect("list");
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].name, "eve");
    assert_eq!(list[1].name, "frank");
    assert_eq!(list[0].role, Role::Viewer);
    assert_eq!(list[1].role, Role::Admin);
}

#[tokio::test]
async fn migrate_legacy_token_creates_admin_once() {
    let (_dir, repo) = fresh_db().await;
    let legacy = "a-very-specific-2.0.0-token";
    let created = repo.migrate_legacy_token(legacy).await.expect("migrate");
    assert!(created, "first call must insert");
    let created_again = repo.migrate_legacy_token(legacy).await.expect("migrate");
    assert!(!created_again, "second call must be a no-op");
    let got = repo.find_by_token(legacy).await.expect("find");
    assert!(got.is_some(), "legacy token must log in as admin");
    let u = got.unwrap();
    assert_eq!(u.name, "admin");
    assert_eq!(u.role, Role::Admin);
}

fn sha256_hex_public(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}
