use super::*;
use crate::infrastructure::repository::users_repository::{Role, UserRepository};
use crate::infrastructure::sqlite::connect;

async fn fresh_db() -> (tempfile::TempDir, SecretRepository, UserRepository) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("secrets.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let secrets = SecretRepository::new(db.pool().clone(), "test-passphrase").expect("vault");
    let users = UserRepository::new(db.pool().clone());
    (dir, secrets, users)
}

#[tokio::test]
async fn create_then_get_value_round_trips() {
    let (_dir, secrets, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let row = secrets
        .create("hermes-api-token", "secret-value-XYZ", op.user.id)
        .await
        .expect("create");
    assert_eq!(row.name, "hermes-api-token");
    let value = secrets
        .get_value("hermes-api-token")
        .await
        .expect("get_value");
    assert_eq!(value.name, "hermes-api-token");
    assert_eq!(value.value, "secret-value-XYZ");
}

#[tokio::test]
async fn list_excludes_the_plaintext_value() {
    let (_dir, secrets, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    secrets
        .create("api-key", "the-actual-secret", op.user.id)
        .await
        .expect("create");
    let list = secrets.list().await.expect("list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "api-key");
    // No `value` field on the list view — by
    // construction, since `SecretRow` does not
    // carry one.
}

#[tokio::test]
async fn get_value_with_wrong_passphrase_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("secrets.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let users = UserRepository::new(db.pool().clone());
    let op = users.create("op", Role::Operator).await.expect("op");
    let a = SecretRepository::new(db.pool().clone(), "passphrase-A").expect("vault A");
    let _ = a
        .create("k", "the-value", op.user.id)
        .await
        .expect("create");
    // Open with a different passphrase — decrypt
    // must fail with a typed error.
    let b = SecretRepository::new(db.pool().clone(), "passphrase-B").expect("vault B");
    let err = b.get_value("k").await.expect_err("must fail");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("AES-GCM decrypt failed"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
async fn update_changes_ciphertext_and_keeps_created_at() {
    let (_dir, secrets, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let v1 = secrets
        .create("k", "value-1", op.user.id)
        .await
        .expect("create");
    let v2 = secrets
        .update("k", "value-2", op.user.id)
        .await
        .expect("update")
        .expect("present");
    assert_eq!(v2.id, v1.id);
    assert_eq!(v2.created_at, v1.created_at, "created_at must not move");
    assert_ne!(v2.updated_at, v1.updated_at, "updated_at must move");
    let read = secrets.get_value("k").await.expect("get");
    assert_eq!(read.value, "value-2");
}

#[tokio::test]
async fn delete_is_hard_and_idempotent() {
    let (_dir, secrets, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    secrets.create("k", "v", op.user.id).await.expect("create");
    let first = secrets.delete("k").await.expect("first delete");
    assert!(first, "first delete returns true");
    let second = secrets.delete("k").await.expect("second delete");
    assert!(!second, "second delete returns false");
    let err = secrets.get_value("k").await.expect_err("must error");
    let msg = format!("{err:?}");
    assert!(msg.contains("no secret named"), "unexpected error: {msg}");
}

#[tokio::test]
async fn count_tracks_rows_for_startup_check() {
    let (_dir, secrets, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    assert_eq!(secrets.count().await.unwrap(), 0);
    secrets.create("a", "1", op.user.id).await.unwrap();
    secrets.create("b", "2", op.user.id).await.unwrap();
    assert_eq!(secrets.count().await.unwrap(), 2);
}

#[tokio::test]
async fn empty_passphrase_is_rejected_at_construction() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("secrets.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let err = SecretRepository::new(db.pool().clone(), "").expect_err("must reject");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("passphrase must not be empty"),
        "unexpected: {msg}"
    );
}
