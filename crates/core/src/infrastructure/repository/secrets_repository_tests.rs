use super::*;
use crate::infrastructure::repository::users_repository::{Role, UserRepository};
use crate::infrastructure::sqlite::connect;

async fn fresh_db() -> (tempfile::TempDir, SecretRepository, UserRepository) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("secrets.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let test_install_salt =
        [1u8; crate::infrastructure::repository::secrets_repository::INSTALL_SALT_LEN];
    let secrets = SecretRepository::new(db.pool().clone(), "test-passphrase", &test_install_salt)
        .expect("vault");
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
    let test_install_salt =
        [1u8; crate::infrastructure::repository::secrets_repository::INSTALL_SALT_LEN];
    let a = SecretRepository::new(db.pool().clone(), "passphrase-A", &test_install_salt)
        .expect("vault A");
    let _ = a
        .create("k", "the-value", op.user.id)
        .await
        .expect("create");
    // Open with a different passphrase — decrypt
    // must fail with a typed error.
    let b = SecretRepository::new(db.pool().clone(), "passphrase-B", &test_install_salt)
        .expect("vault B");
    let err = b.get_value("k").await.expect_err("must fail");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("AES-GCM v2 decrypt failed"),
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
    let test_install_salt =
        [1u8; crate::infrastructure::repository::secrets_repository::INSTALL_SALT_LEN];
    let err =
        SecretRepository::new(db.pool().clone(), "", &test_install_salt).expect_err("must reject");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("passphrase must not be empty"),
        "unexpected: {msg}"
    );
}

// 2.11.0 (P1-F-06, TZ #2 WP-3.2, CWE-916):
// two rows written with the same plaintext
// under the same passphrase must produce
// different ciphertexts (per-secret salt
// means a different KDF input per row).
#[tokio::test]
async fn same_plaintext_under_same_passphrase_yields_different_ciphertexts() {
    let (_dir, secrets, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    secrets
        .create("k1", "the-value", op.user.id)
        .await
        .expect("c1");
    secrets
        .create("k2", "the-value", op.user.id)
        .await
        .expect("c2");
    let row1: (Vec<u8>, Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT ciphertext, nonce, secret_salt FROM secrets WHERE name = ?1")
            .bind("k1")
            .fetch_one(secrets_pool(&secrets))
            .await
            .expect("s1");
    let row2: (Vec<u8>, Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT ciphertext, nonce, secret_salt FROM secrets WHERE name = ?1")
            .bind("k2")
            .fetch_one(secrets_pool(&secrets))
            .await
            .expect("s2");
    // Nonces are random per call, so they
    // always differ — but even if they
    // happened to collide, the per-secret
    // salt input to the KDF means the
    // ciphertexts must still differ.
    assert_ne!(
        row1.0, row2.0,
        "two rows with the same plaintext and passphrase must have different ciphertexts \
         (per-secret salt makes the KDF input row-dependent)"
    );
    assert_ne!(row1.2, row2.2, "per-secret salt must be random per row");
}

// 2.11.0 (P1-F-06, CWE-345 cross-row
// confusion): the AAD is part of the
// ciphertext authentication. Swapping the
// `aad` of one row onto another row's
// ciphertext + nonce must fail the decrypt
// (the GCM tag won't verify). We exercise
// this by direct SQL manipulation: write a
// row with one name, then rewrite its `aad`
// to a different name, and assert the
// decrypt fails with the new AAD.
#[tokio::test]
async fn aad_binding_blocks_cross_row_confusion() {
    let (_dir, secrets, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    secrets
        .create("alpha", "the-value", op.user.id)
        .await
        .expect("c");
    // Read the row's ciphertext + nonce.
    let row: (Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT ciphertext, nonce FROM secrets WHERE name = ?1")
            .bind("alpha")
            .fetch_one(secrets_pool(&secrets))
            .await
            .expect("sel");
    // Simulate a row-swap attack: insert a
    // new row with the same ciphertext +
    // nonce but a different name. The
    // decrypt path will use the new name as
    // AAD; AES-GCM must refuse to decrypt.
    sqlx::query(
        "INSERT INTO secrets (name, ciphertext, nonce, secret_salt, aad, version, \
         created_at, updated_at, created_by, updated_by) \
         VALUES (?1, ?2, ?3, ?4, ?5, 2, ?6, ?6, ?7, ?7)",
    )
    .bind("beta")
    .bind(&row.0)
    .bind(&row.1)
    .bind([0u8; 16].as_slice())
    .bind("beta")
    .bind("2026-01-01T00:00:00.000Z")
    .bind(op.user.id)
    .execute(secrets_pool(&secrets))
    .await
    .expect("insert");
    // Decrypt the original row by its
    // correct name — should succeed.
    let ok = secrets.get_value("alpha").await.expect("alpha");
    assert_eq!(ok.value, "the-value");
    // Decrypt the swapped row by its (new)
    // name — the AAD differs from the AAD
    // under which the ciphertext was
    // produced, so AES-GCM must reject.
    let err = secrets.get_value("beta").await.expect_err("beta must fail");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("AES-GCM v2 decrypt failed"),
        "expected v2 decrypt failure on AAD mismatch, got: {msg}"
    );
}

// 2.11.0 (P1-F-06): the per-row `version`
// column is the dispatch. v1 rows are
// backfilled with `secret_salt = 0^16` and
// `aad = ''`; the legacy decrypt path
// produces the same key as the pre-migration
// path. We simulate a v1 row by inserting
// it directly via SQL.
#[tokio::test]
async fn legacy_v1_row_is_readable_via_legacy_path() {
    let (_dir, secrets, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    // Use a known passphrase so the test
    // is deterministic.
    // 1. Encrypt "the-value" with the
    //    legacy path (install_salt only, no
    //    per-secret salt, no AAD) and
    //    capture the ciphertext + nonce.
    let legacy_pp = "legacy-passphrase";
    let legacy_salt = [7u8; 32];
    let legacy_key = legacy_derive_key(legacy_pp, &legacy_salt);
    let legacy_cipher =
        aes_gcm::Aes256Gcm::new(aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&legacy_key));
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let legacy_ct = legacy_cipher
        .encrypt(nonce, b"the-value".as_ref())
        .expect("enc");
    // 2. Open the same vault with the same
    //    passphrase + install salt and
    //    insert a v1 row by direct SQL.
    let repo = SecretRepository::new(secrets_pool(&secrets).clone(), legacy_pp, &legacy_salt)
        .expect("vault");
    sqlx::query(
        "INSERT INTO secrets (name, ciphertext, nonce, secret_salt, aad, version, \
         created_at, updated_at, created_by, updated_by) \
         VALUES (?1, ?2, ?3, X'00000000000000000000000000000000', '', 1, \
                 ?4, ?4, ?5, ?5)",
    )
    .bind("legacy")
    .bind(&legacy_ct)
    .bind(nonce_bytes.to_vec())
    .bind("2026-01-01T00:00:00.000Z")
    .bind(op.user.id)
    .execute(secrets_pool(&secrets))
    .await
    .expect("insert v1");
    // 3. Decrypt via the legacy path. Must
    //    produce the original plaintext.
    let got = repo.get_value("legacy").await.expect("legacy read");
    assert_eq!(got.value, "the-value");
}

// 2.11.0 (P1-F-06): an `update` on a v1
// row migrates it to v2 in place. The
// resulting row's `version` is 2 and the
// `secret_salt` / `aad` are populated.
#[tokio::test]
async fn update_migrates_v1_row_to_v2_in_place() {
    let (_dir, secrets, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    // Plant a v1 row directly.
    let legacy_pp = "legacy-passphrase";
    let legacy_salt = [7u8; 32];
    let repo = SecretRepository::new(secrets_pool(&secrets).clone(), legacy_pp, &legacy_salt)
        .expect("vault");
    sqlx::query(
        "INSERT INTO secrets (name, ciphertext, nonce, secret_salt, aad, version, \
         created_at, updated_at, created_by, updated_by) \
         VALUES (?1, X'00', X'000000000000000000000000', \
                 X'00000000000000000000000000000000', '', 1, \
                 ?2, ?2, ?3, ?3)",
    )
    .bind("legacy")
    .bind("2026-01-01T00:00:00.000Z")
    .bind(op.user.id)
    .execute(secrets_pool(&secrets))
    .await
    .expect("insert v1");
    // Update it.
    let updated = repo
        .update("legacy", "new-value", op.user.id)
        .await
        .expect("update")
        .expect("present");
    assert_eq!(updated.version, 2, "update must migrate v1 to v2");
    let row: (i64, Vec<u8>, String) =
        sqlx::query_as("SELECT version, secret_salt, aad FROM secrets WHERE name = ?1")
            .bind("legacy")
            .fetch_one(secrets_pool(&secrets))
            .await
            .expect("sel");
    assert_eq!(row.0, 2);
    assert_ne!(
        row.1,
        vec![0u8; 16],
        "migrated row must have a non-zero per-secret salt"
    );
    assert_eq!(row.2, "legacy");
    // Read the migrated row to confirm
    // the new decrypt path works.
    let got = repo.get_value("legacy").await.expect("read");
    assert_eq!(got.value, "new-value");
}

// 2.11.0 (P1-F-06): rows whose AAD is
// empty but whose `version` is 2 are
// rejected. Empty AAD on a v2 row would
// mean the writer forgot to set AAD — a
// bug, not a backfill case.
#[tokio::test]
async fn v2_row_with_empty_aad_is_rejected() {
    let (_dir, secrets, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    sqlx::query(
        "INSERT INTO secrets (name, ciphertext, nonce, secret_salt, aad, version, \
         created_at, updated_at, created_by, updated_by) \
         VALUES (?1, X'00', X'000000000000000000000000', \
                 X'0102030405060708090a0b0c0d0e0f10', '', 2, \
                 ?2, ?2, ?3, ?3)",
    )
    .bind("buggy")
    .bind("2026-01-01T00:00:00.000Z")
    .bind(op.user.id)
    .execute(secrets_pool(&secrets))
    .await
    .expect("insert");
    let err = secrets
        .get_value("buggy")
        .await
        .expect_err("v2 row with empty aad must be rejected");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("v2 row has empty aad"),
        "expected explicit empty-AAD rejection, got: {msg}"
    );
}

// 2.11.0 (P1-F-06): the per-row KDF
// version is the dispatch; a row from a
// future KDF version (>= 3) is rejected
// with a typed error.
#[tokio::test]
async fn future_kdf_version_is_rejected_with_typed_error() {
    let (_dir, secrets, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    sqlx::query(
        "INSERT INTO secrets (name, ciphertext, nonce, secret_salt, aad, version, \
         created_at, updated_at, created_by, updated_by) \
         VALUES (?1, X'00', X'000000000000000000000000', \
                 X'00000000000000000000000000000000', 'a', 99, \
                 ?2, ?2, ?3, ?3)",
    )
    .bind("future")
    .bind("2026-01-01T00:00:00.000Z")
    .bind(op.user.id)
    .execute(secrets_pool(&secrets))
    .await
    .expect("insert");
    let err = secrets
        .get_value("future")
        .await
        .expect_err("future KDF must be rejected");
    let msg = format!("{err:?}");
    assert!(msg.contains("unsupported KDF version 99"), "got: {msg}");
}

// Small helper: pull the pool out of a
// SecretRepository without exposing the
// field publicly.
fn secrets_pool(repo: &SecretRepository) -> &sqlx::SqlitePool {
    repo.pool()
}

// Reproduce the legacy v1 key derivation
// (Argon2id with install_salt only, 32
// bytes output) for the v1-row test. This
// must match the pre-P1-F-06 behaviour
// bit-for-bit; we test it via the
// `derive_key_v2` path with the zero
// per-secret salt, but we want a
// standalone call so the test is not
// circular.
fn legacy_derive_key(passphrase: &str, install_salt: &[u8; 32]) -> [u8; 32] {
    use argon2::{Argon2, Params};
    let mut combined = [0u8; 48];
    combined[..32].copy_from_slice(install_salt);
    combined[32..].copy_from_slice(&[0u8; 16]);
    let params = Params::new(19 * 1024, 2, 1, Some(32)).expect("params");
    let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), &combined, &mut out)
        .expect("argon");
    out
}
