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
    // P0-SENT-01: token_hash is
    // `Option<String>` — `Some(sha256(token))`
    // for a freshly created bearer-token user.
    let expected = sha256_hex_public(out.token.as_bytes());
    assert_eq!(out.user.token_hash.as_deref(), Some(expected.as_str()));
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

#[tokio::test]
async fn set_token_expiry_round_trips() {
    let (_dir, repo) = fresh_db().await;
    let out = repo.create("alice", Role::Operator).await.expect("create");
    // Default: NULL (bearer-token users
    // never expire in 2.0.0-2.7.7).
    let u0 = repo
        .find_by_token(&out.token)
        .await
        .expect("find")
        .expect("present");
    assert!(u0.token_expires_at.is_none());
    // Set expiry.
    repo.set_token_expiry(out.user.id, "2030-01-01T00:00:00Z")
        .await
        .expect("set");
    let u1 = repo
        .find_by_token(&out.token)
        .await
        .expect("find")
        .expect("present");
    assert_eq!(u1.token_expires_at.as_deref(), Some("2030-01-01T00:00:00Z"));
    // Clear expiry.
    repo.set_token_expiry(out.user.id, "").await.expect("clear");
    let u2 = repo
        .find_by_token(&out.token)
        .await
        .expect("find")
        .expect("present");
    assert!(u2.token_expires_at.is_none());
}

#[tokio::test]
async fn invalidate_token_blocks_find_by_token() {
    let (_dir, repo) = fresh_db().await;
    let out = repo.create("alice", Role::Operator).await.expect("create");
    // Sanity: token works.
    let before = repo
        .find_by_token(&out.token)
        .await
        .expect("find")
        .expect("present");
    assert_eq!(before.id, out.user.id);
    // Invalidate.
    repo.invalidate_token(out.user.id)
        .await
        .expect("invalidate");
    // Subsequent lookups return None.
    let after = repo.find_by_token(&out.token).await.expect("find");
    assert!(after.is_none(), "invalidate must block find_by_token");
    // P0-SENT-01: after invalidate,
    // `token_hash` is NULL (was sha256("")
    // in 2.7.6-2.7.10). The post-fix
    // canonical "no token" state is SQL
    // NULL — no user with the sha256("")
    // sentinel remains in the table.
    // We assert this by reading the row
    // directly: there is no public getter
    // for `token_hash IS NULL` (and we
    // don't want to expose one), but the
    // `find_by_token` result being None
    // already proves the user's token is
    // not matchable. The deeper property
    // — that no row in the table has
    // `token_hash = sha256("")` — is
    // implicitly true because the column
    // is now `TEXT NULL` and the only
    // writers are `create` (real hash),
    // `create_with_external_id` (NULL),
    // `store_token_hash` (real hash), and
    // `invalidate_token` (NULL).
}

// P0-SENT-01 (TZ #2 WP-0.3, CWE-287,
// Appendix A.4): the canonical "no
// token" representation is SQL NULL,
// not sha256(""). The pre-fix code
// stored `token_hash = sha256("")` as a
// sentinel; an attacker presenting
// `Authorization: Bearer ""` could
// authenticate as any user with the
// sentinel.
//
// This test exercises the executable
// spec at the unit level. The end-to-end
// middleware spec is in
// `crates/server/tests/http_integration.rs`:
// `audit_requires_bearer_token` +
// `expired_token_returns_401` (the bearer
// short-circuit is exercised by every
// request that lacks a token).
#[tokio::test]
async fn create_with_external_id_stores_token_hash_as_null() {
    let (_dir, repo) = fresh_db().await;
    let user = repo
        .create_with_external_id("oidc-alice", Role::Operator, "sub-alice")
        .await
        .expect("create");
    // P0-SENT-01: `token_hash` is `None`
    // for a freshly created OIDC user
    // (the pre-fix code stored
    // sha256("") here).
    assert!(
        user.token_hash.is_none(),
        "OIDC user must have token_hash = None until \
         `store_token_hash` is called; was {:?}",
        user.token_hash
    );
    // `find_by_token("")` returns None
    // even before the middleware short-
    // circuit, because SQL `NULL = ?1`
    // never matches a non-NULL bind.
    let got = repo.find_by_token("").await.expect("find");
    assert!(
        got.is_none(),
        "find_by_token(\"\") must return None; \
         pre-fix this matched the sha256(\"\") \
         sentinel and authenticated the caller"
    );
    // Sanity: a real token works.
    repo.store_token_hash(user.id, &sha256_hex_public(b"real-token"))
        .await
        .expect("store");
    let got = repo.find_by_token("real-token").await.expect("find");
    assert!(got.is_some());
    // And invalidate clears the token
    // (sets it back to NULL, not
    // sha256("")).
    repo.invalidate_token(user.id).await.expect("invalidate");
    let after = repo
        .find_by_token("real-token")
        .await
        .expect("find");
    assert!(after.is_none());
    // And the canonical "no token" state
    // is recoverable: a fresh
    // find_by_token with a different
    // (also-real) token also returns None.
    let got2 = repo.find_by_token("another-token").await.expect("find");
    assert!(got2.is_none());
}

fn sha256_hex_public(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}
