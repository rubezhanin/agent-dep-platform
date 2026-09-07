use super::*;
use crate::infrastructure::repository::users_repository::{Role, UserRepository};
use crate::infrastructure::sqlite::connect;

async fn fresh_db() -> (tempfile::TempDir, SessionRepository, UserRepository) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sessions.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let sessions = SessionRepository::new(db.pool().clone());
    let users = UserRepository::new(db.pool().clone());
    (dir, sessions, users)
}

#[tokio::test]
async fn create_then_find_round_trips() {
    let (_dir, sessions, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let (id, row) = sessions
        .create(op.user.id, Some("127.0.0.1"), Some("test-ua"))
        .await
        .expect("create");
    assert!(!id.is_empty(), "session id must be non-empty");
    assert!(!row.csrf_token.is_empty(), "csrf token must be non-empty");
    let got = sessions.find(&id).await.expect("find").expect("present");
    assert_eq!(got.user_id, op.user.id);
    assert_eq!(got.csrf_token, row.csrf_token);
    assert_eq!(got.ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(got.user_agent.as_deref(), Some("test-ua"));
    // The find() should have advanced last_used_at
    // to roughly the same as the created_at
    // (we just created it, so the touch is
    // near-instant).
    assert_eq!(got.last_used_at, got.last_used_at);
    assert!(got.revoked_at.is_none());
}

#[tokio::test]
async fn find_returns_none_for_unknown_id() {
    let (_dir, sessions, _users) = fresh_db().await;
    let got = sessions.find("nope").await.expect("find");
    assert!(got.is_none());
}

#[tokio::test]
async fn find_advances_idle_expires_sliding() {
    // 2.11.0 (P1-F-03a): the sliding
    // window. After the first `find`,
    // `idle_expires_at` must be later
    // than the value we read at
    // `create`.
    let (_dir, sessions, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let (_id, row) = sessions
        .create(op.user.id, None, None)
        .await
        .expect("create");
    let idle_at_create = row.idle_expires_at.clone();
    // Tiny delay so the new
    // `idle_expires_at` is strictly
    // later.
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let got = sessions
        .find(&row.id)
        .await
        .expect("find")
        .expect("present");
    assert!(
        got.idle_expires_at > idle_at_create,
        "idle_expires_at must slide forward on find; create={idle_at_create} find={}",
        got.idle_expires_at
    );
    // absolute_expires_at must NOT slide
    // (it's the cap, not the window).
    assert_eq!(
        got.absolute_expires_at, row.absolute_expires_at,
        "absolute_expires_at must not advance on find"
    );
}

#[tokio::test]
async fn find_returns_none_for_revoked_session() {
    let (_dir, sessions, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let (id, _row) = sessions
        .create(op.user.id, None, None)
        .await
        .expect("create");
    let revoked = sessions.revoke(&id).await.expect("revoke");
    assert!(revoked, "revoke must return true for a live row");
    let got = sessions.find(&id).await.expect("find");
    assert!(got.is_none(), "find must return None for a revoked session");
}

#[tokio::test]
async fn revoke_is_idempotent() {
    let (_dir, sessions, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let (id, _row) = sessions
        .create(op.user.id, None, None)
        .await
        .expect("create");
    assert!(sessions.revoke(&id).await.expect("rev1"));
    // Second revoke: row already
    // revoked, the WHERE
    // `revoked_at IS NULL` filters it
    // out, rows_affected = 0,
    // `revoke` returns false. That's
    // the idempotency contract.
    assert!(!sessions.revoke(&id).await.expect("rev2"));
}

#[tokio::test]
async fn revoke_returns_false_for_unknown_id() {
    let (_dir, sessions, _users) = fresh_db().await;
    let revoked = sessions.revoke("nope").await.expect("revoke");
    assert!(!revoked);
}

#[tokio::test]
async fn revoke_all_for_user_kills_every_session() {
    let (_dir, sessions, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let viewer = users.create("viewer", Role::Viewer).await.expect("viewer");
    // Three sessions for op, one for
    // viewer.
    let (id1, _) = sessions.create(op.user.id, None, None).await.expect("c1");
    let (id2, _) = sessions.create(op.user.id, None, None).await.expect("c2");
    let (id3, _) = sessions.create(op.user.id, None, None).await.expect("c3");
    let (vid, _) = sessions
        .create(viewer.user.id, None, None)
        .await
        .expect("cv");
    let n = sessions
        .revoke_all_for_user(op.user.id)
        .await
        .expect("revoke-all");
    assert_eq!(n, 3, "op has 3 sessions; revoke_all must kill all 3");
    // The viewer's session is
    // untouched.
    assert!(sessions.find(&vid).await.expect("find vid").is_some());
    // All three op sessions are dead.
    for id in [&id1, &id2, &id3] {
        assert!(sessions.find(id).await.expect("find").is_none());
    }
}

#[tokio::test]
async fn list_active_for_user_excludes_revoked() {
    let (_dir, sessions, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let (id1, _) = sessions.create(op.user.id, None, None).await.expect("c1");
    let (id2, _) = sessions.create(op.user.id, None, None).await.expect("c2");
    sessions.revoke(&id1).await.expect("revoke");
    let list = sessions
        .list_active_for_user(op.user.id)
        .await
        .expect("list");
    assert_eq!(list.len(), 1, "list must skip the revoked session");
    assert_eq!(list[0].id, id2);
    // The admin-facing summary
    // intentionally does NOT expose
    // the CSRF token (defense in
    // depth: an admin who can list
    // sessions should not be able to
    // forge state-changing requests on
    // the user's behalf).
}

#[tokio::test]
async fn gc_expired_removes_revoked_and_expired() {
    let (_dir, sessions, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    // Two sessions: one we keep, one
    // we revoke. gc_expired should
    // remove only the revoked one.
    let (id_keep, _) = sessions.create(op.user.id, None, None).await.expect("k");
    let (id_drop, _) = sessions.create(op.user.id, None, None).await.expect("d");
    sessions.revoke(&id_drop).await.expect("revoke");
    let deleted = sessions.gc_expired().await.expect("gc");
    assert_eq!(deleted, 1, "gc must remove only the revoked row");
    // Both rows are still SELECTable
    // until gc actually runs the
    // DELETE; after, the kept row is
    // the only one left.
    let list = sessions
        .list_active_for_user(op.user.id)
        .await
        .expect("list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, id_keep);
    // The revoked id is now absent
    // from the table (gc removed it).
    let pool_path = _dir.path().join("sessions.db");
    let db = connect(&pool_path).await.expect("reconnect");
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE id = ?1")
        .bind(&id_drop)
        .fetch_one(db.pool())
        .await
        .expect("cnt");
    assert_eq!(row.0, 0, "revoked id must be hard-deleted by gc");
}

#[tokio::test]
async fn two_sessions_with_same_user_have_independent_ids() {
    let (_dir, sessions, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let (id1, row1) = sessions.create(op.user.id, None, None).await.expect("c1");
    let (id2, row2) = sessions.create(op.user.id, None, None).await.expect("c2");
    assert_ne!(
        id1, id2,
        "two sessions for the same user must have different ids"
    );
    assert_ne!(
        row1.csrf_token, row2.csrf_token,
        "two sessions for the same user must have different CSRF tokens"
    );
}
