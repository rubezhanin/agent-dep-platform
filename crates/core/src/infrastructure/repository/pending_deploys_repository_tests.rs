use super::*;
use crate::infrastructure::repository::targets_repository::{PathKind, TargetRepository};
use crate::infrastructure::repository::users_repository::{Role, UserRepository};
use crate::infrastructure::sqlite::connect;

async fn fresh_db() -> (
    tempfile::TempDir,
    PendingDeployRepository,
    UserRepository,
    TargetRepository,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("approvals.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let pd = PendingDeployRepository::new(db.pool().clone());
    let users = UserRepository::new(db.pool().clone());
    let targets = TargetRepository::new(db.pool().clone());
    (dir, pd, users, targets)
}

/// 2.5.3 (ADR-0033 follow-up): every
/// test that needs to call
/// `request()` must first create a
/// `Target` row (because
/// `pending_deploys.target_id` is
/// now NOT NULL). This helper
/// returns a unique target id per
/// call.
async fn make_target(
    targets: &TargetRepository,
    name: &str,
    env: Environment,
) -> i64 {
    let row = targets
        .create(name, env, "/srv/hermes", PathKind::Posix, None)
        .await
        .expect("target create");
    row.id
}

#[tokio::test]
async fn request_inserts_a_pending_row() {
    let (_dir, pd, users, targets) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let t = make_target(&targets, "saas-stack", Environment::Dev).await;
    let row = pd
        .request(
            "saas-stack",
            r#"{"writes":[]}"#,
            op.user.id,
            Environment::Dev,
            Some(t),
        )
        .await
        .expect("request");
    assert_eq!(row.status, Status::Pending);
    assert_eq!(row.system_id, "saas-stack");
    assert_eq!(row.requested_by, op.user.id);
    assert!(row.approved_by.is_none());
    assert_eq!(row.target_id, Some(t));
}

#[tokio::test]
async fn list_filters_by_status() {
    let (_dir, pd, users, targets) = fresh_db().await;
    let op1 = users.create("op1", Role::Operator).await.expect("op1");
    let op2 = users.create("op2", Role::Operator).await.expect("op2");
    let admin = users.create("admin", Role::Admin).await.expect("admin");
    let ta = make_target(&targets, "a", Environment::Dev).await;
    let tb = make_target(&targets, "b", Environment::Dev).await;
    let r1 = pd
        .request("a", "{}", op1.user.id, Environment::Dev, Some(ta))
        .await
        .expect("r1");
    let _r2 = pd
        .request("b", "{}", op2.user.id, Environment::Dev, Some(tb))
        .await
        .expect("r2");
    pd.approve(r1.id, admin.user.id).await.expect("approve");
    let pending = pd
        .list(Some(Status::Pending), None, 50)
        .await
        .expect("list");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].system_id, "b");
    let approved = pd
        .list(Some(Status::Approved), None, 50)
        .await
        .expect("list");
    assert_eq!(approved.len(), 1);
    assert_eq!(approved[0].system_id, "a");
}

#[tokio::test]
async fn approve_transitions_pending_to_approved() {
    let (_dir, pd, users, targets) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let admin = users.create("admin", Role::Admin).await.expect("admin");
    let t = make_target(&targets, "x", Environment::Dev).await;
    let row = pd
        .request("x", "{}", op.user.id, Environment::Dev, Some(t))
        .await
        .expect("request");
    let out = pd
        .approve(row.id, admin.user.id)
        .await
        .expect("approve")
        .expect("returns updated row");
    assert_eq!(out.status, Status::Approved);
    assert_eq!(out.approved_by, Some(admin.user.id));
    assert!(out.approved_at.is_some());
}

#[tokio::test]
async fn reject_records_reason_and_blocks_replay() {
    let (_dir, pd, users, targets) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let admin1 = users.create("admin1", Role::Admin).await.expect("admin1");
    let admin2 = users.create("admin2", Role::Admin).await.expect("admin2");
    let t = make_target(&targets, "x", Environment::Dev).await;
    let row = pd
        .request("x", "{}", op.user.id, Environment::Dev, Some(t))
        .await
        .expect("request");
    let out = pd
        .reject(row.id, admin1.user.id, Some("policy says no"))
        .await
        .expect("reject")
        .expect("returns updated row");
    assert_eq!(out.status, Status::Rejected);
    assert_eq!(out.rejection_reason.as_deref(), Some("policy says no"));
    // A second approve is a no-op (idempotency).
    let none = pd
        .approve(row.id, admin2.user.id)
        .await
        .expect("approve replay");
    assert!(none.is_none(), "approving a rejected row must be a no-op");
}

#[tokio::test]
async fn mark_applied_only_works_on_approved_rows() {
    let (_dir, pd, users, targets) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let admin = users.create("admin", Role::Admin).await.expect("admin");
    let t = make_target(&targets, "x", Environment::Dev).await;
    let row = pd
        .request("x", "{}", op.user.id, Environment::Dev, Some(t))
        .await
        .expect("request");
    // mark_applied on a pending row is a no-op.
    let none = pd
        .mark_applied(row.id)
        .await
        .expect("mark on pending");
    assert!(none.is_none(), "mark_applied on pending must return None");
    // Approve, then mark applied.
    pd.approve(row.id, admin.user.id)
        .await
        .expect("approve")
        .expect("ok");
    let out = pd
        .mark_applied(row.id)
        .await
        .expect("mark")
        .expect("ok");
    assert_eq!(out.status, Status::Applied);
    assert!(out.applied_at.is_some());
}

#[tokio::test]
async fn approve_uses_real_user_foreign_key() {
    let (_dir, pd, users, targets) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let admin = users.create("admin", Role::Admin).await.expect("admin");
    let t = make_target(&targets, "x", Environment::Dev).await;
    let row = pd
        .request("x", "{}", op.user.id, Environment::Dev, Some(t))
        .await
        .expect("request");
    let out = pd
        .approve(row.id, admin.user.id)
        .await
        .expect("approve")
        .expect("returns row");
    assert_eq!(out.approved_by, Some(admin.user.id));
}

// -----------------------------------------------------------------------
// 2.5.3 (ADR-0033 follow-up)
// -----------------------------------------------------------------------
//
// The 2.5.1 (ADR-0033) backfill
// tooling — `list_orphans` +
// `set_target_id` — is now
// dead code (orphan rows are no
// longer possible). The
// `PendingDeployRepository` still
// exposes the methods so existing
// callers do not break, but
// `list_orphans` will always return
// an empty list, and
// `set_target_id` is a no-op
// (target_id is now NOT NULL).
//
// We test that the methods still
// exist and behave reasonably
// (return an empty list / no error
// for a missing row), without
// requiring any orphan row.

#[tokio::test]
async fn list_orphans_returns_empty_after_not_null_migration() {
    let (_dir, pd, _users, _targets) = fresh_db().await;
    let all = pd.list_orphans(None).await.expect("list all");
    assert!(all.is_empty(), "no orphan rows after 2.5.3");
    let dev = pd
        .list_orphans(Some(Environment::Dev))
        .await
        .expect("list dev");
    assert!(dev.is_empty());
}

#[tokio::test]
async fn set_target_id_returns_none_for_missing_id() {
    // After 2.5.3, the column is NOT
    // NULL. `set_target_id` is now
    // a no-op UPDATE that returns
    // `None` for missing rows (no
    // change from 2.5.1).
    let (_dir, pd, _users, _targets) = fresh_db().await;
    let out = pd
        .set_target_id(99999, 42)
        .await
        .expect("set nonexistent");
    assert!(out.is_none(), "missing id must return None");
}
