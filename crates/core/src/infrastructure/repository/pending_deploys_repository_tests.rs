use super::*;
use crate::infrastructure::repository::users_repository::{Role, UserRepository};
use crate::infrastructure::sqlite::connect;

async fn fresh_db() -> (tempfile::TempDir, PendingDeployRepository, UserRepository) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("approvals.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let pd = PendingDeployRepository::new(db.pool().clone());
    let users = UserRepository::new(db.pool().clone());
    (dir, pd, users)
}

#[tokio::test]
async fn request_inserts_a_pending_row() {
    let (_dir, pd, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let row = pd
        .request(
            "saas-stack",
            r#"{"writes":[]}"#,
            op.user.id,
            Environment::Dev,
        )
        .await
        .expect("request");
    assert_eq!(row.status, Status::Pending);
    assert_eq!(row.system_id, "saas-stack");
    assert_eq!(row.requested_by, op.user.id);
    assert!(row.approved_by.is_none());
}

#[tokio::test]
async fn list_filters_by_status() {
    let (_dir, pd, users) = fresh_db().await;
    let op1 = users.create("op1", Role::Operator).await.expect("op1");
    let op2 = users.create("op2", Role::Operator).await.expect("op2");
    let admin = users.create("admin", Role::Admin).await.expect("admin");
    let r1 = pd
        .request("a", "{}", op1.user.id, Environment::Dev)
        .await
        .expect("r1");
    let _r2 = pd
        .request("b", "{}", op2.user.id, Environment::Dev)
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
    let (_dir, pd, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let admin = users.create("admin", Role::Admin).await.expect("admin");
    let row = pd
        .request("x", "{}", op.user.id, Environment::Dev)
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
    let (_dir, pd, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let admin1 = users.create("admin1", Role::Admin).await.expect("admin1");
    let admin2 = users.create("admin2", Role::Admin).await.expect("admin2");
    let row = pd
        .request("x", "{}", op.user.id, Environment::Dev)
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
    let (_dir, pd, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let admin = users.create("admin", Role::Admin).await.expect("admin");
    let row = pd
        .request("x", "{}", op.user.id, Environment::Dev)
        .await
        .expect("request");
    // Pending → cannot mark applied yet.
    let no = pd.mark_applied(row.id).await.expect("apply");
    assert!(no.is_none());
    // Approve, then mark applied.
    pd.approve(row.id, admin.user.id).await.expect("approve");
    let yes = pd
        .mark_applied(row.id)
        .await
        .expect("apply")
        .expect("returns updated row");
    assert_eq!(yes.status, Status::Applied);
    assert!(yes.applied_at.is_some());
}

#[tokio::test]
async fn approve_uses_real_user_foreign_key() {
    let (_dir, pd, users) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let admin = users.create("admin", Role::Admin).await.expect("admin");
    let row = pd
        .request("x", "{}", op.user.id, Environment::Dev)
        .await
        .expect("request");
    let out = pd
        .approve(row.id, admin.user.id)
        .await
        .expect("approve")
        .expect("returns row");
    assert_eq!(out.approved_by, Some(admin.user.id));
}
