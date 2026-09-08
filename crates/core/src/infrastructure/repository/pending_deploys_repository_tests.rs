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
async fn make_target(targets: &TargetRepository, name: &str, env: Environment) -> i64 {
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
            None,
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
        .request("a", "{}", op1.user.id, Environment::Dev, Some(ta), None)
        .await
        .expect("r1");
    let _r2 = pd
        .request("b", "{}", op2.user.id, Environment::Dev, Some(tb), None)
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
        .request("x", "{}", op.user.id, Environment::Dev, Some(t), None)
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
        .request("x", "{}", op.user.id, Environment::Dev, Some(t), None)
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
        .request("x", "{}", op.user.id, Environment::Dev, Some(t), None)
        .await
        .expect("request");
    // mark_applied on a pending row is a no-op.
    let none = pd.mark_applied(row.id).await.expect("mark on pending");
    assert!(none.is_none(), "mark_applied on pending must return None");
    // Approve, then mark applied.
    pd.approve(row.id, admin.user.id)
        .await
        .expect("approve")
        .expect("ok");
    let out = pd.mark_applied(row.id).await.expect("mark").expect("ok");
    assert_eq!(out.status, Status::Applied);
    assert!(out.applied_at.is_some());
}

// 2.11.0 (P1-D-01b, CWE-494): a
// deploy that captured
// `target_config_version = 1` is
// stale once the target's `version`
// advances to 2. `mark_applied`
// must reject with a typed
// `ErrStaleDeployment` and the row
// must stay in `approved` (not
// silently flipped to `applied`).
#[tokio::test]
async fn mark_applied_rejects_stale_target_version() {
    let (dir, pd, users, targets) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let admin = users.create("admin", Role::Admin).await.expect("admin");
    let t = make_target(&targets, "x", Environment::Dev).await;
    let row = pd
        .request("x", "{}", op.user.id, Environment::Dev, Some(t), None)
        .await
        .expect("request");
    // Manually set the row's
    // `target_config_version` to
    // 1 (the floor) and the target's
    // `version` to 2. Without the
    // freshness check this would
    // be a silent deploy of an
    // artifact the operator did not
    // approve.
    let pool_path = dir.path().join("approvals.db");
    let pool = crate::infrastructure::sqlite::connect(&pool_path)
        .await
        .expect("reconnect")
        .pool()
        .clone();
    sqlx::query("UPDATE targets SET version = 2 WHERE id = ?1")
        .bind(t)
        .execute(&pool)
        .await
        .expect("bump target version");
    sqlx::query("UPDATE pending_deploys SET target_config_version = 1 WHERE id = ?1")
        .bind(row.id)
        .execute(&pool)
        .await
        .expect("set captured version");
    pd.approve(row.id, admin.user.id)
        .await
        .expect("approve")
        .expect("ok");
    // The deploy is stale: target
    // version is 2, captured
    // version is 1.
    let err = pd
        .mark_applied(row.id)
        .await
        .expect_err("mark_applied must reject stale deploy");
    let msg = format!("{err:?}");
    assert!(msg.contains("ErrStaleDeployment"), "got: {msg}");
    assert!(msg.contains("captured_version: 1"), "got: {msg}");
    assert!(msg.contains("current_version: 2"), "got: {msg}");
    // The row must stay in
    // `approved`, not flip to
    // `applied`.
    let after = pd.get(row.id).await.expect("get").expect("present");
    assert_eq!(after.status, Status::Approved);
    assert!(after.applied_at.is_none());
}

// 2.11.0 (P1-D-01b): the happy
// path — the captured
// `target_config_version` matches
// the current `targets.version`
// and `mark_applied` succeeds.
#[tokio::test]
async fn mark_applied_succeeds_when_target_version_matches() {
    let (_dir, pd, users, targets) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let admin = users.create("admin", Role::Admin).await.expect("admin");
    let t = make_target(&targets, "x", Environment::Dev).await;
    let row = pd
        .request("x", "{}", op.user.id, Environment::Dev, Some(t), None)
        .await
        .expect("request");
    pd.approve(row.id, admin.user.id)
        .await
        .expect("approve")
        .expect("ok");
    // Pre-P1-D-01c rows have
    // `target_config_version IS NULL`;
    // the freshness check is a
    // no-op for them, and
    // `mark_applied` succeeds. This
    // covers the migration
    // backfill case.
    let out = pd.mark_applied(row.id).await.expect("mark").expect("ok");
    assert_eq!(out.status, Status::Applied);
}

#[tokio::test]
async fn approve_uses_real_user_foreign_key() {
    let (_dir, pd, users, targets) = fresh_db().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let admin = users.create("admin", Role::Admin).await.expect("admin");
    let t = make_target(&targets, "x", Environment::Dev).await;
    let row = pd
        .request("x", "{}", op.user.id, Environment::Dev, Some(t), None)
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
    let out = pd.set_target_id(99999, 42).await.expect("set nonexistent");
    assert!(out.is_none(), "missing id must return None");
}

// 2.11.0 (P1-D-01c, CWE-494):
// `request` populated the
// `DeploymentIntent` fields when
// `source_snapshot_id` is
// provided. We plant a
// `source_snapshots` row, call
// `request` with its id, then
// change the row's `commit_sha`
// in place and assert that
// `mark_applied` rejects the
// stale deploy with a typed
// `ErrStaleDeployment` whose
// `kind` is the
// `commit_sha (was ...,
// now ...)` string.
#[tokio::test]
async fn mark_applied_rejects_stale_commit_sha() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = connect(&dir.path().join("freshness.db"))
        .await
        .expect("connect");
    db.migrate().await.expect("migrate");
    let pd = PendingDeployRepository::new(db.pool().clone());
    let users = UserRepository::new(db.pool().clone());
    let targets = TargetRepository::new(db.pool().clone());
    let op = users.create("op", Role::Operator).await.expect("op");
    let admin = users.create("admin", Role::Admin).await.expect("admin");
    let t = targets
        .create("x", Environment::Dev, "/srv/hermes", PathKind::Posix, None)
        .await
        .expect("target");
    // Plant a `sources` row first
    // (the `source_snapshots.source_id`
    // FK requires it).
    let source_uuid = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sources (id, kind, location, pinned_ref, display_name, created_at, last_indexed_at) \
         VALUES (?1, 'git+https', 'https://example.com/foo.git', 'main', 'test', \
                 '2026-01-01T00:00:00.000Z', NULL)",
    )
    .bind(source_uuid.to_string())
    .execute(db.pool())
    .await
    .expect("insert source");
    // Plant a `source_snapshots` row.
    let snapshot_id = "00000000-0000-0000-0000-000000000001";
    let original_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    sqlx::query(
        "INSERT INTO source_snapshots \
         (id, source_id, commit_sha, status, agent_count, division_count, \
          created_at, upstream_template_version, scan_note) \
         VALUES (?1, ?2, ?3, 'active', 0, 0, ?4, NULL, NULL)",
    )
    .bind(snapshot_id)
    .bind(source_uuid.to_string())
    .bind(original_sha)
    .bind("2026-01-01T00:00:00.000Z")
    .execute(db.pool())
    .await
    .expect("insert snapshot");
    let row = pd
        .request(
            "x",
            "{}",
            op.user.id,
            Environment::Dev,
            Some(t.id),
            Some(snapshot_id),
        )
        .await
        .expect("request");
    assert_eq!(row.source_snapshot_id.as_deref(), Some(snapshot_id));
    assert_eq!(row.commit_sha.as_deref(), Some(original_sha));
    // The operator (some other
    // process) advances the
    // source — `source_snapshots.commit_sha`
    // changes from `aaaa...` to
    // `bbbb...`. The `pending_deploys`
    // row is still `approved`.
    let new_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    sqlx::query("UPDATE source_snapshots SET commit_sha = ?1 WHERE id = ?2")
        .bind(new_sha)
        .bind(snapshot_id)
        .execute(db.pool())
        .await
        .expect("bump commit");
    pd.approve(row.id, admin.user.id)
        .await
        .expect("approve")
        .expect("ok");
    let err = pd
        .mark_applied(row.id)
        .await
        .expect_err("mark_applied must reject stale commit");
    let msg = format!("{err:?}");
    assert!(msg.contains("ErrStaleDeployment"), "got: {msg}");
    assert!(msg.contains("commit_sha"), "got: {msg}");
    // The deploy must stay
    // `approved`.
    let after = pd.get(row.id).await.expect("get").expect("present");
    assert_eq!(after.status, Status::Approved);
    assert!(after.applied_at.is_none());
}
