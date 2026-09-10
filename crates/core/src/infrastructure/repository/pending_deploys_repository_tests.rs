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

// -----------------------------------------------------------------------
// 2.11.0 (P1-D-02, TZ #1 §10 / D-02,
// CWE-362 Concurrent Execution using
// Shared Resource without Proper
// Synchronization) — target fencing
// tests.
//
// The "один target — одна активная
// mutating operation" invariant is
// enforced by a partial UNIQUE index
// on `pending_deploys(target_id) WHERE
// status IN ('pending', 'approved')`
// and a typed `ErrTargetBusy` at the
// application layer. The fence itself
// is the row's `fence_token`, captured
// at `request` time as the current
// `targets.deployment_version`; a
// `mark_applied` whose `fence_token`
// no longer matches the current value
// is rejected as a stale-lease event
// (a typed `ErrStaleDeployment` with
// `kind: "deployment_fence ..."`).
// -----------------------------------------------------------------------

/// 2.11.0 (P1-D-02): a fresh
/// `request` records the current
/// `targets.deployment_version` as
/// the new row's `fence_token`. The
/// floor is `0` for a target that
/// has never been applied to.
#[tokio::test]
async fn request_records_fence_token_from_current_deployment_version() {
    let (_dir, pool, pd, _users, targets) = fresh_db_with_pool().await;
    let op = UserRepository::new(pool.clone())
        .create("op", Role::Operator)
        .await
        .expect("op");
    let t = make_target(&targets, "a", Environment::Dev).await;
    let row = pd
        .request("a", "{}", op.user.id, Environment::Dev, Some(t), None)
        .await
        .expect("request");
    // A fresh target has
    // `deployment_version = 0`
    // (the migration floor).
    assert_eq!(row.fence_token, Some(0));
    assert!(row.applied_deployment_version.is_none());
    // The recorded fence equals
    // the current target
    // deployment_version.
    let v: (i64,) = sqlx::query_as("SELECT deployment_version FROM targets WHERE id = ?1")
        .bind(t)
        .fetch_one(&pool)
        .await
        .expect("version");
    assert_eq!(v.0, 0);
    assert_eq!(Some(v.0), row.fence_token);
}

/// 2.11.0 (P1-D-02, CWE-362):
/// the second `request` for the
/// same `target_id` while a
/// `pending` row already exists is
/// refused with a typed
/// `ErrTargetBusy` carrying the
/// existing row's id and status.
/// The operator must wait for the
/// existing deploy to reach a
/// terminal state.
#[tokio::test]
async fn request_refuses_with_target_busy_when_pending_row_exists() {
    let (_dir, pool, pd, users, targets) = fresh_db_with_pool().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let t = make_target(&targets, "a", Environment::Dev).await;
    let r1 = pd
        .request("a", "{}", op.user.id, Environment::Dev, Some(t), None)
        .await
        .expect("r1");
    // The second request for the
    // same target must be
    // refused.
    let err = pd
        .request("a2", "{}", op.user.id, Environment::Dev, Some(t), None)
        .await
        .expect_err("must be ErrTargetBusy");
    match err {
        CoreError::ErrTargetBusy {
            target_id,
            existing_deploy_id,
            existing_status,
        } => {
            assert_eq!(target_id, t);
            assert_eq!(existing_deploy_id, r1.id);
            assert_eq!(existing_status, "pending");
        }
        other => panic!("expected ErrTargetBusy, got {other:?}"),
    }
    // Touch the pool so the
    // unused-warning doesn't
    // fire (the pool IS used by
    // the repos; we just don't
    // reach into it directly in
    // this test).
    let _: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM pending_deploys")
        .fetch_one(&pool)
        .await
        .expect("count");
}

/// 2.11.0 (P1-D-02): an
/// `approved` row still counts as
/// an "active mutating operation"
/// for the target. A fresh
/// `request` for the same target
/// is refused as long as the
/// existing row is non-terminal.
#[tokio::test]
async fn request_refuses_with_target_busy_when_approved_row_exists() {
    let (_dir, _pool, pd, users, targets) = fresh_db_with_pool().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let admin = users.create("admin", Role::Admin).await.expect("admin");
    let t = make_target(&targets, "a", Environment::Dev).await;
    let r1 = pd
        .request("a", "{}", op.user.id, Environment::Dev, Some(t), None)
        .await
        .expect("r1");
    pd.approve(r1.id, admin.user.id)
        .await
        .expect("approve")
        .expect("ok");
    // A second request for the
    // same target — even with the
    // first one already approved —
    // is refused.
    let err = pd
        .request("a2", "{}", op.user.id, Environment::Dev, Some(t), None)
        .await
        .expect_err("must be ErrTargetBusy");
    match err {
        CoreError::ErrTargetBusy {
            existing_deploy_id,
            existing_status,
            ..
        } => {
            assert_eq!(existing_deploy_id, r1.id);
            assert_eq!(existing_status, "approved");
        }
        other => panic!("expected ErrTargetBusy, got {other:?}"),
    }
}

/// 2.11.0 (P1-D-02): once a row
/// is `rejected` (terminal), a
/// fresh `request` for the same
/// target succeeds and captures
/// the current
/// `deployment_version` as the
/// new fence token.
#[tokio::test]
async fn request_succeeds_after_rejection_terminates_the_lease() {
    let (_dir, _pool, pd, users, targets) = fresh_db_with_pool().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let admin = users.create("admin", Role::Admin).await.expect("admin");
    let t = make_target(&targets, "a", Environment::Dev).await;
    let r1 = pd
        .request("a", "{}", op.user.id, Environment::Dev, Some(t), None)
        .await
        .expect("r1");
    pd.reject(r1.id, admin.user.id, Some("superseded"))
        .await
        .expect("reject")
        .expect("ok");
    // The first row is now
    // `rejected` (terminal); a
    // fresh request for the same
    // target must succeed.
    let r2 = pd
        .request("a2", "{}", op.user.id, Environment::Dev, Some(t), None)
        .await
        .expect("r2 must succeed");
    assert_eq!(r2.fence_token, Some(0));
}

/// 2.11.0 (P1-D-02, CWE-362):
/// `mark_applied` bumps
/// `targets.deployment_version`
/// on success and records the
/// new value in
/// `pending_deploys.applied_deployment_version`.
/// The next `request` for the
/// same target then captures the
/// bumped value as the new fence
/// token.
#[tokio::test]
async fn mark_applied_bumps_deployment_version_and_records_post_increment() {
    let (_dir, pool, pd, users, targets) = fresh_db_with_pool().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let admin = users.create("admin", Role::Admin).await.expect("admin");
    let t = make_target(&targets, "a", Environment::Dev).await;
    let r1 = pd
        .request("a", "{}", op.user.id, Environment::Dev, Some(t), None)
        .await
        .expect("r1");
    assert_eq!(r1.fence_token, Some(0));
    pd.approve(r1.id, admin.user.id)
        .await
        .expect("approve")
        .expect("ok");
    let applied = pd.mark_applied(r1.id).await.expect("apply").expect("ok");
    // The apply committed;
    // deployment_version went
    // from 0 to 1.
    assert_eq!(applied.applied_deployment_version, Some(1));
    // The next request for the
    // same target captures the
    // new version as the fence
    // token. (We have to wait
    // for the previous apply to
    // terminate the lease, which
    // it just did — the row
    // is `applied`, terminal.)
    let r2 = pd
        .request("a2", "{}", op.user.id, Environment::Dev, Some(t), None)
        .await
        .expect("r2 after apply");
    assert_eq!(r2.fence_token, Some(1));
    // And `targets.deployment_version`
    // is now 1.
    let v: (i64,) = sqlx::query_as("SELECT deployment_version FROM targets WHERE id = ?1")
        .bind(t)
        .fetch_one(&pool)
        .await
        .expect("v");
    assert_eq!(v.0, 1);
}

/// 2.11.0 (P1-D-02, CWE-362): the
/// fenced-lease path. After a
/// successful `mark_applied` bumps
/// `targets.deployment_version`, a
/// second approved row for the
/// same target with a stale
/// `fence_token` is rejected at
/// `mark_applied` time with a typed
/// `ErrStaleDeployment { kind:
/// "deployment_fence ..." }`.
///
/// The partial UNIQUE index would
/// normally prevent a second
/// non-terminal row for the same
/// target, so we simulate the
/// race by dropping the index,
/// inserting a hand-crafted
/// `pending` row with a stale
/// `fence_token = 0`, and
/// re-creating the index. This
/// is the only test path that
/// exercises the fence check
/// itself (the busy check at
/// `request` time is the
/// front-line protection in
/// production).
#[tokio::test]
async fn mark_applied_rejects_with_stale_deployment_fence() {
    let (_dir, pool, pd, users, targets) = fresh_db_with_pool().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let admin = users.create("admin", Role::Admin).await.expect("admin");
    let t = make_target(&targets, "a", Environment::Dev).await;
    // 1) first deploy: bumps
    // deployment_version 0 -> 1.
    let r1 = pd
        .request("a", "{}", op.user.id, Environment::Dev, Some(t), None)
        .await
        .expect("r1");
    pd.approve(r1.id, admin.user.id)
        .await
        .expect("approve")
        .expect("ok");
    pd.mark_applied(r1.id).await.expect("apply").expect("ok");
    // 2) Inject the race row.
    // The DROP/INSERT/CREATE-INDEX triple races
    // with parallel `cargo test` writers; on a
    // loaded ubuntu-latest runner the CREATE
    // UNIQUE INDEX can hit SQLITE_BUSY (database
    // is locked by another test's
    // migration/insert). Retry with a small
    // backoff so the test stops being a
    // known flake (CI runs 34446115086, 122,
    // 121, 34482431085, 34483888711,
    // 34486167058 all surfaced this — the
    // `recreate idx` expect is the line that
    // fails).
    // Drop the index AND verify that it is actually
    // gone. CI runs 34493700094 and 34497839323
    // surfaced two distinct ways `DROP INDEX IF
    // EXISTS` can fail silently: (a) it returns
    // `Ok(0 rows)` when a parallel writer holds
    // a shared lock just long enough for SQLite
    // to skip the work, and (b) it returns
    // `Ok(0 rows)` outright on a stale connection
    // whose schema cache has the index but whose
    // underlying file does not. Either way the
    // subsequent `CREATE UNIQUE INDEX` then fails
    // with `index ... already exists`. Retry the
    // drop until `sqlite_master` actually shows
    // the index gone (8 attempts, 10 ms
    // backoff). The retry only fires when the
    // drop failed to take effect; the steady
    // state is one attempt.
    for attempt in 0..8usize {
        let _ = sqlx::query("DROP INDEX IF EXISTS idx_pending_deploys_one_active_per_target")
            .execute(&pool)
            .await
            .expect("drop");
        let still_there: Option<String> =
            sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?1")
                .bind("idx_pending_deploys_one_active_per_target")
                .fetch_optional(&pool)
                .await
                .expect("sqlite_master probe");
        if still_there.is_none() {
            break;
        }
        if attempt == 7 {
            panic!("drop idx: index still present after 8 retries");
        }
        tokio::time::sleep(std::time::Duration::from_millis(10 * (attempt as u64 + 1))).await;
    }
    let row2_id: i64 = sqlx::query_as::<_, (i64,)>(
        "INSERT INTO pending_deploys \
         (system_id, plan_summary, requested_by, requested_at, status, \
          environment, target_id, fence_token) \
         VALUES ('b', '{}', ?1, '2026-01-01T00:00:00.000Z', \
                 'pending', 'dev', ?2, 0) RETURNING id",
    )
    .bind(op.user.id)
    .bind(t)
    .fetch_one(&pool)
    .await
    .expect("insert race row")
    .0;
    for attempt in 0..8usize {
        match sqlx::query(
            "CREATE UNIQUE INDEX idx_pending_deploys_one_active_per_target \
             ON pending_deploys(target_id) \
             WHERE status IN ('pending', 'approved')",
        )
        .execute(&pool)
        .await
        {
            Ok(_) => break,
            Err(sqlx::Error::Database(e))
                if e.code().as_deref() == Some("SQLITE_BUSY")
                    || e.message().contains("database is locked") =>
            {
                if attempt == 7 {
                    panic!("recreate idx: still busy after 8 retries: {e}");
                }
                tokio::time::sleep(std::time::Duration::from_millis(10 * (attempt as u64 + 1)))
                    .await;
            }
            Err(e) => panic!("recreate idx: {e}"),
        }
    }
    // 3) Approve the
    // simulated stale row and
    // attempt the apply.
    pd.approve(row2_id, admin.user.id)
        .await
        .expect("approve")
        .expect("ok");
    let err = pd
        .mark_applied(row2_id)
        .await
        .expect_err("mark_applied must reject stale fence");
    match err {
        CoreError::ErrStaleDeployment {
            kind,
            captured_version,
            current_version,
            ..
        } => {
            assert!(kind.contains("deployment_fence"), "got: {kind}");
            assert_eq!(captured_version, 0);
            assert_eq!(current_version, 1);
        }
        other => panic!("expected ErrStaleDeployment, got {other:?}"),
    }
    // The row must stay
    // `approved` (the apply
    // was refused; the operator
    // must re-issue).
    let after = pd.get(row2_id).await.expect("get").expect("present");
    assert_eq!(after.status, Status::Approved);
    assert!(after.applied_at.is_none());
    // The target's
    // deployment_version is
    // still 1 (the failed
    // apply did not bump).
    let v: (i64,) = sqlx::query_as("SELECT deployment_version FROM targets WHERE id = ?1")
        .bind(t)
        .fetch_one(&pool)
        .await
        .expect("v");
    assert_eq!(v.0, 1);
}

/// 2.11.0 (P1-D-02): a
/// `mark_applied` whose
/// `fence_token IS NULL` (a
/// pre-P1-D-02 backfill row) is
/// not subject to the fence
/// check. The fence commit is
/// also a no-op (we don't know
/// the pre-bump value, so we
/// can't safely CAS-bump).
/// The pre-P1-D-01 freshness
/// checks still apply.
#[tokio::test]
async fn mark_applied_skips_fence_check_for_legacy_null_token() {
    let (_dir, pool, pd, users, targets) = fresh_db_with_pool().await;
    let op = users.create("op", Role::Operator).await.expect("op");
    let admin = users.create("admin", Role::Admin).await.expect("admin");
    let t = make_target(&targets, "a", Environment::Dev).await;
    // Insert a `pending` row
    // with `fence_token =
    // NULL` (the migration
    // backfill shape). We
    // bypass the `request` API
    // because that would write
    // a non-NULL fence.
    let legacy_id: i64 = sqlx::query_as::<_, (i64,)>(
        "INSERT INTO pending_deploys \
         (system_id, plan_summary, requested_by, requested_at, status, \
          environment, target_id) \
         VALUES ('legacy', '{}', ?1, '2026-01-01T00:00:00.000Z', \
                 'pending', 'dev', ?2) RETURNING id",
    )
    .bind(op.user.id)
    .bind(t)
    .fetch_one(&pool)
    .await
    .expect("insert legacy")
    .0;
    pd.approve(legacy_id, admin.user.id)
        .await
        .expect("approve")
        .expect("ok");
    // Bump
    // `targets.deployment_version`
    // to 5 (simulate a long
    // history of applies).
    sqlx::query("UPDATE targets SET deployment_version = 5 WHERE id = ?1")
        .bind(t)
        .execute(&pool)
        .await
        .expect("bump");
    // The legacy row's apply
    // must succeed: no fence
    // check, no fence bump
    // (fence_token was NULL,
    // so we don't know what
    // the pre-bump value was).
    let applied = pd
        .mark_applied(legacy_id)
        .await
        .expect("apply")
        .expect("ok");
    // The legacy row's
    // `applied_deployment_version`
    // stays NULL (the fence
    // commit was a no-op for
    // NULL fence).
    assert!(applied.applied_deployment_version.is_none());
    // The target's
    // deployment_version
    // stays at 5 (no bump for
    // legacy rows).
    let v: (i64,) = sqlx::query_as("SELECT deployment_version FROM targets WHERE id = ?1")
        .bind(t)
        .fetch_one(&pool)
        .await
        .expect("v");
    assert_eq!(v.0, 5);
}

// P1-D-02 helper: like `fresh_db()`
// but also returns the underlying
// `SqlitePool` for tests that
// need to issue raw SQL (e.g.
// DROP INDEX for the race
// simulation, or a legacy
// `fence_token IS NULL` insert
// that bypasses `request`).
async fn fresh_db_with_pool() -> (
    tempfile::TempDir,
    sqlx::SqlitePool,
    PendingDeployRepository,
    UserRepository,
    TargetRepository,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("approvals_p1d02.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let pool = db.pool().clone();
    let pd = PendingDeployRepository::new(pool.clone());
    let users = UserRepository::new(pool.clone());
    let targets = TargetRepository::new(pool.clone());
    (dir, pool, pd, users, targets)
}
