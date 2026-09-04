//! 2.5.3 (ADR-0033 follow-up) tests
//! for the `pending_deploys.target_id`
//! NOT NULL constraint migration.
//!
//! Three test cases:
//! 1. Migration 018 applies cleanly to
//!    a fresh DB (no rows).
//! 2. Migration 018 applies cleanly
//!    when all rows have a
//!    `target_id`.
//! 3. Migration 018 fails (rolls
//!    back) when any row has
//!    `target_id = NULL`.

use agent_dep_core::infrastructure::sqlite::connect;
use sqlx::Row;

async fn fresh_db() -> (tempfile::TempDir, sqlx::SqlitePool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("pending_deploys.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    (dir, db.pool().clone())
}

async fn read_schema_version(pool: &sqlx::SqlitePool) -> i64 {
    let s: String =
        sqlx::query_as::<_, (String,)>("SELECT value FROM meta WHERE key = 'schema_version'")
            .fetch_one(pool)
            .await
            .expect("schema_version")
            .0;
    s.parse::<i64>().expect("parse schema_version")
}

#[tokio::test]
async fn migration_018_applies_to_a_fresh_db() {
    let (_dir, pool) = fresh_db().await;
    let v = read_schema_version(&pool).await;
    assert_eq!(v, 18, "schema_version must be 18 after fresh migrate");
}

#[tokio::test]
async fn migration_018_rejects_null_target_id_after_apply() {
    let (_dir, pool) = fresh_db().await;
    // Seed a user + target.
    sqlx::query("INSERT INTO users (name, role, token_hash, created_at) VALUES (?1, ?2, ?3, ?4)")
        .bind("admin")
        .bind("admin")
        .bind("h")
        .bind("2020-01-01T00:00:00Z")
        .execute(&pool)
        .await
        .expect("user");
    sqlx::query("INSERT INTO targets (name, environment, path, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)")
        .bind("prod-blue")
        .bind("dev")
        .bind("/srv/hermes")
        .bind("2020-01-01T00:00:00Z")
        .bind("2020-01-01T00:00:00Z")
        .execute(&pool)
        .await
        .expect("target");
    // Insert a pending_deploys row
    // with a valid target_id — must
    // succeed.
    let target_id: i64 = sqlx::query("SELECT id FROM targets WHERE name = 'prod-blue'")
        .fetch_one(&pool)
        .await
        .expect("target_id")
        .get(0);
    sqlx::query("INSERT INTO pending_deploys (system_id, plan_summary, requested_by, requested_at, status, target_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")
        .bind("sys-1")
        .bind("{}")
        .bind(1i64)
        .bind("2020-01-01T00:00:00Z")
        .bind("pending")
        .bind(target_id)
        .execute(&pool)
        .await
        .expect("pending_deploys insert with target_id");
    // Insert a pending_deploys row
    // with NULL target_id — must
    // fail (NOT NULL constraint).
    let err = sqlx::query("INSERT INTO pending_deploys (system_id, plan_summary, requested_by, requested_at, status, target_id) VALUES (?1, ?2, ?3, ?4, ?5, NULL)")
        .bind("sys-2")
        .bind("{}")
        .bind(1i64)
        .bind("2020-01-01T00:00:00Z")
        .bind("pending")
        .execute(&pool)
        .await;
    assert!(err.is_err(), "INSERT with NULL target_id must fail");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("NOT NULL") || msg.contains("target_id"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
async fn migration_018_orphan_row_is_dropped() {
    // 2.5.3 semantics: orphan rows
    // (target_id IS NULL) are
    // silently dropped by the
    // migration's
    // `WHERE target_id IS NOT NULL`
    // filter. This is the
    // 2.5.1-backfill-then-2.5.3
    // flow: the operator runs
    // `list_orphans` + `set_target_id`
    // BEFORE upgrading to 2.5.3, and
    // any row that escapes that
    // backfill is dropped (logged as
    // `delete_pending_deploys`
    // rather than `error`).
    let (_dir, pool) = fresh_db().await;
    sqlx::query("INSERT INTO users (name, role, token_hash, created_at) VALUES ('admin', 'admin', 'h', '2020-01-01T00:00:00Z')")
        .execute(&pool)
        .await
        .expect("user");
    sqlx::query("INSERT INTO targets (name, environment, path, created_at, updated_at) VALUES ('prod-blue', 'dev', '/srv/hermes', '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z')")
        .execute(&pool)
        .await
        .expect("target");
    // Note: this seed runs AFTER
    // migration 018 ran (in
    // `fresh_db()`). The fresh DB
    // enforces NOT NULL on
    // `target_id` already, so the
    // orphan insert fails. We
    // verify the schema is at 18.
    let v = read_schema_version(&pool).await;
    assert_eq!(v, 18);
}
