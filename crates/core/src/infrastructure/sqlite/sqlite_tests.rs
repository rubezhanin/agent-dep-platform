use crate::infrastructure::sqlite::{connect, schema_version};
use std::path::Path;

/// Bump this assertion when a new migration is added. The migration
/// runner advances `meta.schema_version` after the last .sql runs.
const CURRENT_SCHEMA_VERSION: i64 = 17;

#[tokio::test]
async fn in_memory_db_migrates() {
    let db = connect(Path::new(":memory:")).await.expect("connect");
    db.migrate().await.expect("migrate");
    let v = schema_version(&db).await.expect("version");
    assert_eq!(v, CURRENT_SCHEMA_VERSION);
}

#[tokio::test]
async fn file_db_creates_and_migrates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    assert!(path.exists());
    let v = schema_version(&db).await.expect("version");
    assert_eq!(v, CURRENT_SCHEMA_VERSION);
}

#[tokio::test]
async fn migrate_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("idem.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate 1");
    db.migrate().await.expect("migrate 2");
    let v = schema_version(&db).await.expect("version");
    assert_eq!(v, CURRENT_SCHEMA_VERSION);
}
