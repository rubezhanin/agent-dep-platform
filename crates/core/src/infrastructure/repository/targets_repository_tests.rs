use super::*;
use crate::infrastructure::sqlite::connect;

async fn fresh_db() -> (tempfile::TempDir, TargetRepository) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("targets.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let targets = TargetRepository::new(db.pool().clone());
    (dir, targets)
}

#[tokio::test]
async fn create_then_get_round_trips() {
    let (_dir, targets) = fresh_db().await;
    let row = targets
        .create(
            "prod-blue",
            Environment::Production,
            "/srv/hermes/blue",
            None,
        )
        .await
        .expect("create");
    assert_eq!(row.name, "prod-blue");
    assert_eq!(row.environment, Environment::Production);
    assert_eq!(row.path, "/srv/hermes/blue");
    let get = targets.get(row.id).await.expect("get").expect("present");
    assert_eq!(get.name, row.name);
}

#[tokio::test]
async fn find_by_env_name_resolves_correctly() {
    let (_dir, targets) = fresh_db().await;
    targets
        .create(
            "laptop",
            Environment::Dev,
            "/home/op/hermes",
            Some("personal"),
        )
        .await
        .expect("create dev/laptop");
    targets
        .create(
            "laptop",
            Environment::Production,
            "/srv/hermes/blue",
            Some("prod laptop"),
        )
        .await
        .expect("create prod/laptop");
    let dev = targets
        .find_by_env_name(Environment::Dev, "laptop")
        .await
        .expect("find")
        .expect("present");
    assert_eq!(dev.environment, Environment::Dev);
    let prod = targets
        .find_by_env_name(Environment::Production, "laptop")
        .await
        .expect("find")
        .expect("present");
    assert_eq!(prod.environment, Environment::Production);
    assert_ne!(dev.id, prod.id);
}

#[tokio::test]
async fn unique_per_environment_name() {
    let (_dir, targets) = fresh_db().await;
    targets
        .create("prod-blue", Environment::Production, "/srv/a", None)
        .await
        .expect("first");
    let err = targets
        .create("prod-blue", Environment::Production, "/srv/b", None)
        .await
        .expect_err("duplicate must fail");
    let msg = format!("{err:?}");
    assert!(msg.contains("already exists"), "unexpected error: {msg}");
}

#[tokio::test]
async fn list_filters_by_env() {
    let (_dir, targets) = fresh_db().await;
    targets
        .create("a", Environment::Dev, "/tmp/a", None)
        .await
        .unwrap();
    targets
        .create("b", Environment::Staging, "/tmp/b", None)
        .await
        .unwrap();
    let prod = targets.list(Some(Environment::Production)).await.unwrap();
    assert!(prod.is_empty());
    let staging = targets.list(Some(Environment::Staging)).await.unwrap();
    assert_eq!(staging.len(), 1);
    assert_eq!(staging[0].name, "b");
    let all = targets.list(None).await.unwrap();
    assert_eq!(all.len(), 2);
}

#[tokio::test]
async fn delete_is_hard_and_idempotent() {
    let (_dir, targets) = fresh_db().await;
    let row = targets
        .create("x", Environment::Dev, "/tmp/x", None)
        .await
        .unwrap();
    let first = targets.delete(row.id).await.unwrap();
    assert!(first);
    let second = targets.delete(row.id).await.unwrap();
    assert!(!second);
    assert!(targets.get(row.id).await.unwrap().is_none());
}

#[tokio::test]
async fn rejects_empty_path() {
    let (_dir, targets) = fresh_db().await;
    let err = targets
        .create("x", Environment::Dev, "", None)
        .await
        .expect_err("must reject");
    let msg = format!("{err:?}");
    assert!(msg.contains("path must not be empty"), "unexpected: {msg}");
}

#[tokio::test]
async fn accepts_any_non_empty_path_for_cross_platform() {
    // 2.5.0 server stores the path verbatim.
    // Cross-platform absolute-path validation
    // happens on the operator's CLI side.
    let (_dir, targets) = fresh_db().await;
    for (i, path) in [
        "/srv/hermes/blue",
        "C:\\Users\\op\\hermes",
        "relative/looking/path",
    ]
    .into_iter()
    .enumerate()
    {
        let name = format!("t{i}");
        let row = targets
            .create(&name, Environment::Dev, path, None)
            .await
            .unwrap_or_else(|e| panic!("path `{path}` was rejected: {e:?}"));
        assert_eq!(row.path, path);
    }
}

#[tokio::test]
async fn count_tracks_rows() {
    let (_dir, targets) = fresh_db().await;
    assert_eq!(targets.count().await.unwrap(), 0);
    targets
        .create("a", Environment::Dev, "/tmp/a", None)
        .await
        .unwrap();
    targets
        .create("b", Environment::Staging, "/tmp/b", None)
        .await
        .unwrap();
    assert_eq!(targets.count().await.unwrap(), 2);
}
