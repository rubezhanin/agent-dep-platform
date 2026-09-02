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
            PathKind::Posix,
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
            PathKind::Posix,
            Some("personal"),
        )
        .await
        .expect("create dev/laptop");
    targets
        .create(
            "laptop",
            Environment::Production,
            "/srv/hermes/blue",
            PathKind::Posix,
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
        .create("prod-blue", Environment::Production, "/srv/a", PathKind::Posix, None)
        .await
        .expect("first");
    let err = targets
        .create("prod-blue", Environment::Production, "/srv/b", PathKind::Posix, None)
        .await
        .expect_err("duplicate must fail");
    let msg = format!("{err:?}");
    assert!(msg.contains("already exists"), "unexpected error: {msg}");
}

#[tokio::test]
async fn list_filters_by_env() {
    let (_dir, targets) = fresh_db().await;
    targets
        .create("a", Environment::Dev, "/tmp/a", PathKind::Posix, None)
        .await
        .unwrap();
    targets
        .create("b", Environment::Staging, "/tmp/b", PathKind::Posix, None)
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
        .create("x", Environment::Dev, "/tmp/x", PathKind::Posix, None)
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
        .create("x", Environment::Dev, "", PathKind::Posix, None)
        .await
        .expect_err("must reject");
    let msg = format!("{err:?}");
    assert!(msg.contains("path must not be empty"), "unexpected: {msg}");
}

#[tokio::test]
async fn accepts_paths_with_matching_path_kind() {
    // 2.5.0 stored paths verbatim without
    // validation; 2.5.1 (ADR-0029) added the
    // `PathKind` discriminator. Each path
    // must match its declared kind.
    let (_dir, targets) = fresh_db().await;
    // POSIX path with `PathKind::Posix` — accepted.
    let row = targets
        .create(
            "posix-target",
            Environment::Dev,
            "/srv/hermes/blue",
            PathKind::Posix,
            None,
        )
        .await
        .expect("posix path on posix kind");
    assert_eq!(row.path_kind, PathKind::Posix);
    // Windows path with `PathKind::Windows` — accepted.
    let row = targets
        .create(
            "windows-target",
            Environment::Dev,
            "C:\\Users\\op\\hermes",
            PathKind::Windows,
            None,
        )
        .await
        .expect("windows path on windows kind");
    assert_eq!(row.path_kind, PathKind::Windows);
    // POSIX path on Windows kind — rejected.
    let err = targets
        .create(
            "mismatch-1",
            Environment::Dev,
            "/srv/hermes",
            PathKind::Windows,
            None,
        )
        .await
        .expect_err("posix path on windows kind must be rejected");
    // Windows path on POSIX kind — rejected.
    let err = targets
        .create(
            "mismatch-2",
            Environment::Dev,
            "C:\\hermes",
            PathKind::Posix,
            None,
        )
        .await
        .expect_err("windows path on posix kind must be rejected");
}

#[tokio::test]
async fn count_tracks_rows() {
    let (_dir, targets) = fresh_db().await;
    assert_eq!(targets.count().await.unwrap(), 0);
    targets
        .create("a", Environment::Dev, "/tmp/a", PathKind::Posix, None)
        .await
        .unwrap();
    targets
        .create("b", Environment::Staging, "/tmp/b", PathKind::Posix, None)
        .await
        .unwrap();
    assert_eq!(targets.count().await.unwrap(), 2);
}

// -----------------------------------------------------------------------
// 2.5.1 (ADR-0029) — PathKind discriminator tests
// -----------------------------------------------------------------------

#[test]
fn path_kind_parse_round_trip() {
    assert_eq!(PathKind::Posix.as_str(), "posix");
    assert_eq!(PathKind::Windows.as_str(), "windows");
    assert_eq!(PathKind::parse("posix").unwrap(), PathKind::Posix);
    assert_eq!(PathKind::parse("windows").unwrap(), PathKind::Windows);
    assert!(PathKind::parse("wsl").is_err());
}

#[test]
fn path_kind_validate_posix() {
    PathKind::Posix.validate_path("/srv/hermes").unwrap();
    PathKind::Posix.validate_path("/").unwrap();
    // POSIX rejects Windows-style paths.
    let err = PathKind::Posix.validate_path("C:\\hermes").unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("not a POSIX absolute path"), "msg: {msg}");
    // And rejects bare relative paths.
    let err = PathKind::Posix.validate_path("srv/hermes").unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("not a POSIX absolute path"), "msg: {msg}");
}

#[test]
fn path_kind_validate_windows() {
    // Drive letter with backslash.
    PathKind::Windows
        .validate_path("C:\\Users\\op\\hermes")
        .unwrap();
    // Drive letter with forward slash (the
    // scanner's `\\` OR `/` branch handles it).
    PathKind::Windows.validate_path("D:/srv/hermes").unwrap();
    // UNC path with double backslash.
    PathKind::Windows
        .validate_path("\\\\server\\share\\dir")
        .unwrap();
    // UNC path with double forward slash.
    PathKind::Windows.validate_path("//server/share/dir").unwrap();
    // POSIX is rejected.
    let err = PathKind::Windows.validate_path("/srv/hermes").unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("not a Windows absolute path"), "msg: {msg}");
}

#[tokio::test]
async fn create_windows_target_rejects_posix_path() {
    let (_dir, targets) = fresh_db().await;
    let err = targets
        .create("win", Environment::Dev, "/srv/hermes", PathKind::Windows, None)
        .await
        .expect_err("must reject POSIX path on Windows kind");
    let msg = format!("{err:?}");
    assert!(msg.contains("not a Windows absolute path"), "msg: {msg}");
}

#[tokio::test]
async fn create_windows_target_accepts_windows_path() {
    let (_dir, targets) = fresh_db().await;
    let row = targets
        .create(
            "win",
            Environment::Dev,
            "C:\\Users\\op\\hermes",
            PathKind::Windows,
            None,
        )
        .await
        .expect("create");
    assert_eq!(row.path_kind, PathKind::Windows);
    let get = targets.get(row.id).await.unwrap().expect("present");
    assert_eq!(get.path_kind, PathKind::Windows);
    assert_eq!(get.path, "C:\\Users\\op\\hermes");
}

