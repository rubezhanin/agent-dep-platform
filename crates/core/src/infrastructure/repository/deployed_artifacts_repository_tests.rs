use super::*;

async fn make_db() -> (tempfile::TempDir, DeployedArtifactsRepository) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let db = crate::infrastructure::sqlite::connect(&path)
        .await
        .unwrap();
    db.migrate().await.unwrap();
    (
        dir,
        DeployedArtifactsRepository::new(db.pool().clone()),
    )
}

async fn make_source(db: &DeployedArtifactsRepository) {
    // Insert a minimal source + snapshot so the FK from
    // `deployed_artifacts` (none today, but the row needs
    // a system_id that we can later join against).
    let source_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO sources (id, kind, location, display_name, created_at)
         VALUES (?1, 'local', '/tmp/test', 'test', '2026-01-01T00:00:00Z')",
    )
    .bind(&source_id)
    .execute(db.pool())
    .await
    .unwrap();
}

fn row(system_id: &str, target: &str, expected: &str) -> DeployedArtifactRow {
    DeployedArtifactRow {
        system_id: system_id.to_string(),
        target: target.to_string(),
        expected_sha256: expected.to_string(),
        actual_sha256: Some(expected.to_string()),
        state: "current".to_string(),
        deployed_at: "2026-09-01T00:00:00Z".to_string(),
        last_verified_at: None,
    }
}

#[tokio::test]
async fn upsert_and_list_round_trip() {
    let (_dir, repo) = make_db().await;
    make_source(&repo).await;
    repo.upsert(&row("saas", "agents/be@1.0.0/be.md", "aaa"))
        .await
        .unwrap();
    repo.upsert(&row("saas", "agents/fe@1.0.0/fe.md", "bbb"))
        .await
        .unwrap();

    let rows = repo.list_for_system("saas").await.unwrap();
    assert_eq!(rows.len(), 2);
    let by_target: std::collections::HashMap<_, _> =
        rows.iter().map(|(t, e, a)| (t.clone(), (e.clone(), a.clone()))).collect();
    assert_eq!(
        by_target.get("agents/be@1.0.0/be.md").unwrap(),
        &("aaa".to_string(), Some("aaa".to_string()))
    );
}

#[tokio::test]
async fn upsert_replaces_existing_row() {
    let (_dir, repo) = make_db().await;
    make_source(&repo).await;
    repo.upsert(&row("saas", "agents/be/be.md", "aaa"))
        .await
        .unwrap();
    repo.upsert(&row("saas", "agents/be/be.md", "bbb"))
        .await
        .unwrap();

    let rows = repo.list_for_system("saas").await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, "bbb");
}

#[tokio::test]
async fn get_returns_none_for_missing() {
    let (_dir, repo) = make_db().await;
    make_source(&repo).await;
    let row = repo.get("saas", "agents/ghost.md").await.unwrap();
    assert!(row.is_none());
}

#[tokio::test]
async fn delete_for_system_clears_rows() {
    let (_dir, repo) = make_db().await;
    make_source(&repo).await;
    repo.upsert(&row("saas", "a", "x")).await.unwrap();
    repo.upsert(&row("saas", "b", "y")).await.unwrap();
    repo.upsert(&row("other", "c", "z")).await.unwrap();

    let n = repo.delete_for_system("saas").await.unwrap();
    assert_eq!(n, 2);
    let saas = repo.list_for_system("saas").await.unwrap();
    assert!(saas.is_empty());
    let other = repo.list_for_system("other").await.unwrap();
    assert_eq!(other.len(), 1);
}
