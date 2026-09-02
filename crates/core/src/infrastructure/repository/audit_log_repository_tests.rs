use super::*;
use crate::infrastructure::sqlite::connect;

async fn fresh_db() -> (tempfile::TempDir, AuditLogRepository) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let repo = AuditLogRepository::new(db.pool().clone());
    (dir, repo)
}

#[tokio::test]
async fn record_returns_monotonic_ids() {
    let (_dir, repo) = fresh_db().await;
    let a = repo
        .record("operator", "GET /v1/audit", None, AuditOutcome::Ok, None)
        .await
        .expect("record a");
    let b = repo
        .record("operator", "GET /v1/systems", None, AuditOutcome::Ok, None)
        .await
        .expect("record b");
    assert!(a < b, "ids must be monotonic: a={a} b={b}");
}

#[tokio::test]
async fn list_paginates_with_cursor() {
    let (_dir, repo) = fresh_db().await;
    for i in 0..5 {
        repo.record(
            "operator",
            &format!("GET /v1/audit?i={i}"),
            None,
            AuditOutcome::Ok,
            None,
        )
        .await
        .expect("record");
    }
    let page1 = repo.list(None, 2).await.expect("page1");
    assert_eq!(page1.len(), 2);
    let cursor = page1.last().unwrap().id;
    let page2 = repo.list(Some(cursor), 2).await.expect("page2");
    assert_eq!(page2.len(), 2);
    assert!(page2[0].id > cursor);
    let cursor2 = page2.last().unwrap().id;
    let page3 = repo.list(Some(cursor2), 2).await.expect("page3");
    assert_eq!(page3.len(), 1, "fifth row is the last one");
}

#[tokio::test]
async fn record_persists_outcome_and_details() {
    let (_dir, repo) = fresh_db().await;
    repo.record(
        "operator",
        "POST /v1/deploy",
        Some("system:saas-platform"),
        AuditOutcome::Error,
        Some("{\"reason\":\"policy blocked\"}"),
    )
    .await
    .expect("record");
    let rows = repo.list(None, 10).await.expect("list");
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(r.actor, "operator");
    assert_eq!(r.action, "POST /v1/deploy");
    assert_eq!(r.target.as_deref(), Some("system:saas-platform"));
    assert_eq!(r.outcome, AuditOutcome::Error);
    assert_eq!(
        r.details.as_deref(),
        Some("{\"reason\":\"policy blocked\"}")
    );
}
