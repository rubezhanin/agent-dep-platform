//! HTTP integration tests for `agency-server` (2.0.0).
//!
//! Each test binds a real `axum` router to
//! `127.0.0.1:0` (the kernel picks a free port), then
//! drives the API with `reqwest`. The tests use the
//! `router(state)` constructor so they can inject a
//! hermetic SQLite DB and a known bearer token — no
//! filesystem state outside the tempdir.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use agent_dep_core::infrastructure::repository::audit_log_repository::{
    AuditLogRepository, AuditOutcome,
};
use agent_dep_core::infrastructure::sqlite::connect;
use agent_dep_server::{router, ServerState};
use serde_json::json;
use tokio::net::TcpListener;

struct TestServer {
    base: String,
    token: String,
    _dir: tempfile::TempDir,
}

async fn boot() -> TestServer {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path: PathBuf = dir.path().join("audit.db");
    let db = connect(&db_path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let audit = AuditLogRepository::new(db.pool().clone());
    let token = "test-bearer-1".to_string();
    let state = ServerState {
        db,
        audit,
        token: Arc::new(token.clone()),
    };
    let app = router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("local_addr");
    let base = format!("http://{addr}");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    // Give the listener a moment to be ready.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    TestServer {
        base,
        token,
        _dir: dir,
    }
}

#[tokio::test]
async fn health_is_open_and_returns_ok() {
    let srv = boot().await;
    let resp = reqwest::get(format!("{}/v1/health", srv.base))
        .await
        .expect("get");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn audit_requires_bearer_token() {
    let srv = boot().await;
    let resp = reqwest::get(format!("{}/v1/audit", srv.base))
        .await
        .expect("get");
    assert_eq!(resp.status(), 401);
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/audit", srv.base))
        .bearer_auth(&srv.token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn audit_list_records_each_request() {
    let srv = boot().await;
    // Two failed auths (one missing, one bad).
    let _ = reqwest::get(format!("{}/v1/audit", srv.base)).await;
    let _ = reqwest::Client::new()
        .get(format!("{}/v1/audit", srv.base))
        .bearer_auth("wrong-token")
        .send()
        .await;
    // One successful call.
    let _ = reqwest::Client::new()
        .get(format!("{}/v1/audit?limit=10", srv.base))
        .bearer_auth(&srv.token)
        .send()
        .await
        .expect("send");

    let resp = reqwest::Client::new()
        .get(format!("{}/v1/audit?limit=50", srv.base))
        .bearer_auth(&srv.token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    let items = body["items"].as_array().expect("items array");
    assert!(
        items.len() >= 3,
        "expected ≥ 3 audit rows (2 errors + 1 ok), got {}",
        items.len()
    );
    // Oldest first; the first two are the unauth attempts.
    assert_eq!(items[0]["outcome"], "error");
    assert_eq!(items[1]["outcome"], "error");
    assert_eq!(items[2]["outcome"], "ok");
    assert_eq!(items[0]["actor"], "anonymous");
    assert_eq!(items[2]["actor"], "operator");
}

#[tokio::test]
async fn systems_list_is_empty_for_fresh_db() {
    let srv = boot().await;
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/systems", srv.base))
        .bearer_auth(&srv.token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    let arr = body.as_array().expect("array");
    assert!(arr.is_empty(), "fresh DB has no active snapshots");
}

#[tokio::test]
async fn plan_endpoint_returns_writes_for_a_real_catalog() {
    use agent_dep_core::infrastructure::repository::audit_log_repository::AuditLogRepository;
    let dir = tempfile::tempdir().unwrap();
    let cat = dir.path().join("catalog");
    std::fs::create_dir_all(cat.join("agents/engineering")).unwrap();
    std::fs::write(
        cat.join("divisions.json"),
        r#"{"divisions":[{"id": "engineering", "label": "Eng", "order": 0}]}"#,
    )
    .unwrap();
    let be_md = r#"---
id: be
name: Backend
display_name: Backend
division: engineering
role: backend
description: be
version: 1.0.0
sensitive: false
activation_phrases: []
tools: []
---

You are be.
"#;
    std::fs::write(cat.join("agents/engineering/be.md"), be_md).unwrap();
    let sys = r#"apiVersion: agent-dep/v1
kind: System
metadata:
  id: test-sys
  name: test
spec:
  source: ./catalog
  runtime_type: hermes
  agents:
    - ref: be@1.0.0
"#;
    let db_path = dir.path().join("audit.db");
    let db = connect(&db_path).await.unwrap();
    db.migrate().await.unwrap();
    let audit = AuditLogRepository::new(db.pool().clone());
    let token = "t".to_string();
    let state = ServerState {
        db,
        audit,
        token: Arc::new(token.clone()),
    };
    let app = router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let body = json!({
        "catalog": cat.to_string_lossy(),
        "system_yaml": sys,
    });
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/systems/plan"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .expect("post");
    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    assert_eq!(
        status, 200,
        "plan should succeed: status={status} body={body_text}"
    );
    let v: serde_json::Value = serde_json::from_str(&body_text).expect("json");
    assert_eq!(v["system_id"], "test-sys");
    let writes = v["writes"].as_array().expect("writes");
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0]["agent_ref"], "be@1.0.0");
}

#[tokio::test]
async fn plan_endpoint_reports_bad_catalog_as_400() {
    let srv = boot().await;
    let body = json!({
        "catalog": "Z:/does-not-exist",
        "system_yaml": "id: x\n",
    });
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/systems/plan", srv.base))
        .bearer_auth(&srv.token)
        .json(&body)
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), 400);
    let v: serde_json::Value = resp.json().await.expect("json");
    assert!(v["error"].as_str().unwrap().contains("not a directory"));
}

// Suppress unused-import warning for `AuditOutcome`; the
// tests above import the symbol through re-exports.
#[allow(dead_code)]
fn _outcome_marker() -> AuditOutcome {
    AuditOutcome::Ok
}
