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
use agent_dep_core::infrastructure::repository::users_repository::{Role, UserRepository};
use agent_dep_core::infrastructure::sqlite::connect;
use agent_dep_server::{router, ServerState};
use serde_json::json;
use tokio::net::TcpListener;

struct TestServer {
    base: String,
    /// The 2.1.0 server always boots with a single
    /// `admin` user (or migrates a 2.0.0 legacy token
    /// to one). Tests use the admin token for setup
    /// and create additional users for role checks.
    admin_token: String,
    _dir: tempfile::TempDir,
}

async fn boot() -> TestServer {
    boot_with_legacy(None).await
}

async fn boot_with_legacy(legacy: Option<&str>) -> TestServer {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path: PathBuf = dir.path().join("audit.db");
    let db = connect(&db_path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let audit = AuditLogRepository::new(db.pool().clone());
    let users = UserRepository::new(db.pool().clone());
    let admin_token = match legacy {
        Some(t) => {
            // 2.0.0 → 2.1.0 migration path: the legacy
            // token becomes the admin's token. The
            // state holds a hint but the users table
            // is the source of truth.
            users.migrate_legacy_token(t).await.expect("migrate legacy");
            t.to_string()
        }
        None => {
            let created = users
                .create("admin", Role::Admin)
                .await
                .expect("create admin");
            created.token
        }
    };
    let state = ServerState {
        db,
        audit,
        users,
        legacy_token: Arc::new(legacy.map(|s| s.to_string())),
    };
    let app = router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("local_addr");
    let base = format!("http://{addr}");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    TestServer {
        base,
        admin_token,
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
        .bearer_auth(&srv.admin_token)
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
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("send");

    let resp = reqwest::Client::new()
        .get(format!("{}/v1/audit?limit=50", srv.base))
        .bearer_auth(&srv.admin_token)
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
    assert_eq!(items[2]["actor"], "admin");
}

#[tokio::test]
async fn systems_list_is_empty_for_fresh_db() {
    let srv = boot().await;
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/systems", srv.base))
        .bearer_auth(&srv.admin_token)
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
    let users = UserRepository::new(db.pool().clone());
    let created = users
        .create(
            "admin",
            agent_dep_core::infrastructure::repository::users_repository::Role::Admin,
        )
        .await
        .unwrap();
    let token = created.token.clone();
    let state = ServerState {
        db,
        audit,
        users,
        legacy_token: Arc::new(Some(token.clone())),
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
        .bearer_auth(&srv.admin_token)
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

// ---------------------------------------------------------------------------
// 2.1.0 — RBAC integration tests (ADR-0019).
// ---------------------------------------------------------------------------

async fn create_user(srv: &TestServer, name: &str, role: Role) -> String {
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/users", srv.base))
        .bearer_auth(&srv.admin_token)
        .json(&json!({ "name": name, "role": role }))
        .send()
        .await
        .expect("create user");
    assert_eq!(resp.status(), 201, "create user: {:?}", resp);
    let v: serde_json::Value = resp.json().await.expect("json");
    v["token"].as_str().expect("token").to_string()
}

#[tokio::test]
async fn viewer_cannot_trigger_plan() {
    let srv = boot().await;
    let viewer_token = create_user(&srv, "vw", Role::Viewer).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/systems/plan", srv.base))
        .bearer_auth(&viewer_token)
        .json(&json!({ "catalog": "Z:/x", "system_yaml": "id: y" }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), 403, "viewer must be forbidden");
    let v: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(v["error"], "forbidden");
}

#[tokio::test]
async fn operator_can_read_audit() {
    let srv = boot().await;
    let op_token = create_user(&srv, "op", Role::Operator).await;
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/audit?limit=10", srv.base))
        .bearer_auth(&op_token)
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 200, "operator must read the audit log");
    let v: serde_json::Value = resp.json().await.expect("json");
    let items = v["items"].as_array().expect("items");
    assert!(!items.is_empty(), "audit log should have at least one row");
}

#[tokio::test]
async fn admin_can_create_user() {
    let srv = boot().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/users", srv.base))
        .bearer_auth(&srv.admin_token)
        .json(&json!({ "name": "newby", "role": "operator" }))
        .send()
        .await
        .expect("create");
    assert_eq!(resp.status(), 201);
    let v: serde_json::Value = resp.json().await.expect("json");
    let token = v["token"].as_str().expect("token");
    assert!(!token.is_empty());
    assert_eq!(v["name"], "newby");
    assert_eq!(v["role"], "operator");

    // The new user's token works.
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/systems", srv.base))
        .bearer_auth(token)
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn legacy_token_migrates_to_admin_on_first_start() {
    let legacy = "a-very-specific-2.0.0-token";
    let srv = boot_with_legacy(Some(legacy)).await;
    // The legacy token must log in as admin.
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/audit", srv.base))
        .bearer_auth(legacy)
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 200, "legacy token must keep working");
    // A second GET will see the first GET's audit row
    // (we await the audit write before responding,
    // but the response is read before the second
    // request's row is added — so we make a third
    // call to confirm the admin attribution).
    let _ = reqwest::Client::new()
        .get(format!("{}/v1/audit", srv.base))
        .bearer_auth(legacy)
        .send()
        .await
        .expect("get");
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/audit", srv.base))
        .bearer_auth(legacy)
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.expect("json");
    let items = v["items"].as_array().expect("items");
    let ok_row = items
        .iter()
        .find(|r| r["outcome"] == "ok")
        .expect("at least one ok row");
    assert_eq!(
        ok_row["actor"], "admin",
        "legacy token's bearer must attribute rows to `admin`"
    );
}
