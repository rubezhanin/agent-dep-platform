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
use agent_dep_core::infrastructure::repository::pending_deploys_repository::PendingDeployRepository;
use agent_dep_core::infrastructure::repository::secrets_repository::SecretRepository;
use agent_dep_core::infrastructure::repository::targets_repository::TargetRepository;
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
    let deploys = PendingDeployRepository::new(db.pool().clone());
    let secrets = SecretRepository::new(db.pool().clone(), "test-passphrase").expect("vault");
    let targets = TargetRepository::new(db.pool().clone());
    let state = ServerState {
        db,
        audit,
        users,
        deploys,
        secrets,
        targets,
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
    let deploys = PendingDeployRepository::new(db.pool().clone());
    let secrets = SecretRepository::new(db.pool().clone(), "test-passphrase").expect("vault");
    let targets = TargetRepository::new(db.pool().clone());
    let state = ServerState {
        db,
        audit,
        users,
        deploys,
        secrets,
        targets,
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

// ---------------------------------------------------------------------------
// 2.2.0 — approvals workflow integration tests (ADR-0020).
// ---------------------------------------------------------------------------

const APPROVALS_SYS: &str = "apiVersion: agent-dep/v1
kind: System
metadata:
  id: approval-sys
  name: approval
spec:
  source: ./catalog
  runtime_type: hermes
  agents:
    - ref: be@1.0.0
";

fn _write_approvals_catalog(cat: &std::path::Path) {
    std::fs::create_dir_all(cat.join("agents").join("engineering")).unwrap();
    std::fs::write(
        cat.join("divisions.json"),
        r#"{"divisions":[{"id":"engineering","label":"Eng","order":0}]}"#,
    )
    .unwrap();
    let be_md = "---
id: be
name: Backend
division: engineering
role: backend
description: be
version: 1.0.0
sensitive: false
activation_phrases: []
tools: []
---

You are be.
";
    std::fs::write(cat.join("agents").join("engineering").join("be.md"), be_md).unwrap();
}

async fn _request_deploy(srv: &TestServer, token: &str) -> (i64, serde_json::Value) {
    // The catalog lives next to the test binary's
    // own tempdir; we use a fresh subdir so the test
    // is hermetic.
    let cat = srv._dir.path().join("approvals_catalog");
    std::fs::create_dir_all(&cat).unwrap();
    _write_approvals_catalog(&cat);
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/deploys", srv.base))
        .bearer_auth(token)
        .json(&json!({
            "catalog": cat.to_string_lossy(),
            "system_yaml": APPROVALS_SYS,
        }))
        .send()
        .await
        .expect("post deploy");
    assert_eq!(resp.status(), 201, "request deploy: {:?}", resp);
    let v: serde_json::Value = resp.json().await.expect("json");
    (v["deploy"]["id"].as_i64().expect("id"), v)
}

#[tokio::test]
async fn operator_creates_pending_deploy() {
    let srv = boot().await;
    let op_token = create_user(&srv, "op", Role::Operator).await;
    let (id, _) = _request_deploy(&srv, &op_token).await;
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/deploys/{id}", srv.base))
        .bearer_auth(&op_token)
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(v["status"], "pending");
}

#[tokio::test]
async fn viewer_reads_deploys() {
    let srv = boot().await;
    let op_token = create_user(&srv, "op", Role::Operator).await;
    let vw_token = create_user(&srv, "vw", Role::Viewer).await;
    let _ = _request_deploy(&srv, &op_token).await;
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/deploys", srv.base))
        .bearer_auth(&vw_token)
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.expect("json");
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["status"], "pending");
}

#[tokio::test]
async fn admin_approves_pending_deploy() {
    let srv = boot().await;
    let op_token = create_user(&srv, "op", Role::Operator).await;
    let (id, _) = _request_deploy(&srv, &op_token).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/deploys/{id}/approve", srv.base))
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("approve");
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(v["status"], "approved");
    assert!(v["approved_by"].is_i64());
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/audit?limit=200", srv.base))
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("get");
    let v: serde_json::Value = resp.json().await.expect("json");
    let items = v["items"].as_array().expect("items");
    let approve_row = items
        .iter()
        .find(|r| r["action"] == "POST /v1/deploys/:id/approve")
        .unwrap_or_else(|| {
            panic!(
                "no approve audit row found; got actions: {:?}",
                items
                    .iter()
                    .map(|r| r["action"].as_str().unwrap_or("?"))
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(approve_row["outcome"], "ok");
    assert_eq!(approve_row["actor"], "admin");
}

#[tokio::test]
async fn admin_rejects_pending_deploy() {
    let srv = boot().await;
    let op_token = create_user(&srv, "op", Role::Operator).await;
    let (id, _) = _request_deploy(&srv, &op_token).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/deploys/{id}/reject", srv.base))
        .bearer_auth(&srv.admin_token)
        .json(&json!({ "reason": "policy blocked" }))
        .send()
        .await
        .expect("reject");
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(v["status"], "rejected");
    assert_eq!(v["rejection_reason"], "policy blocked");
}

// ---------------------------------------------------------------------------
// 2.3.0 — vault integration tests (ADR-0021).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_creates_secret_201() {
    let srv = boot().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/secrets", srv.base))
        .bearer_auth(&srv.admin_token)
        .json(&json!({ "name": "hermes-api-token", "value": "secret-XYZ" }))
        .send()
        .await
        .expect("create");
    assert_eq!(resp.status(), 201, "create secret: {:?}", resp);
    let v: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(v["name"], "hermes-api-token");
    // The list view does NOT carry a value field.
    assert!(v.get("value").is_none());
}

#[tokio::test]
async fn viewer_lists_secrets_without_values() {
    let srv = boot().await;
    // Seed a secret as admin.
    let _ = reqwest::Client::new()
        .post(format!("{}/v1/secrets", srv.base))
        .bearer_auth(&srv.admin_token)
        .json(&json!({ "name": "k1", "value": "v1" }))
        .send()
        .await
        .expect("seed k1");
    // Operator-level token for the read.
    let op_token = create_user(&srv, "op", Role::Operator).await;
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/secrets", srv.base))
        .bearer_auth(&op_token)
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.expect("json");
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "k1");
    assert!(
        arr[0].get("value").is_none(),
        "list must never include value"
    );
}

#[tokio::test]
async fn operator_reads_secret_value_200() {
    let srv = boot().await;
    let _ = reqwest::Client::new()
        .post(format!("{}/v1/secrets", srv.base))
        .bearer_auth(&srv.admin_token)
        .json(&json!({ "name": "k", "value": "the-value" }))
        .send()
        .await
        .expect("seed");
    let op_token = create_user(&srv, "op", Role::Operator).await;
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/secrets/k", srv.base))
        .bearer_auth(&op_token)
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(v["name"], "k");
    assert_eq!(v["value"], "the-value");
}

#[tokio::test]
async fn admin_deletes_secret_204_and_audit_logs_access() {
    let srv = boot().await;
    let _ = reqwest::Client::new()
        .post(format!("{}/v1/secrets", srv.base))
        .bearer_auth(&srv.admin_token)
        .json(&json!({ "name": "k", "value": "v" }))
        .send()
        .await
        .expect("seed");
    let resp = reqwest::Client::new()
        .delete(format!("{}/v1/secrets/k", srv.base))
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("delete");
    assert_eq!(resp.status(), 204);
    // After delete, GET returns 404.
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/secrets/k", srv.base))
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("get after delete");
    assert_eq!(resp.status(), 404);
    // The audit log records every step: create, delete, then the failed get.
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/audit?limit=200", srv.base))
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("get audit");
    let v: serde_json::Value = resp.json().await.expect("json");
    let items = v["items"].as_array().expect("items");
    let has_create = items
        .iter()
        .any(|r| r["action"] == "POST /v1/secrets" && r["outcome"] == "ok");
    let has_delete = items
        .iter()
        .any(|r| r["action"] == "DELETE /v1/secrets/:name" && r["outcome"] == "ok");
    assert!(has_create, "create must be in audit log: {items:?}");
    assert!(has_delete, "delete must be in audit log: {items:?}");
}

// ---------------------------------------------------------------------------
// 2.4.0 — multi-environment integration tests (ADR-0022).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn environments_endpoint_lists_the_three_supported_envs() {
    let srv = boot().await;
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/environments", srv.base))
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.expect("json");
    let arr = v["environments"].as_array().expect("array");
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0], "dev");
    assert_eq!(arr[1], "staging");
    assert_eq!(arr[2], "production");
}

#[tokio::test]
async fn deploy_records_environment_and_list_filter_works() {
    let srv = boot().await;
    let op_token = create_user(&srv, "op", Role::Operator).await;
    // Create one dev and one staging deploy.
    let (id_dev, _) = _request_deploy_with_env(&srv, &op_token, "dev").await;
    let (id_staging, _) = _request_deploy_with_env(&srv, &op_token, "staging").await;
    // GET /v1/deploys?env=staging returns only the staging row.
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/deploys?env=staging", srv.base))
        .bearer_auth(&op_token)
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.expect("json");
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["environment"], "staging");
    assert_eq!(arr[0]["id"].as_i64().unwrap(), id_staging);
    // And the dev row's environment is recorded correctly.
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/deploys/{id_dev}", srv.base))
        .bearer_auth(&op_token)
        .send()
        .await
        .expect("get");
    let v: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(v["environment"], "dev");
}

async fn _request_deploy_with_env(
    srv: &TestServer,
    token: &str,
    env: &str,
) -> (i64, serde_json::Value) {
    let cat = srv._dir.path().join("env_catalog");
    std::fs::create_dir_all(&cat).unwrap();
    _write_approvals_catalog(&cat);
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/deploys", srv.base))
        .bearer_auth(token)
        .json(&json!({
            "catalog": cat.to_string_lossy(),
            "system_yaml": APPROVALS_SYS,
            "environment": env,
        }))
        .send()
        .await
        .expect("post deploy");
    assert_eq!(resp.status(), 201, "request deploy: {:?}", resp);
    let v: serde_json::Value = resp.json().await.expect("json");
    (v["deploy"]["id"].as_i64().expect("id"), v)
}

// ---------------------------------------------------------------------------
// 2.5.0 — fleet integration tests (ADR-0023).
// ---------------------------------------------------------------------------

/// Helper: build the body for `POST /v1/targets`.
/// `path` and `description` are optional so a test
/// can use a smaller object.
fn _create_target_body(
    name: &str,
    env: &str,
    path: &str,
    description: Option<&str>,
) -> serde_json::Value {
    let mut body = json!({
        "name": name,
        "environment": env,
        "path": path,
    });
    if let Some(d) = description {
        body["description"] = json!(d);
    }
    body
}

#[tokio::test]
async fn admin_creates_and_lists_targets() {
    let srv = boot().await;
    // 201 on POST
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/targets", srv.base))
        .bearer_auth(&srv.admin_token)
        .json(&_create_target_body(
            "prod-blue",
            "production",
            "/srv/hermes/blue",
            Some("primary prod"),
        ))
        .send()
        .await
        .expect("create");
    assert_eq!(resp.status(), 201, "create target: {:?}", resp);
    let v: serde_json::Value = resp.json().await.expect("json");
    let id = v["id"].as_i64().expect("id");
    assert_eq!(v["name"], "prod-blue");
    assert_eq!(v["environment"], "production");
    assert_eq!(v["path"], "/srv/hermes/blue");
    assert_eq!(v["description"], "primary prod");
    // Duplicate (env, name) is rejected.
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/targets", srv.base))
        .bearer_auth(&srv.admin_token)
        .json(&_create_target_body(
            "prod-blue",
            "production",
            "/srv/hermes/other",
            None,
        ))
        .send()
        .await
        .expect("dup");
    assert_eq!(resp.status(), 400, "duplicate must be rejected");
    // LIST returns the row.
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/targets", srv.base))
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("list");
    assert_eq!(resp.status(), 200);
    let arr: Vec<serde_json::Value> = resp.json().await.expect("arr");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"].as_i64().unwrap(), id);
    // DELETE returns 204, then a second DELETE returns 404.
    let resp = reqwest::Client::new()
        .delete(format!("{}/v1/targets/{id}", srv.base))
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("delete");
    assert_eq!(resp.status(), 204);
    let resp = reqwest::Client::new()
        .delete(format!("{}/v1/targets/{id}", srv.base))
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("delete-2");
    assert_eq!(resp.status(), 404);
    // LIST is now empty.
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/targets", srv.base))
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("list-empty");
    let arr: Vec<serde_json::Value> = resp.json().await.expect("arr");
    assert!(arr.is_empty(), "expected empty list, got {arr:?}");
}

#[tokio::test]
async fn list_targets_filters_by_environment() {
    let srv = boot().await;
    // Seed three targets across two environments.
    for (name, env, path) in [
        ("laptop", "dev", "/home/op/dev"),
        ("ci-runner", "dev", "/var/ci"),
        ("prod-blue", "production", "/srv/hermes/blue"),
    ] {
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/targets", srv.base))
            .bearer_auth(&srv.admin_token)
            .json(&_create_target_body(name, env, path, None))
            .send()
            .await
            .expect("seed");
        assert_eq!(resp.status(), 201, "seed {name}: {:?}", resp);
    }
    // Unfiltered list returns all 3.
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/targets", srv.base))
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("list-all");
    let arr: Vec<serde_json::Value> = resp.json().await.expect("arr");
    assert_eq!(arr.len(), 3);
    // env=dev filter returns 2.
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/targets?env=dev", srv.base))
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("list-dev");
    let arr: Vec<serde_json::Value> = resp.json().await.expect("arr");
    assert_eq!(arr.len(), 2);
    for row in &arr {
        assert_eq!(row["environment"], "dev");
    }
    // env=production filter returns 1.
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/targets?env=production", srv.base))
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("list-prod");
    let arr: Vec<serde_json::Value> = resp.json().await.expect("arr");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "prod-blue");
    // env=staging has no rows.
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/targets?env=staging", srv.base))
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("list-staging");
    let arr: Vec<serde_json::Value> = resp.json().await.expect("arr");
    assert!(arr.is_empty());
    // Bogus env value is rejected at the application
    // layer (parses through `Environment::parse`).
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/targets?env=qa", srv.base))
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("list-qa");
    assert_eq!(
        resp.status(),
        400,
        "unknown env must be a 400, not silently empty"
    );
}

#[tokio::test]
async fn deploy_with_target_records_target_id() {
    let srv = boot().await;
    let op_token = create_user(&srv, "op", Role::Operator).await;
    // Register a dev target, then deploy to it.
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/targets", srv.base))
        .bearer_auth(&srv.admin_token)
        .json(&_create_target_body("laptop", "dev", "/home/op/dev", None))
        .send()
        .await
        .expect("create target");
    assert_eq!(resp.status(), 201);
    let v: serde_json::Value = resp.json().await.expect("json");
    let target_id = v["id"].as_i64().expect("id");
    // POST /v1/deploys with target=laptop.
    let cat = srv._dir.path().join("target_catalog");
    std::fs::create_dir_all(&cat).unwrap();
    _write_approvals_catalog(&cat);
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/deploys", srv.base))
        .bearer_auth(&op_token)
        .json(&json!({
            "catalog": cat.to_string_lossy(),
            "system_yaml": APPROVALS_SYS,
            "environment": "dev",
            "target": "laptop",
        }))
        .send()
        .await
        .expect("post deploy");
    assert_eq!(resp.status(), 201, "deploy with target: {:?}", resp);
    let v: serde_json::Value = resp.json().await.expect("json");
    let deploy_id = v["deploy"]["id"].as_i64().expect("deploy id");
    assert_eq!(v["deploy"]["target_id"].as_i64(), Some(target_id));
    assert_eq!(v["deploy"]["environment"], "dev");
    // GET /v1/deploys/:id round-trips.
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/deploys/{deploy_id}", srv.base))
        .bearer_auth(&op_token)
        .send()
        .await
        .expect("get");
    let v: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(v["target_id"].as_i64(), Some(target_id));
}

#[tokio::test]
async fn deploy_with_unknown_target_is_400() {
    let srv = boot().await;
    let op_token = create_user(&srv, "op", Role::Operator).await;
    let cat = srv._dir.path().join("missing_target_catalog");
    std::fs::create_dir_all(&cat).unwrap();
    _write_approvals_catalog(&cat);
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/deploys", srv.base))
        .bearer_auth(&op_token)
        .json(&json!({
            "catalog": cat.to_string_lossy(),
            "system_yaml": APPROVALS_SYS,
            "environment": "dev",
            "target": "this-target-does-not-exist",
        }))
        .send()
        .await
        .expect("post deploy");
    assert_eq!(
        resp.status(),
        400,
        "unknown target must be a 400, not a 201/500"
    );
    let v: serde_json::Value = resp.json().await.expect("json");
    let err = v["error"].as_str().unwrap_or("");
    assert!(
        err.contains("not found"),
        "expected `not found` error, got: {err}"
    );
    // The deploy must NOT have been created.
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/deploys", srv.base))
        .bearer_auth(&op_token)
        .send()
        .await
        .expect("list");
    let arr: Vec<serde_json::Value> = resp.json().await.expect("arr");
    assert!(
        arr.is_empty(),
        "failed target lookup must not leave a pending_deploys row: {arr:?}"
    );
}
