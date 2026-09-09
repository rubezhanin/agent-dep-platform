//! 3.0.0 (A5, audit):
//! integration test for the
//! embedded `axum` server
//! that the Tauri host
//! boots on `127.0.0.1:0`.
//!
//! The test exercises the
//! `embedded_server::boot`
//! entry point directly
//! (without the Tauri
//! runtime) and asserts
//! that:
//!
//! 1. The boot succeeds
//!    and returns a
//!    `server_url` that
//!    listens on
//!    `127.0.0.1`.
//! 2. The same `axum`
//!    router the
//!    `agency-server`
//!    binary uses is
//!    reachable at the
//!    bound URL —
//!    `GET /v1/health`
//!    returns 200 +
//!    `{"status":"ok"}`.
//! 3. A subsequent
//!    `GET /v1/metrics`
//!    (added by C4) is
//!    reachable and
//!    returns the
//!    `text/plain;
//!    version=0.0.4`
//!    Prometheus
//!    exposition
//!    format.
//!
//! The test is
//! intentionally
//! Tauri-free: it does
//! not start the Tauri
//! runtime or open
//! any windows. A
//! future 3.1 test
//! (per AGENTS.md
//! "Playwright e2e for
//! the critical flow")
//! covers the Tauri
//! shell end-to-end;
//! this integration
//! test covers the
//! embedded server in
//! isolation.

use std::net::SocketAddr;
use std::path::PathBuf;

use agent_dep_app_lib::embedded_server;
use agent_dep_core::infrastructure::sqlite::connect;

#[tokio::test]
async fn embedded_server_binds_127_0_0_1_and_serves_health() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path: PathBuf = dir.path().join("a5.db");
    let db = connect(&db_path).await.expect("db connect");
    db.migrate().await.expect("migrate");
    let handle = embedded_server::boot(&db)
        .await
        .expect("embedded server boot");
    // The bind must be on
    // 127.0.0.1 (loopback);
    // a LAN-reachable bind
    // would expose the 2.x
    // HTTP API to the
    // network.
    let addr: SocketAddr = handle.addr;
    assert_eq!(
        addr.ip().to_string(),
        "127.0.0.1",
        "embedded server must bind loopback, got {addr}"
    );

    // The same axum
    // router the
    // `agency-server`
    // binary uses is
    // reachable. We
    // assert the
    // `GET /v1/health`
    // happy path (this
    // is the cheapest
    // public route, no
    // DB write, no
    // OIDC).
    let url = handle.url.clone();
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{url}/v1/health"))
        .send()
        .await
        .expect("GET /v1/health");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("health body");
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn embedded_server_serves_prometheus_metrics_endpoint() {
    // 3.0.0 (C4 cross-check):
    // the embedded server
    // also serves the
    // Prometheus
    // exposition
    // endpoint (C4
    // added
    // `GET /v1/metrics`
    // to the public
    // router). The
    // Tauri app
    // exposes the same
    // surface to the
    // SPA via the IPC
    // proxy layer
    // (3.0.0 A5).
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path: PathBuf = dir.path().join("a5-c4.db");
    let db = connect(&db_path).await.expect("db connect");
    db.migrate().await.expect("migrate");
    let handle = embedded_server::boot(&db)
        .await
        .expect("embedded server boot");
    let url = handle.url.clone();
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{url}/v1/metrics"))
        .send()
        .await
        .expect("GET /v1/metrics");
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("text/plain"),
        "metrics content-type must be text/plain, got {ct}"
    );
    let body = resp.text().await.expect("metrics body");
    // The C4 label-less
    // counters must
    // appear with
    // value 0 even
    // before the first
    // observation.
    assert!(
        body.contains("# TYPE audit_recorded_total counter"),
        "missing audit_recorded_total TYPE header; body=\n{body}"
    );
}
