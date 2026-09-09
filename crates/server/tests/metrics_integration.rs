//! 3.0.0 (C4, audit): integration
//! tests for the
//! `GET /v1/metrics` Prometheus
//! exposition endpoint.
//!
//! These tests exercise the
//! metrics counters end-to-end
//! (the HTTP middleware bumps
//! `http_requests_total` after
//! every served request, the
//! auth layer bumps
//! `auth_rejections_total` on
//! 401/403, the audit recorder
//! bumps `audit_recorded_total`
//! after a successful INSERT).
//! The exposition format is
//! verified by parsing the
//! `text/plain; version=0.0.4`
//! body line-by-line.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use agent_dep_core::infrastructure::repository::audit_log_repository::AuditLogRepository;
use agent_dep_core::infrastructure::repository::pending_deploys_repository::PendingDeployRepository;
use agent_dep_core::infrastructure::repository::secrets_repository::SecretRepository;
use agent_dep_core::infrastructure::repository::targets_repository::TargetRepository;
use agent_dep_core::infrastructure::repository::users_repository::{Role, UserRepository};
use agent_dep_core::infrastructure::sqlite::connect;
use agent_dep_server::audit_recorder::AuditRecorder;
use agent_dep_server::{router, ServerState};
use tokio::net::TcpListener;

struct TestServer {
    base: String,
    admin_token: String,
    _dir: tempfile::TempDir,
}

async fn boot() -> TestServer {
    // SAFETY: set_var is `unsafe`
    // because of libc
    // thread-safety; the
    // metrics_integration
    // suite runs single-
    // threaded (cargo's
    // default per-test-
    // binary scheduling is
    // OK here because the
    // http_integration.rs
    // suite also uses
    // single-threaded
    // scheduling, and
    // cargo test does not
    // share env mutations
    // across binaries).
    unsafe {
        std::env::set_var("AGENCY_BEARER_FALLBACK", "1");
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path: PathBuf = dir.path().join("audit.db");
    let db = connect(&db_path).await.expect("connect");
    db.migrate().await.expect("migrate");
    // 3.0.0 (C4, audit): the
    // test harness uses
    // `direct_with_metrics` so
    // every successful
    // `record_sync` call
    // increments
    // `audit_recorded_total`.
    let metrics = agent_dep_server::metrics::Metrics::new();
    let audit = AuditRecorder::direct_with_metrics(
        AuditLogRepository::new(db.pool().clone()),
        metrics.clone(),
    );
    let users = UserRepository::new(db.pool().clone());
    let created = users
        .create("admin", Role::Admin)
        .await
        .expect("create admin");
    let admin_token = created.token;
    let deploys = PendingDeployRepository::new(db.pool().clone());
    let test_install_salt =
        [0u8; agent_dep_core::infrastructure::repository::secrets_repository::INSTALL_SALT_LEN];
    let secrets = SecretRepository::new(db.pool().clone(), "test-passphrase", &test_install_salt)
        .expect("vault");
    let targets_repo = TargetRepository::new(db.pool().clone());
    let oidc = agent_dep_server::oidc::OidcConfig::default();
    let oidc_pending = std::sync::Arc::new(
        agent_dep_core::infrastructure::repository::oidc_pending_repository::OidcPendingRepository::new(
            db.pool().clone(),
        ),
    );
    let oidc_client: Arc<dyn agent_dep_server::oidc_client::OidcClient> =
        Arc::new(agent_dep_server::oidc_client::MockOidcClient);
    let state = ServerState {
        db: db.clone(),
        audit,
        users,
        deploys,
        secrets,
        targets: targets_repo.clone(),
        oidc,
        oidc_pending,
        oidc_client,
        legacy_token: Arc::new(None),
        sessions:
            agent_dep_core::infrastructure::repository::sessions_repository::SessionRepository::new(
                db.pool().clone(),
            ),
        cookie_secure: false,
        idempotency:
            agent_dep_core::infrastructure::repository::idempotency_repository::IdempotencyRepository::new(
                db.pool().clone(),
            ),
        rate_limiter: Arc::new(agent_dep_server::rate_limit::RateLimiter::new()),
        max_body_bytes: Arc::new(std::sync::atomic::AtomicU32::new(
            agent_dep_server::rate_limit::MAX_BODY_BYTES,
        )),
        max_header_count: Arc::new(std::sync::atomic::AtomicU32::new(
            agent_dep_server::rate_limit::MAX_HEADER_COUNT,
        )),
        // 3.0.0 (C4, audit):
        // share the SAME
        // `Metrics` instance
        // we passed to
        // `direct_with_metrics`
        // above so the
        // audit counter and
        // the HTTP counter
        // live in the same
        // registry.
        metrics,
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

/// Minimal Prometheus exposition
/// format line lookup. The
/// format is:
/// `<metric_name>{labels} <value>`
/// or `<metric_name> <value>`
/// for label-less counters. We
/// only care about the metric
/// name + label-set + value;
/// the `# HELP` and `# TYPE`
/// header lines are not
/// asserted (they're cosmetic
/// for the scraper).
fn find_metric<'a>(body: &'a str, name: &str, labels: &str) -> Option<&'a str> {
    for line in body.lines() {
        if line.starts_with('#') {
            continue;
        }
        if !line.starts_with(name) {
            continue;
        }
        // Either `<name> <value>` (no
        // labels) or
        // `<name>{<labels>} <value>`.
        // Match exactly the prefix
        // `<name>` followed by `{`
        // or ` `.
        let after = &line[name.len()..];
        if labels.is_empty() {
            if after.starts_with(' ') {
                return Some(line);
            }
        } else {
            if let Some(rest) = after.strip_prefix('{') {
                if let Some(close_idx) = rest.find('}') {
                    let actual_labels = &rest[..close_idx];
                    if actual_labels == labels {
                        return Some(line);
                    }
                }
            }
        }
    }
    None
}

#[tokio::test]
async fn metrics_endpoint_returns_text_plain_prometheus() {
    let srv = boot().await;
    // 3.0.0 (C4, audit):
    // `IntCounterVec` only
    // appears in the
    // exposition output
    // after at least one
    // sample with a given
    // label combination has
    // been recorded. To
    // assert the TYPE
    // header for the
    // labelled families,
    // we make a couple of
    // preflight requests
    // first so each family
    // has ≥1 sample.
    //
    // (label-less
    // `audit_recorded_total`
    // and
    // `audit_dropped_to_sync_total`
    // appear with value
    // 0 immediately — those
    // are asserted in
    // `audit_counters_present_at_zero`.)
    let _ = reqwest::Client::new()
        .get(format!("{}/v1/systems", srv.base))
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("get");
    let _ = reqwest::Client::new()
        .get(format!("{}/v1/systems", srv.base))
        .send()
        .await
        .expect("get");
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/metrics", srv.base))
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // The scraper cares about
    // the
    // `text/plain; version=0.0.4`
    // prefix; the `; charset=utf-8`
    // suffix is informational.
    assert!(
        ct.starts_with("text/plain"),
        "unexpected content-type: {ct}"
    );
    let body = resp.text().await.expect("text");
    // The `IntCounter` (no
    // labels) families always
    // appear with value 0
    // even before the first
    // observation.
    for name in ["audit_recorded_total", "audit_dropped_to_sync_total"] {
        assert!(
            body.contains(&format!("# TYPE {name} counter")),
            "missing TYPE header for {name}; body=\n{body}"
        );
    }
    // The `IntCounterVec`
    // families appear AFTER
    // at least one
    // observation per label
    // set. We pre-flighted
    // one GET /v1/systems
    // with a bearer (200) +
    // one without (401), so
    // both `http_requests_total`
    // and
    // `auth_rejections_total`
    // must show a TYPE
    // header.
    for name in ["http_requests_total", "auth_rejections_total"] {
        assert!(
            body.contains(&format!("# TYPE {name} counter")),
            "missing TYPE header for {name} after preflight; body=\n{body}"
        );
    }
    // `oidc_logins_total` and
    // `rate_limit_rejections_total`
    // are NOT asserted here
    // because the preflight
    // did not exercise those
    // paths; their absence
    // is correct Prometheus
    // behaviour (a metric
    // family with zero
    // observations is
    // elided).
}

#[tokio::test]
async fn http_requests_total_increments_after_served_request() {
    let srv = boot().await;
    // Serve a known request:
    // GET /v1/systems (viewer
    // route). Use the admin
    // token (admin ⊇ viewer).
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/systems", srv.base))
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 200);
    // Now scrape /v1/metrics
    // and assert the counter
    // for
    // method=GET, route=/v1/systems,
    // status=200 incremented.
    let metrics_resp = reqwest::Client::new()
        .get(format!("{}/v1/metrics", srv.base))
        .send()
        .await
        .expect("get");
    let body = metrics_resp.text().await.expect("text");
    let line = find_metric(
        &body,
        "http_requests_total",
        r#"method="GET",route="/v1/systems",status="200""#,
    )
    .unwrap_or_else(|| panic!("missing http_requests_total line; body=\n{body}"));
    // The value must be ≥ 1.
    let value: u64 = line
        .rsplit(' ')
        .next()
        .unwrap()
        .parse()
        .expect("parse value");
    assert!(value >= 1, "expected ≥1, got {value}");
}

#[tokio::test]
async fn auth_rejections_total_increments_on_401() {
    let srv = boot().await;
    // A request with no
    // Authorization header
    // on a protected route
    // gets a 401. The
    // `auth_rejections_total`
    // counter for
    // method=GET, route=raw
    // path must increment.
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/systems", srv.base))
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 401);
    let metrics_resp = reqwest::Client::new()
        .get(format!("{}/v1/metrics", srv.base))
        .send()
        .await
        .expect("get");
    let body = metrics_resp.text().await.expect("text");
    // The `auth_rejections_total`
    // label set is
    // (method, route). The
    // route label is the raw
    // path from
    // `unauthorized()` —
    // `/v1/systems`.
    let line = find_metric(
        &body,
        "auth_rejections_total",
        r#"method="GET",route="/v1/systems""#,
    )
    .unwrap_or_else(|| panic!("missing auth_rejections_total line; body=\n{body}"));
    let value: u64 = line
        .rsplit(' ')
        .next()
        .unwrap()
        .parse()
        .expect("parse value");
    assert!(value >= 1, "expected ≥1, got {value}");
}

#[tokio::test]
async fn audit_recorded_total_increments_after_handler_writes_audit() {
    let srv = boot().await;
    // GET /v1/audit is a
    // viewer route; the
    // handler writes an audit
    // row via `record_async`
    // (which the test
    // harness routes through
    // `direct_with_metrics` →
    // spawn-and-insert).
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/audit", srv.base))
        .bearer_auth(&srv.admin_token)
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 200);
    // Give the spawned INSERT
    // a moment to land. The
    // test runtime is
    // `current_thread` so a
    // `tokio::yield_now()`
    // drains the queue.
    for _ in 0..20 {
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let metrics_resp = reqwest::Client::new()
        .get(format!("{}/v1/metrics", srv.base))
        .send()
        .await
        .expect("get");
    let body = metrics_resp.text().await.expect("text");
    // The
    // `audit_recorded_total`
    // counter is label-less;
    // `find_metric(..., "")`
    // matches the bare line.
    let line = find_metric(&body, "audit_recorded_total", "")
        .expect("audit_recorded_total should appear in /v1/metrics");
    let value: u64 = line
        .rsplit(' ')
        .next()
        .unwrap()
        .parse()
        .expect("parse value");
    assert!(value >= 1, "expected ≥1, got {value}");
}

#[tokio::test]
async fn metrics_endpoint_is_public_no_bearer_required() {
    // 3.0.0 (C4, audit): the
    // Prometheus scraper
    // doesn't carry a bearer
    // token. `GET /v1/metrics`
    // must be reachable
    // WITHOUT an Authorization
    // header.
    let srv = boot().await;
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/metrics", srv.base))
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 200, "/v1/metrics must be public");
}
