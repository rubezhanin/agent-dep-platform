//! 3.0.0 (C4, audit): Prometheus
//! metrics for the agency-server
//! HTTP API.
//!
//! The `Metrics` struct owns a
//! dedicated `Registry` and a small
//! set of counters. Handlers and
//! middlewares increment the
//! counters via the typed helpers
//! below (no raw `IntCounter`
//! exposure), and the
//! `GET /v1/metrics` handler
//! renders the registry in the
//! `text/plain; version=0.0.4`
//! Prometheus exposition format.
//!
//! Why a dedicated `Registry`
//! (not the default global):
//! the default global
//! `prometheus::default_registry()`
//! is process-singleton and
//! cannot be reset between
//! integration tests. The
//! integration test suite boots
//! multiple `ServerState`
//! instances in a single test
//! process; a per-`Metrics`
//! registry keeps each test's
//! counters isolated and makes
//! the assertions
//! "counter X incremented by
//! exactly 1" deterministic.
//!
//! Auth: `/v1/metrics` is
//! intentionally PUBLIC. The
//! Prometheus scraper doesn't
//! carry a bearer token. The
//! endpoint lives on the
//! bind address the operator
//! chose; restricting access
//! is the responsibility of the
//! reverse proxy / network
//! policy (the AGENTS.md
//! deployment guide documents
//! the `bind 127.0.0.1` + sidecar
//! pattern).

use std::sync::Arc;

use axum::{
    extract::{MatchedPath, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use prometheus::{Encoder, IntCounter, IntCounterVec, Opts, Registry, TextEncoder};

/// Typed accessor for the
/// counter set. Cloned via
/// `Arc` so each handler holds
/// a cheap reference.
#[derive(Clone)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
}

struct MetricsInner {
    registry: Registry,
    /// 3.0.0 (C4): cumulative
    /// count of audit rows
    /// recorded (via either
    /// `record_async` or
    /// `record_sync`). Monotonic
    /// from process start.
    audit_recorded_total: IntCounter,
    /// 3.0.0 (C4): cumulative
    /// count of `record_async`
    /// calls that fell back to
    /// `record_sync` because the
    /// bounded mpsc channel was
    /// full (back-pressure event).
    /// Mirrors
    /// `AuditRecorder::stats().dropped_to_sync_total`
    /// — the recorder is the
    /// source of truth; this
    /// counter is exposed for
    /// Prometheus so operators
    /// can alert without
    /// scraping the JSON
    /// `/v1/audit/stats` route.
    audit_dropped_to_sync_total: IntCounter,
    /// 3.0.0 (C4): HTTP request
    /// counter, labelled by
    /// `(method, route, status)`.
    /// The `route` label is the
    /// axum matched path
    /// template (e.g.
    /// `/v1/deploys/:id`) so the
    /// label cardinality is
    /// bounded by the number of
    /// declared routes, not the
    /// number of distinct IDs.
    http_requests_total: IntCounterVec,
    /// 3.0.0 (C4): 401 / 403
    /// rejections from the
    /// `require_session_or_bearer`
    /// / `allow_*` layers.
    /// Labelled by `route` (same
    /// template as
    /// `http_requests_total`).
    auth_rejections_total: IntCounterVec,
    /// 3.0.0 (C4): 429 responses
    /// emitted by the rate
    /// limiter. Labelled by
    /// `route` (template).
    rate_limit_rejections_total: IntCounterVec,
    /// 3.0.0 (C4): OIDC login
    /// flow outcomes.
    /// `status=success` for a
    /// successful callback that
    /// minted a session;
    /// `status=error` for any
    /// other terminal state
    /// (cancelled, missing state,
    /// token validation failure).
    oidc_logins_total: IntCounterVec,
}

impl Metrics {
    /// Build a fresh `Metrics`
    /// with an empty registry.
    /// Called once per
    /// `ServerState` in
    /// `boot_default_state` and
    /// in the integration test
    /// harness.
    pub fn new() -> Self {
        let registry = Registry::new();

        let audit_recorded_total = IntCounter::with_opts(Opts::new(
            "audit_recorded_total",
            "Cumulative number of audit rows recorded (async + sync).",
        ))
        .expect("static counter opts are valid");
        let audit_dropped_to_sync_total = IntCounter::with_opts(Opts::new(
            "audit_dropped_to_sync_total",
            "Cumulative number of record_async calls that fell back to a synchronous \
             INSERT because the bounded mpsc channel was full (back-pressure event).",
        ))
        .expect("static counter opts are valid");
        let http_requests_total = IntCounterVec::new(
            Opts::new(
                "http_requests_total",
                "Cumulative number of HTTP requests served, labelled by method, \
                 matched-route template, and response status code.",
            ),
            &["method", "route", "status"],
        )
        .expect("static counter opts are valid");
        let auth_rejections_total = IntCounterVec::new(
            Opts::new(
                "auth_rejections_total",
                "Cumulative number of 401/403 responses from the auth layers, \
                 labelled by matched-route template.",
            ),
            &["method", "route"],
        )
        .expect("static counter opts are valid");
        let rate_limit_rejections_total = IntCounterVec::new(
            Opts::new(
                "rate_limit_rejections_total",
                "Cumulative number of 429 responses from the rate-limit middleware, \
                 labelled by matched-route template.",
            ),
            &["route"],
        )
        .expect("static counter opts are valid");
        let oidc_logins_total = IntCounterVec::new(
            Opts::new(
                "oidc_logins_total",
                "Cumulative number of OIDC login-flow terminal events, labelled by \
                 outcome (success | error).",
            ),
            &["status"],
        )
        .expect("static counter opts are valid");

        registry
            .register(Box::new(audit_recorded_total.clone()))
            .expect("audit_recorded_total registers cleanly");
        registry
            .register(Box::new(audit_dropped_to_sync_total.clone()))
            .expect("audit_dropped_to_sync_total registers cleanly");
        registry
            .register(Box::new(http_requests_total.clone()))
            .expect("http_requests_total registers cleanly");
        registry
            .register(Box::new(auth_rejections_total.clone()))
            .expect("auth_rejections_total registers cleanly");
        registry
            .register(Box::new(rate_limit_rejections_total.clone()))
            .expect("rate_limit_rejections_total registers cleanly");
        registry
            .register(Box::new(oidc_logins_total.clone()))
            .expect("oidc_logins_total registers cleanly");

        Self {
            inner: Arc::new(MetricsInner {
                registry,
                audit_recorded_total,
                audit_dropped_to_sync_total,
                http_requests_total,
                auth_rejections_total,
                rate_limit_rejections_total,
                oidc_logins_total,
            }),
        }
    }

    /// 3.0.0 (C4): handler-side
    /// increment after a
    /// successful audit
    /// `record_async` or
    /// `record_sync` call. Cheap
    /// (`fetch_add(1, Relaxed)`
    /// under the hood).
    pub fn inc_audit_recorded(&self) {
        self.inner.audit_recorded_total.inc();
    }

    /// 3.0.0 (C4): recorder-side
    /// increment for the
    /// dropped-to-sync back-pressure
    /// event. Called from
    /// `AuditRecorder::record_async`
    /// when the channel is
    /// full.
    pub fn inc_audit_dropped_to_sync(&self) {
        self.inner.audit_dropped_to_sync_total.inc();
    }

    /// 3.0.0 (C4): HTTP
    /// middleware increment. The
    /// `route` argument MUST be
    /// the axum matched path
    /// template (e.g.
    /// `/v1/deploys/:id`) so the
    /// label cardinality stays
    /// bounded. `status` is the
    /// string form of the
    /// `StatusCode` (e.g. `200`).
    pub fn inc_http_request(&self, method: &str, route: &str, status: u16) {
        self.inner
            .http_requests_total
            .with_label_values(&[method, route, &status.to_string()])
            .inc();
    }

    /// 3.0.0 (C4): 401 / 403
    /// increment from the
    /// `require_session_or_bearer`
    /// / `allow_*` layers.
    pub fn inc_auth_rejection(&self, method: &str, route: &str) {
        self.inner
            .auth_rejections_total
            .with_label_values(&[method, route])
            .inc();
    }

    /// 3.0.0 (C4): 429
    /// increment from the
    /// rate-limit middleware.
    pub fn inc_rate_limit_rejection(&self, route: &str) {
        self.inner
            .rate_limit_rejections_total
            .with_label_values(&[route])
            .inc();
    }

    /// 3.0.0 (C4): OIDC login
    /// terminal event. Called
    /// from `oidc::callback_handler`
    /// on the success / error
    /// branches.
    pub fn inc_oidc_login(&self, status: &str) {
        self.inner
            .oidc_logins_total
            .with_label_values(&[status])
            .inc();
    }

    /// 3.0.0 (C4): render the
    /// registry in
    /// `text/plain; version=0.0.4`
    /// exposition format. The
    /// output is what
    /// `GET /v1/metrics` returns
    /// to the scraper. Returns
    /// `Err` only on encoder
    /// failure (which is
    /// unreachable for the
    /// `TextEncoder` + a
    /// in-memory registry, but
    /// we propagate it for
    /// `IntoResponse`).
    pub fn render(&self) -> Result<String, prometheus::Error> {
        let mut buf = Vec::new();
        let encoder = TextEncoder::new();
        let metric_families = self.inner.registry.gather();
        encoder.encode(&metric_families, &mut buf)?;
        // The exposition format is
        // valid UTF-8 by
        // construction; the unwrap
        // is the same one
        // `prometheus::TextEncoder`
        // uses in its own example
        // server.
        Ok(String::from_utf8(buf).expect("prometheus text encoder emits valid UTF-8"))
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// 3.0.0 (C4, audit): `GET
/// /v1/metrics` handler. Public
/// (no `require_session_or_bearer`),
/// Prometheus scraper doesn't
/// carry a bearer token. The
/// `text/plain; version=0.0.4`
/// content type is what
/// Prometheus / Grafana Agent /
/// VictoriaMetrics / OpenObserve
/// all accept.
pub async fn metrics_handler(State(state): State<super::state::ServerState>) -> Response {
    match state.metrics.render() {
        Ok(body) => {
            let mut resp = (StatusCode::OK, body).into_response();
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                // The exposition format
                // charset is
                // `text/plain;
                // version=0.0.4;
                // charset=utf-8`. The
                // semicolon after the
                // type keeps strict
                // scrapers happy.
                HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
            );
            resp
        }
        Err(e) => {
            // The encoder only fails
            // on programmer error
            // (metric name collisions,
            // etc.); we already
            // asserted the names at
            // construction time. A
            // 500 here means the
            // registry was corrupted
            // at runtime — operator
            // should see the error in
            // logs.
            tracing::error!(error = %e, "failed to render prometheus metrics");
            (StatusCode::INTERNAL_SERVER_ERROR, "metrics render failed").into_response()
        }
    }
}

/// 3.0.0 (C4, audit): HTTP
/// middleware that records the
/// `http_requests_total` counter
/// after every served request.
/// Layered on the public router
/// so it sees every route
/// (including `/v1/metrics`
/// itself — operators can
/// scrape the scraper).
///
/// The middleware is registered
/// AFTER the rate-limit /
/// auth / body-size layers so
/// a request that was rejected
/// before reaching the handler
/// is still counted (the
/// `StatusCode` on the response
/// is the rejection status:
/// 401 / 403 / 413 / 429 / 400).
pub async fn http_metrics_middleware(
    State(state): State<super::state::ServerState>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().as_str().to_string();
    // The matched-path template
    // (e.g. `/v1/deploys/:id`)
    // keeps the label
    // cardinality bounded; the
    // fallback to the raw path
    // catches requests that
    // didn't match any route
    // (404s, typos).
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());
    let response = next.run(request).await;
    state
        .metrics
        .inc_http_request(&method, &route, response.status().as_u16());
    response
}
