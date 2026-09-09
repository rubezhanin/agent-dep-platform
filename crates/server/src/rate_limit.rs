//! P1-RL-01 (TZ #2 WP-0.5 / SEC-09,
//! CWE-770 Allocation of Resources
//! Without Limits or Throttling) +
//! P1-API-01..03 (TZ #1 §17,
//! CWE-770 / CWE-400).
//!
//! ## Threat model
//!
//! Pre-fix: every endpoint accepted
//! unlimited request volume, unlimited
//! request body size, and unlimited
//! JSON nesting depth. A single
//! misbehaving client (or a deliberate
//! attacker) could:
//! 1. Send 10 000 GETs per second to
//!    `GET /v1/systems`, saturating the
//!    audit-write path and starving
//!    legitimate clients.
//! 2. Send a 100 MB JSON body to
//!    `POST /v1/deploys`, exhausting
//!    the server's RSS.
//! 3. Send a JSON document with 10 000
//!    levels of nesting, triggering
//!    serde's recursive descent and
//!    blowing the stack.
//!
//! CWE-770 / CWE-400: the server
//! allocated resources (audit rows,
//! body bytes, recursion depth) without
//! bounding them per principal.
//!
//! ## Fix
//!
//! Three middlewares attached to the
//! `axum::Router`:
//! 1. `body_size_limit_middleware`
//!    rejects `Content-Length` > 1 MiB
//!    with 413.
//! 2. `header_count_limit_middleware`
//!    rejects requests with > 100
//!    headers.
//! 3. `rate_limit_middleware` is a
//!    per-(principal, route) token
//!    bucket; on rejection returns
//!    429 with a `Retry-After` header
//!    and fires a fire-and-forget
//!    audit row (the row's
//!    `sample_and_keep` flag is set
//!    on a uniform 1% of rejections
//!    so the operator can see the
//!    payload distribution in the
//!    audit log without filling it
//!    with duplicates).
//!
//! The bucket is `Mutex<HashMap<...>>`
//! (expected cardinality is in the
//! hundreds at most; the lock is hot
//! only at >10 kHz QPS, which the
//! 100 req/s default rejects).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Instant;

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use rand::Rng;
use serde_json::json;

use crate::auth::AuthenticatedUser;
use crate::state::ServerState;

pub const MAX_BODY_BYTES: u32 = 1024 * 1024;
pub const MAX_HEADER_COUNT: u32 = 100;
pub const REQUESTS_PER_SECOND: u32 = 100;
pub const BURST_TOKENS: u32 = 200;
pub const SAMPLE_AND_KEEP_PERCENT: u8 = 1;

#[derive(Debug, Clone)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
    capacity: f64,
    rate: f64,
}

impl Bucket {
    fn new(capacity: f64, rate: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            capacity,
            rate,
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn retry_after(&self) -> u32 {
        let needed = 1.0 - self.tokens;
        let secs = (needed / self.rate).ceil().max(1.0) as u64;
        secs.min(60) as u32
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    capacity: f64,
    rate: f64,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::with_capacity_and_rate(
            f64::from(BURST_TOKENS),
            f64::from(REQUESTS_PER_SECOND),
        )
    }

    pub fn with_capacity_and_rate(capacity: f64, rate: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            capacity,
            rate,
        }
    }

    pub fn check(&self, key: &str) -> (bool, u32) {
        let mut buckets = self
            .buckets
            .lock()
            .expect("rate-limit mutex poisoned");
        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| Bucket::new(self.capacity, self.rate));
        let allowed = bucket.try_consume();
        let retry_after = if allowed { 0 } else { bucket.retry_after() };
        (allowed, retry_after)
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sample_kept() -> bool {
    rand::thread_rng().gen_range(0..100) < u32::from(SAMPLE_AND_KEEP_PERCENT)
}

fn route_key(req: &Request) -> String {
    use axum::extract::MatchedPath;
    req.extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string())
}

pub async fn body_size_limit_middleware(
    State(state): State<ServerState>,
    request: Request,
    next: Next,
) -> Response {
    let max = state
        .max_body_bytes
        .load(std::sync::atomic::Ordering::Relaxed);
    if max > 0 {
        if let Some(cl) = request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok())
        {
            if cl > max {
                return body_size_too_large_response(cl, max);
            }
        }
    }
    next.run(request).await
}

pub async fn header_count_limit_middleware(
    State(state): State<ServerState>,
    request: Request,
    next: Next,
) -> Response {
    let max = state
        .max_header_count
        .load(std::sync::atomic::Ordering::Relaxed);
    if max > 0 {
        let count = request.headers().len() as u32;
        if count > max {
            return header_count_too_large_response(count, max);
        }
    }
    next.run(request).await
}

pub async fn rate_limit_middleware(
    State(state): State<ServerState>,
    request: Request,
    next: Next,
) -> Response {
    let route = route_key(&request);
    let user = request.extensions().get::<AuthenticatedUser>().cloned();
    let source_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_string())
        .unwrap_or_default();
    let actor = user
        .as_ref()
        .map(|u| u.name.clone())
        .unwrap_or_else(|| "anon".to_string());
    let key = format!("{actor}:{source_ip}:{route}");
    let (allowed, retry_after) = state.rate_limiter.check(&key);
    if !allowed {
        let method = request.method().to_string();
        let path = request.uri().path().to_string();
        let content_length = request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        let kept = sample_kept();
        let details = json!({
            "route": route,
            "method": method,
            "path": path,
            "source_ip": source_ip,
            "sample_and_keep": kept,
            "content_length": content_length,
        });
        let details_str = details.to_string();
        let action = format!("REJECTED {} {}", method, path);
        let audit = state.audit.clone();
        let route_str = route.clone();
        let actor_str = actor.clone();
        tokio::spawn(async move {
            let _ = audit
                .record_sync(
                    &actor_str,
                    &action,
                    Some(&route_str),
                    agent_dep_core::infrastructure::repository::audit_log_repository::AuditOutcome::Error,
                    Some(&details_str),
                )
                .await;
        });
        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "code": "rate_limited",
                "kind": "too_many_requests",
                "hint": format!(
                    "rate limit exceeded for this principal/route; \
                     retry after {retry_after}s"
                ),
            })),
        )
            .into_response();
        if let Ok(v) = HeaderValue::from_str(&format!("{retry_after}")) {
            response.headers_mut().insert(header::RETRY_AFTER, v);
        }
        return response;
    }
    next.run(request).await
}

fn body_size_too_large_response(content_length: u32, max: u32) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(json!({
            "code": "body_too_large",
            "kind": "payload_too_large",
            "hint": format!(
                "request body is {content_length} bytes; \
                 max allowed is {max} bytes"
            ),
        })),
    )
        .into_response()
}

fn header_count_too_large_response(count: u32, max: u32) -> Response {
    (
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        Json(json!({
            "code": "too_many_headers",
            "kind": "request_header_fields_too_large",
            "hint": format!(
                "request has {count} headers; \
                 max allowed is {max}"
            ),
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bucket_starts_full_and_allows_up_to_capacity() {
        let mut b = Bucket::new(5.0, 1.0);
        for _ in 0..5 {
            assert!(b.try_consume(), "first 5 consumes must succeed");
        }
        assert!(!b.try_consume(), "6th consume must fail");
    }

    #[test]
    fn bucket_refills_over_time() {
        let mut b = Bucket::new(1.0, 1000.0);
        assert!(b.try_consume());
        assert!(!b.try_consume());
        std::thread::sleep(Duration::from_millis(50));
        assert!(b.try_consume(), "bucket should have refilled");
    }

    #[test]
    fn rate_limiter_keys_are_isolated() {
        let rl = RateLimiter::with_capacity_and_rate(1.0, 0.001);
        assert!(rl.check("a:/v1/systems").0);
        assert!(!rl.check("a:/v1/systems").0, "a is exhausted");
        assert!(rl.check("a:/v1/users").0);
        assert!(rl.check("b:/v1/systems").0);
    }

    #[test]
    fn rate_limiter_default_has_generous_capacity() {
        let rl = RateLimiter::new();
        for _ in 0..10 {
            let (allowed, _) = rl.check("u:/v1/audit");
            assert!(allowed, "default rate limiter must allow 10 back-to-back");
        }
    }

    #[test]
    fn retry_after_is_at_least_one_second() {
        let mut b = Bucket::new(1.0, 0.5);
        b.try_consume();
        assert!(b.retry_after() >= 1);
    }

    #[test]
    fn sample_kept_is_roughly_one_percent() {
        let kept: u32 = (0..10_000)
            .map(|_| u32::from(sample_kept()))
            .sum();
        assert!(kept > 70 && kept < 130, "ratio: {kept}/10000");
    }
}
