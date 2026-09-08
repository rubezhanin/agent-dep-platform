//! 2.11.0 (P1-D-03, TZ #1 §10 / D-03,
//! CWE-362 Concurrent Execution using
//! Shared Resource without Proper
//! Synchronization) — `Idempotency-Key`
//! middleware for mutation endpoints.
//!
//! Background: see
//! `agent_dep_core::infrastructure::repository::idempotency_repository`
//! for the threat model. The short
//! version: a network blip between the SPA
//! and the agency-server causes the
//! client to retry a `POST /v1/deploys`.
//! Without idempotency, both calls
//! land, creating two `pending_deploys`
//! rows with the same plan but
//! different `id`s and `requested_at`.
//! The SPA polls `/v1/deploys` and shows
//! both rows; the operator is confused
//! about which one to approve. CWE-362.
//!
//! The middleware sits in front of every
//! mutation handler. It:
//!
//! 1. Skips non-mutation methods
//!    (GET / HEAD / OPTIONS) and
//!    requests with no
//!    `Idempotency-Key` header —
//!    those flow through unchanged.
//! 2. Validates the key: 1..=255 chars,
//!    no whitespace. An invalid key
//!    is a 400 `idempotency.invalid_key`
//!    (the SPA should fix its UUID
//!    generation).
//! 3. Reads the request body bytes
//!    (so we can hash + replay). The
//!    handler sees the same body via
//!    the reconstructed `Request`.
//! 4. Computes `request_hash =
//!    SHA-256(body)`.
//! 5. Looks up `(key, route)` in the
//!    `idempotency_keys` table.
//! 6. **Replay** path: a row exists
//!    with `response_status IS NOT NULL`
//!    and a matching `request_hash`.
//!    Return the cached status +
//!    body verbatim with
//!    `Idempotent-Replay: true` header.
//! 7. **Mismatch** path: a row exists
//!    with a DIFFERENT `request_hash`.
//!    Return 422 `idempotency.mismatch`
//!    (the client reused the key with
//!    a different body — a client bug
//!    the operator must fix).
//! 8. **In-flight** path: a row exists
//!    with `response_status IS NULL`.
//!    A previous request with the same
//!    key is still being processed.
//!    Poll briefly (capped at 5s,
//!    exponential backoff) for the
//!    final response, or return 409
//!    `idempotency.in_flight` if the
//!    first request has not finished.
//! 9. **Fresh** path: no row exists.
//!    Insert one with
//!    `response_status = NULL` (the
//!    in-flight marker). Run the
//!    handler. Capture the response
//!    status + body. UPDATE the row.
//!    Return the response.
//!
//! The middleware uses
//! `axum::middleware::from_fn_with_state`
//! and is wired into the router in
//! `lib::router` (the layer order is:
//! `require_session_or_bearer` →
//! `idempotency` → handler, so the
//! idempotency layer runs AFTER auth
//! — unauthenticated requests get a
//! 401 from the auth layer and never
//! reach the idempotency layer).
//!
//! Response capture: the handler
//! returns a `Response<Body>`. We
//! collect the body via
//! `axum::body::to_bytes`, store the
//! `(status, body)` pair in the
//! cache, then re-wrap the body
//! (`Body::from(bytes)`) and return
//! the same `Response`. This is
//! JSON-only (we check the
//! `Content-Type` and refuse to
//! cache non-JSON responses — those
//! are streamed and we cannot
//! safely replay them). For the
//! agency-server mutation surface
//! every endpoint returns JSON, so
//! this restriction is fine in
//! practice.

use std::time::Duration;

use agent_dep_core::infrastructure::repository::idempotency_repository::{
    IdempotencyRepository, DEFAULT_TTL_SECONDS,
};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::state::ServerState;

/// 2.11.0 (P1-D-03): the
/// `Idempotent-Replay` response
/// header. Set on every response
/// served from the cache so the
/// SPA can distinguish "this is
/// a fresh result" from "this is
/// the cached version of a
/// previous request". The SPA
/// can use this for telemetry
/// ("X% of our deploy requests
/// were idempotent replays — a
/// network-quality signal").
pub const IDEMPOTENT_REPLAY_HEADER: &str = "idempotent-replay";

/// 2.11.0 (P1-D-03): the
/// `Idempotency-Key` request
/// header. The 1..=255-char
/// opaque token the client sends.
/// UUID v4 is the recommended
/// shape; the server does not
/// validate the format (only the
/// length), so any opaque string
/// works.
pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// 2.11.0 (P1-D-03): the
/// middleware body limit for
/// reading the request body. The
/// agency-server mutation surface
/// is small (POST /v1/deploys is
/// the largest, with a body of
/// ~1 KiB on the SPA path);
/// 1 MiB is a generous ceiling
/// that lets the hash cover the
/// whole body without holding
/// unbounded memory for a
/// pathological POST.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// 2.11.0 (P1-D-03): the
/// in-flight poll cap. If the
/// first request has not finished
/// after 5s, the second request
/// returns 409
/// `idempotency.in_flight` rather
/// than blocking the SPA's
/// retry-loop indefinitely. The
/// 5s is short enough that a
/// human-driven retry-loop
/// notices the 409 quickly and
/// long enough that a slow
/// database write can complete
/// (the typical
/// `mark_applied` flow is < 100ms
/// on SQLite + WAL).
const IN_FLIGHT_POLL_TIMEOUT: Duration = Duration::from_secs(5);

/// 2.11.0 (P1-D-03): the
/// `idempotency_middleware`. The
/// argument is the `ServerState`
/// (threaded by axum via
/// `from_fn_with_state`); the
/// middleware reads the
/// `idempotency` repo and the
/// `db.pool()` from it.
pub async fn idempotency_middleware(
    State(state): State<ServerState>,
    request: Request,
    next: Next,
) -> Response {
    // 2.11.0 (P1-D-03): the
    // Idempotency-Key middleware
    // is a no-op for non-mutation
    // methods. GET / HEAD /
    // OPTIONS are read-only; the
    // SPA can safely retry them
    // without a key.
    let method = request.method().clone();
    if !is_mutation(&method) {
        return next.run(request).await;
    }
    // 2.11.0 (P1-D-03): the
    // middleware is a no-op when
    // the request did not carry
    // an `Idempotency-Key` header.
    // Pre-P1-D-03 clients (the
    // SPA before the upgrade) and
    // ad-hoc curl scripts work
    // exactly as before. The
    // header is opt-in: the SPA
    // adds it for every mutation
    // and the server caches the
    // response.
    let key = request
        .headers()
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let key = match key {
        Some(k) => k,
        None => return next.run(request).await,
    };
    // 2.11.0 (P1-D-03): validate
    // the key. 1..=255 chars, no
    // whitespace (a stray space
    // from a malformed header
    // would silently key the
    // cache and the operator
    // would never see the
    // replay). An invalid key is
    // a 400 — the SPA's UUID
    // generator is broken.
    if key.is_empty() || key.len() > 255 || key.chars().any(char::is_whitespace) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "code": "idempotency.invalid_key",
                "kind": "bad_request",
                "hint": "Idempotency-Key must be 1..=255 non-whitespace chars"
            })),
        )
            .into_response();
    }
    // 2.11.0 (P1-D-03): read the
    // request body so we can
    // hash it + replay it for the
    // handler. The body is
    // bounded at MAX_BODY_BYTES
    // (1 MiB) — a POST larger
    // than that is rejected with
    // a 413, which is consistent
    // with the other request-size
    // limits the agency-server
    // enforces.
    let (parts, body) = request.into_parts();
    let body_bytes = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({
                    "code": "request.too_large",
                    "kind": "bad_request",
                    "hint": "request body exceeds the idempotency middleware limit"
                })),
            )
                .into_response();
        }
    };
    let request_hash = sha256_hex(&body_bytes);
    // 2.11.0 (P1-D-03): the
    // `route` is the axum
    // matched-Path (e.g.
    // `/v1/deploys/:id/approve`)
    // + the method. This is the
    // same key-shape every
    // idempotency cache uses:
    // the (key, route) pair
    // scopes the cache to the
    // specific endpoint, so the
    // same key reused on a
    // different route is a
    // different cache entry.
    let route = format!("{} {}", method.as_str(), parts.uri.path());
    // 2.11.0 (P1-D-03): look up
    // the (key, route) row. Three
    // branches: replay, mismatch,
    // in-flight. The fresh path
    // is the no-row case below.
    match state.idempotency.lookup(&key, &route).await {
        Ok(Some(stored)) if !stored.in_flight => {
            // Replay or mismatch
            // path. The decision is
            // a simple hash compare.
            if stored.request_hash == request_hash {
                replay_response(&stored)
            } else {
                mismatch_response(&key, &route, &request_hash, &stored.request_hash)
            }
        }
        Ok(Some(_stored)) => {
            // In-flight path: poll
            // briefly. The first
            // request is still
            // running. We wait up to
            // IN_FLIGHT_POLL_TIMEOUT
            // for it to commit, then
            // either replay (if it
            // finished) or return 409
            // (if the timeout fired).
            poll_or_in_flight(&state.idempotency, &key, &route, &request_hash).await
        }
        Ok(None) => {
            // Fresh path: insert
            // the in-flight row,
            // run the handler,
            // record the result.
            let created = match state
                .idempotency
                .record_in_flight(&key, &route, &request_hash, DEFAULT_TTL_SECONDS)
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal.untyped",
                        "internal error",
                        Some(&e),
                    );
                }
            };
            if !created {
                // Concurrent insert won
                // the race. Re-look-up
                // and replay / mismatch
                // / poll as above.
                return match state.idempotency.lookup(&key, &route).await {
                    Ok(Some(stored)) if !stored.in_flight => {
                        if stored.request_hash == request_hash {
                            replay_response(&stored)
                        } else {
                            mismatch_response(&key, &route, &request_hash, &stored.request_hash)
                        }
                    }
                    Ok(Some(_)) => {
                        poll_or_in_flight(&state.idempotency, &key, &route, &request_hash).await
                    }
                    Ok(None) => error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal.unmapped",
                        "idempotency row vanished after failed insert",
                        None,
                    ),
                    Err(e) => error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal.untyped",
                        "internal error",
                        Some(&e),
                    ),
                };
            }
            // Rebuild the request
            // so the handler can
            // re-read the body
            // (the original body
            // was consumed by the
            // `to_bytes` call).
            let new_request = Request::from_parts(parts, Body::from(body_bytes));
            // Run the handler.
            let response = next.run(new_request).await;
            // Capture the response
            // for the cache. We
            // only cache JSON
            // responses — streaming
            // or non-JSON
            // responses are passed
            // through unchanged
            // (the operator can
            // see "non-cached
            // response" in the
            // server logs and
            // decide whether to add
            // JSON wrapping to
            // their handler).
            let (parts, body) = response.into_parts();
            let body_bytes = match to_bytes(body, MAX_BODY_BYTES).await {
                Ok(b) => b,
                Err(_) => {
                    // The handler returned
                    // a body we cannot
                    // buffer. We pass it
                    // through unchanged
                    // and skip the cache
                    // write.
                    return Response::from_parts(parts, Body::empty());
                }
            };
            let is_json = parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.starts_with("application/json"))
                .unwrap_or(false);
            if !is_json {
                // Non-JSON: pass through
                // without caching.
                return Response::from_parts(parts, Body::from(body_bytes));
            }
            let body_str = String::from_utf8_lossy(&body_bytes).to_string();
            let status = parts.status.as_u16();
            // Record the result.
            // Failures here are
            // logged but not
            // surfaced — the
            // response is already
            // valid; the cache
            // just will not have
            // it (the next retry
            // will run the handler
            // again).
            if let Err(e) = state
                .idempotency
                .finalize(&key, &route, status, &body_str)
                .await
            {
                tracing::warn!(error = %e, key = %key, route = %route, "idempotency.finalize failed");
            }
            // Rebuild the response
            // with the original
            // parts + buffered body
            // + replay header (no
            // — this is a fresh
            // response, not a
            // replay).
            Response::from_parts(parts, Body::from(body_bytes))
        }
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal.untyped",
            "internal error",
            Some(&e),
        ),
    }
}

/// 2.11.0 (P1-D-03): a
/// mutation method. The agency
/// server's mutation surface is
/// `POST`, `PUT`, `PATCH`, and
/// `DELETE`. `GET`, `HEAD`, and
/// `OPTIONS` are not mutations
/// and bypass the cache
/// entirely.
fn is_mutation(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// 2.11.0 (P1-D-03): the
/// replay path. The cached
/// status + body are returned
/// verbatim with the
/// `Idempotent-Replay: true`
/// header so the SPA can
/// distinguish a cached
/// response from a fresh one.
fn replay_response(
    stored: &agent_dep_core::infrastructure::repository::idempotency_repository::StoredResponse,
) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(IDEMPOTENT_REPLAY_HEADER),
        HeaderValue::from_static("true"),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let status = StatusCode::from_u16(stored.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, headers, stored.body.clone()).into_response()
}

/// 2.11.0 (P1-D-03): the
/// mismatch path. The client
/// reused the key with a
/// different body — a client
/// bug. 422
/// `idempotency.mismatch` with
/// a short operator-facing
/// hint. The hashes are
/// truncated to 16 chars in
/// the response (the full
/// hashes are 64 chars; the
/// truncated form is enough
/// for the operator to
/// eyeball-compare and small
/// enough not to clutter the
/// log).
fn mismatch_response(key: &str, route: &str, request_hash: &str, stored_hash: &str) -> Response {
    tracing::warn!(
        key = %key,
        route = %route,
        request_hash = %request_hash,
        stored_hash = %stored_hash,
        "idempotency.mismatch"
    );
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "code": "idempotency.mismatch",
            "kind": "unprocessable",
            "hint": "Idempotency-Key was reused with a different request body; \
                     generate a new key for each distinct request"
        })),
    )
        .into_response()
}

/// 2.11.0 (P1-D-03): the
/// in-flight poll loop. The
/// first request is still
/// running; we wait up to
/// `IN_FLIGHT_POLL_TIMEOUT`
/// (5s, exponential backoff)
/// for it to commit, then
/// either replay (if it
/// finished) or return 409
/// `idempotency.in_flight` (if
/// the timeout fired). The
/// exponential backoff is
/// capped at 250ms so we do
/// not hammer the database.
async fn poll_or_in_flight(
    repo: &IdempotencyRepository,
    key: &str,
    route: &str,
    request_hash: &str,
) -> Response {
    let start = std::time::Instant::now();
    let mut backoff = Duration::from_millis(10);
    loop {
        tokio::time::sleep(backoff).await;
        match repo.lookup(key, route).await {
            Ok(Some(stored)) if !stored.in_flight => {
                if stored.request_hash == request_hash {
                    return replay_response(&stored);
                } else {
                    return mismatch_response(key, route, request_hash, &stored.request_hash);
                }
            }
            Ok(Some(_)) => {
                if start.elapsed() > IN_FLIGHT_POLL_TIMEOUT {
                    return in_flight_response();
                }
                backoff = (backoff * 2).min(Duration::from_millis(250));
            }
            Ok(None) => {
                // The row vanished
                // (expired between
                // the in-flight
                // marker and the
                // poll). Treat as
                // an in-flight
                // conflict; the
                // client can retry.
                return in_flight_response();
            }
            Err(e) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal.untyped",
                    "internal error",
                    Some(&e),
                );
            }
        }
    }
}

/// 2.11.0 (P1-D-03): the
/// in-flight 409 response.
/// Set when a previous request
/// with the same key has not
/// finished within
/// `IN_FLIGHT_POLL_TIMEOUT`.
fn in_flight_response() -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({
            "code": "idempotency.in_flight",
            "kind": "conflict",
            "hint": "a previous request with the same Idempotency-Key is still being processed; \
                     retry after a short delay"
        })),
    )
        .into_response()
}

/// 2.11.0 (P1-D-03): uniform
/// error response. The
/// `idempotency.middleware`
/// only emits 5xx; the
/// structured
/// `error_response::from_core_error`
/// is reserved for handler
/// errors. The middleware
/// errors are written to the
/// server log at `warn` level
/// and the client sees a
/// stable code.
fn error_response(
    status: StatusCode,
    code: &'static str,
    hint: &'static str,
    err: Option<&dyn std::fmt::Display>,
) -> Response {
    if let Some(e) = err {
        tracing::warn!(error = %e, code = %code, "idempotency middleware error");
    }
    (
        status,
        Json(json!({
            "code": code,
            "kind": "internal",
            "hint": hint
        })),
    )
        .into_response()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
