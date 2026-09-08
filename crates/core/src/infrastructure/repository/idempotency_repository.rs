//! 2.11.0 (P1-D-03, TZ #1 §10 / D-03,
//! CWE-362) — Idempotency-Key cache.
//!
//! Every mutation endpoint (POST,
//! PUT, PATCH, DELETE) is wrapped
//! by an `axum` middleware that
//! reads the `Idempotency-Key`
//! header, hashes the request body
//! with SHA-256, and either:
//!
//! 1. **replay** — if a row exists
//!    with the same `(key, route)`
//!    AND a matching `request_hash`
//!    AND `response_status IS NOT
//!    NULL`, the cached
//!    `response_status` and
//!    `response_body` are returned
//!    verbatim with an
//!    `Idempotent-Replay: true`
//!    header. The handler is not
//!    run. This is the common case
//!    (network retry).
//!
//! 2. **mismatch** — if a row
//!    exists with the same
//!    `(key, route)` but a
//!    DIFFERENT `request_hash`, the
//!    server returns 422
//!    `idempotency.mismatch`
//!    (cached) instead of running
//!    the handler. This catches
//!    the "client reused the key
//!    with a different body"
//!    client bug — without this
//!    check, the second call
//!    would silently run a
//!    different handler.
//!
//! 3. **in-flight** — if a row
//!    exists with the same
//!    `(key, route)` AND
//!    `response_status IS NULL`,
//!    a previous request with the
//!    same key is still being
//!    processed. The middleware
//!    polls the row briefly
//!    (capped at 5s, exponential
//!    backoff) and either returns
//!    the cached response (the
//!    replay path above) or
//!    `409 idempotency.in_flight`
//!    if the first request has
//!    not finished.
//!
//! 4. **fresh** — if no row
//!    exists, the middleware
//!    inserts one with
//!    `response_status = NULL`,
//!    runs the handler, and
//!    UPDATE-s the row with the
//!    final response.
//!
//! The PRIMARY KEY `(key, route)`
//! means the same key can be
//! reused on a different route
//! without collision (the SPA
//! uses one key per user-action
//! rather than one key per
//! server endpoint).
//!
//! The pre-P1-D-03 design had no
//! Idempotency-Key support. A
//! network blip between the SPA
//! and the agency-server caused
//! the client to retry a
//! `POST /v1/deploys`; both
//! calls landed, creating two
//! `pending_deploys` rows with
//! the same plan but different
//! `id`s and `requested_at`. CWE-362.

use chrono::{DateTime, Duration, Utc};
use sqlx::SqlitePool;

use crate::error::{CoreError, CoreResult};

/// 2.11.0 (P1-D-03): default
/// retention for an
/// `idempotency_keys` row. The
/// TTL is per-row (an operator
/// can override with a
/// `Cache-Control: max-age=N`
/// header on the original
/// request, but the default is
/// 24h).
pub const DEFAULT_TTL_SECONDS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone)]
pub struct StoredResponse {
    /// 2.11.0 (P1-D-03): the HTTP
    /// status the original
    /// handler returned. The
    /// middleware echoes this
    /// verbatim on replay.
    pub status: u16,
    /// 2.11.0 (P1-D-03): the
    /// response body bytes the
    /// original handler returned.
    /// The middleware writes
    /// these into the new
    /// response. JSON-only (the
    /// middleware checks the
    /// `Content-Type` and refuses
    /// to cache non-JSON
    /// responses).
    pub body: String,
    /// 2.11.0 (P1-D-03): the
    /// SHA-256 of the original
    /// request body. The
    /// middleware compares it to
    /// the new request's hash; a
    /// mismatch is a 422.
    pub request_hash: String,
    /// 2.11.0 (P1-D-03): the
    /// `response_status` /
    /// `response_body` columns
    /// are NULL while the
    /// original request is in
    /// flight. A second request
    /// that arrives during the
    /// in-flight window sees
    /// `Some(this)` with
    /// `in_flight: true` and
    /// either polls (briefly) or
    /// returns 409.
    pub in_flight: bool,
}

#[derive(Clone)]
pub struct IdempotencyRepository {
    pool: SqlitePool,
}

impl IdempotencyRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// 2.11.0 (P1-D-03): the
    /// unique key for a cached
    /// response. `(key, route)`
    /// — the same key can be
    /// reused on a different
    /// route without collision.
    /// `route` is the
    /// `METHOD /path/:id` string
    /// (e.g. `"POST /v1/deploys"`),
    /// not the
    /// `Method`-matched-axum-Path.
    pub async fn lookup(&self, key: &str, route: &str) -> CoreResult<Option<StoredResponse>> {
        let row: Option<(String, Option<i64>, Option<String>)> = sqlx::query_as(
            "SELECT request_hash, response_status, response_body \
             FROM idempotency_keys \
             WHERE key = ?1 AND route = ?2",
        )
        .bind(key)
        .bind(route)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(request_hash, status, body)| StoredResponse {
            // `response_status IS NULL`
            // means the original
            // request is still in
            // flight. The middleware
            // treats this as a
            // transient conflict.
            in_flight: status.is_none(),
            request_hash,
            status: status.map(|n| n as u16).unwrap_or(0),
            body: body.unwrap_or_default(),
        }))
    }

    /// 2.11.0 (P1-D-03): reserve
    /// a `(key, route)` slot for a
    /// new request. The row is
    /// inserted with
    /// `response_status = NULL`
    /// (in-flight marker). A
    /// second call that races
    /// this one (e.g. a TCP
    /// retry) gets a UNIQUE
    /// constraint violation,
    /// which the middleware
    /// maps to a "look up the
    /// existing row" path.
    ///
    /// Returns `Ok(true)` if the
    /// row was created (this
    /// caller is the first), or
    /// `Ok(false)` if the row
    /// already existed (this
    /// caller lost the race —
    /// re-look-up and replay).
    pub async fn record_in_flight(
        &self,
        key: &str,
        route: &str,
        request_hash: &str,
        ttl_seconds: i64,
    ) -> CoreResult<bool> {
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let exp_str = (now + Duration::seconds(ttl_seconds))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let res = sqlx::query(
            "INSERT INTO idempotency_keys \
             (key, route, request_hash, response_status, response_body, \
              created_at, expires_at) \
             VALUES (?1, ?2, ?3, NULL, NULL, ?4, ?5)",
        )
        .bind(key)
        .bind(route)
        .bind(request_hash)
        .bind(&now_str)
        .bind(&exp_str)
        .execute(&self.pool)
        .await;
        match res {
            Ok(_) => Ok(true),
            Err(sqlx::Error::Database(db))
                if db.message().contains("UNIQUE") || db.message().contains("PRIMARY KEY") =>
            {
                Ok(false)
            }
            Err(e) => Err(CoreError::ErrSqlx(e)),
        }
    }

    /// 2.11.0 (P1-D-03): commit
    /// the handler's response
    /// into the in-flight row.
    /// Called after the handler
    /// returns (success or
    /// error). The `status` and
    /// `body` are stored
    /// verbatim; a subsequent
    /// replay returns the
    /// identical
    /// `(status, body)` pair.
    pub async fn finalize(
        &self,
        key: &str,
        route: &str,
        response_status: u16,
        response_body: &str,
    ) -> CoreResult<()> {
        sqlx::query(
            "UPDATE idempotency_keys \
             SET response_status = ?1, response_body = ?2 \
             WHERE key = ?3 AND route = ?4",
        )
        .bind(response_status as i64)
        .bind(response_body)
        .bind(key)
        .bind(route)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 2.11.0 (P1-D-03): reap
    /// expired rows. Called by
    /// the GC task on the same
    /// 60s timer as the
    /// `sessions` and
    /// `oidc_pending_state` GCs.
    /// Returns the number of
    /// rows removed (mostly for
    /// the audit log; the
    /// operator can see
    /// "gc_idempotency removed N
    /// expired keys" every
    /// hour).
    pub async fn gc_expired(&self) -> CoreResult<u64> {
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let affected = sqlx::query("DELETE FROM idempotency_keys WHERE expires_at < ?1")
            .bind(&now_str)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(affected)
    }
}

#[cfg(test)]
#[path = "idempotency_repository_tests.rs"]
mod tests;
