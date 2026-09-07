//! 2.11.0 server-side session store
//! (P1-F-03a, TZ #2 WP-3.3, CWE-613).
//!
//! Replaces the 2.10.0 design where the
//! local bearer (in JSON) was held by the
//! SPA in JavaScript memory / local storage
//! and not revocable server-side. The
//! `SessionRepository` is the data layer
//! for the cookie-based session model
//! that lands in P1-F-03b; this commit
//! is the schema + repository only —
//! no API change yet.
//!
//! Threat model (CWE-613 Insufficient
//! Session Expiration):
//! - **Idle timeout.** Every successful
//!   `find` advances `idle_expires_at`
//!   (sliding window). A captured cookie
//!   that the attacker forgets about
//!   expires on its own.
//! - **Absolute timeout.** Created
//!   `now + ABSOLUTE_TTL_SECS`; never
//!   advanced. Caps the total lifetime
//!   of a single session regardless of
//!   activity, so even a keep-alive
//!   script can't extend it.
//! - **Server-side revoke.** `revoke` and
//!   `revoke_all_for_user` set
//!   `revoked_at`; the next `find`
//!   returns `None` immediately. The
//!   P1-F-03b `logout_handler` calls
//!   `revoke` on the current session.
//!
//! TTLs are baked into the repository
//! constants so all call sites use the
//! same policy. Operators can override
//! via env vars at a higher layer (a
//! future 2.x follow-up; the 2.11.0
//! default is conservative enough for
//! server-to-server deployments).
//!
//! Tests live in
//! `sessions_repository_tests.rs` and
//! cover round-trip, idle / absolute
//! expiry, sliding touch, revoke, and
//! `revoke_all_for_user`.

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::{CoreError, CoreResult};

/// Sliding window. Every successful `find`
/// advances `idle_expires_at` to
/// `now + IDLE_TTL_SECS`. 1 hour matches
/// the 2.10.0 `token_expires_at` policy
/// (the cookie auth is a strict superset
/// of the bearer auth's lifetime).
pub const IDLE_TTL_SECS: i64 = 3600;

/// Absolute lifetime cap. Created
/// `now + ABSOLUTE_TTL_SECS`; never
/// advanced. 8 hours is the upper bound
/// for a single working day — beyond
/// that, the user has to re-authenticate
/// at the IdP, which exercises the full
/// OIDC flow (and any group-membership
/// changes since the original login).
pub const ABSOLUTE_TTL_SECS: i64 = 8 * 3600;

/// Length of the session id in bytes.
/// 32 bytes = 256 bits, encoded as
/// base64url (43 chars). The session id
/// is the cookie value; 256 bits makes
/// it infeasible to guess or brute-force.
pub const SESSION_ID_LEN: usize = 32;

/// Raw row shape read in `find`. The
/// 10-tuple is wrapped in a type alias
/// to keep `clippy::type_complexity`
/// happy (it flags 10-element inline
/// tuples as "very complex"). `_last_used_at`
/// and `_idle_expires_at` are read by
/// the SQL predicate but are
/// immediately overwritten by the
/// sliding touch in the returned
/// `SessionRow`; the underscores mark
/// that we are deliberately dropping
/// the values.
type SessionRowTuple = (
    String,
    i64,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Length of the CSRF token in bytes.
/// 32 bytes, also encoded base64url.
/// Used in the `X-CSRF-Token` header
/// for state-changing requests; the
/// server compares it to the value
/// stored in the row.
pub const CSRF_TOKEN_LEN: usize = 32;

/// One session row. Returned to callers
/// that own the session (the OIDC
/// handler creating it, the middleware
/// reading it). Never returned across
/// the public HTTP API — the JSON
/// response carries `expires_at` only,
/// not the underlying row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRow {
    pub id: String,
    pub user_id: i64,
    pub csrf_token: String,
    pub created_at: String,
    pub last_used_at: String,
    pub idle_expires_at: String,
    pub absolute_expires_at: String,
    pub revoked_at: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Clone)]
pub struct SessionRepository {
    pool: SqlitePool,
}

impl std::fmt::Debug for SessionRepository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The session rows are
        // bearer-equivalent material;
        // we do not format them. The
        // pool is fine.
        f.debug_struct("SessionRepository")
            .field("pool", &self.pool)
            .finish()
    }
}

impl SessionRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create a new session. The id and
    /// CSRF token are random base64url
    /// strings; `idle_expires_at` and
    /// `absolute_expires_at` are computed
    /// from the constants. The id is
    /// returned to the caller (it is the
    /// cookie value); the CSRF token is
    /// stored in the row and is also
    /// returned so the caller can hand
    /// it to the SPA via a
    /// `X-CSRF-Token` header on the
    /// first response.
    pub async fn create(
        &self,
        user_id: i64,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> CoreResult<(String, SessionRow)> {
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let idle_expires = now + Duration::seconds(IDLE_TTL_SECS);
        let absolute_expires = now + Duration::seconds(ABSOLUTE_TTL_SECS);
        let id = random_token(SESSION_ID_LEN);
        let csrf = random_token(CSRF_TOKEN_LEN);
        sqlx::query(
            "INSERT INTO sessions \
             (id, user_id, csrf_token, created_at, last_used_at, \
              idle_expires_at, absolute_expires_at, revoked_at, ip, user_agent) \
             VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6, NULL, ?7, ?8)",
        )
        .bind(&id)
        .bind(user_id)
        .bind(&csrf)
        .bind(&now_str)
        .bind(idle_expires.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .bind(absolute_expires.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .bind(ip)
        .bind(user_agent)
        .execute(&self.pool)
        .await?;
        let row = SessionRow {
            id: id.clone(),
            user_id,
            csrf_token: csrf,
            created_at: now_str.clone(),
            last_used_at: now_str,
            idle_expires_at: idle_expires.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            absolute_expires_at: absolute_expires
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            revoked_at: None,
            ip: ip.map(String::from),
            user_agent: user_agent.map(String::from),
        };
        Ok((id, row))
    }

    /// Find a session by id and verify
    /// it is still valid. Returns
    /// `None` for: unknown id, revoked,
    /// past `idle_expires_at`, or past
    /// `absolute_expires_at`. On a
    /// successful hit the row is
    /// `touch`ed (sliding update of
    /// `last_used_at` and
    /// `idle_expires_at`); the returned
    /// row reflects the new timestamps.
    pub async fn find(&self, id: &str) -> CoreResult<Option<SessionRow>> {
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let new_idle = now + Duration::seconds(IDLE_TTL_SECS);
        let new_idle_str = new_idle.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        // Atomic read-then-touch: SELECT
        // first to know whether the row is
        // valid; UPDATE only on a valid
        // hit. A row that was just revoked
        // is filtered out by the WHERE
        // clause (revoked_at IS NULL AND
        // idle_expires_at > now AND
        // absolute_expires_at > now).
        // The UPDATE is best-effort; the
        // atomicity we care about is the
        // read-side predicate.
        let row: Option<SessionRowTuple> = sqlx::query_as(
            "SELECT id, user_id, csrf_token, created_at, last_used_at, \
             idle_expires_at, absolute_expires_at, revoked_at, ip, user_agent \
             FROM sessions \
             WHERE id = ?1 \
               AND revoked_at IS NULL \
               AND idle_expires_at > ?2 \
               AND absolute_expires_at > ?2",
        )
        .bind(id)
        .bind(&now_str)
        .fetch_optional(&self.pool)
        .await?;
        let (
            sid,
            user_id,
            csrf,
            created_at,
            _last_used_at,
            _idle_expires_at,
            absolute_expires_at,
            revoked_at,
            ip,
            user_agent,
        ) = match row {
            Some(r) => r,
            None => return Ok(None),
        };
        // Defense-in-depth: belt-and-
        // suspenders check on
        // absolute_expires_at. The SQL
        // predicate already filters, but
        // the row is in memory now and we
        // want a typed error if a future
        // migration accidentally drops
        // the predicate. (This is the same
        // pattern as `SecretRepository`
        // version dispatch.)
        if let Ok(absolute) = chrono::DateTime::parse_from_rfc3339(&absolute_expires_at) {
            if absolute <= now {
                return Err(CoreError::ErrSchemaInvalid {
                    path: "sessions.absolute_expires_at".to_string(),
                    reason: format!("session {sid} past absolute_expires_at despite SQL predicate"),
                });
            }
        }
        // Sliding touch. Best-effort:
        // if the UPDATE fails we still
        // return the row, since the
        // caller authenticated and the
        // next request will retry.
        let _ = sqlx::query(
            "UPDATE sessions \
             SET last_used_at = ?1, idle_expires_at = ?2 \
             WHERE id = ?3",
        )
        .bind(&now_str)
        .bind(&new_idle_str)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(Some(SessionRow {
            id: sid,
            user_id,
            csrf_token: csrf,
            created_at,
            last_used_at: now_str,
            idle_expires_at: new_idle_str,
            absolute_expires_at,
            revoked_at,
            ip,
            user_agent,
        }))
    }

    /// Revoke a single session by id.
    /// Returns `true` if a row was
    /// updated, `false` if the id did
    /// not exist (or was already
    /// revoked). Idempotent: revoking
    /// an already-revoked session is a
    /// no-op.
    pub async fn revoke(&self, id: &str) -> CoreResult<bool> {
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let affected = sqlx::query(
            "UPDATE sessions SET revoked_at = ?1 \
             WHERE id = ?2 AND revoked_at IS NULL",
        )
        .bind(&now_str)
        .bind(id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(affected > 0)
    }

    /// Revoke every active session for a
    /// user. Used by the future
    /// `/v1/auth/sessions` admin
    /// "log out everywhere" button. The
    /// current session is also revoked
    /// (the operator calling the admin
    /// endpoint re-authenticates via the
    /// OIDC flow afterwards). Returns
    /// the number of rows updated.
    pub async fn revoke_all_for_user(&self, user_id: i64) -> CoreResult<usize> {
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let affected = sqlx::query(
            "UPDATE sessions SET revoked_at = ?1 \
             WHERE user_id = ?2 AND revoked_at IS NULL",
        )
        .bind(&now_str)
        .bind(user_id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(affected as usize)
    }

    /// Best-effort cleanup of sessions
    /// that are either revoked, past
    /// their idle expiry, or past
    /// their absolute expiry. Returns
    /// the number of rows deleted.
    /// Designed to be called by the
    /// server's background GC task
    /// every 60 seconds (same cadence
    /// as the existing
    /// `OidcPendingRepository::gc_expired`
    /// task in `lib::boot_default_state`).
    pub async fn gc_expired(&self) -> CoreResult<usize> {
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let affected = sqlx::query(
            "DELETE FROM sessions \
             WHERE revoked_at IS NOT NULL \
                OR idle_expires_at < ?1 \
                OR absolute_expires_at < ?1",
        )
        .bind(&now_str)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(affected as usize)
    }

    /// List every active session for a
    /// user. Used by the future
    /// `/v1/auth/sessions` admin
    /// endpoint. The list does NOT
    /// include `csrf_token` — admin
    /// views should not be able to
    /// forge state-changing requests on
    /// behalf of the user.
    pub async fn list_active_for_user(&self, user_id: i64) -> CoreResult<Vec<SessionSummary>> {
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let rows: Vec<SessionSummaryTuple> = sqlx::query_as(
            "SELECT id, created_at, last_used_at, \
             idle_expires_at, absolute_expires_at, ip, user_agent \
             FROM sessions \
             WHERE user_id = ?1 \
               AND revoked_at IS NULL \
               AND idle_expires_at > ?2 \
               AND absolute_expires_at > ?2 \
             ORDER BY last_used_at DESC",
        )
        .bind(user_id)
        .bind(&now_str)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    created_at,
                    last_used_at,
                    idle_expires_at,
                    absolute_expires_at,
                    ip,
                    user_agent,
                )| SessionSummary {
                    id,
                    created_at,
                    last_used_at,
                    idle_expires_at,
                    absolute_expires_at,
                    ip,
                    user_agent,
                },
            )
            .collect())
    }
}

/// Admin-facing session summary (no
/// `csrf_token`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: String,
    pub created_at: String,
    pub last_used_at: String,
    pub idle_expires_at: String,
    pub absolute_expires_at: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

/// Raw row shape for `list_active_for_user`.
/// 7-tuple; aliased to keep
/// `clippy::type_complexity` happy.
type SessionSummaryTuple = (
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
);

/// Generate a `len`-byte random string,
/// base64url-encoded. Used for both
/// session id and CSRF token.
fn random_token(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
#[path = "sessions_repository_tests.rs"]
mod tests;
