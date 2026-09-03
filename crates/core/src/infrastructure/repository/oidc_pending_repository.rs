//! 2.7.10 (ADR-0038) DB-backed OIDC
//! pending state. The 2.7.6 in-memory
//! `Arc<Mutex<HashMap<String,
//! PendingAuth>>>` is replaced by a
//! SQLite table (`oidc_pending_state`)
//! so multi-instance `agency-server`
//! deployments can hand the callback
//! request off to a different replica
//! than the one that handled
//! `/v1/auth/oidc/login`.
//!
//! API:
//! - `insert(state, pkce, nonce, ttl_secs)`
//!   — store a new pending auth.
//! - `take(state) -> Option<PendingAuth>`
//!   — atomically `SELECT` + `DELETE`
//!   the row.
//! - `gc_expired(max_age_secs) -> usize`
//!   — best-effort cleanup.

use sqlx::SqlitePool;

use crate::error::CoreResult;

#[derive(Debug, Clone)]
pub struct PendingAuth {
    pub pkce_verifier: String,
    pub nonce: String,
    /// Unix-epoch seconds when the
    /// entry was created. Replaces
    /// the 2.7.6 `std::time::Instant`
    /// so the expiry is preserved
    /// across server restarts.
    pub created_at_secs: i64,
}

#[derive(Clone)]
pub struct OidcPendingRepository {
    pool: SqlitePool,
}

impl OidcPendingRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(
        &self,
        state: &str,
        pkce_verifier: &str,
        nonce: &str,
        created_at_secs: i64,
    ) -> CoreResult<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO oidc_pending_state \
             (state, pkce_verifier, nonce, created_at) \
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(state)
        .bind(pkce_verifier)
        .bind(nonce)
        .bind(created_at_secs)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Atomically `SELECT` + `DELETE` the
    /// row. Returns `None` if the row
    /// does not exist OR is expired
    /// (older than `max_age_secs`).
    pub async fn take(
        &self,
        state: &str,
        max_age_secs: i64,
    ) -> CoreResult<Option<PendingAuth>> {
        let now = chrono::Utc::now().timestamp();
        let min_created = now - max_age_secs;
        // Use a single transaction so
        // the SELECT + DELETE is
        // atomic. SQLite's default
        // DEFERRED isolation is
        // sufficient for the
        // single-DB case (a concurrent
        // `take` blocks until our
        // transaction commits, then
        // sees no row).
        let mut tx = self.pool.begin().await?;
        let row: Option<(String, String, i64)> = sqlx::query_as(
            "SELECT pkce_verifier, nonce, created_at \
             FROM oidc_pending_state \
             WHERE state = ?1 AND created_at >= ?2",
        )
        .bind(state)
        .bind(min_created)
        .fetch_optional(&mut *tx)
        .await?;
        if row.is_none() {
            tx.commit().await?;
            return Ok(None);
        }
        sqlx::query("DELETE FROM oidc_pending_state WHERE state = ?1")
            .bind(state)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        let (pkce_verifier, nonce, created_at_secs) = row.expect("checked Some");
        Ok(Some(PendingAuth {
            pkce_verifier,
            nonce,
            created_at_secs,
        }))
    }

    /// Best-effort cleanup of rows
    /// older than `max_age_secs`.
    /// Returns the number of rows
    /// deleted.
    pub async fn gc_expired(&self, max_age_secs: i64) -> CoreResult<usize> {
        let now = chrono::Utc::now().timestamp();
        let min_created = now - max_age_secs;
        let affected = sqlx::query(
            "DELETE FROM oidc_pending_state \
             WHERE created_at < ?1",
        )
        .bind(min_created)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(affected as usize)
    }
}

#[cfg(test)]
#[path = "oidc_pending_repository_tests.rs"]
mod tests;
