//! Per-user RBAC table (2.1.0, ADR-0019).
//!
//! Each row is one operator. The plain bearer token
//! is never stored — only its sha256 — so a database
//! dump does not leak active credentials. The plain
//! token is returned to the admin exactly once at
//! creation time, and again on `rotate_token`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::error::{CoreError, CoreResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Operator,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> CoreResult<Self> {
        match s {
            "viewer" => Ok(Role::Viewer),
            "operator" => Ok(Role::Operator),
            "admin" => Ok(Role::Admin),
            other => Err(CoreError::ErrSchemaInvalid {
                path: "users.role".to_string(),
                reason: format!("unknown role `{other}`"),
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UserRow {
    pub id: i64,
    pub name: String,
    pub role: Role,
    pub token_hash: String,
    pub created_at: String,
    pub last_seen_at: Option<String>,
    pub disabled_at: Option<String>,
    /// 2.7.6 (ADR-0034): stable OIDC subject
    /// (the `sub` claim). `None` for
    /// bearer-token users (2.0.0-2.7.5).
    pub external_id: Option<String>,
    /// 2.7.8 (ADR-0036): local bearer
    /// expiry (RFC 3339). `None` for
    /// bearer-token users (2.0.0-2.7.7)
    /// and OIDC users that have not yet
    /// been refreshed.
    pub token_expires_at: Option<String>,
}

/// Tuple shape returned by `sqlx::query_as` for
/// `SELECT id, name, role, token_hash, created_at,
/// last_seen_at, disabled_at, external_id,
/// token_expires_at FROM users`. The nine
/// fields map 1:1 to [`UserRow`].
pub type UserRowTuple = (
    i64,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// One row + the **plain** token, returned by
/// [`UserRepository::create`] and
/// [`UserRepository::rotate_token`]. The plain token
/// is the only time the server hands the secret out.
#[derive(Debug, Clone)]
pub struct UserCreated {
    pub user: UserRow,
    pub token: String,
}

#[derive(Clone)]
pub struct UserRepository {
    pool: SqlitePool,
}

impl UserRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create a new user with a freshly generated
    /// bearer token. The plain token is returned in
    /// [`UserCreated::token`] and is **not** stored
    /// anywhere on disk or in the DB.
    pub async fn create(&self, name: &str, role: Role) -> CoreResult<UserCreated> {
        if name.is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "users.name".to_string(),
                reason: "name must not be empty".to_string(),
            });
        }
        let token = generate_token();
        let token_hash = sha256_hex(token.as_bytes());
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO users (name, role, token_hash, created_at) \
             VALUES (?1, ?2, ?3, ?4) RETURNING id",
        )
        .bind(name)
        .bind(role.as_str())
        .bind(&token_hash)
        .bind(&now_str)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.message().contains("UNIQUE") => {
                CoreError::ErrSchemaInvalid {
                    path: "users.name".to_string(),
                    reason: format!("a user named `{name}` already exists"),
                }
            }
            _ => CoreError::ErrSqlx(e),
        })?;
        let user = UserRow {
            id: row.0,
            name: name.to_string(),
            role,
            token_hash,
            created_at: now_str,
            last_seen_at: None,
            disabled_at: None,
            external_id: None,
            token_expires_at: None,
        };
        Ok(UserCreated { user, token })
    }

    /// Look up a user by their bearer token. Returns
    /// `None` if the token does not match any active
    /// row (unknown token OR `disabled_at IS NOT
    /// NULL`).
    pub async fn find_by_token(&self, plain_token: &str) -> CoreResult<Option<UserRow>> {
        let token_hash = sha256_hex(plain_token.as_bytes());
        let row: Option<UserRowTuple> = sqlx::query_as(
            "SELECT id, name, role, token_hash, created_at, last_seen_at, disabled_at, external_id, token_expires_at \
             FROM users WHERE token_hash = ?1",
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            None => Ok(None),
            Some((
                id,
                name,
                role_str,
                token_hash,
                created_at,
                last_seen_at,
                disabled_at,
                external_id,
                token_expires_at,
            )) => {
                if disabled_at.is_some() {
                    return Ok(None);
                }
                let role = Role::parse(&role_str)?;
                Ok(Some(UserRow {
                    id,
                    name,
                    role,
                    token_hash,
                    created_at,
                    last_seen_at,
                    disabled_at,
                    external_id,
                    token_expires_at,
                }))
            }
        }
    }

    /// Best-effort `last_seen_at = now()`. The 2.1.0
    /// middleware calls this on a 1-in-10 sample so
    /// the read path does not write on every
    /// request.
    pub async fn touch_last_seen(&self, user_id: i64) -> CoreResult<()> {
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        sqlx::query("UPDATE users SET last_seen_at = ?1 WHERE id = ?2")
            .bind(&now_str)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Soft-delete a user. Subsequent `find_by_token`
    /// calls return `None` immediately.
    pub async fn disable(&self, user_id: i64) -> CoreResult<bool> {
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let affected =
            sqlx::query("UPDATE users SET disabled_at = ?1 WHERE id = ?2 AND disabled_at IS NULL")
                .bind(&now_str)
                .bind(user_id)
                .execute(&self.pool)
                .await?
                .rows_affected();
        Ok(affected > 0)
    }

    /// Generate a fresh token for the user. The old
    /// token stops working immediately.
    pub async fn rotate_token(&self, user_id: i64) -> CoreResult<Option<String>> {
        let token = generate_token();
        let token_hash = sha256_hex(token.as_bytes());
        let affected =
            sqlx::query("UPDATE users SET token_hash = ?1 WHERE id = ?2 AND disabled_at IS NULL")
                .bind(&token_hash)
                .bind(user_id)
                .execute(&self.pool)
                .await?
                .rows_affected();
        if affected == 0 {
            return Ok(None);
        }
        Ok(Some(token))
    }

    /// List every user, oldest-first. The
    /// `token_hash` is never returned; the
    /// `last_seen_at` and `disabled_at` are.
    pub async fn list(&self) -> CoreResult<Vec<UserRow>> {
        let rows: Vec<UserRowTuple> = sqlx::query_as(
            "SELECT id, name, role, token_hash, created_at, last_seen_at, disabled_at, external_id, token_expires_at \
             FROM users ORDER BY id ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for (id, name, role_str, token_hash, created_at, last_seen_at, disabled_at, external_id, token_expires_at) in
            rows
        {
            out.push(UserRow {
                id,
                name,
                role: Role::parse(&role_str)?,
                token_hash,
                created_at,
                last_seen_at,
                disabled_at,
                external_id,
                token_expires_at,
            });
        }
        Ok(out)
    }

    /// One-shot migration from a 2.0.0 single-token
    /// file. If the `users` table is empty and the
    /// caller passes a non-empty `legacy_token`, an
    /// `admin` user is created with the matching
    /// `token_hash`. Returns `true` if a row was
    /// inserted.
    pub async fn migrate_legacy_token(&self, legacy_token: &str) -> CoreResult<bool> {
        if legacy_token.is_empty() {
            return Ok(false);
        }
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await?;
        if count.0 > 0 {
            return Ok(false);
        }
        let created = self.create("admin", Role::Admin).await?;
        // Replace the auto-generated token with the
        // legacy one so existing scripts keep
        // working. We do this by inserting the row
        // directly, since `create` would create a
        // second one.
        let token_hash = sha256_hex(legacy_token.as_bytes());
        sqlx::query("UPDATE users SET token_hash = ?1 WHERE id = ?2")
            .bind(&token_hash)
            .bind(created.user.id)
            .execute(&self.pool)
            .await?;
        Ok(true)
    }

    /// 2.7.6 (ADR-0034): look up a user by
    /// OIDC `sub` claim. Returns `None` if no
    /// user with this `external_id` exists.
    pub async fn find_by_external_id(&self, external_id: &str) -> CoreResult<Option<UserRow>> {
        if external_id.is_empty() {
            return Ok(None);
        }
        let row: Option<UserRowTuple> = sqlx::query_as(
            "SELECT id, name, role, token_hash, created_at, last_seen_at, disabled_at, external_id, token_expires_at \
             FROM users WHERE external_id = ?1",
        )
        .bind(external_id)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            None => Ok(None),
            Some((
                id,
                name,
                role_str,
                token_hash,
                created_at,
                last_seen_at,
                disabled_at,
                external_id,
                token_expires_at,
            )) => {
                if disabled_at.is_some() {
                    return Ok(None);
                }
                let role = Role::parse(&role_str)?;
                Ok(Some(UserRow {
                    id,
                    name,
                    role,
                    token_hash,
                    created_at,
                    last_seen_at,
                    disabled_at,
                    external_id,
                    token_expires_at,
                }))
            }
        }
    }

    /// 2.7.6 (ADR-0034): create a user with an
    /// OIDC `sub` claim as the stable
    /// `external_id`. Returns the user row
    /// (the bearer token is issued separately
    /// via `store_token_hash`).
    pub async fn create_with_external_id(
        &self,
        name: &str,
        role: Role,
        external_id: &str,
    ) -> CoreResult<UserRow> {
        if name.is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "users.name".to_string(),
                reason: "name must not be empty".to_string(),
            });
        }
        if external_id.is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "users.external_id".to_string(),
                reason: "external_id must not be empty".to_string(),
            });
        }
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        // Initial token_hash is the SHA-256 of
        // an empty string; it gets overwritten
        // by `store_token_hash` on first
        // bearer-token issuance.
        let initial_hash = sha256_hex(b"");
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO users (name, role, token_hash, created_at, external_id) \
             VALUES (?1, ?2, ?3, ?4, ?5) RETURNING id",
        )
        .bind(name)
        .bind(role.as_str())
        .bind(&initial_hash)
        .bind(&now_str)
        .bind(external_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.message().contains("UNIQUE") => {
                CoreError::ErrSchemaInvalid {
                    path: "users.external_id".to_string(),
                    reason: format!("a user with external_id `{external_id}` already exists"),
                }
            }
            _ => CoreError::ErrSqlx(e),
        })?;
        Ok(UserRow {
            id: row.0,
            name: name.to_string(),
            role,
            token_hash: initial_hash,
            created_at: now_str,
            last_seen_at: None,
            disabled_at: None,
            external_id: Some(external_id.to_string()),
            token_expires_at: None,
        })
    }

    /// 2.7.6 (ADR-0034): overwrite the
    /// `token_hash` for a user. Used by the
    /// OIDC callback handler to issue a
    /// fresh local bearer token on every
    /// OIDC login.
    pub async fn store_token_hash(&self, user_id: i64, token_hash: &str) -> CoreResult<()> {
        sqlx::query("UPDATE users SET token_hash = ?1 WHERE id = ?2")
            .bind(token_hash)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 2.7.8 (ADR-0036): set the local
    /// bearer token's expiry. The
    /// `auth::require_bearer` middleware
    /// returns 401 once the wall clock
    /// passes `expires_at`. Pass an empty
    /// string to clear the expiry (the
    /// user reverts to non-expiring,
    /// matching the 2.7.7 behaviour).
    pub async fn set_token_expiry(
        &self,
        user_id: i64,
        expires_at: &str,
    ) -> CoreResult<()> {
        let value: Option<&str> = if expires_at.is_empty() {
            None
        } else {
            Some(expires_at)
        };
        sqlx::query("UPDATE users SET token_expires_at = ?1 WHERE id = ?2")
            .bind(value)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 2.7.8 (ADR-0036): invalidate the
    /// local bearer token by setting
    /// `token_hash = sha256("")` (the
    /// "empty hash" sentinel from
    /// `create_with_external_id` in
    /// 2.7.6). Subsequent
    /// `find_by_token` calls return
    /// `None` for this user.
    pub async fn invalidate_token(&self, user_id: i64) -> CoreResult<()> {
        let empty_hash = sha256_hex(b"");
        sqlx::query("UPDATE users SET token_hash = ?1 WHERE id = ?2")
            .bind(&empty_hash)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// Generate a fresh 256-bit bearer token, base64url
/// (no padding). Public for use by the OIDC
/// callback handler in 2.7.6 (ADR-0034).
pub fn generate_token() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 hex digest. Public for the OIDC
/// callback handler in 2.7.6 (ADR-0034).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[cfg(test)]
#[path = "users_repository_tests.rs"]
mod tests;
