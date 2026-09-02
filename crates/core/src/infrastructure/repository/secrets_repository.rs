//! 2.3.0 vault (ADR-0021).
//!
//! One row per secret. The plain value is never
//! stored — only the AES-256-GCM ciphertext with
//! the per-secret 12-byte nonce. The symmetric
//! key is derived from the operator's passphrase
//! at server startup via Argon2id (OWASP 2026
//! defaults). The passphrase itself is held in
//! memory for the process lifetime and is not
//! persisted.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use argon2::{Argon2, Params};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::{CoreError, CoreResult};

/// KDF version recorded in every row. Lets 2.3.1
/// introduce a new KDF without a migration; the
/// reader falls back to a clear error if it sees
/// a future version.
const KDF_VERSION: i64 = 1;

/// Application-level salt. Per-secret nonces are
/// in the row; this is the second input to the KDF
/// and is **not** secret (it is a fixed project-
/// wide value). The passphrase is the secret
/// input.
const APP_SALT: &[u8] = b"agent-dep-platform/vault/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRow {
    pub id: i64,
    pub name: String,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
    pub created_by: i64,
    pub updated_by: i64,
}

/// Decrypted secret view. Returned only to
/// `operator+` callers; `list()` returns
/// `SecretRow` (no value).
#[derive(Debug, Clone, Serialize)]
pub struct SecretValue {
    pub name: String,
    pub value: String,
}

#[derive(Clone)]
pub struct SecretRepository {
    pool: SqlitePool,
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for SecretRepository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The cipher is the secret material; we
        // intentionally do not format it. The
        // pool is fine to print.
        f.debug_struct("SecretRepository")
            .field("pool", &self.pool)
            .field("cipher", &"<redacted>")
            .finish()
    }
}

impl SecretRepository {
    /// Build a `SecretRepository` from a passphrase.
    /// The passphrase is run through Argon2id once
    /// (with the fixed `APP_SALT`) to derive a
    /// 32-byte key. The cipher is reused for every
    /// encrypt/decrypt; only the per-secret nonce
    /// changes.
    pub fn new(pool: SqlitePool, passphrase: &str) -> CoreResult<Self> {
        if passphrase.is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "vault.passphrase".to_string(),
                reason: "passphrase must not be empty".to_string(),
            });
        }
        let key_bytes = derive_key(passphrase)?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        Ok(Self { pool, cipher })
    }

    /// Encrypt and store a new secret. Returns the
    /// new row. The plain value is never persisted;
    /// only the AES-256-GCM output + the per-secret
    /// nonce.
    pub async fn create(&self, name: &str, value: &str, user_id: i64) -> CoreResult<SecretRow> {
        if name.is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "secrets.name".to_string(),
                reason: "name must not be empty".to_string(),
            });
        }
        let (ciphertext, nonce) = self.encrypt(value)?;
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO secrets \
             (name, ciphertext, nonce, version, created_at, updated_at, \
              created_by, updated_by) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?6) RETURNING id",
        )
        .bind(name)
        .bind(&ciphertext)
        .bind(&nonce)
        .bind(KDF_VERSION)
        .bind(&now_str)
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.message().contains("UNIQUE") => {
                CoreError::ErrSchemaInvalid {
                    path: "secrets.name".to_string(),
                    reason: format!("a secret named `{name}` already exists"),
                }
            }
            _ => CoreError::ErrSqlx(e),
        })?;
        Ok(SecretRow {
            id: row.0,
            name: name.to_string(),
            version: KDF_VERSION,
            created_at: now_str.clone(),
            updated_at: now_str,
            created_by: user_id,
            updated_by: user_id,
        })
    }

    /// Decrypt a secret by name. Returns
    /// `ErrSchemaInvalid` if the secret does not
    /// exist.
    pub async fn get_value(&self, name: &str) -> CoreResult<SecretValue> {
        let row: Option<(Vec<u8>, Vec<u8>, i64)> =
            sqlx::query_as("SELECT ciphertext, nonce, version FROM secrets WHERE name = ?1")
                .bind(name)
                .fetch_optional(&self.pool)
                .await?;
        let (ciphertext, nonce, version) = row.ok_or_else(|| CoreError::ErrSchemaInvalid {
            path: "secrets.name".to_string(),
            reason: format!("no secret named `{name}`"),
        })?;
        if version != KDF_VERSION {
            return Err(CoreError::ErrSchemaInvalid {
                path: "secrets.version".to_string(),
                reason: format!(
                    "unsupported KDF version {version}; the server only knows v{KDF_VERSION}"
                ),
            });
        }
        let value = self.decrypt(&ciphertext, &nonce)?;
        Ok(SecretValue {
            name: name.to_string(),
            value,
        })
    }

    /// List every secret's metadata. The plain
    /// value is **never** returned by this method.
    pub async fn list(&self) -> CoreResult<Vec<SecretRow>> {
        let rows: Vec<(i64, String, i64, String, String, i64, i64)> = sqlx::query_as(
            "SELECT id, name, version, created_at, updated_at, created_by, updated_by \
             FROM secrets ORDER BY id ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(id, name, version, created_at, updated_at, created_by, updated_by)| SecretRow {
                    id,
                    name,
                    version,
                    created_at,
                    updated_at,
                    created_by,
                    updated_by,
                },
            )
            .collect())
    }

    /// Update the value of an existing secret.
    /// Returns the new row, or `None` if the name
    /// did not exist.
    pub async fn update(
        &self,
        name: &str,
        value: &str,
        user_id: i64,
    ) -> CoreResult<Option<SecretRow>> {
        let (ciphertext, nonce) = self.encrypt(value)?;
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let affected = sqlx::query(
            "UPDATE secrets \
             SET ciphertext = ?1, nonce = ?2, version = ?3, \
                 updated_at = ?4, updated_by = ?5 \
             WHERE name = ?6",
        )
        .bind(&ciphertext)
        .bind(&nonce)
        .bind(KDF_VERSION)
        .bind(&now_str)
        .bind(user_id)
        .bind(name)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if affected == 0 {
            return Ok(None);
        }
        let row: Option<(i64, i64, String, String, i64, i64)> = sqlx::query_as(
            "SELECT id, version, created_at, updated_at, created_by, updated_by \
             FROM secrets WHERE name = ?1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        let (id, version, created_at, updated_at, created_by, updated_by) =
            row.ok_or_else(|| CoreError::ErrSchemaInvalid {
                path: "secrets.name".to_string(),
                reason: "row disappeared between update and select".to_string(),
            })?;
        Ok(Some(SecretRow {
            id,
            name: name.to_string(),
            version,
            created_at,
            updated_at,
            created_by,
            updated_by,
        }))
    }

    /// Hard-delete a secret. Returns `true` if a
    /// row was removed, `false` if the name did
    /// not exist.
    pub async fn delete(&self, name: &str) -> CoreResult<bool> {
        let affected = sqlx::query("DELETE FROM secrets WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(affected > 0)
    }

    /// Count rows. Used by the server to refuse
    /// startup if the `secrets` table is non-empty
    /// but no passphrase is configured.
    pub async fn count(&self) -> CoreResult<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM secrets")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }

    fn encrypt(&self, value: &str) -> CoreResult<(Vec<u8>, Vec<u8>)> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self.cipher.encrypt(nonce, value.as_bytes()).map_err(|e| {
            CoreError::ErrSchemaInvalid {
                path: "secrets".to_string(),
                reason: format!("AES-GCM encrypt failed: {e}"),
            }
        })?;
        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> CoreResult<String> {
        let nonce = Nonce::from_slice(nonce);
        let plain =
            self.cipher
                .decrypt(nonce, ciphertext)
                .map_err(|e| CoreError::ErrSchemaInvalid {
                    path: "secrets".to_string(),
                    reason: format!(
                        "AES-GCM decrypt failed (wrong passphrase or corrupted row): {e}"
                    ),
                })?;
        String::from_utf8(plain).map_err(|e| CoreError::ErrSchemaInvalid {
            path: "secrets".to_string(),
            reason: format!("plaintext is not UTF-8: {e}"),
        })
    }
}

fn derive_key(passphrase: &str) -> CoreResult<[u8; 32]> {
    let params =
        Params::new(19 * 1024, 2, 1, Some(32)).map_err(|e| CoreError::ErrSchemaInvalid {
            path: "vault.kdf".to_string(),
            reason: format!("argon2 params: {e}"),
        })?;
    let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), APP_SALT, &mut out)
        .map_err(|e| CoreError::ErrSchemaInvalid {
            path: "vault.kdf".to_string(),
            reason: format!("argon2 derive: {e}"),
        })?;
    Ok(out)
}

#[cfg(test)]
#[path = "secrets_repository_tests.rs"]
mod tests;
