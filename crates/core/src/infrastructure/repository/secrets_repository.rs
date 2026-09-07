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
//!
//! 3.0.0 (P0-F-05, TZ #1 §6 F-05 + TZ #2 WP-2.1):
//! KDF input is now `passphrase || install_salt`,
//! not a project-wide constant. The install salt
//! is generated on first boot and persisted to
//! `<data_dir>/vault.salt` (mode 0600) by
//! `agency_server::vault_init::load_or_generate_install_salt`.
//! Two installs with the same passphrase now
//! derive different keys, breaking the cross-install
//! link that the fixed `APP_SALT` allowed.
//!
//! 2.11.0 (P1-F-06, TZ #2 WP-3.2, CWE-916 + CWE-326):
//! KDF v2 — per-secret salt + AAD.
//!  - The KDF input salt is now
//!    `install_salt || secret_salt` (32 + 16
//!    bytes), where `secret_salt` is a 16-byte
//!    random value generated on every
//!    `create` / `update` via `OsRng`. Two
//!    rows with the same plaintext under the
//!    same passphrase now derive different
//!    keys even within one install.
//!  - AES-GCM is called with AAD =
//!    `secret_name`. The AAD is authenticated
//!    but not encrypted; AES-GCM will refuse
//!    to decrypt a row whose AAD does not
//!    match the value the ciphertext was
//!    produced under. This blocks cross-row
//!    confusion: an attacker who swaps the
//!    `ciphertext` of one row with that of
//!    another row at the same nonce cannot
//!    be authenticated. CWE-345.
//!  - The per-row `version` column tracks
//!    which KDF was used to write the row.
//!    `version = 1` (legacy, pre-P1-F-06)
//!    and `version = 2` (per-secret salt +
//!    AAD). The reader dispatches on
//!    `version`. New rows are written with
//!    `version = 2`; the next `update` of a
//!    legacy `version = 1` row migrates it
//!    to v2 on the spot (lazy migration,
//!    no offline re-encryption).
//!  - Legacy v1 rows are backfilled at
//!    migration 020 with
//!    `secret_salt = 16 zero bytes` and
//!    `aad = ''` so they satisfy the
//!    `NOT NULL` constraints. The legacy
//!    decrypt path derives the key from
//!    `install_salt || 0^16`, which equals
//!    the pre-migration install salt, so
//!    ciphertexts remain readable bit-for-bit.
//!  - The cipher is no longer cached on the
//!    `SecretRepository`; it is derived
//!    per-secret via `derive_key_v2`. The
//!    Argon2id call is ~50-200 ms on a
//!    typical box, which is acceptable for
//!    the secret-management workload (the
//!    hot path of the server does not read
//!    secrets in a tight loop; secret reads
//!    are interactive operator actions).

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use argon2::{Argon2, Params};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::{CoreError, CoreResult};

/// KDF version recorded in every row. KDF v2 is
/// the new default: per-secret salt + AAD. The
/// constant is read by the migration path
/// (`INSERT ... version = ?KDF_VERSION`) and by
/// the runtime check that rejects rows from a
/// future KDF version the running binary does
/// not know how to handle.
const KDF_VERSION: i64 = 2;

/// Length of the per-install salt in bytes. 32
/// bytes = 256 bits, matches the KDF output length
/// so there's no truncation / padding mismatch.
pub const INSTALL_SALT_LEN: usize = 32;

/// Length of the per-secret salt in bytes. 16
/// bytes = 128 bits, generated via `OsRng` on
/// every `create` / `update`. The combined KDF
/// salt is `install_salt || secret_salt` (48
/// bytes total). The choice of 128 bits is
/// deliberate: enough to make rainbow-table
/// precomputation per-secret infeasible, but
/// small enough that the per-secret slice fits
/// comfortably in the row.
pub const SECRET_SALT_LEN: usize = 16;

/// Raw row shape read in `get_value`. The
/// 5-tuple `(ciphertext, nonce, secret_salt, aad,
/// version)` is wrapped in a type alias to keep
/// `clippy::type_complexity` happy (it flags
/// 5-element inline tuples as "very complex").
type SecretRowRaw = (Vec<u8>, Vec<u8>, Vec<u8>, String, i64);

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
    passphrase: String,
    install_salt: [u8; INSTALL_SALT_LEN],
}

impl std::fmt::Debug for SecretRepository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The passphrase and install salt are the
        // secret material; we intentionally do not
        // format them. The pool is fine to print.
        f.debug_struct("SecretRepository")
            .field("pool", &self.pool)
            .field("passphrase", &"<redacted>")
            .field("install_salt", &"<redacted>")
            .finish()
    }
}

impl SecretRepository {
    /// Build a `SecretRepository` from a passphrase
    /// and the per-install salt.
    ///
    /// **P0-F-05 (TZ #1 §6 F-05 + TZ #2 WP-2.1):**
    /// the install salt is now a required argument.
    /// Two installs with the same passphrase now
    /// derive different keys. The salt is generated
    /// and persisted by
    /// `agency_server::vault_init::load_or_generate_install_salt`
    /// on first boot.
    ///
    /// **P1-F-06 (TZ #2 WP-3.2):** the cipher is
    /// no longer derived once at construction. It
    /// is derived per-secret inside `encrypt` /
    /// `decrypt` via `derive_key_v2`, with the
    /// per-secret salt folded into the KDF input.
    /// The passphrase and install salt are held in
    /// memory for the process lifetime.
    pub fn new(
        pool: SqlitePool,
        passphrase: &str,
        install_salt: &[u8; INSTALL_SALT_LEN],
    ) -> CoreResult<Self> {
        if passphrase.is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "vault.passphrase".to_string(),
                reason: "passphrase must not be empty".to_string(),
            });
        }
        Ok(Self {
            pool,
            passphrase: passphrase.to_string(),
            install_salt: *install_salt,
        })
    }

    /// Encrypt and store a new secret. Returns the
    /// new row. The plain value is never persisted;
    /// only the AES-256-GCM output + the per-secret
    /// nonce.
    ///
    /// **P1-F-06:** writes a v2 row with a fresh
    /// per-secret salt and AAD = `name`.
    pub async fn create(&self, name: &str, value: &str, user_id: i64) -> CoreResult<SecretRow> {
        if name.is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "secrets.name".to_string(),
                reason: "name must not be empty".to_string(),
            });
        }
        // Fresh per-secret salt: every write is
        // an independent KDF input. Two rows
        // with the same plaintext under the same
        // passphrase derive different keys.
        let mut secret_salt = [0u8; SECRET_SALT_LEN];
        rand::thread_rng().fill_bytes(&mut secret_salt);
        let (ciphertext, nonce) = self.encrypt_v2(value, &secret_salt, name)?;
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO secrets \
             (name, ciphertext, nonce, secret_salt, aad, version, \
              created_at, updated_at, created_by, updated_by) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, ?8) RETURNING id",
        )
        .bind(name)
        .bind(&ciphertext)
        .bind(&nonce)
        .bind(&secret_salt[..])
        .bind(name)
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
    ///
    /// **P1-F-06:** dispatches on the row's
    /// `version` column. v2 rows go through the
    /// per-secret-salt + AAD path; v1 rows go
    /// through the legacy path with the zero
    /// sentinel salt and empty AAD. A row from a
    /// future KDF version (>= 3) is rejected
    /// with a typed error.
    pub async fn get_value(&self, name: &str) -> CoreResult<SecretValue> {
        let row: Option<SecretRowRaw> = sqlx::query_as(
            "SELECT ciphertext, nonce, secret_salt, aad, version \
             FROM secrets WHERE name = ?1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        let (ciphertext, nonce, secret_salt, aad, version) =
            row.ok_or_else(|| CoreError::ErrSchemaInvalid {
                path: "secrets.name".to_string(),
                reason: format!("no secret named `{name}`"),
            })?;
        let value = match version {
            1 => {
                // Legacy v1: the secret_salt is the
                // 16 zero bytes backfilled at
                // migration 020 and aad is empty.
                // derive_key_v1 yields the same key
                // the pre-migration derive_key
                // produced (install_salt alone).
                if secret_salt.len() != SECRET_SALT_LEN {
                    return Err(CoreError::ErrSchemaInvalid {
                        path: "secrets.secret_salt".to_string(),
                        reason: format!(
                            "v1 row has secret_salt of length {}; expected {SECRET_SALT_LEN}",
                            secret_salt.len()
                        ),
                    });
                }
                if !aad.is_empty() {
                    return Err(CoreError::ErrSchemaInvalid {
                        path: "secrets.aad".to_string(),
                        reason: "v1 row has non-empty aad; backfill expected ''".to_string(),
                    });
                }
                let mut salt_arr = [0u8; SECRET_SALT_LEN];
                salt_arr.copy_from_slice(&secret_salt);
                self.decrypt_v1(&ciphertext, &nonce, &salt_arr)?
            }
            2 => {
                // KDF v2: AAD must be present (the
                // column is NOT NULL DEFAULT '' but
                // a write path that forgets to set
                // it would be a bug, not a backfill
                // case, so reject explicitly).
                if aad.is_empty() {
                    return Err(CoreError::ErrSchemaInvalid {
                        path: "secrets.aad".to_string(),
                        reason: "v2 row has empty aad; expected secret name".to_string(),
                    });
                }
                if secret_salt.len() != SECRET_SALT_LEN {
                    return Err(CoreError::ErrSchemaInvalid {
                        path: "secrets.secret_salt".to_string(),
                        reason: format!(
                            "v2 row has secret_salt of length {}; expected {SECRET_SALT_LEN}",
                            secret_salt.len()
                        ),
                    });
                }
                let mut salt_arr = [0u8; SECRET_SALT_LEN];
                salt_arr.copy_from_slice(&secret_salt);
                self.decrypt_v2(&ciphertext, &nonce, &salt_arr, &aad)?
            }
            other => {
                return Err(CoreError::ErrSchemaInvalid {
                    path: "secrets.version".to_string(),
                    reason: format!(
                        "unsupported KDF version {other}; the server only knows v1 and v{KDF_VERSION}"
                    ),
                });
            }
        };
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
    ///
    /// **P1-F-06:** always writes a v2 row with a
    /// fresh per-secret salt. Updating a legacy
    /// v1 row migrates it to v2 on the spot
    /// (lazy migration).
    pub async fn update(
        &self,
        name: &str,
        value: &str,
        user_id: i64,
    ) -> CoreResult<Option<SecretRow>> {
        let mut secret_salt = [0u8; SECRET_SALT_LEN];
        rand::thread_rng().fill_bytes(&mut secret_salt);
        let (ciphertext, nonce) = self.encrypt_v2(value, &secret_salt, name)?;
        let now: DateTime<Utc> = Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let affected = sqlx::query(
            "UPDATE secrets \
             SET ciphertext = ?1, nonce = ?2, secret_salt = ?3, \
                 aad = ?4, version = ?5, \
                 updated_at = ?6, updated_by = ?7 \
             WHERE name = ?8",
        )
        .bind(&ciphertext)
        .bind(&nonce)
        .bind(&secret_salt[..])
        .bind(name)
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

    /// Borrow the underlying pool. Test-only
    /// accessor: lets the integration tests in
    /// `secrets_repository_tests.rs` plant
    /// pre-migration v1 rows or future-version
    /// rows directly via SQL. Not used by the
    /// production path.
    #[cfg(test)]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// KDF v2 encrypt. Derives a per-secret cipher
    /// via `derive_key_v2` and calls AES-GCM with
    /// AAD = `aad_bytes`. The AAD is authenticated
    /// but not encrypted; AES-GCM will refuse to
    /// decrypt a row whose AAD does not match the
    /// value the ciphertext was produced under.
    fn encrypt_v2(
        &self,
        value: &str,
        secret_salt: &[u8; SECRET_SALT_LEN],
        aad: &str,
    ) -> CoreResult<(Vec<u8>, Vec<u8>)> {
        let key_bytes = derive_key_v2(&self.passphrase, &self.install_salt, secret_salt)?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: value.as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|e| CoreError::ErrSchemaInvalid {
                path: "secrets".to_string(),
                reason: format!("AES-GCM encrypt failed: {e}"),
            })?;
        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    /// KDF v2 decrypt. Derives the per-secret
    /// cipher from the row's `secret_salt` and
    /// passes the row's `aad` to AES-GCM. A
    /// mismatch on either input fails the
    /// authentication check.
    fn decrypt_v2(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        secret_salt: &[u8; SECRET_SALT_LEN],
        aad: &str,
    ) -> CoreResult<String> {
        let key_bytes = derive_key_v2(&self.passphrase, &self.install_salt, secret_salt)?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);
        let plain = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|e| CoreError::ErrSchemaInvalid {
                path: "secrets".to_string(),
                reason: format!(
                    "AES-GCM v2 decrypt failed (wrong passphrase, wrong aad, or corrupted row): {e}"
                ),
            })?;
        String::from_utf8(plain).map_err(|e| CoreError::ErrSchemaInvalid {
            path: "secrets".to_string(),
            reason: format!("plaintext is not UTF-8: {e}"),
        })
    }

    /// Legacy v1 decrypt. `secret_salt` is the
    /// 16 zero bytes backfilled at migration 020,
    /// so `derive_key_v2` collapses to
    /// `derive_key(install_salt)` — bit-for-bit
    /// identical to the pre-P1-F-06 path. AAD is
    /// not passed (AES-GCM `decrypt` with no AAD).
    fn decrypt_v1(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        secret_salt: &[u8; SECRET_SALT_LEN],
    ) -> CoreResult<String> {
        let key_bytes = derive_key_v2(&self.passphrase, &self.install_salt, secret_salt)?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);
        let plain = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CoreError::ErrSchemaInvalid {
                path: "secrets".to_string(),
                reason: format!(
                    "AES-GCM v1 decrypt failed (wrong passphrase or corrupted row): {e}"
                ),
            })?;
        String::from_utf8(plain).map_err(|e| CoreError::ErrSchemaInvalid {
            path: "secrets".to_string(),
            reason: format!("plaintext is not UTF-8: {e}"),
        })
    }
}

/// KDF v2: derive a 32-byte AES-256-GCM key from
/// the operator's passphrase, the per-install salt,
/// and a per-secret salt. The KDF input salt is
/// `install_salt || secret_salt` (32 + 16 = 48
/// bytes). The output is 32 bytes, matching the
/// AES-256 key size.
///
/// **P1-F-06 (CWE-916 / CWE-326):** the
/// per-secret salt input means the same
/// passphrase and the same install salt produce
/// different derived keys for every row. An
/// attacker who captures `secrets.db` and a
/// known (plaintext, ciphertext) pair still has
/// to brute-force the passphrase for that
/// single row's salt; the cost does not
/// transfer to other rows.
fn derive_key_v2(
    passphrase: &str,
    install_salt: &[u8; INSTALL_SALT_LEN],
    secret_salt: &[u8; SECRET_SALT_LEN],
) -> CoreResult<[u8; 32]> {
    let mut combined_salt = [0u8; INSTALL_SALT_LEN + SECRET_SALT_LEN];
    combined_salt[..INSTALL_SALT_LEN].copy_from_slice(install_salt);
    combined_salt[INSTALL_SALT_LEN..].copy_from_slice(secret_salt);
    let params =
        Params::new(19 * 1024, 2, 1, Some(32)).map_err(|e| CoreError::ErrSchemaInvalid {
            path: "vault.kdf".to_string(),
            reason: format!("argon2 params: {e}"),
        })?;
    let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), &combined_salt, &mut out)
        .map_err(|e| CoreError::ErrSchemaInvalid {
            path: "vault.kdf".to_string(),
            reason: format!("argon2 derive: {e}"),
        })?;
    Ok(out)
}

#[cfg(test)]
#[path = "secrets_repository_tests.rs"]
mod tests;
