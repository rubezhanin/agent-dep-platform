//! Vault initialization — fail-closed passphrase policy
//! + per-install salt (P0-F-05, TZ #1 §6 F-05 + TZ #2 WP-2.1).
//!
//! **What this module is responsible for:**
//! 1. Loading the vault passphrase from `AGENCY_VAULT_PASSPHRASE_FILE`
//!    (preferred) or `AGENCY_VAULT_PASSPHRASE` (fallback).
//! 2. Rejecting known placeholder values in release builds.
//! 3. Enforcing a minimum Shannon-entropy threshold (≥ 80 bits).
//! 4. Loading or generating a per-install salt, persisted to
//!    `<data_dir>/vault.salt` (mode 0600).
//!
//! **What this module is NOT responsible for:**
//! - The KDF itself (Argon2id lives in `secrets_repository.rs`).
//! - Per-secret salts (those land in P1-F-06, KDF v2 migration).
//! - Storing the admin token (lives in `server.token`, mode 0600,
//!   created in `boot_default_state`).
//!
//! **Why fail-closed:**
//! The pre-fix code accepted the placeholder
//! `"unset-rotate-before-first-use"` in fresh installs. An attacker
//! who knew the placeholder (it's in the public repo's env examples)
//! could decrypt every secret in the vault. CWE-798.
//!
//! **Why per-install salt:**
//! Without it, two installs with the same passphrase derive the
//! same KDF output. An attacker who captures one vault's KDF
//! output can decrypt another vault with the same passphrase.
//! Per-install salt breaks that across-installs link. The salt
//! is stored in `<data_dir>/vault.salt` and never leaves the
//! host.
//!
//! References:
//! - `TZ_agent-dep-platform-REMEDIATION-PLAN.md` §3.1 P0-F-05
//! - `TZ_agent-dep-platform-HARDENING-TZ.md` WP-2.1
//! - `crates/core/tests/security_replays.rs::a5_vault_placeholder_secret_accepted_in_production`
//! - `docs/AGENT_DOD.md` §1 (12-point DoD for this finding)

use std::path::Path;
use thiserror::Error;

/// The "known insecure placeholder" the pre-fix code accepted
/// silently. Any match against this constant in release builds
/// is a hard fail.
pub const PLACEHOLDER_PASSPHRASE: &str = "unset-rotate-before-first-use";

/// Common "I copied this from a tutorial" passphrases we also
/// reject. Not exhaustive — this is a defense-in-depth list, the
/// entropy check is the primary control.
const OTHER_KNOWN_BAD: &[&str] = &[
    "change-me",
    "changeme",
    "password",
    "admin",
    "secret",
    "test",
    "12345678",
    "agency-server",
];

/// Minimum passphrase entropy in bits. NIST SP 800-63B recommends
/// ≥ 30 bits for memorized secrets; we require 80 bits because
/// the passphrase protects a high-value key (the vault master key)
/// and the operator is a system, not a human, so it can easily
/// generate a high-entropy value (e.g. `openssl rand -base64 32`).
pub const MIN_ENTROPY_BITS: f64 = 80.0;

/// Length of the per-install salt in bytes. 32 bytes = 256 bits,
/// matches the KDF output length so there's no truncation / padding
/// mismatch when the salt is fed into Argon2id.
pub const INSTALL_SALT_LEN: usize = 32;

/// Filename of the per-install salt, relative to the data dir.
pub const INSTALL_SALT_FILENAME: &str = "vault.salt";

/// Errors that can occur during vault initialization.
#[derive(Debug, Error)]
pub enum VaultInitError {
    #[error(
        "placeholder passphrase rejected: '{0}' is in the known-bad list. \
             Use `openssl rand -base64 32` to generate a high-entropy passphrase."
    )]
    PlaceholderRejected(String),

    #[error(
        "passphrase entropy {measured:.1} bits is below the minimum \
             {required:.1} bits. Use `openssl rand -base64 32` to generate \
             a high-entropy passphrase."
    )]
    LowEntropy { measured: f64, required: f64 },

    #[error(
        "passphrase is empty. Set AGENCY_VAULT_PASSPHRASE or \
             AGENCY_VAULT_PASSPHRASE_FILE before starting the server."
    )]
    Empty,

    #[error("could not read passphrase file {path}: {source}")]
    PassphraseFile {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("could not read install salt file {path}: {source}")]
    SaltFileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("could not write install salt file {path}: {source}")]
    SaltFileWrite {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("install salt file {path} has wrong length: got {got}, expected {expected}")]
    SaltLength {
        path: String,
        got: usize,
        expected: usize,
    },

    #[error("AGENCY_VAULT_PASSPHRASE_FILE points to a file that does not exist: {0}")]
    PassphraseFileMissing(String),
}

// ============================================================================
// Placeholder detection
// ============================================================================

/// Returns `true` if `s` matches a known placeholder passphrase.
/// Comparison is exact (case-sensitive) — defense in depth, not
/// the primary control (entropy check is).
pub fn is_placeholder(s: &str) -> bool {
    if s == PLACEHOLDER_PASSPHRASE {
        return true;
    }
    OTHER_KNOWN_BAD.contains(&s)
}

// ============================================================================
// Entropy estimation
// ============================================================================

/// Estimate the Shannon entropy of a string in bits.
///
/// This is a *practical* estimate, not a cryptographic one. It
/// assumes each character is drawn independently from the
/// character set that appears in the string (a worst-case
/// "Markov-0" model). Real passphrases have lower entropy than
/// this estimate, but the overestimate is safe (it errs on the
/// side of accepting) and the alternative (a full entropy model)
/// would require choosing an alphabet we don't know.
///
/// For the typical `openssl rand -base64 32` output (~256 bits of
/// entropy), this returns ~5.0 bits/char × 43 chars ≈ 215 bits,
/// well above MIN_ENTROPY_BITS. For `"password"`, it returns
/// ~2.75 bits/char × 8 chars ≈ 22 bits, well below.
pub fn shannon_entropy_bits(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::<char, usize>::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let len = s.chars().count() as f64;
    let mut h = 0.0_f64;
    for &count in counts.values() {
        let p = (count as f64) / len;
        // log2(p) < 0 when p > 1, which can't happen here since
        // p = count/total and total >= count. So no -p.abs().
        h -= p * p.log2();
    }
    // Multiply by length to get total entropy (bits/char * chars = bits).
    h * len
}

// ============================================================================
// Passphrase loading
// ============================================================================

/// Load the vault passphrase from the environment.
///
/// Priority:
/// 1. `AGENCY_VAULT_PASSPHRASE_FILE` — path to a file (mode 0600).
///    Preferred for production. File is read once at boot, never
///    cached in memory beyond the function return.
/// 2. `AGENCY_VAULT_PASSPHRASE` — direct env value. Convenience for
///    dev / test / docker-compose. **Will be deprecated** once
///    operator documentation catches up.
///
/// Returns the passphrase as a `String` (NOT zeroized — Rust's
/// `String` cannot be securely zeroized without an explicit
/// `Zeroize` wrapper; that's a follow-up).
pub fn load_passphrase() -> Result<String, VaultInitError> {
    if let Ok(path) = std::env::var("AGENCY_VAULT_PASSPHRASE_FILE") {
        let s = std::fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                VaultInitError::PassphraseFileMissing(path)
            } else {
                VaultInitError::PassphraseFile { path, source: e }
            }
        })?;
        return Ok(s.trim().to_string());
    }
    if let Ok(s) = std::env::var("AGENCY_VAULT_PASSPHRASE") {
        return Ok(s);
    }
    // No env set. The caller (boot_default_state) decides whether
    // this is a fatal error or a "fresh install, no secrets yet"
    // case. We return Empty so the caller can apply its own policy.
    Ok(String::new())
}

// ============================================================================
// Passphrase validation
// ============================================================================

/// Validate the passphrase against the security policy.
///
/// In release builds, this is *always* called before constructing
/// a `SecretRepository`. In `#[cfg(test)]` and `#[cfg(debug_assertions)]`
/// builds, tests that explicitly want to bypass the policy
/// (e.g. for fixture-only passphrases) can skip the call, but
/// production code MUST call it.
pub fn validate_passphrase(passphrase: &str) -> Result<(), VaultInitError> {
    if passphrase.is_empty() {
        return Err(VaultInitError::Empty);
    }
    if is_placeholder(passphrase) {
        return Err(VaultInitError::PlaceholderRejected(passphrase.to_string()));
    }
    let bits = shannon_entropy_bits(passphrase);
    if bits < MIN_ENTROPY_BITS {
        return Err(VaultInitError::LowEntropy {
            measured: bits,
            required: MIN_ENTROPY_BITS,
        });
    }
    Ok(())
}

// ============================================================================
// Per-install salt
// ============================================================================

/// Load the per-install salt from `<data_dir>/vault.salt`, or
/// generate a new one if the file does not exist.
///
/// The salt file is written with mode 0600 on Unix (no-op on
/// Windows where the file ACL is controlled by the operator).
/// On first boot, the salt is generated using `getrandom`
/// (transitively via `rand`'s `OsRng`).
pub fn load_or_generate_install_salt(
    data_dir: &Path,
) -> Result<[u8; INSTALL_SALT_LEN], VaultInitError> {
    let path = data_dir.join(INSTALL_SALT_FILENAME);
    if path.is_file() {
        let bytes = std::fs::read(&path).map_err(|e| VaultInitError::SaltFileRead {
            path: path.display().to_string(),
            source: e,
        })?;
        if bytes.len() != INSTALL_SALT_LEN {
            return Err(VaultInitError::SaltLength {
                path: path.display().to_string(),
                got: bytes.len(),
                expected: INSTALL_SALT_LEN,
            });
        }
        let mut salt = [0u8; INSTALL_SALT_LEN];
        salt.copy_from_slice(&bytes);
        return Ok(salt);
    }
    // First boot: generate and persist.
    use rand::RngCore;
    let mut salt = [0u8; INSTALL_SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    std::fs::write(&path, salt).map_err(|e| VaultInitError::SaltFileWrite {
        path: path.display().to_string(),
        source: e,
    })?;
    set_salt_file_mode(&path);
    Ok(salt)
}

/// Set the install salt file to mode 0600 on Unix.
/// No-op on Windows.
#[cfg(unix)]
fn set_salt_file_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn set_salt_file_mode(_path: &Path) {
    // Windows: file ACL is the operator's responsibility.
    // We document this in docs/DEPLOY.md.
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_constant_matches_pre_fix_default() {
        // The exact string the pre-fix code silently accepted.
        // If this assertion ever fires, the placeholder constant
        // has drifted and we should re-check the env examples.
        assert_eq!(PLACEHOLDER_PASSPHRASE, "unset-rotate-before-first-use");
    }

    #[test]
    fn is_placeholder_detects_known_bad() {
        assert!(is_placeholder("unset-rotate-before-first-use"));
        assert!(is_placeholder("change-me"));
        assert!(is_placeholder("password"));
        assert!(!is_placeholder("correct horse battery staple"));
        assert!(!is_placeholder(""));
    }

    #[test]
    fn shannon_entropy_of_random_base64_is_above_threshold() {
        // A typical `openssl rand -base64 32` output.
        let s = "5R9k2PqL8tNwV3YjH7mZxKcDfG4sB1aE0iXuWvT6oJ9M=";
        let bits = shannon_entropy_bits(s);
        assert!(
            bits >= MIN_ENTROPY_BITS,
            "expected >= {MIN_ENTROPY_BITS} bits, got {bits}"
        );
    }

    #[test]
    fn shannon_entropy_of_short_password_is_below_threshold() {
        let s = "password";
        let bits = shannon_entropy_bits(s);
        assert!(
            bits < MIN_ENTROPY_BITS,
            "expected < {MIN_ENTROPY_BITS} bits, got {bits}"
        );
    }

    #[test]
    fn shannon_entropy_of_empty_is_zero() {
        assert_eq!(shannon_entropy_bits(""), 0.0);
    }

    #[test]
    fn validate_rejects_placeholder() {
        let err = validate_passphrase("unset-rotate-before-first-use")
            .expect_err("placeholder must be rejected");
        assert!(matches!(err, VaultInitError::PlaceholderRejected(_)));
    }

    #[test]
    fn validate_rejects_low_entropy() {
        // "abc" — 3 unique chars over 3 chars.
        //   H = log2(3) ≈ 1.58 bits/char * 3 = ~4.75 bits total.
        // Well below MIN_ENTROPY_BITS = 80.
        // Note: "password" is in OTHER_KNOWN_BAD so it
        // hits PlaceholderRejected first; we use "abc"
        // to test the entropy path specifically.
        let err = validate_passphrase("abc").expect_err("low entropy must be rejected");
        assert!(matches!(err, VaultInitError::LowEntropy { .. }));
    }

    #[test]
    fn validate_rejects_empty() {
        let err = validate_passphrase("").expect_err("empty must be rejected");
        assert!(matches!(err, VaultInitError::Empty));
    }

    #[test]
    fn validate_accepts_high_entropy() {
        validate_passphrase("5R9k2PqL8tNwV3YjH7mZxKcDfG4sB1aE0iXuWvT6oJ9M=")
            .expect("high-entropy passphrase must be accepted");
    }

    #[test]
    fn load_or_generate_install_salt_creates_then_reads() {
        let dir = tempfile::tempdir().expect("tempdir");
        // First call: generates.
        let s1 = load_or_generate_install_salt(dir.path()).expect("first gen");
        assert_eq!(s1.len(), INSTALL_SALT_LEN);
        assert!(dir.path().join(INSTALL_SALT_FILENAME).is_file());
        // Second call: reads.
        let s2 = load_or_generate_install_salt(dir.path()).expect("second read");
        assert_eq!(s1, s2, "salt must be stable across reads");
    }

    #[test]
    fn load_or_generate_install_salt_rejects_wrong_length() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(INSTALL_SALT_FILENAME);
        std::fs::write(&path, vec![0u8; 16]).expect("write short salt");
        let err =
            load_or_generate_install_salt(dir.path()).expect_err("short salt must be rejected");
        assert!(matches!(err, VaultInitError::SaltLength { .. }));
    }
}
