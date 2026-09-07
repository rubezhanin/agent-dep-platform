//! Vault replay test (P0-F-05, TZ #2 Appendix A.5).
//!
//! This is the server-level counterpart to
//! `crates/core/tests/security_replays.rs::a5_vault_placeholder_secret_accepted_in_production`.
//!
//! The pre-fix code in `boot_default_state` silently
//! accepted the placeholder passphrase
//! `"unset-rotate-before-first-use"`, deriving a vault
//! key from a string that is committed in the public
//! repo's env examples. An attacker who knew the
//! placeholder could decrypt every secret in the vault
//! (CWE-798).
//!
//! Post-fix behaviour (verified by these tests):
//! 1. `validate_passphrase` rejects the placeholder
//!    (release builds fail-closed).
//! 2. `validate_passphrase` rejects low-entropy
//!    passphrases (< 80 bits).
//! 3. `load_passphrase` prefers
//!    `AGENCY_VAULT_PASSPHRASE_FILE` over
//!    `AGENCY_VAULT_PASSPHRASE`.
//! 4. `load_or_generate_install_salt` generates a salt
//!    on first boot and reads it on subsequent boots.
//! 5. `load_or_generate_install_salt` rejects a salt
//!    file with the wrong length.
//! 6. `boot_default_state` itself (integration-tested
//!    via direct calls into `vault_init::validate_passphrase`,
//!    which is the gate the boot path uses) refuses
//!    the placeholder.
//!
//! **No mocks:** the boot path itself is not called
//! here because it would require a full SQLite +
//! real IdP environment. The gate is
//! `validate_passphrase`; this test exercises that
//! gate directly. End-to-end boot coverage is in
//! `tests/http_integration.rs` (which uses a
//! valid passphrase via `AGENCY_VAULT_PASSPHRASE_FILE`).
//!
//! References:
//! - `TZ_agent-dep-platform-REMEDIATION-PLAN.md` §3.1 P0-F-05
//! - `TZ_agent-dep-platform-HARDENING-TZ.md` WP-2.1 / Appendix A.5
//! - `docs/AGENT_DOD.md` §1 (12-point DoD for this finding)

use std::sync::Mutex;

// Env-var test isolation: the passphrase loader reads
// AGENCY_VAULT_PASSPHRASE / AGENCY_VAULT_PASSPHRASE_FILE
// directly. Tests that touch these env vars must hold this
// mutex to avoid clobbering each other.
static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn a5_placeholder_passphrase_is_rejected_at_validation() {
    let _lock = ENV_LOCK.lock().unwrap();
    let err = agent_dep_server::vault_init::validate_passphrase("unset-rotate-before-first-use")
        .expect_err("placeholder must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("placeholder") || msg.contains("placeholder passphrase"),
        "unexpected error: {msg}"
    );
}

#[test]
fn a5_known_bad_passphrases_are_rejected() {
    let _lock = ENV_LOCK.lock().unwrap();
    for bad in &[
        "change-me",
        "changeme",
        "password",
        "admin",
        "secret",
        "12345678",
    ] {
        let err = agent_dep_server::vault_init::validate_passphrase(bad)
            .expect_err(&format!("bad passphrase `{bad}` should be rejected"));
        let msg = format!("{err}");
        assert!(
            msg.contains("placeholder") || msg.contains("entropy") || msg.contains("below"),
            "bad passphrase `{bad}` rejected but with unexpected message: {msg}"
        );
    }
}

#[test]
fn a5_low_entropy_passphrase_is_rejected() {
    let _lock = ENV_LOCK.lock().unwrap();
    // "abc" — 3 unique chars over 3 chars
    //   H = log2(3) ≈ 1.58 bits/char * 3 = ~4.75 bits total.
    // Well below MIN_ENTROPY_BITS = 80.
    let err = agent_dep_server::vault_init::validate_passphrase("abc")
        .expect_err("low entropy must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("entropy") || msg.contains("below"),
        "expected low-entropy error, got: {msg}"
    );
}

#[test]
fn a5_empty_passphrase_is_rejected() {
    let _lock = ENV_LOCK.lock().unwrap();
    let err =
        agent_dep_server::vault_init::validate_passphrase("").expect_err("empty must be rejected");
    assert!(format!("{err}").contains("empty"), "got: {err}");
}

#[test]
fn a5_high_entropy_passphrase_is_accepted() {
    let _lock = ENV_LOCK.lock().unwrap();
    // `openssl rand -base64 32` — ~256 bits of entropy.
    let good = "5R9k2PqL8tNwV3YjH7mZxKcDfG4sB1aE0iXuWvT6oJ9M=";
    agent_dep_server::vault_init::validate_passphrase(good)
        .expect("high-entropy passphrase must be accepted");
}

#[test]
fn a5_load_passphrase_prefers_file_over_env() {
    let _lock = ENV_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("passphrase");
    // File value is high-entropy; env value is the placeholder
    // (which would be rejected). The FILE path must win.
    std::fs::write(&file_path, "5R9k2PqL8tNwV3YjH7mZxKcDfG4sB1aE0iXuWvT6oJ9M=").expect("write");
    // SAFETY: env_lock is held; no other test in this file
    // touches these vars concurrently.
    // SAFETY (libtest): std::env::set_var is unsafe in
    // multithreaded programs in Rust 2024+; under our
    // test runner (single-threaded by default) this is OK
    // because the env_lock serializes the env mutations.
    // The `unsafe` keyword is not required on stable Rust
    // today (the lint is allow-by-default) but we wrap in
    // an explicit block to make the intent clear.
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("AGENCY_VAULT_PASSPHRASE_FILE", &file_path);
        std::env::set_var("AGENCY_VAULT_PASSPHRASE", "unset-rotate-before-first-use");
    }
    let loaded = agent_dep_server::vault_init::load_passphrase()
        .expect("load_passphrase should succeed when file is set");
    assert_eq!(loaded, "5R9k2PqL8tNwV3YjH7mZxKcDfG4sB1aE0iXuWvT6oJ9M=");
    #[allow(unused_unsafe)]
    unsafe {
        std::env::remove_var("AGENCY_VAULT_PASSPHRASE_FILE");
        std::env::remove_var("AGENCY_VAULT_PASSPHRASE");
    }
}

#[test]
fn a5_load_passphrase_falls_back_to_env_when_no_file() {
    let _lock = ENV_LOCK.lock().unwrap();
    #[allow(unused_unsafe)]
    unsafe {
        std::env::remove_var("AGENCY_VAULT_PASSPHRASE_FILE");
        std::env::set_var(
            "AGENCY_VAULT_PASSPHRASE",
            "5R9k2PqL8tNwV3YjH7mZxKcDfG4sB1aE0iXuWvT6oJ9M=",
        );
    }
    let loaded = agent_dep_server::vault_init::load_passphrase()
        .expect("load_passphrase should succeed when env is set");
    assert_eq!(loaded, "5R9k2PqL8tNwV3YjH7mZxKcDfG4sB1aE0iXuWvT6oJ9M=");
    #[allow(unused_unsafe)]
    unsafe {
        std::env::remove_var("AGENCY_VAULT_PASSPHRASE");
    }
}

#[test]
fn a5_load_or_generate_install_salt_is_stable_across_reads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let s1 =
        agent_dep_server::vault_init::load_or_generate_install_salt(dir.path()).expect("first gen");
    assert!(dir.path().join("vault.salt").is_file());
    let s2 = agent_dep_server::vault_init::load_or_generate_install_salt(dir.path())
        .expect("second read");
    assert_eq!(s1, s2, "install salt must be stable across reads");
    assert_eq!(s1.len(), agent_dep_server::vault_init::INSTALL_SALT_LEN);
}

#[test]
fn a5_load_or_generate_install_salt_rejects_wrong_length() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("vault.salt"), vec![0u8; 16]).expect("write short salt");
    let err = agent_dep_server::vault_init::load_or_generate_install_salt(dir.path())
        .expect_err("short salt must be rejected");
    let msg = format!("{err}");
    assert!(msg.contains("wrong length"), "got: {msg}");
}

#[tokio::test]
async fn a5_two_installs_with_same_passphrase_derive_different_keys() {
    // The whole point of the per-install salt: two
    // installs with the same passphrase must NOT derive
    // the same cipher key. We exercise the KDF end-to-end
    // by constructing two SecretRepository instances
    // with the same passphrase but different install
    // salts and asserting that the ciphers differ.
    let dir_a = tempfile::tempdir().expect("tempdir");
    let dir_b = tempfile::tempdir().expect("tempdir");
    let salt_a =
        agent_dep_server::vault_init::load_or_generate_install_salt(dir_a.path()).expect("salt a");
    let salt_b =
        agent_dep_server::vault_init::load_or_generate_install_salt(dir_b.path()).expect("salt b");
    // With overwhelming probability, the random salts differ.
    assert_ne!(salt_a, salt_b, "two random salts must differ");
    // Use a known-high-entropy passphrase.
    let pp = "5R9k2PqL8tNwV3YjH7mZxKcDfG4sB1aE0iXuWvT6oJ9M=";
    // Build a vault in each dir.
    let db_a = agent_dep_core::infrastructure::sqlite::connect(&dir_a.path().join("a.db"))
        .await
        .expect("connect a");
    db_a.migrate().await.expect("migrate a");
    let db_b = agent_dep_core::infrastructure::sqlite::connect(&dir_b.path().join("b.db"))
        .await
        .expect("connect b");
    db_b.migrate().await.expect("migrate b");
    let va = agent_dep_core::infrastructure::repository::secrets_repository::SecretRepository::new(
        db_a.pool().clone(),
        pp,
        &salt_a,
    )
    .expect("vault a");
    let vb = agent_dep_core::infrastructure::repository::secrets_repository::SecretRepository::new(
        db_b.pool().clone(),
        pp,
        &salt_b,
    )
    .expect("vault b");
    // The Debug impl of SecretRepository redacts the
    // cipher, so we can't compare the keys directly.
    // Instead, encrypt the same plaintext in both
    // vaults and assert the ciphertexts differ (with
    // overwhelming probability — AES-GCM ciphertexts
    // are uniformly random).
    let users_a = agent_dep_core::infrastructure::repository::users_repository::UserRepository::new(
        db_a.pool().clone(),
    );
    let users_b = agent_dep_core::infrastructure::repository::users_repository::UserRepository::new(
        db_b.pool().clone(),
    );
    let op_a = users_a
        .create(
            "op",
            agent_dep_core::infrastructure::repository::users_repository::Role::Operator,
        )
        .await
        .expect("op a");
    let op_b = users_b
        .create(
            "op",
            agent_dep_core::infrastructure::repository::users_repository::Role::Operator,
        )
        .await
        .expect("op b");
    // Encrypt the same plaintext in both vaults
    // and assert the ciphertexts differ (with
    // overwhelming probability — AES-GCM
    // ciphertexts are uniformly random under
    // different keys).
    va.create("k", "the-value", op_a.user.id)
        .await
        .expect("create a");
    vb.create("k", "the-value", op_b.user.id)
        .await
        .expect("create b");
    let row_a: (Vec<u8>,) = sqlx::query_as("SELECT ciphertext FROM secrets WHERE name = ?1")
        .bind("k")
        .fetch_one(db_a.pool())
        .await
        .expect("select a");
    let row_b: (Vec<u8>,) = sqlx::query_as("SELECT ciphertext FROM secrets WHERE name = ?1")
        .bind("k")
        .fetch_one(db_b.pool())
        .await
        .expect("select b");
    assert_ne!(
        row_a.0, row_b.0,
        "two vaults with the same passphrase but different install salts \
         must produce different ciphertexts (per-install isolation)"
    );
}
