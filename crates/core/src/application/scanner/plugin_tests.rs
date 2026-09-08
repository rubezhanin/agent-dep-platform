//! 2.7.0 plugin scanner tests (ADR-0028).
//!
//! Two categories:
//!  - JSON envelope parse / rule-prefix tests
//!    (no exec).
//!  - End-to-end exec tests using a small
//!    shell script as the "plugin binary".
//!    The tests use a tempdir + a POSIX shell
//!    script. On Windows, the same test path
//!    uses `cmd.exe` (see `bin` below).

use std::fs;
use std::path::PathBuf;

use super::*;

fn fresh_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("catalog");
    fs::create_dir_all(&path).unwrap();
    (dir, path)
}

#[test]
fn missing_binary_errors() {
    let (_dir, root) = fresh_dir();
    let scanner = PluginScanner::new("missing", "/no/such/binary");
    let result = scanner.scan(&root, &ScanPolicy::mvp_default());
    assert!(result.is_err(), "missing binary must error");
}

#[cfg(unix)]
#[test]
fn rule_prefix_added_for_unprefixed_rules() {
    // The plugin emits a finding with rule
    // "secret.custom-token" (no prefix). The
    // scanner renames it to
    // "plugin.myplugin.secret.custom-token" so
    // the operator can tell which scanner
    // produced it.
    let (dir, root) = fresh_dir();
    fs::write(root.join("a.md"), "harmless").unwrap();
    let script = dir.path().join("plugin.sh");
    fs::write(
        &script,
        r#"#!/bin/sh
# Echo back one finding with an unprefixed rule.
cat <<'EOF'
{"findings":[{"severity":"WARN","rule":"secret.custom-token","path":"a.md","reason":"test"}]}
EOF
"#,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();
    }
    let scanner = PluginScanner::new("myplugin", &script);
    let findings = scanner
        .scan(&root, &ScanPolicy::mvp_default())
        .expect("scan");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule, "plugin.myplugin.secret.custom-token");
    assert_eq!(findings[0].severity, Severity::Warn);
}

#[cfg(unix)]
#[test]
fn rule_prefix_preserved_when_already_prefixed() {
    // If the plugin already emits a
    // "plugin.<name>.<rule>" rule, the scanner
    // does NOT re-prefix. This lets a plugin
    // group its findings under sub-namespaces
    // (e.g. "plugin.semgrep.security.tainted-env").
    let (dir, root) = fresh_dir();
    fs::write(root.join("a.md"), "harmless").unwrap();
    let script = dir.path().join("plugin.sh");
    fs::write(
        &script,
        r#"#!/bin/sh
cat <<'EOF'
{"findings":[{"severity":"BLOCK","rule":"plugin.myplugin.security.tainted-env","path":"a.md","reason":"test"}]}
EOF
"#,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();
    }
    let scanner = PluginScanner::new("myplugin", &script);
    let findings = scanner
        .scan(&root, &ScanPolicy::mvp_default())
        .expect("scan");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule, "plugin.myplugin.security.tainted-env");
}

#[cfg(unix)]
#[test]
fn plugin_failure_produces_exec_failed_finding() {
    // The plugin exits non-zero. The scanner
    // returns a synthetic WARN finding tagged
    // `plugin.<name>.exec-failed` so the
    // operator sees the failure in the SARIF
    // / text output.
    let (dir, root) = fresh_dir();
    let script = dir.path().join("plugin.sh");
    fs::write(
        &script,
        r#"#!/bin/sh
echo "broken plugin" 1>&2
exit 1
"#,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();
    }
    let scanner = PluginScanner::new("broken", &script);
    let findings = scanner
        .scan(&root, &ScanPolicy::mvp_default())
        .expect("scan");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule, "plugin.broken.exec-failed");
    assert_eq!(findings[0].severity, Severity::Warn);
    assert!(findings[0].reason.contains("exit"));
}

// -----------------------------------------------------------------------
// P0-ENV-01 (TZ #2 WP-1.1, CWE-200):
// plugin env isolation. The pre-fix code
// spawned the plugin with `Command::new(bin)`
// and called `.env("AGENCY_PLUGIN_NAME", ...)`
// / `.env("AGENCY_ROOT", ...)` — without
// `env_clear()`. The child inherited the
// parent's full environment, including
// `AGENCY_VAULT_PASSPHRASE`,
// `AGENCY_ADMIN_TOKEN`, and any other
// secret-bearing env vars. A compromised
// plugin could exfiltrate them.
//
// The post-fix code builds an explicit
// whitelist via `PluginScanner::plugin_safe_env`.
// This test asserts the whitelist shape
// directly, without spawning a process —
// the test is hermetic and CI-friendly.
// -----------------------------------------------------------------------

#[test]
fn plugin_safe_env_excludes_sensitive_parent_env() {
    // We DO NOT set any parent env vars for
    // this test (the `plugin_safe_env` helper
    // reads the parent env at call time, so
    // we cannot influence it from inside
    // the test in a multi-threaded process
    // anyway). We assert on the SHAPE of the
    // whitelist: only the documented vars
    // are present, and no `AGENCY_*` other
    // than the two contract vars is.
    let dir = tempfile::tempdir().expect("tempdir");
    let env = PluginScanner::plugin_safe_env("test-plugin", dir.path());
    let keys: std::collections::HashSet<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
    // The 6 documented entries must all be
    // present.
    for required in &[
        "PATH",
        "HOME",
        "TMPDIR",
        "LANG",
        "AGENCY_PLUGIN_NAME",
        "AGENCY_ROOT",
    ] {
        assert!(
            keys.contains(required),
            "plugin_safe_env MUST include {required}; got {keys:?}"
        );
    }
    // Nothing else. In particular, no
    // sensitive AGENCY_* vars.
    for forbidden in &[
        "AGENCY_VAULT_PASSPHRASE",
        "AGENCY_ADMIN_TOKEN",
        "AGENCY_BIND_IP",
        "AGENCY_BIND_PORT",
        "AGENCY_OIDC_ISSUER",
        "AGENCY_OIDC_CLIENT_SECRET",
        "AGENCY_OIDC_JWKS_URL",
        "AGENCY_DB_URL",
    ] {
        assert!(
            !keys.contains(forbidden),
            "plugin_safe_env MUST NOT include {forbidden}; got {keys:?}"
        );
    }
    // Exact count: 6 keys (PATH, HOME, TMPDIR,
    // LANG, AGENCY_PLUGIN_NAME, AGENCY_ROOT).
    // If a future change adds a 7th key, this
    // assertion will fire and force a review
    // of the security contract.
    assert_eq!(
        env.len(),
        6,
        "plugin_safe_env has unexpected number of entries: {env:?}"
    );
    // Spot-check the values for the two
    // contract vars.
    let plugin_name = env
        .iter()
        .find(|(k, _)| k == "AGENCY_PLUGIN_NAME")
        .map(|(_, v)| v.as_str())
        .expect("present");
    assert_eq!(plugin_name, "test-plugin");
    let root = env
        .iter()
        .find(|(k, _)| k == "AGENCY_ROOT")
        .map(|(_, v)| v.as_str())
        .expect("present");
    assert_eq!(root, dir.path().display().to_string());
}

#[test]
fn plugin_safe_env_ignores_parent_secret_env() {
    // This test demonstrates the post-fix
    // control: even if a parent env var is
    // set BEFORE this function is called,
    // `plugin_safe_env` returns ONLY the
    // whitelist. The whitelist copy from
    // the parent for the 4 generic OS vars
    // (`PATH` / `HOME` / `TMPDIR` / `LANG`)
    // is intentional and benign — those vars
    // are not secrets. For sensitive vars
    // like `AGENCY_VAULT_PASSPHRASE`, the
    // whitelist does NOT copy from the
    // parent at all, so a parent-set value
    // is dropped.
    //
    // We do NOT mutate the parent env (Rust
    // 2024 makes `set_var` unsafe in
    // multi-threaded contexts; the test
    // runner shares the process with other
    // tests). Instead, we rely on the
    // structural property: `plugin_safe_env`
    // builds a fresh `Vec<(String, String)>`
    // and never consults the parent for
    // `AGENCY_VAULT_PASSPHRASE` /
    // `AGENCY_ADMIN_TOKEN` / etc. The
    // `plugin_safe_env_excludes_sensitive_parent_env`
    // test above asserts the static
    // whitelist; this test asserts the
    // same property under a name that makes
    // the threat model explicit.
    let dir = tempfile::tempdir().expect("tempdir");
    let env = PluginScanner::plugin_safe_env("test-plugin", dir.path());
    // Regardless of what the parent has set
    // (we did not touch it), the returned
    // list does not contain any sensitive
    // `AGENCY_*` var. The pre-fix code did
    // not drop the parent env, so a plugin
    // could read `AGENCY_VAULT_PASSPHRASE`
    // from its own env; the post-fix code
    // does not pass any such var to the
    // child.
    let sensitive = [
        "AGENCY_VAULT_PASSPHRASE",
        "AGENCY_ADMIN_TOKEN",
        "AGENCY_OIDC_CLIENT_SECRET",
    ];
    for k in &sensitive {
        assert!(
            !env.iter().any(|(name, _)| name == k),
            "{k} MUST NOT appear in plugin_safe_env"
        );
    }
}

// -----------------------------------------------------------------------
// 2.7.2 plugin auto-discovery (ADR-0030)
// -----------------------------------------------------------------------

#[test]
fn discover_empty_dir() {
    let dir = tempfile::tempdir().unwrap();
    let found = discover_plugins(dir.path()).unwrap();
    assert!(found.is_empty());
}

#[test]
fn discover_nonexistent_dir_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist");
    let found = discover_plugins(&missing).unwrap();
    assert!(found.is_empty());
}

#[cfg(unix)]
#[test]
fn discover_picks_executable_sh() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("semgrep.sh");
    std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(&p).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&p, perms).unwrap();
    let found = discover_plugins(dir.path()).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].name, "semgrep");
    assert_eq!(found[0].binary, p);
}

#[cfg(unix)]
#[test]
fn discover_skips_non_executable() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("not-exec.sh");
    std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
    // Deliberately do NOT chmod_exec. The
    // file is non-executable and must be
    // skipped.
    let found = discover_plugins(dir.path()).unwrap();
    assert!(
        found.is_empty(),
        "non-executable must be skipped: {found:?}"
    );
}

#[test]
fn discover_skips_unknown_extension() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("README.md");
    std::fs::write(&p, "# docs").unwrap();
    let found = discover_plugins(dir.path()).unwrap();
    assert!(found.is_empty(), ".md must be ignored: {found:?}");
}

#[cfg(unix)]
#[test]
fn discover_name_uses_stem_not_full_basename() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("my-plugin.sh");
    std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(&p).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&p, perms).unwrap();
    let found = discover_plugins(dir.path()).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(
        found[0].name, "my-plugin",
        "name must be the file stem, not the basename"
    );
}

// -----------------------------------------------------------------------
// 2.7.3 plugin manifest (ADR-0031)
// -----------------------------------------------------------------------

#[test]
fn manifest_minimal_round_trip() {
    let bytes = br#"
name = "semgrep"
version = "0.1.0"
binary = "./semgrep.sh"
"#;
    let m = PluginManifest::parse(bytes).expect("parse");
    assert_eq!(m.name, "semgrep");
    assert_eq!(m.version, "0.1.0");
    assert_eq!(m.binary, "./semgrep.sh");
    assert_eq!(m.description, None);
    assert_eq!(m.author, None);
    assert!(m.env.is_empty());
    assert!(m.capabilities.is_empty());
}

#[test]
fn manifest_with_all_optional_fields() {
    let bytes = br#"
name = "semgrep"
version = "0.1.0"
binary = "./semgrep.sh"
description = "Semgrep SAST scanner"
author = "agency-team"
timeout_seconds = 60
max_output_bytes = 134217728
env = ["SEMGREP_SEND_METRICS=off", "X=1"]
capabilities = ["sast", "secrets"]
"#;
    let m = PluginManifest::parse(bytes).expect("parse");
    assert_eq!(m.description.as_deref(), Some("Semgrep SAST scanner"));
    assert_eq!(m.author.as_deref(), Some("agency-team"));
    assert_eq!(m.timeout_seconds, Some(60));
    assert_eq!(m.max_output_bytes, Some(134217728));
    assert_eq!(m.env, vec!["SEMGREP_SEND_METRICS=off", "X=1"]);
    assert_eq!(m.capabilities, vec!["sast", "secrets"]);
}

#[test]
fn manifest_rejects_empty_name() {
    let bytes = br#"
name = ""
version = "0.1.0"
binary = "./x.sh"
"#;
    let err = PluginManifest::parse(bytes).expect_err("must reject");
    assert!(format!("{err:?}").contains("name must not be empty"));
}

#[test]
fn manifest_rejects_empty_version() {
    let bytes = br#"
name = "x"
version = ""
binary = "./x.sh"
"#;
    let err = PluginManifest::parse(bytes).expect_err("must reject");
    assert!(format!("{err:?}").contains("version must not be empty"));
}

#[test]
fn manifest_rejects_empty_binary() {
    let bytes = br#"
name = "x"
version = "0.1.0"
binary = ""
"#;
    let err = PluginManifest::parse(bytes).expect_err("must reject");
    assert!(format!("{err:?}").contains("binary must not be empty"));
}

#[test]
fn manifest_rejects_malformed_toml() {
    let bytes = br#"
this is not = = = valid toml
"#;
    let err = PluginManifest::parse(bytes).expect_err("must reject");
    assert!(format!("{err:?}").contains("parse toml"));
}

#[test]
fn manifest_binary_path_resolves_relative() {
    let bytes = br#"
name = "x"
version = "0.1.0"
binary = "./x.sh"
"#;
    let m = PluginManifest::parse(bytes).expect("parse");
    let dir = std::path::Path::new("/opt/agency/scanners.d/x");
    let resolved = m.resolved_binary(dir);
    assert_eq!(
        resolved,
        std::path::PathBuf::from("/opt/agency/scanners.d/x/./x.sh")
    );
}

#[test]
fn manifest_binary_path_resolves_absolute() {
    let bytes = br#"
name = "x"
version = "0.1.0"
binary = "/usr/local/bin/x"
"#;
    let m = PluginManifest::parse(bytes).expect("parse");
    let dir = std::path::Path::new("/opt/agency/scanners.d/x");
    let resolved = m.resolved_binary(dir);
    assert_eq!(resolved, std::path::PathBuf::from("/usr/local/bin/x"));
}

#[test]
fn discover_picks_manifest_form() {
    let dir = tempfile::tempdir().unwrap();
    let plugin_dir = dir.path().join("semgrep");
    std::fs::create_dir(&plugin_dir).unwrap();
    std::fs::write(plugin_dir.join("semgrep.sh"), "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::write(
        plugin_dir.join("plugin.toml"),
        r#"
name = "semgrep"
version = "0.1.0"
binary = "./semgrep.sh"
"#,
    )
    .unwrap();
    let found = discover_plugins(dir.path()).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].name, "semgrep");
    assert_eq!(found[0].binary, plugin_dir.join("semgrep.sh"));
}

#[test]
fn discover_manifest_wins_over_bare_script() {
    // Both `semgrep/plugin.toml` (manifest) and
    // `semgrep.sh` (bare script) exist with the
    // same plugin name. The manifest wins.
    let dir = tempfile::tempdir().unwrap();
    let plugin_dir = dir.path().join("semgrep");
    std::fs::create_dir(&plugin_dir).unwrap();
    std::fs::write(plugin_dir.join("semgrep.sh"), "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::write(
        plugin_dir.join("plugin.toml"),
        r#"
name = "semgrep"
version = "0.1.0"
binary = "./semgrep.sh"
"#,
    )
    .unwrap();
    // Also create a bare top-level `semgrep.sh`.
    std::fs::write(dir.path().join("semgrep.sh"), "#!/bin/sh\nexit 0\n").unwrap();
    let found = discover_plugins(dir.path()).unwrap();
    assert_eq!(found.len(), 1, "manifest must win over bare script");
    assert_eq!(found[0].name, "semgrep");
    // Binary is the manifest's resolved path,
    // which is the plugin subdir's semgrep.sh
    // (not the top-level one).
    assert_eq!(found[0].binary, plugin_dir.join("semgrep.sh"));
}

#[test]
fn discover_skips_manifest_with_name_mismatch() {
    // The directory is named `semgrep` but the
    // manifest's `name` field is `other`. The
    // mismatch is a hard skip.
    let dir = tempfile::tempdir().unwrap();
    let plugin_dir = dir.path().join("semgrep");
    std::fs::create_dir(&plugin_dir).unwrap();
    std::fs::write(plugin_dir.join("semgrep.sh"), "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::write(
        plugin_dir.join("plugin.toml"),
        r#"
name = "other"
version = "0.1.0"
binary = "./semgrep.sh"
"#,
    )
    .unwrap();
    let found = discover_plugins(dir.path()).unwrap();
    // The mismatched manifest is skipped; the
    // top-level bare script would be picked
    // up, but the manifest takes precedence
    // and rejects it. In this case, the
    // manifest's name `other` doesn't match
    // the dir `semgrep`, so the manifest is
    // skipped. The result is the same as if
    // the directory was empty (the dir
    // contains no executable files at the
    // top level).
    assert!(
        found.is_empty(),
        "name-mismatched manifest must be skipped, got {found:?}"
    );
}

// ---------------------------------------------------------------------
// 2.7.4 (ADR-0032) — plugin manifest
// signature + trust store tests.
//
// These tests live in `plugin_tests.rs`
// rather than in `trust_store.rs`
// because they exercise the
// end-to-end `parse → verify` flow
// against a real `plugin.toml` byte
// buffer.
// ---------------------------------------------------------------------

use super::super::trust_store::TrustStore;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

/// Build a minimal `plugin.toml`
/// string and return
/// `(manifest_toml_bytes, base_payload_without_sig)`.
fn minimal_manifest_toml(name: &str) -> (String, String) {
    // Two-field payload; we keep it
    // simple so the canonical
    // re-serialisation is
    // deterministic.
    let payload = format!("name = \"{name}\"\nversion = \"1.0.0\"\nbinary = \"plugin.sh\"\n");
    (payload.clone(), payload)
}

/// Sign a manifest's canonical
/// bytes and return
/// `(signer_id, public_key_b64, signed_toml)`.
fn signed_manifest(name: &str) -> (String, String, String) {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let pk_bytes = sk.verifying_key().to_bytes();
    let pk_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk_bytes);
    let mut h = Sha256::new();
    h.update(pk_bytes);
    let signer_id = hex::encode(&h.finalize()[..8]);
    let (payload, _raw) = minimal_manifest_toml(name);
    let canonical = payload.as_bytes();
    let sig = sk.sign(canonical);
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let signed = format!("{payload}signer_id = \"{signer_id}\"\nsignature = \"{sig_b64}\"\n");
    (signer_id, pk_b64, signed)
}

fn trust_store_with(signer_id: &str, pk_b64: &str) -> TrustStore {
    // Build the trust store via the
    // public `parse` API (the
    // internal `signers` map is
    // private; constructing one
    // through a JSON document is
    // also a useful round-trip
    // test in its own right).
    let json = serde_json::json!({
        "signers": [{
            "id": signer_id,
            "public_key": pk_b64,
            "label": "test-signer",
        }]
    })
    .to_string();
    TrustStore::parse(json.as_bytes()).expect("parse trust store")
}

#[test]
fn manifest_parse_accepts_signed_toml() {
    let (_id, _pk, toml) = signed_manifest("good");
    let m = PluginManifest::parse(toml.as_bytes()).expect("parse signed");
    assert_eq!(m.name, "good");
    assert!(m.signature.is_some());
    assert!(m.signer_id.is_some());
}

#[test]
fn manifest_parse_rejects_partial_signature() {
    // signature present, no signer_id
    let bad = "name = \"x\"\nversion = \"1.0.0\"\nbinary = \"p.sh\"\nsignature = \"abc\"\n";
    let err = PluginManifest::parse(bad.as_bytes()).expect_err("must reject");
    assert!(format!("{err:?}").contains("signer_id"));

    // signer_id present, no signature
    let bad2 = "name = \"x\"\nversion = \"1.0.0\"\nbinary = \"p.sh\"\nsigner_id = \"abc\"\n";
    let err2 = PluginManifest::parse(bad2.as_bytes()).expect_err("must reject");
    assert!(format!("{err2:?}").contains("signature"));
}

#[test]
fn verify_signature_happy_path() {
    let (id, pk, toml) = signed_manifest("good");
    let ts = trust_store_with(&id, &pk);
    let m = PluginManifest::parse(toml.as_bytes()).expect("parse");
    m.verify_signature(&ts)
        .expect("valid signature must verify");
}

#[test]
fn verify_signature_rejects_unsigned_manifest() {
    // 2.7.4 production policy: an
    // unsigned manifest is REJECTED
    // outright, even when the
    // trust store is non-empty.
    let (payload, _raw) = minimal_manifest_toml("plain");
    let m = PluginManifest::parse(payload.as_bytes()).expect("parse");
    let (_id, pk, _toml) = signed_manifest("good");
    let ts = trust_store_with("anything", &pk);
    let err = m.verify_signature(&ts).expect_err("unsigned must reject");
    assert!(format!("{err:?}").contains("unsigned"));
}

#[test]
fn verify_signature_rejects_tampered_name() {
    // Sign a manifest with one
    // name; flip the name in the
    // bytes; verify fails.
    let (id, pk, toml) = signed_manifest("original");
    let ts = trust_store_with(&id, &pk);
    // Replace `original` with
    // `attacker` in the manifest
    // (after the signature is
    // computed).
    let tampered = toml.replace("original", "attacker");
    let m = PluginManifest::parse(tampered.as_bytes()).expect("parse");
    let err = m.verify_signature(&ts).expect_err("tampered must reject");
    assert!(format!("{err:?}").contains("signature verification failed"));
}

#[test]
fn verify_signature_rejects_wrong_signer() {
    // Sign with key A; trust store
    // has key B under the same id.
    let (id, _pk_a, toml) = signed_manifest("plug");
    let (_id2, pk_b, _toml2) = signed_manifest("plug");
    let ts = trust_store_with(&id, &pk_b);
    let m = PluginManifest::parse(toml.as_bytes()).expect("parse");
    let err = m.verify_signature(&ts).expect_err("wrong key must reject");
    assert!(format!("{err:?}").contains("signature verification failed"));
}

#[test]
fn verify_signature_rejects_unknown_signer() {
    let (_id, _pk, toml) = signed_manifest("plug");
    // Trust store is empty.
    let ts = TrustStore::default();
    let m = PluginManifest::parse(toml.as_bytes()).expect("parse");
    let err = m
        .verify_signature(&ts)
        .expect_err("unknown signer must reject");
    assert!(format!("{err:?}").contains("unknown signer"));
}

#[test]
fn canonical_bytes_strip_signature_and_signer_id() {
    let (_id, _pk, toml) = signed_manifest("plug");
    let m = PluginManifest::parse(toml.as_bytes()).expect("parse");
    let canonical = m.canonical_bytes().expect("canonical");
    let s = std::str::from_utf8(&canonical).expect("utf8");
    assert!(
        !s.contains("signature"),
        "canonical must strip signature: {s}"
    );
    assert!(
        !s.contains("signer_id"),
        "canonical must strip signer_id: {s}"
    );
    assert!(s.contains("plug"), "canonical must keep name: {s}");
}

// -----------------------------------------------------------------------
// 2.11.0 (P1-S-02, TZ #1 §9 / S-02,
// TZ #2 WP-1.2 / SEC-07,
// CWE-400 Uncontrolled Resource
// Consumption) — wall-clock timeout
// tests.
//
// The wall-clock timeout is the
// last-line defense against a
// runaway plugin: an infinite
// loop, a deadlock, or a
// network call that never
// returns would otherwise block
// the parent `agency catalog
// scan` process forever. The
// post-fix `PluginScanner::scan`
// polls `child.try_wait` every
// 100ms against a deadline
// (`AGENCY_PLUGIN_TIMEOUT_SECS`,
// default 30s); on timeout, it
// `child.kill()`s the plugin
// (SIGKILL on Unix,
// TerminateProcess on Windows),
// waits for the kernel to reap,
// and returns a synthetic
// `plugin.<name>.timed-out`
// finding so the operator sees
// the failure in the SARIF /
// text output. The two tests
// below use a short timeout (2s)
// and a 10s sleep so the test
// finishes in ~3-4s end-to-end
// even on a slow CI machine.
// -----------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn wall_clock_timeout_kills_runaway_plugin() {
    use std::time::Duration;
    // Set a 2-second timeout for
    // this test (the default is
    // 30s; the test would take
    // 30s+ otherwise). The env
    // var is read by
    // `default_timeout()` at
    // scan time, so it must be
    // set BEFORE the scan call.
    // The previous test's env
    // may have left a stale
    // value; `set_var` is the
    // only safe way to override
    // for this test (the helper
    // re-reads on every call).
    std::env::set_var("AGENCY_PLUGIN_TIMEOUT_SECS", "2");
    let (dir, root) = fresh_dir();
    // A 10s-sleep script. The
    // wall-clock timeout at 2s
    // is well under the sleep
    // duration, so the plugin
    // is guaranteed to be killed
    // before it exits
    // naturally.
    let script = dir.path().join("hanging_plugin.sh");
    fs::write(&script, "#!/bin/sh\nsleep 10\necho '{\"findings\":[]}'\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();
    }
    let scanner = PluginScanner::new("hanging", &script);
    let start = std::time::Instant::now();
    let findings = scanner
        .scan(&root, &ScanPolicy::mvp_default())
        .expect("scan must return Ok with a synthetic finding, not Err");
    let elapsed = start.elapsed();
    // The scanner must return
    // well before the script's
    // 10s sleep would have
    // completed. The deadline is
    // 2s + the 100ms poll
    // granularity, so we assert
    // < 5s to leave headroom on
    // a slow CI machine.
    assert!(
        elapsed < Duration::from_secs(5),
        "scan took {elapsed:?}; wall-clock timeout did not fire"
    );
    // The synthetic finding is
    // the ONLY result. The
    // rule prefix is
    // `plugin.<name>.timed-out`.
    assert_eq!(findings.len(), 1, "got: {findings:?}");
    assert_eq!(findings[0].rule, "plugin.hanging.timed-out");
    assert_eq!(findings[0].severity, Severity::Warn);
    assert!(
        findings[0].reason.contains("wall-clock timeout"),
        "reason should mention timeout: {}",
        findings[0].reason
    );
    assert!(
        findings[0].reason.contains("2s"),
        "reason should mention the timeout duration: {}",
        findings[0].reason
    );
    // Clean up the env var so
    // the next test inherits a
    // known default.
    std::env::remove_var("AGENCY_PLUGIN_TIMEOUT_SECS");
}

#[cfg(unix)]
#[test]
fn fast_plugin_completes_before_timeout() {
    // The timeout is set to 5s
    // (generous) and the plugin
    // exits in < 100ms. The
    // scanner must return the
    // plugin's findings verbatim
    // (no synthetic
    // `timed-out` finding).
    std::env::set_var("AGENCY_PLUGIN_TIMEOUT_SECS", "5");
    let (dir, root) = fresh_dir();
    fs::write(root.join("a.md"), "harmless").unwrap();
    let script = dir.path().join("fast_plugin.sh");
    fs::write(
        &script,
        r#"#!/bin/sh
cat <<'EOF'
{"findings":[{"severity":"INFO","rule":"custom.fast","path":"a.md","reason":"quick"}]}
EOF
"#,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();
    }
    let scanner = PluginScanner::new("fast", &script);
    let findings = scanner
        .scan(&root, &ScanPolicy::mvp_default())
        .expect("scan must return Ok");
    // The plugin's real
    // finding, NOT a
    // `timed-out` finding.
    assert_eq!(findings.len(), 1, "got: {findings:?}");
    assert_eq!(findings[0].rule, "plugin.fast.custom.fast");
    assert_eq!(findings[0].reason, "quick");
    std::env::remove_var("AGENCY_PLUGIN_TIMEOUT_SECS");
}
