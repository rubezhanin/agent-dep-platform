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
    let payload = format!(
        "name = \"{name}\"\nversion = \"1.0.0\"\nbinary = \"plugin.sh\"\n"
    );
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
    let sig_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let signed = format!(
        "{payload}signer_id = \"{signer_id}\"\nsignature = \"{sig_b64}\"\n"
    );
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
    let err = m
        .verify_signature(&ts)
        .expect_err("tampered must reject");
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
    let err = m
        .verify_signature(&ts)
        .expect_err("wrong key must reject");
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
    assert!(!s.contains("signature"), "canonical must strip signature: {s}");
    assert!(!s.contains("signer_id"), "canonical must strip signer_id: {s}");
    assert!(s.contains("plug"), "canonical must keep name: {s}");
}
