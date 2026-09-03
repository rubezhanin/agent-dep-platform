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
use std::io::Write;
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
    assert_eq!(
        findings[0].rule,
        "plugin.myplugin.security.tainted-env"
    );
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
    assert_eq!(resolved, std::path::PathBuf::from("/opt/agency/scanners.d/x/./x.sh"));
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
