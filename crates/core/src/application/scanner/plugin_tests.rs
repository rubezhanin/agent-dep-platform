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
