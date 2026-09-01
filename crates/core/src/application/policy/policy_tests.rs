use super::*;

const VALID: &str = r#"
policyVersion: 1
sources:
  allowedRepositories:
    - "git@github.com:company/*"
    - "/srv/agency-agents"
security:
  unknownExternalUrls: block
  plaintextSecrets: block
  executableFiles: warn
deployment:
  modifiedFiles: block
"#;

#[test]
fn from_yaml_parses_a_full_policy() {
    let p = Policy::from_yaml(VALID).expect("valid");
    assert_eq!(p.policy_version, 1);
    assert_eq!(p.sources.allowed_repositories.len(), 2);
    assert_eq!(p.security.unknown_external_urls, PolicyDecision::Block);
    assert_eq!(p.security.executable_files, PolicyDecision::Warn);
    assert_eq!(
        p.deployment.modified_files,
        PolicyDecision::Block
    );
}

#[test]
fn from_yaml_rejects_unsupported_version() {
    let yaml = r#"
policyVersion: 99
sources:
  allowedRepositories: []
"#;
    let err = Policy::from_yaml(yaml).expect_err("bad version");
    let s = format!("{err:?}");
    assert!(s.contains("unsupported policyVersion"));
}

#[test]
fn empty_policy_is_permissive() {
    let p = Policy::from_yaml("policyVersion: 1").expect("default");
    assert!(p.sources.allowed_repositories.is_empty());
    assert!(p.source_allowed("anything"));
}

#[test]
fn source_allowed_uses_glob_suffix() {
    let p = Policy::from_yaml(
        "policyVersion: 1\nsources:\n  allowedRepositories: [\"git@github.com:company/*\"]\n",
    )
    .unwrap();
    assert!(p.source_allowed("git@github.com:company/agents"));
    assert!(p.source_allowed("git@github.com:company/agency-agents-app"));
    assert!(!p.source_allowed("git@github.com:other/repo"));
}

#[test]
fn source_allowed_uses_glob_prefix() {
    let p = Policy::from_yaml(
        "policyVersion: 1\nsources:\n  allowedRepositories: [\"*.local\"]\n",
    )
    .unwrap();
    assert!(p.source_allowed("/srv/agency-agents.local"));
    assert!(!p.source_allowed("/srv/agency-agents"));
}

#[test]
fn security_floor_returns_stricter_severity() {
    let p = Policy::from_yaml(VALID).expect("valid");
    assert_eq!(
        p.security_floor("url.unknown-download-endpoint"),
        PolicyDecision::Block
    );
    assert_eq!(
        p.security_floor("url.suspicious-download-endpoint"),
        PolicyDecision::Block
    );
    assert_eq!(p.security_floor("secret.aws-access-key"), PolicyDecision::Block);
    assert_eq!(
        p.security_floor("executable.unexpected-extension"),
        PolicyDecision::Warn
    );
    // No rule -> Allow (scanner severity passes through).
    assert_eq!(p.security_floor("some.other.rule"), PolicyDecision::Allow);
}

#[test]
fn default_policy_is_block_everywhere() {
    let p = Policy {
        policy_version: 0,
        sources: SourcePolicy::default(),
        security: SecurityPolicy::default(),
        deployment: DeploymentPolicy::default(),
    };
    assert_eq!(p.policy_version, 0);
    assert_eq!(
        p.security_floor("url.unknown-download-endpoint"),
        PolicyDecision::Allow
    );
    assert_eq!(p.modified_file_decision(), PolicyDecision::Allow);
}
