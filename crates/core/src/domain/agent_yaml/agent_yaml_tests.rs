use super::*;

const VALID: &str = r#"$schema: "https://schemas.agent-dep.platform/agent/v1.json"
apiVersion: agency/v1
kind: Agent
metadata:
  id: backend-architect
  name: Backend Architect
  version: 2.4.0
  description: Designs backend architectures and APIs.
  tags:
    - backend
    - api
spec:
  instructions: instructions.md
  skills:
    - ref: postgres@3.1.0
    - ref: api-design@2.2.0
  runtime:
    hermes:
      supported: true
"#;

#[test]
fn parses_minimal_valid_manifest() {
    let y = parse_agent_yaml(VALID).expect("valid");
    assert_eq!(y.metadata.id, "backend-architect");
    assert_eq!(y.metadata.version, "2.4.0");
    assert_eq!(y.spec.instructions, "instructions.md");
    assert_eq!(y.spec.skills.len(), 2);
    assert!(y.spec.runtime.hermes.supported);
}

#[test]
fn rejects_wrong_schema_url() {
    let bad = VALID.replace("agent/v1.json", "wrong.json");
    let err = parse_agent_yaml(&bad).expect_err("wrong schema");
    assert!(err.contains("unsupported $schema"));
}

#[test]
fn rejects_wrong_api_version() {
    let bad = VALID.replace("agency/v1", "agency/v2");
    let err = parse_agent_yaml(&bad).expect_err("wrong api version");
    assert!(err.contains("unsupported apiVersion"));
}

#[test]
fn rejects_wrong_kind() {
    let bad = VALID.replace("kind: Agent", "kind: Skill");
    let err = parse_agent_yaml(&bad).expect_err("wrong kind");
    assert!(err.contains("unsupported kind"));
}

#[test]
fn rejects_invalid_semver_in_metadata_version() {
    let bad = VALID.replace("version: 2.4.0", "version: 2.4");
    let err = parse_agent_yaml(&bad).expect_err("bad version");
    assert!(err.contains("not a valid SemVer"));
}

#[test]
fn rejects_skill_ref_without_at_sign() {
    let bad = VALID.replace("postgres@3.1.0", "postgres");
    let err = parse_agent_yaml(&bad).expect_err("bad ref");
    assert!(err.contains("id@version"));
}

#[test]
fn rejects_missing_runtime_hermes_supported() {
    let bad = r#"$schema: "https://schemas.agent-dep.platform/agent/v1.json"
apiVersion: agency/v1
kind: Agent
metadata:
  id: a
  name: A
  version: 1.0.0
  description: d
spec:
  instructions: instructions.md
  runtime:
    hermes: {}
"#;
    let err = parse_agent_yaml(bad).expect_err("missing supported");
    assert!(err.to_lowercase().contains("missing field")
        || err.to_lowercase().contains("supported"));
}

#[test]
fn rejects_empty_required_metadata_field() {
    let bad = VALID.replace("name: Backend Architect", "name: \"\"");
    let err = parse_agent_yaml(&bad).expect_err("empty name");
    assert!(err.contains("non-empty"));
}
