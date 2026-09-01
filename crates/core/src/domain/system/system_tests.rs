use super::*;

#[test]
fn agent_ref_parse_valid() {
    let r = AgentRef::parse("backend-engineer@1.2.3").unwrap();
    assert_eq!(r.id, "backend-engineer");
    assert_eq!(r.version, super::super::version::Version::new(1, 2, 3));
    assert_eq!(format!("{r}"), "backend-engineer@1.2.3");
}

#[test]
fn agent_ref_parse_rejects_no_at() {
    assert!(AgentRef::parse("nope").is_err());
}

#[test]
fn agent_ref_parse_rejects_empty_id() {
    assert!(AgentRef::parse("@1.0.0").is_err());
}

#[test]
fn agent_ref_parse_rejects_bad_version() {
    assert!(AgentRef::parse("x@not-a-version").is_err());
}

#[test]
fn skill_ref_parse_valid() {
    let r = SkillRef::parse("postgres@3.1.0").unwrap();
    assert_eq!(r.id, "postgres");
    assert_eq!(r.version, super::super::version::Version::new(3, 1, 0));
}

#[test]
fn skill_ref_parse_rejects_no_at() {
    assert!(SkillRef::parse("nope").is_err());
}

// ----- v1 system file -----

#[test]
fn v1_system_file_deserialize_minimal() {
    let yaml = r#"
apiVersion: agent-dep/v1
kind: System
metadata:
  id: saas-platform
  name: SaaS Platform
spec:
  source: agency-agents
  agents:
    - ref: backend-engineer@1.0.0
    - ref: frontend-architect@1.0.0
"#;
    let f = SystemFile::from_yaml_v1(yaml).expect("parse v1");
    assert_eq!(f.metadata.id, "saas-platform");
    assert_eq!(f.kind, "System");
    assert_eq!(f.spec.agents.len(), 2);
    assert_eq!(f.spec.agents[0].agent_ref.id, "backend-engineer");
}

#[test]
fn v1_system_file_rejects_wrong_api_version() {
    let yaml = r#"
apiVersion: agency/v1
kind: System
metadata:
  id: x
  name: X
spec:
  source: s
  agents:
    - ref: a@1.0.0
"#;
    let err = SystemFile::from_yaml_v1(yaml).expect_err("v1 rejects v2 api");
    assert!(err.contains("unsupported apiVersion"));
}

#[test]
fn v1_system_file_rejects_empty_agents() {
    let yaml = r#"
apiVersion: agent-dep/v1
kind: System
metadata:
  id: x
  name: X
spec:
  source: s
  agents: []
"#;
    let err = SystemFile::from_yaml_v1(yaml).expect_err("empty agents");
    assert!(err.contains("at least one"));
}

// ----- v2 system file -----

const V2_MINIMAL: &str = r#"
$schema: "https://schemas.agent-dep.platform/system/v1.json"
apiVersion: agency/v1
kind: System
metadata:
  id: saas-platform
  name: SaaS Platform
  version: 1.8.0
  description: A minimal two-agent system.
spec:
  runtime:
    type: hermes
  agents:
    - ref: backend-architect@2.4.0
    - ref: database-engineer@1.3.0
  skills:
    - ref: observability@2.0.1
  project:
    root: ~/projects/my-saas
"#;

#[test]
fn v2_system_file_deserialize_minimal() {
    let f = SystemFileV2::from_yaml(V2_MINIMAL).expect("v2 minimal");
    assert_eq!(f.metadata.id, "saas-platform");
    assert_eq!(f.metadata.version.as_deref(), Some("1.8.0"));
    assert_eq!(f.spec.runtime.runtime_type, "hermes");
    assert_eq!(f.spec.agents.len(), 2);
    assert_eq!(f.spec.skills.len(), 1);
    assert_eq!(
        f.spec.project.as_ref().map(|p| p.root.as_str()),
        Some("~/projects/my-saas")
    );
}

#[test]
fn v2_system_file_with_only_skills_is_valid() {
    let yaml = r#"
$schema: "https://schemas.agent-dep.platform/system/v1.json"
apiVersion: agency/v1
kind: System
metadata:
  id: skills-only
  name: Skills Only
spec:
  runtime:
    type: hermes
  skills:
    - ref: observability@2.0.1
"#;
    let f = SystemFileV2::from_yaml(yaml).expect("skills-only");
    assert!(f.spec.agents.is_empty());
    assert_eq!(f.spec.skills.len(), 1);
}

#[test]
fn v2_system_file_rejects_non_hermes_runtime() {
    let yaml = r#"
$schema: "https://schemas.agent-dep.platform/system/v1.json"
apiVersion: agency/v1
kind: System
metadata:
  id: x
  name: X
spec:
  runtime:
    type: langchain
  agents:
    - ref: a@1.0.0
"#;
    let err = SystemFileV2::from_yaml(yaml).expect_err("non-hermes");
    assert!(err.contains("unsupported spec.runtime.type"));
}

#[test]
fn v2_system_file_rejects_wrong_schema_url() {
    let yaml = V2_MINIMAL.replace("system/v1.json", "wrong.json");
    let err = SystemFileV2::from_yaml(&yaml).expect_err("wrong schema");
    assert!(err.contains("unsupported $schema"));
}

#[test]
fn v2_system_file_rejects_invalid_metadata_version() {
    let yaml = V2_MINIMAL.replace("version: 1.8.0", "version: not-a-version");
    let err = SystemFileV2::from_yaml(&yaml).expect_err("bad metadata version");
    assert!(err.contains("not a valid SemVer"));
}

#[test]
fn v2_system_file_rejects_empty_agents_and_skills() {
    let yaml = r#"
$schema: "https://schemas.agent-dep.platform/system/v1.json"
apiVersion: agency/v1
kind: System
metadata:
  id: x
  name: X
spec:
  runtime:
    type: hermes
"#;
    let err = SystemFileV2::from_yaml(yaml).expect_err("nothing to deploy");
    assert!(err.contains("at least one agent or one skill"));
}

#[test]
fn v2_system_file_rejects_unknown_top_level_field() {
    let yaml = format!("{V2_MINIMAL}\nextra: oops\n");
    let err = SystemFileV2::from_yaml(&yaml).expect_err("extra field");
    assert!(err.to_lowercase().contains("unknown field") || err.contains("extra"));
}

// ----- auto-detect -----

#[test]
fn parse_system_file_dispatches_to_v1() {
    let yaml = r#"
apiVersion: agent-dep/v1
kind: System
metadata:
  id: x
  name: X
spec:
  source: s
  agents:
    - ref: a@1.0.0
"#;
    let p = parse_system_file(yaml).expect("auto v1");
    assert_eq!(p.format(), SystemFileFormat::V1);
}

#[test]
fn parse_system_file_dispatches_to_v2() {
    let p = parse_system_file(V2_MINIMAL).expect("auto v2");
    assert_eq!(p.format(), SystemFileFormat::V2);
}

#[test]
fn parse_system_file_rejects_unsupported_api_version() {
    let yaml = r#"
apiVersion: something-else/v9
kind: System
metadata:
  id: x
  name: X
spec:
  source: s
  agents:
    - ref: a@1.0.0
"#;
    let err = parse_system_file(yaml).expect_err("unsupported");
    assert!(err.contains("unsupported system file apiVersion"));
}
