use super::*;

const VALID: &str = r#"$schema: "https://schemas.agent-dep.platform/skill/v1.json"
apiVersion: agency/v1
kind: Skill
metadata:
  id: postgres
  name: PostgreSQL
  version: 3.1.0
  description: PostgreSQL design, migrations and diagnostics.
  tags:
    - postgres
    - database
spec:
  body: SKILL.md
  dependencies:
    - id: api-design
      version: 2.2.0
  permissions:
    - read_env
    - network
"#;

#[test]
fn parses_minimal_valid_manifest() {
    let y = parse_skill_yaml(VALID).expect("valid");
    assert_eq!(y.metadata.id, "postgres");
    assert_eq!(y.metadata.version, "3.1.0");
    assert_eq!(y.spec.body, "SKILL.md");
    assert_eq!(y.spec.dependencies.len(), 1);
    assert_eq!(y.spec.permissions.len(), 2);
}

#[test]
fn rejects_wrong_schema_url() {
    let bad = r#"$schema: "https://example.com/wrong.json"
apiVersion: agency/v1
kind: Skill
metadata:
  id: a
  name: A
  version: 1.0.0
  description: d
spec:
  body: SKILL.md
"#;
    let err = parse_skill_yaml(bad).expect_err("wrong schema");
    assert!(err.contains("unsupported $schema"));
}

#[test]
fn rejects_wrong_api_version() {
    let bad = r#"$schema: "https://schemas.agent-dep.platform/skill/v1.json"
apiVersion: agency/v2
kind: Skill
metadata:
  id: a
  name: A
  version: 1.0.0
  description: d
spec:
  body: SKILL.md
"#;
    let err = parse_skill_yaml(bad).expect_err("wrong api version");
    assert!(err.contains("unsupported apiVersion"));
}

#[test]
fn rejects_wrong_kind() {
    let bad = r#"$schema: "https://schemas.agent-dep.platform/skill/v1.json"
apiVersion: agency/v1
kind: Agent
metadata:
  id: a
  name: A
  version: 1.0.0
  description: d
spec:
  body: SKILL.md
"#;
    let err = parse_skill_yaml(bad).expect_err("wrong kind");
    assert!(err.contains("unsupported kind"));
}

#[test]
fn rejects_invalid_semver_in_metadata_version() {
    let bad = r#"$schema: "https://schemas.agent-dep.platform/skill/v1.json"
apiVersion: agency/v1
kind: Skill
metadata:
  id: a
  name: A
  version: not-a-version
  description: d
spec:
  body: SKILL.md
"#;
    let err = parse_skill_yaml(bad).expect_err("bad version");
    assert!(err.contains("not a valid SemVer"));
}

#[test]
fn rejects_invalid_semver_in_dependency_version() {
    let bad = r#"$schema: "https://schemas.agent-dep.platform/skill/v1.json"
apiVersion: agency/v1
kind: Skill
metadata:
  id: a
  name: A
  version: 1.0.0
  description: d
spec:
  body: SKILL.md
  dependencies:
    - id: b
      version: also-not-a-version
"#;
    let err = parse_skill_yaml(bad).expect_err("bad dep version");
    assert!(err.contains("dependency `b`"));
}

#[test]
fn rejects_empty_required_metadata_field() {
    let bad = r#"$schema: "https://schemas.agent-dep.platform/skill/v1.json"
apiVersion: agency/v1
kind: Skill
metadata:
  id: ""
  name: A
  version: 1.0.0
  description: d
spec:
  body: SKILL.md
"#;
    let err = parse_skill_yaml(bad).expect_err("empty id");
    assert!(err.contains("non-empty"));
}

#[test]
fn rejects_unknown_top_level_field() {
    let bad = r#"$schema: "https://schemas.agent-dep.platform/skill/v1.json"
apiVersion: agency/v1
kind: Skill
metadata:
  id: a
  name: A
  version: 1.0.0
  description: d
spec:
  body: SKILL.md
extra: oops
"#;
    let err = parse_skill_yaml(bad).expect_err("extra field");
    assert!(err.to_lowercase().contains("unknown field") || err.contains("extra"));
}

#[test]
fn permission_yaml_maps_to_domain_enum() {
    let p: SkillPermission = SkillPermissionYaml::ReadEnv.into();
    assert_eq!(p, SkillPermission::ReadEnv);
    let p: SkillPermission = SkillPermissionYaml::Filesystem.into();
    assert_eq!(p, SkillPermission::Filesystem);
}
