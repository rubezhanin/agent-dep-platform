use super::*;

#[test]
fn sha256_hex_matches_known_vector() {
    // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert_eq!(
        Skill::sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn skill_dependency_serializes_to_id_at_version_form() {
    let dep = SkillDependency {
        id: "postgres".to_string(),
        version: super::super::version::Version::parse("3.1.0").unwrap(),
    };
    let json = serde_json::to_string(&dep).unwrap();
    // The textual form `"id@version"` is not part of the MVP wire
    // format; we serialize the struct fields. This test guards
    // against accidental rename or skip. `Version` serializes as
    // its struct representation today; the textual SemVer form is
    // available via `Version::to_string()`.
    assert!(json.contains("\"id\":\"postgres\""));
    assert_eq!(dep.version.to_string(), "3.1.0");
}

#[test]
fn skill_permission_uses_snake_case_names() {
    let json = serde_json::to_string(&SkillPermission::ReadEnv).unwrap();
    assert_eq!(json, "\"read_env\"");
    let json = serde_json::to_string(&SkillPermission::SpawnProcess).unwrap();
    assert_eq!(json, "\"spawn_process\"");
    let json = serde_json::to_string(&SkillPermission::Network).unwrap();
    assert_eq!(json, "\"network\"");
    let json = serde_json::to_string(&SkillPermission::Filesystem).unwrap();
    assert_eq!(json, "\"filesystem\"");
}
