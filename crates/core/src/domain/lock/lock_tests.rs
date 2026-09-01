use super::*;

fn sample() -> LockFile {
    LockFile::from_resolved(
        "git@github.com:rubezhanin/agency-agents",
        "5308f3fcb30a5c28d0da5d89c2aee90d9fdf9784ddb4a06931bc8b8bde6263b5",
        &[
            ("backend-engineer".to_string(), Version::parse("1.0.0").unwrap()),
            ("frontend-architect".to_string(), Version::parse("1.0.0").unwrap()),
        ],
        &[("observability".to_string(), Version::parse("2.0.1").unwrap())],
    )
}

#[test]
fn from_resolved_pins_all_versions() {
    let f = sample();
    assert_eq!(f.lock_version, 1);
    assert_eq!(f.agents.len(), 2);
    assert_eq!(f.skills.len(), 1);
    assert_eq!(f.renderers.len(), 1);
    assert!(f.renderers.contains_key("hermes-router"));
    assert_eq!(
        f.agents.get("backend-engineer").map(String::as_str),
        Some("1.0.0")
    );
}

#[test]
fn round_trip_yaml_is_byte_stable() {
    let a = sample();
    let ya = a.to_yaml().unwrap();
    let b = LockFile::from_yaml(&ya).expect("parse");
    let yb = b.to_yaml().unwrap();
    assert_eq!(ya, yb, "two serializations must match");
    assert_eq!(a, b, "round trip must preserve data");
}

#[test]
fn rejects_unsupported_lock_version() {
    let mut f = sample();
    f.lock_version = 99;
    let yaml = f.to_yaml().unwrap();
    let err = LockFile::from_yaml(&yaml).expect_err("rejects new version");
    assert!(err.contains("unsupported lockVersion"));
}

#[test]
fn rejects_empty_repository() {
    let mut f = sample();
    f.source.repository = String::new();
    let yaml = f.to_yaml().unwrap();
    let err = LockFile::from_yaml(&yaml).expect_err("empty repo");
    assert!(err.contains("source.repository"));
}

#[test]
fn rejects_empty_commit() {
    let mut f = sample();
    f.source.commit = String::new();
    let yaml = f.to_yaml().unwrap();
    let err = LockFile::from_yaml(&yaml).expect_err("empty commit");
    assert!(err.contains("source.commit"));
}

#[test]
fn rejects_empty_agent_key() {
    let mut f = sample();
    f.agents.insert(String::new(), "1.0.0".to_string());
    let yaml = f.to_yaml().unwrap();
    let err = LockFile::from_yaml(&yaml).expect_err("empty agent key");
    assert!(err.contains("agents key"));
}

#[test]
fn rejects_invalid_semver_in_agent() {
    let mut f = sample();
    f.agents
        .insert("bogus".to_string(), "not-a-version".to_string());
    let yaml = f.to_yaml().unwrap();
    let err = LockFile::from_yaml(&yaml).expect_err("bad semver");
    assert!(err.contains("invalid SemVer"));
}

#[test]
fn deterministic_agents_order() {
    // Insert in different orders; the serialized form must
    // match (BTreeMap guarantees lexicographic key order).
    let mut a = LockFile::from_resolved("r", "c", &[], &[]);
    let mut b = LockFile::from_resolved("r", "c", &[], &[]);
    a.agents.insert("zeta".to_string(), "1.0.0".to_string());
    a.agents.insert("alpha".to_string(), "2.0.0".to_string());
    b.agents.insert("alpha".to_string(), "2.0.0".to_string());
    b.agents.insert("zeta".to_string(), "1.0.0".to_string());
    assert_eq!(a.to_yaml().unwrap(), b.to_yaml().unwrap());
}

#[test]
fn agent_versions_returns_typed_pairs() {
    let f = sample();
    let versions = f.agent_versions().expect("parse");
    assert_eq!(versions.len(), 2);
    for (id, v) in &versions {
        assert_eq!(v.to_string(), f.agents.get(id).cloned().unwrap_or_default());
    }
}
