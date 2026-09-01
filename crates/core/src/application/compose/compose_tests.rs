//! Tests for `CompositionService`.

use super::*;
use crate::domain::agent::Agent;
use crate::domain::system::{AgentRef, SystemAgentRef, SystemFile, SystemMetadata, SystemSpec};
use crate::domain::version::Version;
use crate::error::CoreError;
use uuid::Uuid;

fn make_agent(id: &str, version: &str) -> Agent {
    Agent {
        snapshot_id: Uuid::nil(),
        id: id.to_string(),
        division: "engineering".to_string(),
        name: format!("{id} display"),
        display_name: None,
        role: "role".to_string(),
        description: "desc".to_string(),
        version: Version::parse(version).unwrap(),
        sensitive: false,
        tools: vec![],
        activation_phrases: vec![],
        body: "body".to_string(),
        body_hash: "deadbeef".to_string(),
    }
}

fn make_file(refs: &[(&str, &str)]) -> SystemFile {
    SystemFile {
        api_version: "agent-dep/v1".to_string(),
        kind: "System".to_string(),
        metadata: SystemMetadata {
            id: "saas-platform".to_string(),
            name: "SaaS Platform".to_string(),
            description: None,
        },
        spec: SystemSpec {
            source: "agency-agents".to_string(),
            agents: refs
                .iter()
                .map(|(id, v)| SystemAgentRef {
                    agent_ref: AgentRef {
                        id: (*id).to_string(),
                        version: Version::parse(v).unwrap(),
                    },
                    r#override: None,
                })
                .collect(),
        },
    }
}

#[test]
fn compose_resolves_single_ref() {
    let svc = CompositionService::new();
    let agents = vec![make_agent("be", "1.0.0"), make_agent("fe", "1.0.0")];
    let file = make_file(&[("be", "1.0.0")]);
    let sys = svc
        .compose(Uuid::nil(), Uuid::nil(), &agents, &file)
        .expect("compose");
    assert_eq!(sys.metadata.id, "saas-platform");
    assert_eq!(sys.resolved.len(), 1);
    assert_eq!(sys.resolved[0].agent.id, "be");
    assert_eq!(sys.resolved[0].agent.version, Version::new(1, 0, 0));
}

#[test]
fn compose_resolves_multiple_refs_in_spec_order() {
    let svc = CompositionService::new();
    let agents = vec![
        make_agent("be", "1.0.0"),
        make_agent("fe", "1.0.0"),
        make_agent("devops", "1.0.0"),
    ];
    let file = make_file(&[("devops", "1.0.0"), ("be", "1.0.0"), ("fe", "1.0.0")]);
    let sys = svc
        .compose(Uuid::nil(), Uuid::nil(), &agents, &file)
        .unwrap();
    let order: Vec<&str> = sys.resolved.iter().map(|r| r.agent.id.as_str()).collect();
    assert_eq!(order, vec!["devops", "be", "fe"]);
}

#[test]
fn compose_rejects_unknown_ref() {
    let svc = CompositionService::new();
    let agents = vec![make_agent("be", "1.0.0")];
    let file = make_file(&[("nope", "1.0.0")]);
    let err = svc
        .compose(Uuid::nil(), Uuid::nil(), &agents, &file)
        .expect_err("unknown ref");
    let msg = err.to_string();
    assert!(msg.contains("agent:nope@1.0.0"), "msg: {msg}");
}

#[test]
fn compose_rejects_wrong_version() {
    let svc = CompositionService::new();
    let agents = vec![make_agent("be", "1.0.0")];
    let file = make_file(&[("be", "2.0.0")]);
    let err = svc
        .compose(Uuid::nil(), Uuid::nil(), &agents, &file)
        .expect_err("wrong version");
    let msg = err.to_string();
    assert!(msg.contains("agent:be@2.0.0"));
    // The error should surface the known versions.
    assert!(msg.contains("1.0.0"), "should list known versions: {msg}");
}

#[test]
fn compose_rejects_duplicate_ref() {
    let svc = CompositionService::new();
    let agents = vec![make_agent("be", "1.0.0")];
    let file = make_file(&[("be", "1.0.0"), ("be", "1.0.0")]);
    let err = svc
        .compose(Uuid::nil(), Uuid::nil(), &agents, &file)
        .expect_err("duplicate");
    assert!(err.to_string().contains("duplicate agent ref"));
}

#[test]
fn compose_rejects_unsupported_api_version() {
    let svc = CompositionService::new();
    let mut file = make_file(&[("be", "1.0.0")]);
    file.api_version = "agent-dep/v2".to_string();
    let agents = vec![make_agent("be", "1.0.0")];
    let err = svc
        .compose(Uuid::nil(), Uuid::nil(), &agents, &file)
        .expect_err("bad api version");
    assert!(err.to_string().contains("apiVersion"));
}

#[test]
fn compose_rejects_wrong_kind() {
    let svc = CompositionService::new();
    let mut file = make_file(&[("be", "1.0.0")]);
    file.kind = "NotSystem".to_string();
    let agents = vec![make_agent("be", "1.0.0")];
    let err = svc
        .compose(Uuid::nil(), Uuid::nil(), &agents, &file)
        .expect_err("bad kind");
    assert!(err.to_string().contains("expected kind"));
}

#[test]
fn compose_rejects_empty_agents() {
    let svc = CompositionService::new();
    let file = make_file(&[]);
    let agents = vec![];
    let err = svc
        .compose(Uuid::nil(), Uuid::nil(), &agents, &file)
        .expect_err("empty");
    assert!(err.to_string().contains("at least one"));
}

#[test]
fn compose_rejects_empty_metadata_id() {
    let svc = CompositionService::new();
    let mut file = make_file(&[("be", "1.0.0")]);
    file.metadata.id = "  ".to_string();
    let agents = vec![make_agent("be", "1.0.0")];
    let err = svc
        .compose(Uuid::nil(), Uuid::nil(), &agents, &file)
        .expect_err("empty id");
    assert!(err.to_string().contains("metadata.id"));
}

#[test]
fn compose_applies_display_name_override() {
    use crate::domain::system::AgentOverride;
    let svc = CompositionService::new();
    let agents = vec![make_agent("be", "1.0.0")];
    let mut file = make_file(&[("be", "1.0.0")]);
    file.spec.agents[0].r#override = Some(AgentOverride {
        display_name: Some("Senior Backend Engineer".to_string()),
        role: Some("lead backend".to_string()),
        description: None,
    });
    let sys = svc
        .compose(Uuid::nil(), Uuid::nil(), &agents, &file)
        .unwrap();
    assert_eq!(
        sys.resolved[0].agent.display_name.as_deref(),
        Some("Senior Backend Engineer")
    );
    assert_eq!(sys.resolved[0].agent.role, "lead backend");
    assert_eq!(sys.resolved[0].agent.description, "desc"); // unchanged
}

#[test]
fn compose_sets_source_and_snapshot_id() {
    let svc = CompositionService::new();
    let agents = vec![make_agent("be", "1.0.0")];
    let file = make_file(&[("be", "1.0.0")]);
    let sid = Uuid::new_v4();
    let snap = Uuid::new_v4();
    let sys = svc.compose(sid, snap, &agents, &file).unwrap();
    assert_eq!(sys.source_id, sid);
    assert_eq!(sys.snapshot_id, snap);
}

// Smoke check: CoreError::ErrDependencyMissing carries the right
// fields (so the error type evolves predictably).
#[test]
fn core_error_dependency_missing_shape() {
    let e = CoreError::ErrDependencyMissing {
        dependency: "agent:be@1.0.0".to_string(),
        required_by: "system:saas".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("agent:be@1.0.0"));
    assert!(s.contains("system:saas"));
}
