//! Tests for `PlanService`.

use super::*;
use crate::application::compose::CompositionService;
use crate::domain::agent::Agent;
use crate::domain::system::{
    AgentRef, ParsedSystemFile, ResolvedAgent, System, SystemAgentRef, SystemFile,
    SystemMetadata, SystemSpec, SystemSpecV1,
};
use crate::domain::version::Version;
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

fn make_system() -> crate::domain::system::System {
    let agents = vec![
        make_agent("be", "1.0.0"),
        make_agent("fe", "1.0.0"),
        make_agent("devops", "0.9.0"),
    ];
    let file = SystemFile {
        api_version: "agent-dep/v1".to_string(),
        kind: "System".to_string(),
        metadata: SystemMetadata {
            id: "saas".to_string(),
            name: "SaaS".to_string(),
            description: None,
        },
        spec: SystemSpecV1 {
            source: "agency-agents".to_string(),
            agents: vec![
                SystemAgentRef {
                    agent_ref: AgentRef {
                        id: "be".to_string(),
                        version: Version::new(1, 0, 0),
                    },
                    r#override: None,
                },
                SystemAgentRef {
                    agent_ref: AgentRef {
                        id: "fe".to_string(),
                        version: Version::new(1, 0, 0),
                    },
                    r#override: None,
                },
                SystemAgentRef {
                    agent_ref: AgentRef {
                        id: "devops".to_string(),
                        version: Version::new(0, 9, 0),
                    },
                    r#override: None,
                },
            ],
        },
    };
    CompositionService::new()
        .compose(Uuid::nil(), Uuid::nil(), &agents, &[], &ParsedSystemFile::V1(file))
        .expect("compose")
}

#[test]
fn plan_for_emits_add_per_resolved_agent() {
    let sys = make_system();
    let plan = PlanService::new().plan_for(&sys, None);
    assert_eq!(plan.system_id, "saas");
    assert_eq!(plan.operations.len(), 3);
    for op in &plan.operations {
        assert_eq!(op.kind, PlanOperationKind::Add);
        assert!(
            op.target.starts_with("agent:"),
            "target should be `agent:...`"
        );
        assert!(op.reason.contains("saas"));
    }
    let targets: Vec<&str> = plan.operations.iter().map(|o| o.target.as_str()).collect();
    assert!(targets.contains(&"agent:be@1.0.0"));
    assert!(targets.contains(&"agent:fe@1.0.0"));
    assert!(targets.contains(&"agent:devops@0.9.0"));
    assert_eq!(plan.risk, PlanRisk::Low);
}

#[test]
fn plan_for_empty_system_is_empty_plan() {
    let sys = System {
        metadata: SystemMetadata {
            id: "x".to_string(),
            name: "X".to_string(),
            description: None,
        },
        spec: SystemSpec {
            runtime_type: "hermes".to_string(),
            source: "x".to_string(),
            agents: vec![],
            skills: vec![],
            project_root: None,
        },
        source_id: Uuid::nil(),
        snapshot_id: Uuid::nil(),
        // Unusual state (the composer would reject empty agents),
        // but the planner should still be well-defined.
        resolved: vec![ResolvedAgent {
            agent: make_agent("be", "1.0.0"),
            from_ref: AgentRef {
                id: "be".to_string(),
                version: Version::new(1, 0, 0),
            },
            applied_override: None,
        }],
        resolved_skills: vec![],
    };
    let plan = PlanService::new().plan_for(&sys, None);
    assert_eq!(plan.operations.len(), 1);
    assert_eq!(plan.risk, PlanRisk::Low);
}

#[test]
fn plan_for_emits_noop_when_actual_sha_matches_desired() {
    use std::collections::HashMap;
    let mut sys = make_system();
    // The fixture's `be@1.0.0` body is "You are be.\n" with
    // body_hash "deadbeef" (the placeholder we set in
    // `make_agent`). The map below claims the on-disk file
    // for `be@1.0.0` already has the same hash. The plan
    // should mark `be@1.0.0` as Noop and the other two as
    // Add.
    let mut actual: HashMap<String, String> = HashMap::new();
    actual.insert("be@1.0.0".to_string(), "deadbeef".to_string());
    let plan = PlanService::new().plan_for(&sys, Some(&actual));

    let be = plan
        .operations
        .iter()
        .find(|o| o.target == "agent:be@1.0.0")
        .expect("be op");
    assert_eq!(be.kind, PlanOperationKind::Noop);
    assert!(be.reason.contains("nothing to write"));

    for op in &plan.operations {
        if op.target != "agent:be@1.0.0" {
            assert_eq!(op.kind, PlanOperationKind::Add);
        }
    }
}

#[test]
fn plan_for_emits_add_when_actual_sha_mismatches() {
    use std::collections::HashMap;
    let sys = make_system();
    let mut actual: HashMap<String, String> = HashMap::new();
    actual.insert(
        "be@1.0.0".to_string(),
        "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    );
    let plan = PlanService::new().plan_for(&sys, Some(&actual));
    let be = plan
        .operations
        .iter()
        .find(|o| o.target == "agent:be@1.0.0")
        .expect("be op");
    assert_eq!(be.kind, PlanOperationKind::Add);
}
