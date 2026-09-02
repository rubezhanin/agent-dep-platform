//! Integration test: ingest the real upstream `agency-agents` catalog
//! and verify the result.
//!
//! This test is gated on the catalog existing. The location is taken
//! from the `AGENCY_AGENTS_DIR` environment variable; if that is unset
//! the test is skipped (not failed) so the suite still runs in CI.
//! See `AGENTS.md` for the convention.

use agent_dep_core::application::ingest::IngestService;
use agent_dep_core::domain::source::{Source, SourceKind};
use std::path::PathBuf;

fn real_agency_agents_path() -> Option<PathBuf> {
    let raw = std::env::var_os("AGENCY_AGENTS_DIR")?;
    let p = PathBuf::from(raw);
    if p.join("divisions.json").exists() && p.join("agents").is_dir() {
        Some(p)
    } else {
        None
    }
}

#[test]
fn ingest_real_agency_agents_catalog() {
    let Some(root) = real_agency_agents_path() else {
        eprintln!("skip: upstream `agency-agents` catalog not present in any known location");
        return;
    };

    let source = Source::new(SourceKind::local(root.clone()));
    let svc = IngestService::new();
    let (result, report) = svc.ingest_local(&source, None).expect("ingest real catalog");

    // The seed catalog ships 3 demo agents in `agents/engineering/`.
    assert!(
        result.agents.len() >= 3,
        "expected at least 3 demo agents, got {}",
        result.agents.len()
    );
    assert_eq!(report.agents_parsed, result.agents.len() as u32);

    // Spot-check the known IDs.
    let ids: Vec<&str> = result.agents.iter().map(|a| a.id.as_str()).collect();
    for expected in [
        "backend-engineer",
        "frontend-architect",
        "devops-specialist",
    ] {
        assert!(
            ids.contains(&expected),
            "missing expected agent id `{expected}`; got {ids:?}"
        );
    }

    // Division count should be 1 (engineering).
    assert_eq!(result.divisions.len(), 1);
    assert!(result.divisions.get("engineering").is_some());

    // Snapshot identity is non-empty and deterministic.
    assert_eq!(result.snapshot.commit_sha.len(), 64);

    // Re-ingestion yields the same commit (idempotent).
    let (again, _) = svc.ingest_local(&source, None).expect("re-ingest");
    assert_eq!(result.snapshot.commit_sha, again.snapshot.commit_sha);

    // Each agent has a body and a body hash.
    for a in &result.agents {
        assert!(!a.body.is_empty(), "agent `{}` has empty body", a.id);
        assert_eq!(a.body_hash.len(), 64, "agent `{}` bad body_hash", a.id);
    }
}
