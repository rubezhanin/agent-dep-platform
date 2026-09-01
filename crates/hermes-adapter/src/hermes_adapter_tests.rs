use crate::adapter::RuntimeAdapter;
use crate::detection::detect_hermes;
use crate::router_plugin::{AgentFile, RouterPluginInputs};
use crate::hermes_adapter::HermesAdapter;

#[test]
fn detect_returns_not_found_when_home_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let result = detect_hermes(dir.path());
    assert!(matches!(
        result,
        Err(agent_dep_core::error::CoreError::ErrHermesNotFound)
    ));
}

#[test]
fn hermes_adapter_struct_can_be_constructed() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = HermesAdapter::new(dir.path().to_path_buf());
    assert_eq!(adapter.hermes_home(), dir.path());
}

fn sample_inputs() -> RouterPluginInputs {
    RouterPluginInputs {
        plugin_id: "agency-agents-router".to_string(),
        display_name: "Agency Agents Router".to_string(),
        description: "Routes the agency-agents catalog.".to_string(),
        catalog_source: "github:rubezhanin/agency-agents".to_string(),
        catalog_commit_sha: "abc123".to_string(),
        router_skills: vec![
            "agency_agents_search".to_string(),
            "agency_agents_inspect".to_string(),
            "agency_agents_load".to_string(),
            "agency_agents_delegate".to_string(),
        ],
        agent_files: vec![AgentFile {
            slug: "backend-engineer".to_string(),
            body: "# Backend Engineer\n\nYou build APIs.\n".to_string(),
        }],
    }
}

#[test]
fn plan_returns_inputs_unchanged_in_mvp() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = HermesAdapter::new(dir.path().to_path_buf());
    let inputs = sample_inputs();
    let planned = adapter.plan(&inputs).expect("plan");
    assert_eq!(planned.plugin_id, inputs.plugin_id);
    assert_eq!(planned.agent_files.len(), inputs.agent_files.len());
    assert_eq!(planned.catalog_commit_sha, inputs.catalog_commit_sha);
}

#[test]
fn deploy_writes_plugin_through_adapter() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = HermesAdapter::new(dir.path().to_path_buf());
    let inputs = sample_inputs();
    let layout = adapter.deploy(&inputs).expect("deploy");
    assert!(layout.plugin_dir.is_dir());
    assert!(layout.manifest_path.is_file());
    assert!(layout.entry_point_path.is_file());
    assert_eq!(layout.skill_paths.len(), 1);
}

#[test]
fn verify_passes_after_deploy() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = HermesAdapter::new(dir.path().to_path_buf());
    let inputs = sample_inputs();
    adapter.deploy(&inputs).expect("deploy");
    adapter.verify().expect("verify ok");
}

#[test]
fn verify_passes_on_empty_hermes_home() {
    // No `plugins/` dir at all: nothing to verify, success.
    let dir = tempfile::tempdir().unwrap();
    let adapter = HermesAdapter::new(dir.path().to_path_buf());
    adapter.verify().expect("verify empty home");
}

#[test]
fn deploy_rejects_unsafe_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = HermesAdapter::new(dir.path().to_path_buf());
    let mut inputs = sample_inputs();
    inputs.plugin_id = "../escape".to_string();
    let err = adapter.deploy(&inputs).expect_err("unsafe plugin_id");
    let s = format!("{err:?}");
    assert!(s.contains("plugin_id") || s.contains("outside"), "got: {s}");
}
