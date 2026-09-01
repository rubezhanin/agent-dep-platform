use super::*;

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
        agent_files: vec![
            AgentFile {
                slug: "backend-engineer".to_string(),
                body: "# Backend Engineer\n\nYou build APIs.\n".to_string(),
            },
            AgentFile {
                slug: "frontend-architect".to_string(),
                body: "# Frontend Architect\n\nYou architect SPAs.\n".to_string(),
            },
        ],
    }
}

#[test]
fn materialize_writes_plugin_tree() {
    let home = tempfile::tempdir().unwrap();
    let layout = materialize_router_plugin(home.path(), &sample_inputs()).expect("ok");
    assert!(layout.plugin_dir.is_dir());
    assert!(layout.manifest_path.is_file());
    assert!(layout.entry_point_path.is_file());
    assert!(layout.skills_dir.is_dir());
    assert_eq!(layout.skill_paths.len(), 2);
    for p in &layout.skill_paths {
        assert!(p.is_file(), "missing: {p:?}");
    }
    assert_eq!(layout.catalog_commit_sha, "abc123");
    assert_eq!(layout.manifest_sha256.len(), 64);
    assert_eq!(layout.skills_sha256.len(), 64);
}

#[test]
fn materialize_is_byte_deterministic() {
    let home1 = tempfile::tempdir().unwrap();
    let home2 = tempfile::tempdir().unwrap();
    let a = materialize_router_plugin(home1.path(), &sample_inputs()).unwrap();
    let b = materialize_router_plugin(home2.path(), &sample_inputs()).unwrap();
    let ma = std::fs::read(a.manifest_path).unwrap();
    let mb = std::fs::read(b.manifest_path).unwrap();
    assert_eq!(ma, mb, "manifest must be byte-identical");
    let ea = std::fs::read(a.entry_point_path).unwrap();
    let eb = std::fs::read(b.entry_point_path).unwrap();
    assert_eq!(ea, eb, "entry point must be byte-identical");
}

#[test]
fn materialize_sorts_agent_files_by_slug() {
    let home = tempfile::tempdir().unwrap();
    let mut inputs = sample_inputs();
    // Swap order: should still produce the same files.
    inputs.agent_files = inputs.agent_files.into_iter().rev().collect();
    let layout = materialize_router_plugin(home.path(), &inputs).unwrap();
    let names: Vec<String> = layout
        .skill_paths
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert_eq!(
        names,
        vec!["backend-engineer.md".to_string(), "frontend-architect.md".to_string()]
    );
}

#[test]
fn materialize_rejects_unsafe_plugin_id() {
    let home = tempfile::tempdir().unwrap();
    let mut inputs = sample_inputs();
    inputs.plugin_id = "../etc".to_string();
    let err = materialize_router_plugin(home.path(), &inputs).expect_err("escape");
    let s = format!("{err:?}");
    assert!(s.contains("plugin_id") || s.contains("outside"), "got: {s}");
}

#[test]
fn materialize_rejects_unsafe_agent_slug() {
    let home = tempfile::tempdir().unwrap();
    let mut inputs = sample_inputs();
    inputs.agent_files[0].slug = "evil/../path".to_string();
    let err = materialize_router_plugin(home.path(), &inputs).expect_err("bad slug");
    let s = format!("{err:?}");
    assert!(s.contains("agent.slug") || s.contains("outside"), "got: {s}");
}

#[test]
fn materialize_rejects_empty_agent_list() {
    let home = tempfile::tempdir().unwrap();
    let mut inputs = sample_inputs();
    inputs.agent_files.clear();
    let err = materialize_router_plugin(home.path(), &inputs).expect_err("empty");
    assert!(format!("{err:?}").contains("at least one"));
}

#[test]
fn manifest_yaml_contains_required_fields() {
    let home = tempfile::tempdir().unwrap();
    let layout = materialize_router_plugin(home.path(), &sample_inputs()).unwrap();
    let text = std::fs::read_to_string(layout.manifest_path).unwrap();
    assert!(text.contains("manifest_version: 1"));
    assert!(text.contains("id: agency-agents-router"));
    assert!(text.contains("type: router"));
    assert!(text.contains("entry: SKILL.md"));
    assert!(text.contains("ref: abc123"));
    assert!(text.contains("routing: kanban"));
    assert!(text.contains("auto_install_hermes: false"));
    assert!(text.contains("  - id: backend-engineer"));
    assert!(text.contains("  - id: frontend-architect"));
}

#[test]
fn entry_point_mentions_all_four_router_tools() {
    let home = tempfile::tempdir().unwrap();
    let layout = materialize_router_plugin(home.path(), &sample_inputs()).unwrap();
    let text = std::fs::read_to_string(layout.entry_point_path).unwrap();
    for tool in &sample_inputs().router_skills {
        assert!(text.contains(tool), "missing tool: {tool}");
    }
}
