use crate::adapter::RuntimeAdapter;
use crate::detection::detect_hermes;
use crate::hermes_adapter::{HermesAdapter, ProbeStatus};
use crate::router_plugin::{AgentFile, RouterPluginInputs};
use crate::types::ArtifactHealthStatus;
use std::collections::BTreeMap;

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

fn sha_of(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(text.as_bytes());
    hex::encode(h.finalize())
}

#[test]
fn health_reports_all_current_after_deploy() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = HermesAdapter::new(dir.path().to_path_buf());
    let inputs = sample_inputs();
    let layout = adapter.deploy(&inputs).expect("deploy");

    // Baseline = exactly the files the deploy wrote, with the
    // hashes the adapter computed. All entries should be
    // `Current` and the report's `ok` should be true.
    let mut baseline = BTreeMap::new();
    baseline.insert(
        format!(
            "plugins/{}/manifest.yaml",
            inputs.plugin_id
        ),
        layout.manifest_sha256.clone(),
    );
    let skill_entry = std::fs::read_to_string(&layout.entry_point_path)
        .expect("read SKILL.md");
    baseline.insert(
        format!("plugins/{}/SKILL.md", inputs.plugin_id),
        sha_of(&skill_entry),
    );
    for p in &layout.skill_paths {
        // Build the relative path manually: every skill lives
        // under `plugin_dir/<filename>`. `strip_prefix` is
        // fragile on Windows because of `\\?\` UNC prefixes
        // returned by `tempfile::tempdir()`; relative-to-plugin
        // is the path `health()` actually uses anyway.
        let file_name = p
            .file_name()
            .expect("skill path has a file name")
            .to_string_lossy()
            .to_string();
        let rel = format!("plugins/{}/skills/{}", inputs.plugin_id, file_name);
        let body = std::fs::read_to_string(p).expect("read skill");
        baseline.insert(rel, sha_of(&body));
    }
    let _ = dir;

    let report = adapter
        .health(&inputs.plugin_id, &baseline)
        .expect("health");
    assert!(report.ok, "report should be ok: {report:?}");
    assert_eq!(report.plugin_id, inputs.plugin_id);
    assert!(report.artifacts.len() >= 3, "at least 3 artifacts: {report:?}");
    for a in &report.artifacts {
        assert_eq!(a.status, ArtifactHealthStatus::Current, "{a:?}");
    }
}

#[test]
fn health_detects_modified_file() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = HermesAdapter::new(dir.path().to_path_buf());
    let inputs = sample_inputs();
    let layout = adapter.deploy(&inputs).expect("deploy");

    // Mutate the manifest on disk.
    let manifest_path = layout.manifest_path.clone();
    let original = std::fs::read_to_string(&manifest_path).expect("read");
    std::fs::write(&manifest_path, format!("{original}\n# tampered\n"))
        .expect("write tampered");

    // Build baseline from the *original* deploy hashes.
    let mut baseline = BTreeMap::new();
    baseline.insert(
        format!("plugins/{}/manifest.yaml", inputs.plugin_id),
        layout.manifest_sha256.clone(),
    );
    let skill_entry = std::fs::read_to_string(&layout.entry_point_path)
        .expect("read SKILL.md");
    baseline.insert(
        format!("plugins/{}/SKILL.md", inputs.plugin_id),
        sha_of(&skill_entry),
    );

    let report = adapter
        .health(&inputs.plugin_id, &baseline)
        .expect("health");
    assert!(!report.ok, "modified manifest must fail the report");
    let manifest_health = report
        .artifacts
        .iter()
        .find(|a| a.target.ends_with("manifest.yaml"))
        .expect("manifest in report");
    assert_eq!(manifest_health.status, ArtifactHealthStatus::Modified);
}

#[test]
fn health_marks_missing_baseline_file() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = HermesAdapter::new(dir.path().to_path_buf());
    let inputs = sample_inputs();
    adapter.deploy(&inputs).expect("deploy");

    // Baseline claims a file that does NOT exist on disk.
    let mut baseline = BTreeMap::new();
    baseline.insert(
        format!("plugins/{}/manifest.yaml", inputs.plugin_id),
        "deadbeef".repeat(8),
    );
    baseline.insert(
        format!("plugins/{}/skills/ghost.md", inputs.plugin_id),
        "cafebabe".repeat(8),
    );

    let report = adapter
        .health(&inputs.plugin_id, &baseline)
        .expect("health");
    assert!(!report.ok);
    let ghost = report
        .artifacts
        .iter()
        .find(|a| a.target.ends_with("ghost.md"))
        .expect("ghost in report");
    assert_eq!(ghost.status, ArtifactHealthStatus::Missing);
    assert!(ghost.observed_sha256.is_none());
}

#[test]
fn health_marks_foreign_file() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = HermesAdapter::new(dir.path().to_path_buf());
    let inputs = sample_inputs();
    adapter.deploy(&inputs).expect("deploy");

    // Drop a hand-written file into the plugin tree. The
    // adapter did not produce it, so it must be flagged as
    // `Foreign`.
    let extra = dir
        .path()
        .join("plugins")
        .join(&inputs.plugin_id)
        .join("README.md");
    std::fs::write(&extra, "hi\n").expect("write extra");

    let baseline: BTreeMap<String, String> = BTreeMap::new();
    let report = adapter
        .health(&inputs.plugin_id, &baseline)
        .expect("health");
    assert!(!report.ok, "foreign file must fail the report");
    let readme = report
        .artifacts
        .iter()
        .find(|a| a.target.ends_with("README.md"))
        .expect("readme in report");
    assert_eq!(readme.status, ArtifactHealthStatus::Foreign);
    assert!(readme.expected_sha256.is_none());
    assert!(readme.observed_sha256.is_some());
}

#[test]
fn health_on_missing_plugin_dir_reports_baseline_as_missing() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = HermesAdapter::new(dir.path().to_path_buf());
    // No deploy happened at all.
    let mut baseline = BTreeMap::new();
    baseline.insert(
        "plugins/agency-agents-router/manifest.yaml".to_string(),
        "deadbeef".repeat(8),
    );
    let report = adapter
        .health("agency-agents-router", &baseline)
        .expect("health");
    assert!(!report.ok);
    assert_eq!(report.artifacts.len(), 1);
    assert_eq!(report.artifacts[0].status, ArtifactHealthStatus::Missing);
}

#[test]
fn health_on_missing_plugin_dir_with_empty_baseline_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = HermesAdapter::new(dir.path().to_path_buf());
    let report = adapter
        .health("agency-agents-router", &BTreeMap::new())
        .expect("health");
    assert!(report.ok, "empty baseline + missing dir is vacuously healthy");
    assert!(report.artifacts.is_empty());
}

// ---------------------------------------------------------------------------
// Structural probe (1.4.0, ADR-0012)
// ---------------------------------------------------------------------------

#[test]
fn probe_reports_ok_after_fresh_deploy() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = HermesAdapter::new(dir.path().to_path_buf());
    adapter.deploy(&sample_inputs()).expect("deploy");
    let report = adapter.probe("agency-agents-router").expect("probe");
    assert!(report.ok, "fresh deploy should pass: {report:?}");
    assert!(report
        .checks
        .iter()
        .all(|c| c.name == "plugin_dir"
            || c.name == "manifest.yaml"
            || c.name == "SKILL.md"
            || c.name.starts_with("skills/")));
    // One check per agent file plus the three fixed ones.
    // `sample_inputs` ships one agent, so 1 + 3 = 4.
    assert_eq!(report.checks.len(), 4);
}

#[test]
fn probe_reports_missing_when_plugin_dir_absent() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = HermesAdapter::new(dir.path().to_path_buf());
    let report = adapter.probe("nope").expect("probe");
    assert!(!report.ok);
    assert_eq!(report.checks.len(), 1);
    assert_eq!(report.checks[0].name, "plugin_dir");
    assert_eq!(report.checks[0].status, ProbeStatus::Missing);
}

#[test]
fn probe_reports_error_when_manifest_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = HermesAdapter::new(dir.path().to_path_buf());
    adapter.deploy(&sample_inputs()).expect("deploy");
    // Remove the manifest but leave the dir + SKILL.md.
    std::fs::remove_file(
        dir.path()
            .join("plugins/agency-agents-router/manifest.yaml"),
    )
    .expect("remove manifest");
    let report = adapter.probe("agency-agents-router").expect("probe");
    assert!(!report.ok);
    let manifest_check = report
        .checks
        .iter()
        .find(|c| c.name == "manifest.yaml")
        .expect("manifest check present");
    assert_eq!(manifest_check.status, ProbeStatus::Error);
}

#[test]
fn probe_reports_missing_when_skill_md_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = HermesAdapter::new(dir.path().to_path_buf());
    adapter.deploy(&sample_inputs()).expect("deploy");
    let path = dir.path().join("plugins/agency-agents-router/SKILL.md");
    std::fs::write(&path, "").expect("truncate");
    let report = adapter.probe("agency-agents-router").expect("probe");
    assert!(!report.ok);
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "SKILL.md")
        .expect("SKILL.md check");
    assert_eq!(check.status, ProbeStatus::Missing);
}

#[test]
fn probe_reports_mismatch_when_manifest_references_missing_agent() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = HermesAdapter::new(dir.path().to_path_buf());
    let mut inputs = sample_inputs();
    // Add a phantom agent the materializer does not write out.
    inputs
        .agent_files
        .push(AgentFile { slug: "phantom".to_string(), body: "# phantom".to_string() });
    // The materializer writes skills/<slug>.md for every
    // agent, so to provoke a real mismatch we instead drop
    // one of the real skill files post-deploy.
    adapter.deploy(&inputs).expect("deploy");
    let removed = dir
        .path()
        .join("plugins/agency-agents-router/skills/backend-engineer.md");
    std::fs::remove_file(&removed).expect("remove");
    let report = adapter.probe("agency-agents-router").expect("probe");
    assert!(!report.ok);
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "skills/backend-engineer.md")
        .expect("backend-engineer check");
    assert_eq!(check.status, ProbeStatus::Mismatch);
}

#[test]
fn probe_ok_flag_reflects_every_check() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = HermesAdapter::new(dir.path().to_path_buf());
    adapter.deploy(&sample_inputs()).expect("deploy");
    // Tamper: zero out SKILL.md.
    let path = dir.path().join("plugins/agency-agents-router/SKILL.md");
    std::fs::write(&path, "   \n   ").expect("blank out");
    let report = adapter.probe("agency-agents-router").expect("probe");
    assert!(!report.ok, "tampered SKILL.md must flip the top-level ok");
    assert!(report
        .checks
        .iter()
        .any(|c| c.name == "SKILL.md" && c.status == ProbeStatus::Missing));
}
