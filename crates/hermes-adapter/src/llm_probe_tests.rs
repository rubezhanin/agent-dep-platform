//! 2.7.4 LLM probe tests (ADR-0032).

use super::*;
use crate::hermes_adapter::{ProbeCheck, ProbeReport, ProbeStatus};

fn make_structural(ok: bool) -> ProbeReport {
    ProbeReport {
        plugin_id: "test-plugin".to_string(),
        ok,
        checks: vec![ProbeCheck {
            name: "manifest.yaml".to_string(),
            status: if ok {
                ProbeStatus::Ok
            } else {
                ProbeStatus::Missing
            },
            detail: "test".to_string(),
            sha256: None,
        }],
    }
}

#[test]
fn build_prompt_includes_manifest_skill_and_structural_summary() {
    let s = make_structural(true);
    let prompt = LlmProbe::build_prompt(
        &s,
        "name: my-plugin\nversion: 0.1.0",
        "# My Plugin\nDoes things.",
    );
    assert!(prompt.contains("manifest.yaml"));
    assert!(prompt.contains("name: my-plugin"));
    assert!(prompt.contains("SKILL.md"));
    assert!(prompt.contains("# My Plugin"));
    assert!(prompt.contains("PASSED"));
    assert!(prompt.contains("ok"));
    assert!(prompt.contains("detail"));
}

#[test]
fn build_prompt_marks_failed_structural() {
    let s = make_structural(false);
    let prompt = LlmProbe::build_prompt(&s, "manifest", "skill");
    assert!(prompt.contains("FAILED"));
    assert!(prompt.contains("manifest.yaml"));
    assert!(prompt.contains("MISSING"));
}

#[test]
fn parse_response_valid_ok() {
    let resp = r#"{"ok": true, "detail": "all good"}"#;
    let check = LlmProbe::parse_response(resp);
    assert_eq!(check.name, "llm_review");
    assert_eq!(check.status, ProbeStatus::Ok);
    assert_eq!(check.detail, "all good");
}

#[test]
fn parse_response_valid_error() {
    let resp = r#"{"ok": false, "detail": "manifest references agent X but SKILL.md does not document it"}"#;
    let check = LlmProbe::parse_response(resp);
    assert_eq!(check.status, ProbeStatus::Error);
    assert!(check.detail.contains("X"));
}

#[test]
fn parse_response_truncates_long_details() {
    let long_detail = "x".repeat(500);
    let resp = format!(r#"{{"ok": true, "detail": "{long_detail}"}}"#);
    let check = LlmProbe::parse_response(&resp);
    assert!(check.detail.chars().count() <= 201); // 200 + ellipsis
    assert!(check.detail.ends_with('…'));
}

#[test]
fn parse_response_extracts_json_from_prose() {
    // Real LLMs sometimes wrap JSON in
    // explanatory prose. The parser should
    // find the JSON object.
    let resp = "Here is my verdict: {\"ok\": true, \"detail\": \"clean\"} -- end.";
    let check = LlmProbe::parse_response(resp);
    assert_eq!(check.status, ProbeStatus::Ok);
    assert_eq!(check.detail, "clean");
}

#[test]
fn parse_response_malformed_returns_error_check() {
    let resp = "I don't know what to say, this is not JSON.";
    let check = LlmProbe::parse_response(resp);
    assert_eq!(check.status, ProbeStatus::Error);
    assert!(check.detail.contains("non-JSON"));
    assert!(check.detail.len() <= 250);
}

#[test]
fn extend_with_mock_ok_appends_llm_review_check() {
    let probe = LlmProbe::new(Box::new(MockLlmClient {
        response: r#"{"ok": true, "detail": "looks good"}"#.to_string(),
    }));
    let s = make_structural(true);
    let extended = probe
        .extend(s, "name: my-plugin", "does things")
        .expect("extend");
    assert_eq!(extended.plugin_id, "test-plugin");
    assert!(extended.ok, "ok should be true when both pass");
    // Original structural check is preserved.
    assert!(extended.checks.iter().any(|c| c.name == "manifest.yaml"));
    // New llm_review check is appended.
    assert!(extended.checks.iter().any(|c| c.name == "llm_review"));
    assert_eq!(extended.checks.len(), 2);
}

#[test]
fn extend_with_mock_fail_marks_overall_failed() {
    let probe = LlmProbe::new(Box::new(MockLlmClient {
        response: r#"{"ok": false, "detail": "agent X not in SKILL.md"}"#.to_string(),
    }));
    let s = make_structural(true);
    let extended = probe.extend(s, "manifest", "skill").expect("extend");
    assert!(!extended.ok, "ok must be false when LLM flags a problem");
    let llm_check = extended
        .checks
        .iter()
        .find(|c| c.name == "llm_review")
        .expect("llm_review check present");
    assert_eq!(llm_check.status, ProbeStatus::Error);
}

#[test]
fn extend_with_structural_fail_still_runs_llm() {
    // Structural check failed (e.g. missing
    // manifest). The LLM probe is still
    // invoked, but the overall `ok` is false
    // regardless of what the LLM says.
    let probe = LlmProbe::new(Box::new(MockLlmClient {
        response: r#"{"ok": true, "detail": "looks good"}"#.to_string(),
    }));
    let s = make_structural(false);
    let extended = probe.extend(s, "manifest", "skill").expect("extend");
    assert!(!extended.ok, "ok must be false when structural failed");
    // The LLM check is still present.
    let llm_check = extended
        .checks
        .iter()
        .find(|c| c.name == "llm_review")
        .expect("llm_review check present");
    assert_eq!(llm_check.status, ProbeStatus::Ok);
}
