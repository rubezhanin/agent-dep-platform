use super::*;

#[test]
fn matching_hashes_is_current() {
    let (s, r) = classify(Some("deadbeef"), Some("deadbeef"), false);
    assert_eq!(s, ReconcileState::Current);
    assert_eq!(r, DriftReason::Unknown);
}

#[test]
fn user_modified_takes_precedence_over_outdated() {
    let (s, r) = classify(Some("new"), Some("old"), true);
    assert_eq!(s, ReconcileState::Modified);
    assert_eq!(r, DriftReason::UserModified);
}

#[test]
fn differing_hashes_no_user_flag_is_outdated() {
    let (s, r) = classify(Some("new"), Some("old"), false);
    assert_eq!(s, ReconcileState::Outdated);
    assert_eq!(r, DriftReason::SourceChanged);
}

#[test]
fn desired_only_is_missing() {
    let (s, r) = classify(Some("h"), None, false);
    assert_eq!(s, ReconcileState::Missing);
    assert_eq!(r, DriftReason::TargetMissing);
}

#[test]
fn actual_only_is_foreign() {
    let (s, r) = classify(None, Some("h"), false);
    assert_eq!(s, ReconcileState::Foreign);
    assert_eq!(r, DriftReason::Unknown);
}

#[test]
fn both_none_is_unknown() {
    let (s, _) = classify(None, None, false);
    assert_eq!(s, ReconcileState::Unknown);
}

#[test]
fn row_serializes_to_json_with_snake_case_states() {
    let row = ReconcileRow {
        target: "agents/be@1.0.0/be.md".to_string(),
        expected_sha256: Some("aaa".to_string()),
        actual_sha256: Some("bbb".to_string()),
        state: ReconcileState::Outdated,
        reason: DriftReason::SourceChanged,
    };
    let json = serde_json::to_string(&row).unwrap();
    assert!(json.contains("\"state\":\"outdated\""));
    assert!(json.contains("\"reason\":\"source_changed\""));
    assert!(json.contains("\"target\":\"agents/be@1.0.0/be.md\""));
}
