use super::*;
use crate::infrastructure::sqlite::connect;

async fn fresh_db() -> (tempfile::TempDir, AuditLogRepository) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let repo = AuditLogRepository::new(db.pool().clone());
    (dir, repo)
}

#[tokio::test]
async fn record_returns_monotonic_ids() {
    let (_dir, repo) = fresh_db().await;
    let a = repo
        .record("operator", "GET /v1/audit", None, AuditOutcome::Ok, None)
        .await
        .expect("record a");
    let b = repo
        .record("operator", "GET /v1/systems", None, AuditOutcome::Ok, None)
        .await
        .expect("record b");
    assert!(a < b, "ids must be monotonic: a={a} b={b}");
}

#[tokio::test]
async fn list_paginates_with_cursor() {
    let (_dir, repo) = fresh_db().await;
    for i in 0..5 {
        repo.record(
            "operator",
            &format!("GET /v1/audit?i={i}"),
            None,
            AuditOutcome::Ok,
            None,
        )
        .await
        .expect("record");
    }
    let page1 = repo.list(None, 2).await.expect("page1");
    assert_eq!(page1.len(), 2);
    let cursor = page1.last().unwrap().id;
    let page2 = repo.list(Some(cursor), 2).await.expect("page2");
    assert_eq!(page2.len(), 2);
    assert!(page2[0].id > cursor);
    let cursor2 = page2.last().unwrap().id;
    let page3 = repo.list(Some(cursor2), 2).await.expect("page3");
    assert_eq!(page3.len(), 1, "fifth row is the last one");
}

#[tokio::test]
async fn record_persists_outcome_and_details() {
    let (_dir, repo) = fresh_db().await;
    repo.record(
        "operator",
        "POST /v1/deploy",
        Some("system:saas-platform"),
        AuditOutcome::Error,
        Some("{\"reason\":\"policy blocked\"}"),
    )
    .await
    .expect("record");
    let rows = repo.list(None, 10).await.expect("list");
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(r.actor, "operator");
    assert_eq!(r.action, "POST /v1/deploy");
    assert_eq!(r.target.as_deref(), Some("system:saas-platform"));
    assert_eq!(r.outcome, AuditOutcome::Error);
    assert_eq!(
        r.details.as_deref(),
        Some("{\"reason\":\"policy blocked\"}")
    );
}

// P0-AUD-01 (TZ #1 §16 / AUD-01): the audit `details`
// field MUST be a JSON document that round-trips through
// `serde_json::from_str` without corruption. Callers that
// build the JSON via `serde_json::json!({...})` get
// correct escaping for free; callers that build it via
// `format!("{{...}}")` break on special characters in
// the data (quotes, backslashes, control chars, U+2028 /
// U+2029 in older JSON parsers).
//
// This test exercises the round-trip end-to-end: a `sub`
// value with embedded `"`, `\`, and a control character
// must come back out identical after a write + read.
// If any caller reintroduces manual JSON concatenation,
// this test still passes (the repo is value-agnostic) —
// but the in-tree callers (oidc.rs's `oidc.login` and
// `oidc.refresh` audit records) are now using
// `serde_json::json!`, which is what this test guards.
#[tokio::test]
async fn details_round_trips_through_serde_json() {
    use serde_json::Value;
    let (_dir, repo) = fresh_db().await;
    // A subject that contains JSON-special characters.
    // `serde_json::json!` will correctly escape these.
    let nasty_sub = "evil\"user\\with\nnewline";
    let details = serde_json::json!({"sub": nasty_sub}).to_string();
    repo.record(
        "oidc",
        "oidc.login",
        Some("user:1"),
        AuditOutcome::Ok,
        Some(&details),
    )
    .await
    .expect("record");
    let rows = repo.list(None, 10).await.expect("list");
    assert_eq!(rows.len(), 1);
    let parsed: Value = serde_json::from_str(rows[0].details.as_deref().expect("details present"))
        .expect("details must be valid JSON");
    let sub = parsed
        .get("sub")
        .and_then(|v| v.as_str())
        .expect("sub field");
    assert_eq!(
        sub, nasty_sub,
        "round-trip must preserve the original (unescaped) value"
    );
}

// Regression test for the P0-AUD-01 pre-fix pattern:
// a value built via manual `format!("{{...}}")`
// concatenation is recorded as-is, but it is NOT
// guaranteed to be valid JSON. This test demonstrates
// the failure mode the fix prevents: a `sub` containing
// a quote would produce a malformed JSON document that
// fails to parse.
//
// We don't assert the manual-concat call (we removed
// it from the in-tree callers). Instead, we assert
// that *if* a malformed string somehow got into the
// `details` column, the round-trip would fail loudly
// rather than silently — the parser is a tripwire, not
// a sanitizer.
#[tokio::test]
async fn malformed_json_details_is_detected() {
    let (_dir, repo) = fresh_db().await;
    // Manually construct the kind of broken JSON the
    // pre-fix code emitted when `sub` contained a `"`
    // character. `sub` would have been written raw
    // between the outer quotes, producing
    // `{"sub":"evil"injection"}` — syntactically
    // invalid JSON.
    let broken = r#"{"sub":"evil"injection"}"#;
    repo.record(
        "oidc",
        "oidc.login",
        Some("user:1"),
        AuditOutcome::Ok,
        Some(broken),
    )
    .await
    .expect("record accepts any string — the parser is the tripwire");
    let rows = repo.list(None, 10).await.expect("list");
    let parsed: Result<serde_json::Value, _> =
        serde_json::from_str(rows[0].details.as_deref().unwrap());
    assert!(
        parsed.is_err(),
        "malformed JSON in `details` MUST be detectable; \
         the pre-fix callers produced this kind of breakage"
    );
}
