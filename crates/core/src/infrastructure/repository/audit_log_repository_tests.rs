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
async fn worm_triggers_block_update_and_delete() {
    use sqlx::Executor;
    let (_dir, repo) = fresh_db().await;
    // Insert one row (chain mode: no HMAC
    // key, so the chain columns stay empty
    // — the row is "legacy" from
    // verify_chain's perspective, but the
    // WORM triggers still apply to it).
    repo.record("alice", "GET /v1/systems", None, AuditOutcome::Ok, None)
        .await
        .expect("record");
    // UPDATE must fail with
    // SQLITE_CONSTRAINT_TRIGGER (code 1811).
    let res = repo
        .pool()
        .execute("UPDATE audit_log SET actor = 'mallory' WHERE id = 1")
        .await;
    let err = res.expect_err("UPDATE must be blocked by WORM trigger");
    let msg = format!("{err}");
    assert!(
        msg.contains("WORM") || msg.contains("UPDATEd"),
        "expected WORM error, got: {msg}"
    );
    // DELETE must also fail.
    let res = repo.pool().execute("DELETE FROM audit_log WHERE id = 1").await;
    let err = res.expect_err("DELETE must be blocked by WORM trigger");
    let msg = format!("{err}");
    assert!(
        msg.contains("WORM") || msg.contains("DELETEd"),
        "expected WORM error, got: {msg}"
    );
}

#[tokio::test]
async fn record_writes_chain_columns_with_hmac() {
    // 2.11.0 (P1-AUD-02): a repo built with
    // an HMAC key writes the chain columns
    // + the HMAC on every record. The chain
    // is the SHA-256 of
    // (sequence, prev_hash, occurred_at, actor,
    // action, target, outcome, details).
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let key: Vec<u8> = (0..32u8).collect();
    let repo =
        AuditLogRepository::with_hmac_key(db.pool().clone(), key.clone()).expect("hmac key");
    repo.record("alice", "GET /v1/systems", None, AuditOutcome::Ok, None)
        .await
        .expect("record a");
    repo.record("alice", "POST /v1/deploys", Some("d-1"), AuditOutcome::Ok, None)
        .await
        .expect("record b");
    // Both rows must have non-empty
    // prev_hash, record_hash, hmac.
    let rows: Vec<(i64, String, String, String)> = sqlx::query_as(
        "SELECT id, prev_hash, record_hash, hmac \
         FROM audit_log ORDER BY id ASC",
    )
    .fetch_all(repo.pool())
    .await
    .expect("select");
    assert_eq!(rows.len(), 2);
    // Row 1: prev_hash == GENESIS.
    assert_eq!(rows[0].1, GENESIS_PREV_HASH);
    assert_ne!(rows[0].2, "", "row 1 record_hash must be set");
    assert_ne!(rows[0].3, "", "row 1 hmac must be set");
    // Row 2: prev_hash == row 1's record_hash.
    assert_eq!(rows[1].1, rows[0].2, "row 2 prev_hash must equal row 1 record_hash");
    assert_ne!(rows[1].2, "", "row 2 record_hash must be set");
    assert_ne!(rows[1].3, "", "row 2 hmac must be set");
}

#[tokio::test]
async fn verify_chain_accepts_a_well_formed_chain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let key: Vec<u8> = (0..32u8).collect();
    let repo =
        AuditLogRepository::with_hmac_key(db.pool().clone(), key.clone()).expect("hmac key");
    for i in 0..5 {
        repo.record(
            "alice",
            "GET /v1/audit",
            Some(&format!("row-{i}")),
            AuditOutcome::Ok,
            Some(&format!("{{\"i\":{i}}}")),
        )
        .await
        .expect("record");
    }
    repo.verify_chain().await.expect("verify_chain must succeed on a clean chain");
}

#[tokio::test]
async fn verify_chain_rejects_a_tampered_record_hash() {
    use sqlx::Executor;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let key: Vec<u8> = (0..32u8).collect();
    let repo =
        AuditLogRepository::with_hmac_key(db.pool().clone(), key.clone()).expect("hmac key");
    repo.record("alice", "GET /v1/audit", None, AuditOutcome::Ok, None)
        .await
        .expect("record a");
    repo.record("alice", "POST /v1/deploys", None, AuditOutcome::Ok, None)
        .await
        .expect("record b");
    // Tamper with row 1's details.
    // (The UPDATE is blocked by the WORM
    // trigger; bypass it by dropping the
    // trigger, mimicking a malicious DBA who
    // has full file access.)
    repo.pool()
        .execute("DROP TRIGGER audit_log_no_update")
        .await
        .expect("drop trigger");
    repo.pool()
        .execute("UPDATE audit_log SET details = 'tampered' WHERE id = 1")
        .await
        .expect("tamper");
    // Re-add the trigger so subsequent
    // mutations are still blocked (the
    // tamper happened, but the verify call
    // is the post-mortem check).
    repo.pool()
        .execute(
            "CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log \
             BEGIN SELECT RAISE(ABORT, 'audit_log is WORM'); END",
        )
        .await
        .expect("re-add trigger");
    let err = repo.verify_chain().await.expect_err("verify_chain must reject tamper");
    let msg = format!("{err}");
    // The tamper changed the details, so the
    // recomputed record_hash does not match.
    // verify_chain returns a BadRecordHash
    // for row 1.
    assert!(
        msg.contains("tampered") || msg.contains("record_hash") || msg.contains("row id=1"),
        "expected BadRecordHash for row 1, got: {msg}"
    );
}

#[tokio::test]
async fn with_hmac_key_rejects_short_keys() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    let short_key = vec![0u8; 16];
    match AuditLogRepository::with_hmac_key(db.pool().clone(), short_key) {
        Ok(_) => panic!("short HMAC key must be rejected"),
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("32 bytes"),
                "expected HMAC key length error, got: {msg}"
            );
        }
    }
}

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
