-- P1-AUD-02 (TZ #1 §16, CWE-345 Insufficient
-- Verification of Data Authenticity): hash chain
-- + HMAC + WORM retention for the audit log.
--
-- ## Threat model
--
-- Pre-fix: the `audit_log` table was a plain
-- append-only-by-convention table. An attacker
-- (or a misconfigured backup-restore, or a
-- curious operator with DB access) could:
-- 1. DELETE a row to hide a malicious action
--    (the `id` autoincrement would not be
--    re-used so the row would just be missing).
-- 2. UPDATE a row to change the outcome from
--    "error" to "ok" (or vice versa) and break
--    the operator's incident review.
-- 3. INSERT a forged row to cover tracks
--    (a "we did approve this" audit row that
--    was never actually written by the server).
--
-- CWE-345: the audit log was insufficiently
-- verified data — the operator had no way to
-- prove that what they read was what the server
-- actually wrote, and no way to detect tampering
-- after the fact.
--
-- ## Fix
--
-- Three columns added:
-- 1. `prev_hash` (TEXT) — the `record_hash` of
--    the previous row, or 32 zero bytes for the
--    first row. The chain anchors every row to
--    its predecessor; deleting or reordering any
--    row breaks the chain at every subsequent
--    row.
-- 2. `record_hash` (TEXT) — the SHA-256 of
--    (sequence || prev_hash || occurred_at ||
--    actor || action || target || outcome ||
--    details), as a 64-char hex string. The
--    sequence is the autoincrement `id`, so
--    inserting or deleting a row in the middle
--    of the chain breaks every subsequent
--    `record_hash`.
-- 3. `hmac` (TEXT) — HMAC-SHA-256 of the
--    `record_hash` keyed with the server's
--    `AGENCY_AUDIT_HMAC_KEY` (loaded via the
--    vault; the same fail-closed path as
--    `AGENCY_VAULT_PASSPHRASE`). The HMAC is
--    verified at every read of the audit log;
--    a row whose `record_hash` was tampered
--    with but whose `hmac` is also recomputed
--    (which requires the secret) still fails
--    the HMAC check.
--
-- Pre-existing rows (pre-2.11.0) hydrate with
-- `prev_hash = ""` and `record_hash = ""` and
-- `hmac = ""`. The verify-chain API treats
-- these rows as "legacy" and only checks the
-- chain from the first non-legacy row onward.
-- The operator can re-mint the chain for
-- pre-existing rows via a one-shot admin
-- command (not in this migration; deferred to
-- 2.11.x).
--
-- ## WORM retention
--
-- Two triggers enforce the WORM invariant at
-- the engine level:
--
-- 1. `audit_log_no_update` (BEFORE UPDATE):
--    abort every UPDATE on `audit_log`. The
--    application computes the chain columns
--    (prev_hash, record_hash, hmac) in
--    advance and includes them in the INSERT
--    statement; no UPDATE is ever issued. The
--    pre-fix "convention" is enforced by the
--    engine; the only way to mutate the table
--    is to drop the trigger, which is itself
--    an auditable schema change.
--
-- 2. `audit_log_no_delete` (BEFORE DELETE):
--    abort all DELETEs. Same rationale.
--
-- Why app-side chain computation (rather than
-- a BEFORE INSERT trigger)? SQLite has no
-- built-in SHA-256 function and the hash
-- inputs (sequence id, prev_hash, all 7
-- data columns) cross multiple rows; doing
-- it in SQL would require a custom function
-- registered via `sqlite3_create_function`,
-- which is a more invasive change to the
-- connection setup. The Rust-side computation
-- is straightforward (see
-- `compute_record_hash` / `compute_hmac_hex`
-- in `audit_log_repository.rs`) and the
-- chain is still anchored to the row id, so
-- a tampering attempt is still detectable by
-- `verify_chain`.
--
-- The WORM enforcement is per-connection. The
-- server uses a single `SqlitePool`, so all
-- connections share the trigger; dev / test
-- fixtures that want to test the WORM path
-- (e.g. assert that an UPDATE returns
-- `SQLITE_CONSTRAINT_TRIGGER`) see the same
-- behavior as production.

ALTER TABLE audit_log
    ADD COLUMN prev_hash    TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_log
    ADD COLUMN record_hash  TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_log
    ADD COLUMN hmac         TEXT NOT NULL DEFAULT '';

DROP TRIGGER IF EXISTS audit_log_no_update;
CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE ON audit_log
    BEGIN
        SELECT RAISE(ABORT,
            'audit_log is WORM (P1-AUD-02, CWE-345); rows cannot be UPDATEd. Drop the audit_log_no_update trigger explicitly if you really mean to mutate the table.');
    END;

DROP TRIGGER IF EXISTS audit_log_no_delete;
CREATE TRIGGER audit_log_no_delete
    BEFORE DELETE ON audit_log
    BEGIN
        SELECT RAISE(ABORT,
            'audit_log is WORM (P1-AUD-02, CWE-345); rows cannot be DELETEd. Drop the audit_log_no_delete trigger explicitly if you really mean to mutate the table.');
    END;

UPDATE meta SET value = '27' WHERE key = 'schema_version';
