-- Audit log for the 2.0.0 enterprise server (ADR-0017, ADR-0018).
--
-- One row per HTTP request served by `agency-server`. The
-- existing `operations_journal` table is a deploy state
-- machine (Preparing / Writing / Committed / RolledBack);
-- it is NOT an audit trail. The `audit_log` here is the
-- per-request record kept for the operator.
--
-- Stored columns:
--   id          autoincrement PK
--   occurred_at ISO 8601 UTC with millis (matches the
--                `now_iso()` style used by deploy/mod.rs)
--   actor       bearer-token label or "anonymous" for
--                the `/v1/health` endpoint. 2.0.0 ships a
--                single operator token, so `actor` is the
--                constant `"operator"` in practice. 2.1.x
--                will set it from the OIDC subject.
--   action      the HTTP method + path, e.g.
--                "GET /v1/audit?cursor=…"
--   target      the entity the action targeted (e.g. a
--                system_id, a deploy operation_id). May be
--                NULL for collection-level reads.
--   outcome     "ok" or "error". Errors are recorded with
--                the same row so a failed auth attempt
--                shows up in the log.
--   details     free-form JSON for the request / response
--                body, escaped as TEXT. The 2.0.0 server
--                stores at most a small summary; 2.1.x
--                expands it.
--
-- Index on (occurred_at) so the default `?order=asc` list
-- is a sequential scan in the common case (operator pulls
-- the last hour of activity).

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT,
    outcome     TEXT NOT NULL CHECK (outcome IN ('ok', 'error')),
    details     TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_log_occurred_at
    ON audit_log(occurred_at);

UPDATE meta SET value = '7' WHERE key = 'schema_version';
