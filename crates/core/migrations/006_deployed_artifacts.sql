-- Per-deployment artifact state (TZ v2 §20).
--
-- One row per `(system_id, target)` pair, written by
-- `DeploymentService::apply` and read by `PlanService`
-- to produce a real diff (the `Update` / `Delete` / `Noop`
-- branches in TZ §16.1).
--
-- The schema is intentionally narrow: we only need the
-- four columns the diff + the reconciliation classifier
-- care about. A future `audit` table holds the
-- per-operation history (already in `004_operations_
-- journal.sql`).
--
-- The `state` column mirrors `ReconcileState`; we keep it
-- as TEXT to avoid coupling the SQL schema to the
-- Rust enum. The classifier (`application::reconcile::
-- classify`) reads it via `serde_json`.

CREATE TABLE IF NOT EXISTS deployed_artifacts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    system_id       TEXT NOT NULL,                  -- e.g. "saas-platform"
    target          TEXT NOT NULL,                  -- e.g. "agents/be@1.0.0/be.md"
    expected_sha256 TEXT NOT NULL,                  -- desired body hash
    actual_sha256   TEXT,                           -- last observed body hash
    state           TEXT NOT NULL CHECK (state IN (
        'current', 'outdated', 'modified', 'foreign',
        'missing', 'incompatible', 'error', 'unknown'
    )),
    deployed_at     TEXT NOT NULL,                  -- ISO 8601 UTC
    last_verified_at TEXT,                          -- ISO 8601 UTC
    UNIQUE (system_id, target)
);
CREATE INDEX IF NOT EXISTS idx_deployed_artifacts_system
    ON deployed_artifacts(system_id);
CREATE INDEX IF NOT EXISTS idx_deployed_artifacts_state
    ON deployed_artifacts(system_id, state);

UPDATE meta SET value = '6' WHERE key = 'schema_version';
