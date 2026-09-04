-- 2.5.3 (ADR-0033 follow-up) pending_deploys.target_id NOT NULL.
--
-- Migration 013 (2.5.0) added
-- `pending_deploys.target_id` as
-- nullable for backfill compatibility.
-- 2.5.1 (ADR-0033) shipped the
-- `list_orphans` + `set_target_id`
-- backfill helpers. 2.5.3 finalises
-- the schema: every pending deploy
-- MUST have a `target_id`.
--
-- Operators must run
-- `agency targets backfill` (or
-- the library helpers) to NULL-fill
-- any orphan rows BEFORE applying
-- this migration.
--
-- The migration is a single
-- transaction (the 12-step table-
-- rebuild pattern). SQLite's
-- `ALTER TABLE` does not support
-- adding a NOT NULL constraint
-- directly. The `sqlx::migrate!`
-- runner wraps the whole file in
-- a single transaction; do NOT
-- add `BEGIN;` / `COMMIT;` here
-- (that nests transactions and
-- fails on SQLite). The whole
-- file is one implicit transaction.
PRAGMA foreign_keys = OFF;

CREATE TABLE pending_deploys_new (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    system_id         TEXT NOT NULL,
    plan_summary      TEXT NOT NULL,
    requested_by      INTEGER NOT NULL,
    requested_at      TEXT NOT NULL,
    status            TEXT NOT NULL CHECK (status IN (
        'pending','approved','rejected','applied'
    )),
    approved_by       INTEGER,
    approved_at       TEXT,
    rejection_reason  TEXT,
    applied_at        TEXT,
    environment       TEXT NOT NULL DEFAULT 'dev',
    target_id         INTEGER NOT NULL,
    FOREIGN KEY (requested_by) REFERENCES users(id),
    FOREIGN KEY (approved_by)  REFERENCES users(id),
    FOREIGN KEY (target_id)    REFERENCES targets(id)
);

-- Refuse to apply if any row is
-- still NULL. (If a row is NULL,
-- the INSERT INTO ... SELECT will
-- fail with a NOT NULL constraint
-- violation, and the transaction
-- will roll back.)
INSERT INTO pending_deploys_new
    SELECT id, system_id, plan_summary,
           requested_by, requested_at, status,
           approved_by, approved_at, rejection_reason,
           applied_at, environment, target_id
      FROM pending_deploys
     WHERE target_id IS NOT NULL;

DROP TABLE pending_deploys;
ALTER TABLE pending_deploys_new RENAME TO pending_deploys;

CREATE INDEX IF NOT EXISTS idx_pending_deploys_status
    ON pending_deploys(status);
CREATE INDEX IF NOT EXISTS idx_pending_deploys_environment
    ON pending_deploys(environment);
CREATE INDEX IF NOT EXISTS idx_pending_deploys_target_id
    ON pending_deploys(target_id);

PRAGMA foreign_keys = ON;

UPDATE meta SET value = '18' WHERE key = 'schema_version';
