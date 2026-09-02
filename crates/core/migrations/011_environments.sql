-- 2.4.0 multi-environment (ADR-0022).
--
-- Adds the `environment` column to the two
-- per-deploy tables: `pending_deploys` (2.2.0)
-- and `deployed_artifacts` (1.5.0). Both default
-- to `'dev'`, so the migration is safe for every
-- row that already exists in a 2.x install.
--
-- We deliberately do NOT add a `CHECK`
-- constraint yet. 2.4.0 ships the hard-coded
-- set (dev / staging / production), but a
-- future 2.5.x may add a custom-environment
-- field; locking the column to the 2.4.0 enum
-- would force a migration when that lands.
-- 2.4.1 will add the CHECK once the 2.4.0
-- surface has stabilised.
--
-- `audit_log` is unchanged. The handler writes
-- the environment into `details` as
-- `{"environment": "production", ...}`; the
-- per-row JSON is the operator's "what env was
-- that deploy for?" answer for 2.4.0. 2.4.1
-- can promote the field to a real column.

ALTER TABLE pending_deploys
    ADD COLUMN environment TEXT NOT NULL DEFAULT 'dev';
ALTER TABLE deployed_artifacts
    ADD COLUMN environment TEXT NOT NULL DEFAULT 'dev';
CREATE INDEX IF NOT EXISTS idx_pending_deploys_environment
    ON pending_deploys(environment);
CREATE INDEX IF NOT EXISTS idx_deployed_artifacts_environment
    ON deployed_artifacts(environment);

UPDATE meta SET value = '11' WHERE key = 'schema_version';
