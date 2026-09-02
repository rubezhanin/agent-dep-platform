-- 2.5.0 fleet (ADR-0023).
--
-- One row per named target. The `path` is the
-- absolute filesystem path on the operator's box;
-- 2.5.0 ships no fleet-orchestration, so the path
-- is consulted by the operator's CLI when they
-- run `agency deploy apply`. The server only
-- stores the metadata.
--
-- Columns:
--   id            autoincrement PK
--   name          operator-chosen label (e.g. "prod-blue")
--   environment   the same enum as pending_deploys (the
--                  application-layer Environment::parse
--                  is the source of truth; no CHECK
--                  constraint here, per the 2.4.1 lesson)
--   path          absolute path on the operator's box
--   description   free-form, set on create
--   created_at    ISO 8601 UTC with millis
--   updated_at    ISO 8601 UTC with millis
--
-- `UNIQUE (environment, name)` so the same name
-- can exist in two environments (e.g. `laptop`
-- in `dev` and `production`) but not twice in
-- the same environment.

CREATE TABLE IF NOT EXISTS targets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    environment   TEXT NOT NULL,
    path          TEXT NOT NULL,
    description   TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (environment, name)
);
CREATE INDEX IF NOT EXISTS idx_targets_environment
    ON targets(environment);

-- 2.5.0 also adds `target_id` to pending_deploys
-- as a nullable column. Existing 2.4.0 rows have
-- NULL — they were deployed before the registry
-- existed. 2.5.1 will add a NOT NULL constraint
-- once every operator has migrated.
ALTER TABLE pending_deploys ADD COLUMN target_id INTEGER;

UPDATE meta SET value = '13' WHERE key = 'schema_version';
