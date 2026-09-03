-- 2.7.6 OIDC authentication (ADR-0034).
--
-- Adds an `external_id` column to `users` for
-- OIDC subject binding. The column is
-- nullable: bearer-token users (2.0.0-2.7.5)
-- have no `external_id`. OIDC users (2.7.6+)
-- have the IdP's `sub` claim as their
-- `external_id`.
--
-- The UNIQUE index lets the OIDC callback
-- handler look up the local user by IdP
-- subject in O(1). Without the UNIQUE
-- constraint, a misbehaving IdP could
-- create duplicate local users for the
-- same subject.
ALTER TABLE users ADD COLUMN external_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_id
    ON users(external_id) WHERE external_id IS NOT NULL;

UPDATE meta SET value = '15' WHERE key = 'schema_version';
