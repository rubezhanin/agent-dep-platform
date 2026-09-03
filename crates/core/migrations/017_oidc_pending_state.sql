-- 2.7.10 DB-backed OidcPending (ADR-0038).
--
-- The 2.7.6 in-memory
-- `Arc<Mutex<HashMap<String, PendingAuth>>>`
-- is replaced by a SQLite table. This
-- is the prerequisite for multi-process
-- / multi-instance `agency-server`
-- deployments: a `state` token
-- generated on replica A is now
-- visible to the callback handler on
-- replica B.
CREATE TABLE IF NOT EXISTS oidc_pending_state (
    state TEXT PRIMARY KEY,
    pkce_verifier TEXT NOT NULL,
    nonce TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    metadata TEXT NULL
);
CREATE INDEX IF NOT EXISTS idx_oidc_pending_created_at
    ON oidc_pending_state(created_at);
UPDATE meta SET value = '17' WHERE key = 'schema_version';
