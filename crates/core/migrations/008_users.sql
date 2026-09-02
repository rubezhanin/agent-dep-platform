-- Per-user RBAC table (2.1.0, ADR-0019).
--
-- One row per operator. The `token_hash` is sha256
-- of the bearer token (lowercase hex, 64 chars);
-- the plain token is returned to the admin once at
-- creation time, never stored. A database dump
-- does not leak active credentials.
--
-- Columns:
--   id            autoincrement PK
--   name          unique human-readable label
--   role          one of 'viewer' | 'operator' | 'admin'
--   token_hash    sha256 of the bearer token; UNIQUE
--                 so the same token never logs in twice
--   created_at    ISO 8601 UTC with millis
--   last_seen_at  ISO 8601 UTC with millis; NULL on
--                 never-seen rows
--   disabled_at   ISO 8601 UTC with millis; NULL =
--                 active. Soft-delete only — we keep
--                 the row so the audit_log entries
--                 attributed to that name still
--                 resolve.
--
-- The index on (token_hash) is the hot path for
-- every authenticated request; (name) is unique
-- implicitly.

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL UNIQUE,
    role            TEXT NOT NULL CHECK (role IN ('viewer','operator','admin')),
    token_hash      TEXT NOT NULL UNIQUE,
    created_at      TEXT NOT NULL,
    last_seen_at    TEXT,
    disabled_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_users_token_hash
    ON users(token_hash);

UPDATE meta SET value = '8' WHERE key = 'schema_version';
