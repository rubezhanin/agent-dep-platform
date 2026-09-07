-- 2.10.0 (P0-SENT-01, TZ #2 WP-0.3, CWE-287,
-- Appendix A.4): make `users.token_hash`
-- nullable and backfill the pre-fix
-- `sha256("")` sentinel to NULL.
--
-- Background:
-- The 2.7.6 `create_with_external_id` and the
-- 2.7.8 `invalidate_token` operations
-- represented "no token issued" / "token
-- invalidated" by storing
-- `token_hash = sha256("")` (a 64-char
-- lowercase hex of the SHA-256 of the empty
-- string). The 2.0.0-2.7.5 `users` table had
-- `token_hash TEXT NOT NULL UNIQUE`, so
-- there was no way to store "no token"
-- except by abusing the sha256("") sentinel.
--
-- Threat (the bug):
-- The `auth::require_bearer` middleware
-- computed `sha256(presented_token)` and
-- looked up `WHERE token_hash = ?1`. An
-- attacker presenting
-- `Authorization: Bearer ""` (or no header
-- at all in a misconfigured client) would
-- compute `sha256("")` — which is exactly
-- the sentinel. If any active user (in
-- particular, a future `admin` user) had
-- `token_hash = sha256("")` (because their
-- OIDC token hadn't been refreshed yet, or
-- because they'd been `invalidate_token`'d
-- but the row hadn't been removed), the
-- attacker would authenticate as that user.
-- CWE-287 (Improper Authentication).
--
-- Fix (this migration):
-- 1. Rebuild `users` with `token_hash TEXT
--    NULL UNIQUE`. SQLite does not support
--    `ALTER TABLE ... DROP NOT NULL`, so
--    the standard SQLite pattern of
--    `CREATE NEW / COPY / DROP / RENAME` is
--    used. All other columns, constraints,
--    and indexes are preserved.
-- 2. Backfill: any row where `token_hash`
--    equals the sha256("") sentinel is
--    rewritten to NULL. Note: the sentinel
--    is a 64-char lowercase hex constant;
--    SQLite stores it as TEXT.
-- 3. The `idx_users_token_hash` index is
--    re-created (it does not need to be
--    dropped because the table was rebuilt
--    in step 1; but we re-create it
--    explicitly for clarity).
--
-- Application-layer follow-up
-- (not in this migration, in the
-- application code that lands with
-- P0-SENT-01):
--  - `UserRow.token_hash` becomes
--    `Option<String>`.
--  - `require_bearer` middleware short-
--    circuits on empty / missing bearer
--    before computing the SHA-256, so
--    `Bearer ""` always returns 401.
--  - `create_with_external_id` no longer
--    stores the sentinel; it inserts
--    `token_hash = NULL`.
--  - `invalidate_token` no longer stores
--    the sentinel; it sets
--    `token_hash = NULL`.
--  - New UNIQUE behavior: SQLite UNIQUE
--    columns treat NULL as distinct, so
--    multiple users can have
--    `token_hash = NULL` simultaneously.
--    This is the desired semantics ("no
--    token issued" for many users, none of
--    which can be authenticated by a
--    bearer token).
--
-- The sha256("") sentinel hex value, in
-- lowercase (64 chars), is:
--   e3b0c44298fc1c149afbf4c8996fb924
--   27ae41e4649b934ca495991b7852b855
-- (standard, well-known constant for
-- SHA-256 of the empty input).
--
-- This migration is a no-op on databases
-- that have never had the sentinel written
-- (fresh installs). It is also safe on
-- databases where the sentinel was
-- overwritten before the operator upgraded
-- to 2.10.0; the `UPDATE` simply matches
-- zero rows.

-- P0-SENT-01 (TZ #2 WP-0.3, CWE-287,
-- Appendix A.4): make `users.token_hash`
-- nullable and backfill the pre-fix
-- sha256("") sentinel to NULL.
--
-- Note: this migration is run by
-- `sqlx::migrate!`, which already wraps
-- every migration in a transaction. Do NOT
-- add explicit `BEGIN;` / `COMMIT;` — SQLite
-- rejects nested transactions and the
-- migration will fail with
-- "cannot start a transaction within a
-- transaction".

CREATE TABLE IF NOT EXISTS users_new (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL UNIQUE,
    role            TEXT NOT NULL CHECK (role IN ('viewer','operator','admin')),
    -- token_hash is now NULL for "no token
    -- issued yet" / "token invalidated".
    -- A real token's hash is a 64-char
    -- lowercase hex string; a NULL value
    -- means the user cannot be authenticated
    -- by bearer token (the middleware
    -- short-circuits to 401 on empty bearer
    -- and on the empty hash).
    token_hash      TEXT NULL UNIQUE,
    created_at      TEXT NOT NULL,
    last_seen_at    TEXT,
    disabled_at     TEXT,
    -- 2.7.6 (ADR-0034) additions carried
    -- forward from 015 / 016.
    external_id     TEXT,
    token_expires_at TEXT
);

INSERT INTO users_new (
    id, name, role, token_hash, created_at,
    last_seen_at, disabled_at,
    external_id, token_expires_at
)
SELECT
    id, name, role,
    CASE
        WHEN token_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        THEN NULL
        ELSE token_hash
    END,
    created_at,
    last_seen_at,
    disabled_at,
    external_id,
    token_expires_at
FROM users;

DROP TABLE users;

ALTER TABLE users_new RENAME TO users;

CREATE INDEX IF NOT EXISTS idx_users_token_hash
    ON users(token_hash);

-- 2.7.6 / 2.7.8 indexes (carried forward
-- from 015 / 016). Re-create explicitly so
-- the table is identical to the pre-rebuild
-- schema.
CREATE INDEX IF NOT EXISTS idx_users_external_id
    ON users(external_id);

-- sha256("") lowercase hex:
--   e3b0c44298fc1c149afbf4c8996fb924
--   27ae41e4649b934ca495991b7852b855
-- (split for readability)
UPDATE meta
SET value = '19'
WHERE key = 'schema_version';
