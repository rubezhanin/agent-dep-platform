-- 2.11.0 (P1-F-03a, TZ #2 WP-3.3, CWE-613
-- Insufficient Session Expiration).
--
-- Server-side session store for
-- HttpOnly+Secure+SameSite=Strict cookie
-- auth. Replaces the 2.10.0 design where
-- the local bearer (in JSON) was held by
-- the SPA in JavaScript memory / local
-- storage and not revocable server-side.
--
-- Background:
-- The 2.10.0 OIDC flow issues a local
-- bearer in the JSON body of
-- `/v1/auth/oidc/callback`; the SPA stores
-- it and uses it as `Authorization: Bearer`
-- on every subsequent request. The bearer
-- has a 1-hour `token_expires_at` but is
-- otherwise immutable. The pre-fix design
-- has three security weaknesses that
-- together amount to CWE-613 (Insufficient
-- Session Expiration):
--
-- 1. **No server-side revoke.** `logout_handler`
--    invalidates the local bearer only if the
--    Authorization header is present in the
--    logout request. A client whose bearer is
--    leaked (via XSS, browser history, a
--    shared workstation, etc.) cannot be
--    remotely killed; the only recourse is
--    for the operator to rotate the install
--    salt and re-encrypt the vault.
-- 2. **No idle timeout.** A 1-hour bearer
--    expires at a fixed wall-clock instant;
--    an active session gets killed exactly
--    at expiry even if the user is still
--    working, and a token captured at minute
--    59 stays valid for 1 more minute
--    regardless of how long ago the user
--    actually stopped using the system.
--    A proper session has a sliding
--    `idle_expires_at` that the server
--    advances on every authenticated
--    request.
-- 3. **No absolute timeout.** Even with
--    a sliding window, a long-lived
--    cookie-captured token can grant
--    indefinite access if the attacker
--    keeps using it. A proper session
--    has an `absolute_expires_at` that
--    caps the total session lifetime
--    regardless of activity.
--
-- The P1-F-03b follow-up commit wires the
-- `SessionRepository` into the OIDC handlers
-- (callback, refresh, logout) and adds a
-- `require_session_or_bearer` middleware
-- that prefers the session cookie and
-- falls back to the legacy bearer (with a
-- deprecation warning). This migration
-- is the data layer only.
--
-- Schema:
--   id                  session UUID (also the
--                       cookie value). 32 bytes
--                       of `OsRng` encoded as
--                       hex (64 chars) or
--                       base64url (43 chars).
--                       Hex is used here for
--                       log / audit readability.
--   user_id             FK to `users.id`.
--   csrf_token          32-byte random token
--                       used in the
--                       `X-CSRF-Token` header
--                       for state-changing
--                       requests. The
--                       `require_session` middleware
--                       (P1-F-03b) verifies the
--                       header against the
--                       session row.
--   created_at          ISO 8601 UTC.
--   last_used_at        ISO 8601 UTC, advanced
--                       on every successful
--                       auth.
--   idle_expires_at     ISO 8601 UTC, sliding
--                       (now + IDLE_TTL_SECS on
--                       every touch).
--   absolute_expires_at ISO 8601 UTC, fixed
--                       at create time
--                       (now + ABSOLUTE_TTL_SECS).
--                       Never advances; once
--                       past, the session is
--                       dead even if it's been
--                       touched every minute.
--   revoked_at          ISO 8601 UTC, or NULL
--                       for active sessions.
--                       `logout` sets this.
--   ip                  Optional client IP at
--                       create time; for the
--                       audit log only.
--   user_agent          Optional User-Agent at
--                       create time; for the
--                       audit log only.
--
-- All expiry checks (idle and absolute)
-- happen in the application layer
-- (`SessionRepository::find`) because
-- SQLite's date / time arithmetic is
-- limited and we want a single source of
-- truth for the `revoked_at IS NULL AND
-- now < idle AND now < absolute`
-- predicate.
--
-- Indexes:
--   user_id: list-active-sessions-by-user
--     (used by the future
--     `/v1/auth/sessions` admin endpoint
--     and by `revoke_all_for_user`).
--   revoked_at + idle_expires_at: gc
--     pass.

CREATE TABLE IF NOT EXISTS sessions (
    id                  TEXT PRIMARY KEY,
    user_id             INTEGER NOT NULL,
    csrf_token          TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    last_used_at        TEXT NOT NULL,
    idle_expires_at     TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL,
    revoked_at          TEXT,
    ip                  TEXT,
    user_agent          TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id
    ON sessions(user_id);

CREATE INDEX IF NOT EXISTS idx_sessions_revoked_idle
    ON sessions(revoked_at, idle_expires_at);

-- 2.11.0 (P1-F-03a): bump schema_version
-- 20 -> 21.
UPDATE meta
SET value = '21'
WHERE key = 'schema_version';
