-- 2.11.0 (P1-D-03, TZ #1 §10 / D-03,
-- CWE-362 Concurrent Execution using
-- Shared Resource without Proper
-- Synchronization) — Idempotency-Key
-- on every mutation endpoint.
--
-- Background:
-- The pre-fix mutation endpoints
-- (`POST /v1/deploys`,
-- `POST /v1/deploys/:id/approve`,
-- `POST /v1/deploys/:id/reject`,
-- `POST /v1/deploys/:id/applied`,
-- `POST /v1/targets`,
-- `PUT /v1/secrets/:name`,
-- etc.) had no protection against
-- duplicate-request replays. The
-- realistic threat: a network
-- blip between the SPA and the
-- agency-server causes the
-- client to retry a `POST
-- /v1/deploys`. The first request
-- landed (created row #1,
-- scheduled the apply); the
-- retry lands too (creates row
-- #2 — a different deploy, with
-- the same plan, but a different
-- `pending_deploys.id` and
-- `requested_at`). The SPA
-- polls `/v1/deploys` and shows
-- both rows; the operator is
-- confused about which one to
-- approve. CWE-362.
--
-- The post-fix design: every
-- mutation endpoint accepts an
-- `Idempotency-Key` header
-- (1..=255 chars, opaque to the
-- server). A request that
-- arrives with a key the server
-- has seen in the last 24h
-- returns the cached response
-- verbatim (with an
-- `Idempotent-Replay: true`
-- header) instead of running
-- the handler again. The
-- `request_hash` field
-- (SHA-256 of the canonical
-- request body) detects the
-- "client reused the key with a
-- different body" mistake and
-- returns 422
-- `idempotency.mismatch` — the
-- cache key is the
-- (key, route, body) triple, not
-- just the key.
--
-- Schema:
--
--   idempotency_keys (
--     key            TEXT NOT NULL,
--     route          TEXT NOT NULL,
--     request_hash   TEXT NOT NULL,
--     response_status INTEGER,
--     response_body  TEXT,
--     created_at     TEXT NOT NULL,
--     expires_at     TEXT NOT NULL,
--     PRIMARY KEY (key, route)
--   )
--
-- The PRIMARY KEY is (key, route)
-- so the same key can be reused
-- on a different route (e.g. the
-- SPA uses one key per
-- user-action, not one key per
-- server endpoint). The
-- `response_status` / `response_body`
-- columns are NULL while the
-- request is in flight (the
-- middleware inserts the row
-- before running the handler,
-- then UPDATE-s it after the
-- handler returns). A second
-- request that arrives while the
-- first is still running sees
-- `response_status IS NULL` and
-- either polls (briefly) or
-- returns 409
-- `idempotency.in_flight`.
--
-- `expires_at` defaults to
-- `created_at + 24h`. A
-- background GC task (added in
-- the post-migration commit,
-- alongside the
-- `idempotency_keys.gc_expired`
-- repository method) reaps
-- expired rows on the same 60s
-- timer as the `sessions` and
-- `oidc_pending_state` GCs.
--
-- 2.11.0 (P1-D-03): bump
-- schema_version 24 -> 25.

CREATE TABLE IF NOT EXISTS idempotency_keys (
    key              TEXT    NOT NULL,
    route            TEXT    NOT NULL,
    request_hash     TEXT    NOT NULL,
    -- NULL while the request is in
    -- flight; populated by the
    -- middleware after the handler
    -- returns. The 422
    -- `idempotency.mismatch` path
    -- also records the response
    -- (so a third call with the
    -- wrong body sees the cached
    -- 422, not a fresh recompute).
    response_status  INTEGER,
    response_body    TEXT,
    created_at       TEXT    NOT NULL,
    expires_at       TEXT    NOT NULL,
    PRIMARY KEY (key, route)
);

CREATE INDEX IF NOT EXISTS idx_idempotency_keys_expires
    ON idempotency_keys(expires_at);

UPDATE meta
SET value = '25'
WHERE key = 'schema_version';
