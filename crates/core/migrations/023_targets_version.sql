-- 2.11.0 (P1-D-01b, TZ #1 §10 / D-01,
-- CWE-494): monotonic `version`
-- column on `targets`.
--
-- The pre-fix `targets` table had
-- no monotonic-version field, so
-- a `pending_deploys` row could
-- not detect drift: the operator
-- could approve a deploy against
-- `target.path = /srv/hermes`
-- and a few minutes later a
-- `PUT /v1/targets/:id` could
-- change the path to
-- `/srv/hermes-2`; the deploy
-- would land on the old path
-- anyway, because nothing tracked
-- the version. CWE-494.
--
-- The post-fix `targets.version`
-- is a monotonic integer that
-- the `agency-server` increments
-- on every `PUT /v1/targets/:id`
-- (the increment is the
-- `PendingDeployRepository` /
-- `mark_applied` freshness
-- anchor). The migration seeds
-- every existing row with `1`
-- (the floor); a fresh `target`
-- `create` will start at `1` and
-- advance on each update.
--
-- 2.11.0: the increment-on-update
-- policy itself is wired in
-- P1-D-01c (a follow-up commit).
-- This migration adds the column
-- and backfills; P1-D-01c wires
-- the `targets_repository::update`
-- to do
-- `version = version + 1` and
-- the `pending_deploys::request`
-- to copy the current `version`
-- into the new
-- `target_config_version` column
-- from migration 022. P1-D-01b
-- only adds the read-side check
-- at `mark_applied` time
-- (a no-op for pre-P1-D-01c
-- rows whose
-- `target_config_version IS NULL`).

ALTER TABLE targets
    ADD COLUMN version INTEGER NOT NULL DEFAULT 1;

CREATE INDEX IF NOT EXISTS idx_targets_version
    ON targets(version);

-- 2.11.0 (P1-D-01b): bump
-- schema_version 22 -> 23.
UPDATE meta
SET value = '23'
WHERE key = 'schema_version';
