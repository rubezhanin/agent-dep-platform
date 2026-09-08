-- 2.11.0 (P1-D-01, TZ #1 §10 / D-01,
-- CWE-494 Download of Code Without
-- Integrity Check) — extend
-- `pending_deploys` with the
-- `DeploymentIntent` fields.
--
-- Background:
-- The 2.10.0 `pending_deploys` row
-- carries a `plan_summary` JSON
-- blob, an `environment`, and a
-- `target_id`. That is enough to
-- APPROVE a deploy, but not
-- enough to detect drift between
-- approval time and apply time:
-- the operator could approve a
-- deploy against snapshot N, and
-- by the time the deploy runs
-- (hours or days later) the
-- source could have advanced to
-- snapshot N+1 (a new commit,
-- new files, new manifest). A
-- naive apply would deploy a
-- different artifact than the
-- one the operator approved. CWE-494.
--
-- The post-fix `DeploymentIntent`
-- captures six pieces of identity
-- at approval time and re-verifies
-- them at apply time:
--
--   source_snapshot_id      — the
--     `source_snapshots.id`
--     (UUID) the plan was built
--     against. Resolved at
--     `request_deploy` time; the
--     plan is rejected if the
--     source has no current
--     snapshot.
--
--   commit_sha              — the
--     resolved HEAD commit SHA
--     (40 hex chars) at
--     `request_deploy` time.
--     This is the actual artefact
--     the deploy will ship, not a
--     branch name that may have
--     moved.
--
--   plan_hash               —
--     SHA-256 of the canonical
--     `plan_summary` JSON. The
--     apply path recomputes the
--     hash and refuses to apply
--     if it differs (catches
--     hand-edits in the DB and
--     version-skew between
--     server restarts).
--
--   policy_set_version      —
--     opaque string identifying
--     the policy set in force at
--     approval time. The
--     `agency-server` boot path
--     writes a constant for now
--     (a follow-up will turn
--     this into a per-tenant
--     versioned table).
--
--   artifact_manifest_hash  —
--     hex hash of the
--     `artifact_manifest` (file
--     list + sizes + sha256s)
--     the plan was built
--     against. Re-verified at
--     apply time; a file added or
--     removed in the source
--     between request and apply
--     trips the freshness check.
--
--   target_config_version   —
--     monotonic integer per
--     `targets` row. The `targets`
--     table already has a
--     `version` column (ADR-0023);
--     we copy it into the
--     `pending_deploys` row at
--     request time and verify it
--     matches the current
--     `targets.version` at apply
--     time. A `PUT /v1/targets/:id`
--     between request and apply
--     trips the freshness check
--     (no `target_id` re-binding
--     by hand).
--
-- All five `*_at_apply` checks
-- happen in the application
-- layer (`mark_applied`), not as
-- SQLite CHECK constraints, so
-- the rejection surfaces a typed
-- `CoreError::ErrStaleDeployment`
-- that the operator can see in
-- the audit log and the API can
-- surface to the SPA. SQLite
-- would only let us return a
-- generic `CHECK constraint
-- failed` string, which is not
-- enough to drive a retry.
--
-- The columns are **nullable**
-- for the migration. Pre-P1-D-01
-- `pending_deploys` rows are
-- backfilled with `NULL`; the
-- `mark_applied` freshness check
-- is a no-op for those rows
-- (P1-D-01a is a foundation, the
-- enforcement is layered in
-- once every operator has had
-- time to re-issue their
-- pending deploys under the
-- new schema — see the
-- "deprecation" entry in the
-- CHANGELOG). The follow-up
-- P1-D-01b commit makes the
-- columns `NOT NULL` for fresh
-- rows and rejects `mark_applied`
-- on legacy rows.

CREATE TABLE IF NOT EXISTS pending_deploys_new (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    system_id       TEXT NOT NULL,
    plan_summary    TEXT NOT NULL,
    requested_by    INTEGER NOT NULL,
    requested_at    TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'applied')),
    environment     TEXT NOT NULL DEFAULT 'dev',
    target_id       INTEGER NOT NULL,
    -- 2.11.0 (P1-D-01): the
    -- `DeploymentIntent` fields.
    -- All nullable in this
    -- commit (P1-D-01a
    -- foundation); the follow-up
    -- P1-D-01b promotes them to
    -- `NOT NULL` for fresh rows.
    source_snapshot_id     TEXT,
    commit_sha             TEXT,
    plan_hash              TEXT,
    policy_set_version     TEXT,
    artifact_manifest_hash TEXT,
    target_config_version  INTEGER,
    -- End 2.11.0 (P1-D-01) block.
    approved_by    INTEGER,
    approved_at    TEXT,
    rejection_reason TEXT,
    applied_at     TEXT,
    FOREIGN KEY (requested_by) REFERENCES users(id),
    FOREIGN KEY (approved_by)   REFERENCES users(id),
    FOREIGN KEY (target_id)     REFERENCES targets(id)
);

INSERT INTO pending_deploys_new (
    id, system_id, plan_summary, requested_by, requested_at,
    status, environment, target_id,
    source_snapshot_id, commit_sha, plan_hash,
    policy_set_version, artifact_manifest_hash, target_config_version,
    approved_by, approved_at, rejection_reason, applied_at
)
SELECT
    id, system_id, plan_summary, requested_by, requested_at,
    status, environment, target_id,
    NULL, NULL, NULL, NULL, NULL, NULL,
    approved_by, approved_at, rejection_reason, applied_at
FROM pending_deploys;

DROP TABLE pending_deploys;

ALTER TABLE pending_deploys_new RENAME TO pending_deploys;

CREATE INDEX IF NOT EXISTS idx_pending_deploys_source_snapshot
    ON pending_deploys(source_snapshot_id);

CREATE INDEX IF NOT EXISTS idx_pending_deploys_target_version
    ON pending_deploys(target_id, target_config_version);

-- 2.11.0 (P1-D-01): bump
-- schema_version 21 -> 22.
UPDATE meta
SET value = '22'
WHERE key = 'schema_version';
