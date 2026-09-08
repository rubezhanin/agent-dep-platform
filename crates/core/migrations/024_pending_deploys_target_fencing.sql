-- 2.11.0 (P1-D-02, TZ #1 §10 / D-02,
-- CWE-362 Concurrent Execution using
-- Shared Resource without Proper
-- Synchronization) — target fencing.
--
-- Background:
-- The pre-fix `pending_deploys` flow
-- had no protection against two
-- concurrent mutating operations on
-- the same `target_id`. The realistic
-- threat is two operators approving
-- different deploys to the same
-- target at the same time, or one
-- operator racing the operator's own
-- re-issue: both rows reach
-- `mark_applied` before the other
-- is rejected, and the target
-- filesystem ends up in an
-- inconsistent state. CWE-362.
--
-- The post-fix invariant: "один
-- target — одна активная mutating
-- operation" (TZ #1 §10 / D-02). A
-- target is considered busy while
-- ANY `pending` or `approved`
-- `pending_deploys` row exists for
-- it; the `request` flow refuses
-- new rows while busy, and the
-- `mark_applied` flow bumps a
-- monotonic `targets.deployment_version`
-- counter that the next operator's
-- request captures as a fencing
-- token. A `mark_applied` whose
-- captured token does not match the
-- current `targets.deployment_version`
-- is rejected with a typed
-- `ErrStaleDeployment` — the row
-- stays `approved` and the operator
-- must re-issue.
--
-- Schema additions:
--
-- 1. `targets.deployment_version`
--    INTEGER NOT NULL DEFAULT 0.
--    Monotonic per-row counter,
--    separate from `targets.version`
--    (which tracks P1-D-01b config
--    drift). Increments on every
--    successful `mark_applied` for
--    that target. The `request`
--    flow captures the current value
--    as the new row's
--    `fence_token`. A subsequent
--    `mark_applied` whose
--    `fence_token` no longer matches
--    the current value is a
--    CWE-362 stale-lease event and
--    must be rejected.
--
-- 2. `pending_deploys.fence_token`
--    INTEGER NULL. Captured at
--    `request` time as the current
--    `targets.deployment_version` for
--    the row's `target_id`. NULL for
--    pre-P1-D-02 rows (the backfill
--    is `NULL`); the `mark_applied`
--    fence check is a no-op for
--    those rows.
--
-- 3. `pending_deploys.applied_deployment_version`
--    INTEGER NULL. Recorded on every
--    successful `mark_applied` as the
--    post-increment
--    `targets.deployment_version`.
--    The pair
--    `(fence_token, applied_deployment_version)`
--    in the audit log lets a future
--    operator see "my deploy A was
--    the one that bumped from 5 to
--    6; deploy B (which followed)
--    bumped from 6 to 7". NULL for
--    pending / approved / rejected
--    rows; populated for `applied`
--    rows.
--
-- 4. UNIQUE partial index
--    `idx_pending_deploys_one_active_per_target`
--    on `(target_id) WHERE status IN
--    ('pending', 'approved')`. The
--    SQL-level enforcement of "one
--    target — one active mutating
--    operation". Two `pending` rows
--    for the same `target_id` is a
--    CWE-362 race; the INSERT fails
--    with a UNIQUE constraint
--    violation, and the application
--    layer maps that to a typed
--    `ErrTargetBusy` carrying the
--    existing row's id.
--
-- 5. Index `idx_targets_deployment_version`
--    on `targets(deployment_version)`
--    for the rare "find all targets
--    at version N" admin query (3.x
--    dashboards). Cheap to maintain
--    because the column is mostly
--    write-only.
--
-- Existing rows are backfilled with
-- `deployment_version = 0` (the
-- floor) and `fence_token = NULL`.
-- The application-layer fence check
-- at `mark_applied` time is a no-op
-- for those rows; the unique index
-- is fine because pre-P1-D-02 rows
-- are already in terminal states
-- (`rejected` or `applied`) and
-- won't conflict with new rows.

ALTER TABLE targets
    ADD COLUMN deployment_version INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_targets_deployment_version
    ON targets(deployment_version);

ALTER TABLE pending_deploys
    ADD COLUMN fence_token INTEGER;

ALTER TABLE pending_deploys
    ADD COLUMN applied_deployment_version INTEGER;

-- 2.11.0 (P1-D-02): the partial
-- UNIQUE index that enforces "one
-- active mutating operation per
-- target". The
-- `status IN ('pending', 'approved')`
-- filter means a target can have
-- many historical `applied` or
-- `rejected` rows, plus at most one
-- row in either `pending` or
-- `approved` state.
CREATE UNIQUE INDEX IF NOT EXISTS
    idx_pending_deploys_one_active_per_target
    ON pending_deploys(target_id)
    WHERE status IN ('pending', 'approved');

-- 2.11.0 (P1-D-02): bump
-- schema_version 23 -> 24.
UPDATE meta
SET value = '24'
WHERE key = 'schema_version';
