-- MVP-3 recovery journal (TZ §17.3 / §18 + ADR-0006).
--
-- Every state-changing operation (deploy, rollback, plan, audit) is
-- journaled with enough information to either finish or roll back
-- the work after a crash. The journal is the authoritative state for
-- recovery; terminal rows are history.
--
-- State machine (ADR-0006):
--   prepared -> writing -> committing -> committed
--                                      \-> failed
--   committed -> rolled_back
--   prepared | writing -> rolled_back   (recovery: nothing or partial)
--   committing -> committed             (recovery: verify then commit)
--
-- Non-terminal statuses: prepared, writing, committing.
-- Terminal statuses:    committed, rolled_back, failed.
--
-- Bounded retention: a startup-time GC keeps the most recent 100
-- non-terminal rows; anything older is force-failed with the
-- "stale operation aborted" marker (see JournalService::gc_stale).

CREATE TABLE IF NOT EXISTS operations (
    operation_id  TEXT PRIMARY KEY,                    -- uuid v4
    type          TEXT NOT NULL CHECK (type IN ('deploy','rollback','plan','audit')),
    status        TEXT NOT NULL CHECK (status IN
                      ('prepared','writing','committing',
                       'committed','rolled_back','failed')),
    plan_hash     TEXT NOT NULL,                        -- sha256 of plan that produced this op
    started_at    TEXT NOT NULL,                        -- ISO 8601
    finished_at   TEXT,                                 -- ISO 8601, set on terminal
    effect_json   TEXT NOT NULL,                        -- JSON; size capped at 1 MB per op
    error         TEXT                                  -- free-form, set on `failed`
);
CREATE INDEX IF NOT EXISTS idx_operations_status
    ON operations(status);
CREATE INDEX IF NOT EXISTS idx_operations_plan_hash
    ON operations(plan_hash);
CREATE INDEX IF NOT EXISTS idx_operations_type_started_at
    ON operations(type, started_at);

UPDATE meta SET value = '4' WHERE key = 'schema_version';
