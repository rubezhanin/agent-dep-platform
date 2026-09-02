-- 2.2.0 approvals workflow (ADR-0020).
--
-- One row per `POST /v1/deploys` request. The row
-- stays in `pending` until an admin approves or
-- rejects it, then the operator reports back via
-- `POST /v1/deploys/:id/applied` to close the loop.
-- The server never runs the deploy itself; the
-- snapshot is enough for a paper trail and the
-- operator runs `agency deploy apply` against the
-- same target tree.
--
-- Columns:
--   id                autoincrement PK
--   system_id         the composed system's metadata.id
--   plan_summary      JSON snapshot of the plan
--                      (same shape as `POST
--                      /v1/systems/plan` response)
--   requested_by      users.id — the operator who
--                      submitted the request
--   requested_at      ISO 8601 UTC with millis
--   status            'pending' | 'approved' |
--                      'rejected' | 'applied'
--   approved_by       users.id — the admin who
--                      approved or rejected
--                      (NULL while still pending)
--   approved_at       ISO 8601 UTC with millis
--   rejection_reason  free-form text, set on reject
--   applied_at        ISO 8601 UTC with millis
--
-- The `idx_pending_deploys_status` index supports
-- the common `?status=pending` filter; an admin
-- polling for new requests hits the index range
-- every time.

CREATE TABLE IF NOT EXISTS pending_deploys (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    system_id         TEXT NOT NULL,
    plan_summary      TEXT NOT NULL,
    requested_by      INTEGER NOT NULL,
    requested_at      TEXT NOT NULL,
    status            TEXT NOT NULL CHECK (status IN (
        'pending','approved','rejected','applied'
    )),
    approved_by       INTEGER,
    approved_at       TEXT,
    rejection_reason  TEXT,
    applied_at        TEXT,
    FOREIGN KEY (requested_by) REFERENCES users(id),
    FOREIGN KEY (approved_by)  REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_pending_deploys_status
    ON pending_deploys(status);

UPDATE meta SET value = '9' WHERE key = 'schema_version';
