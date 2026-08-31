-- MVP-3 security scanner persistence (TZ §23 + ADR-0005).
--
-- Each finding emitted by the scanner during ingestion is recorded
-- so the user can inspect *why* a snapshot was Blocked (or why a
-- WARN was raised). The findings table is the audit trail; the
-- snapshot row's `scan_note` carries a short summary.
--
-- Position is preserved so BLOCK > WARN > PASS order from the
-- scanner is round-tripped (helpful for "show first failure" UX).
-- Same severity + same position can repeat across rules; the PK
-- includes the rule id to disambiguate.

CREATE TABLE IF NOT EXISTS snapshot_findings (
    snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
    position    INTEGER NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('PASS','WARN','BLOCK')),
    rule        TEXT NOT NULL,
    path        TEXT NOT NULL,
    reason      TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, position, rule)
);
CREATE INDEX IF NOT EXISTS idx_snapshot_findings_snapshot_id
    ON snapshot_findings(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_snapshot_findings_severity
    ON snapshot_findings(snapshot_id, severity);

UPDATE meta SET value = '3' WHERE key = 'schema_version';
