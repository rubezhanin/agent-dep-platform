-- MVP-3 schema: sources, source_snapshots, divisions, agents, and link tables
-- for tools / activation_phrases. Snapshot bodies live inline in the agents
-- table for MVP; CAS-storing the body is a follow-up (ADR-0004 §"CAS layout").
--
-- Per ADR-0004: this DB is METADATA ONLY. System definitions still live in
-- the user's Git repo. Per ADR-0003: snapshot identity is the commit_sha
-- (or, for Local, the content-derived sha256). Per ADR-0006: snapshots are
-- immutable once written; recovery uses the same tables.

-- Sources: a catalog repository the user has registered. One row per
-- physical location. Re-ingestion updates `last_indexed_at`.
CREATE TABLE IF NOT EXISTS sources (
    id              TEXT PRIMARY KEY,           -- UUID v4
    kind            TEXT NOT NULL,              -- 'local' | 'git_https' | 'git_ssh'
    location        TEXT NOT NULL,              -- path (local) or url (git)
    pinned_ref      TEXT,                       -- commit/branch/tag, NULL for ad-hoc Local
    display_name    TEXT,
    created_at      TEXT NOT NULL,              -- ISO 8601 UTC
    last_indexed_at TEXT,                       -- ISO 8601 UTC
    UNIQUE (kind, location)
);

-- Snapshots: each ingest produces one row. Active <= 1 per source at any
-- time; older actives are flipped to 'superseded' by the repository layer
-- on the next successful ingest of the same source.
CREATE TABLE IF NOT EXISTS source_snapshots (
    id                          TEXT PRIMARY KEY,   -- UUID v4
    source_id                   TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    commit_sha                  TEXT NOT NULL,
    status                      TEXT NOT NULL CHECK (status IN ('active','superseded','blocked','failed')),
    agent_count                 INTEGER NOT NULL DEFAULT 0,
    division_count              INTEGER NOT NULL DEFAULT 0,
    created_at                  TEXT NOT NULL,
    upstream_template_version   TEXT,
    scan_note                   TEXT
    -- No UNIQUE(source_id, commit_sha): re-ingesting the same content
    -- with a different scanner verdict (e.g. Blocked then Active, or
    -- repeated ingest runs) must produce a new row, not collide. The
    -- snapshot's own UUID is the row identity; commit_sha is just
    -- the content-derived identity. Per ADR-0006, a recovery code
    -- path can re-insert the same plan; the supersede UPDATE handles
    -- Active->Superseded transition in the same transaction.
);
CREATE INDEX IF NOT EXISTS idx_source_snapshots_source_id ON source_snapshots(source_id);
CREATE INDEX IF NOT EXISTS idx_source_snapshots_source_status ON source_snapshots(source_id, status);

-- Divisions belonging to a snapshot.
CREATE TABLE IF NOT EXISTS divisions (
    id              TEXT NOT NULL,                  -- division slug (e.g. "engineering")
    snapshot_id     TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
    display_order   INTEGER NOT NULL,
    label           TEXT NOT NULL,
    description     TEXT,
    PRIMARY KEY (snapshot_id, id)
);
CREATE INDEX IF NOT EXISTS idx_divisions_snapshot_id ON divisions(snapshot_id);

-- Agents belonging to a snapshot. body is stored inline for MVP
-- (snapshot size is bounded by the source; in practice ~100 KB per
-- agent at most). FK to divisions is a soft check (division must
-- exist in the same snapshot).
CREATE TABLE IF NOT EXISTS agents (
    id              TEXT NOT NULL,                  -- agent slug (matches file stem)
    snapshot_id     TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
    division        TEXT NOT NULL,
    name            TEXT NOT NULL,
    display_name    TEXT,
    role            TEXT NOT NULL,
    description     TEXT NOT NULL,
    version         TEXT NOT NULL,                  -- SemVer string
    sensitive       INTEGER NOT NULL DEFAULT 0,     -- 0/1
    body            TEXT NOT NULL,                  -- Markdown body
    body_hash       TEXT NOT NULL,                  -- sha256 of body
    PRIMARY KEY (snapshot_id, id),
    FOREIGN KEY (snapshot_id, division) REFERENCES divisions(snapshot_id, id)
);
CREATE INDEX IF NOT EXISTS idx_agents_snapshot_id ON agents(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_agents_snapshot_division ON agents(snapshot_id, division);

-- Per-agent tools and activation phrases. Stored as ordered rows so the
-- order from the source is preserved (relevant for activation phrases).
CREATE TABLE IF NOT EXISTS agent_tools (
    snapshot_id TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    position    INTEGER NOT NULL,
    tool        TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, agent_id, position),
    FOREIGN KEY (snapshot_id, agent_id) REFERENCES agents(snapshot_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS agent_activation_phrases (
    snapshot_id TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    position    INTEGER NOT NULL,
    phrase      TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, agent_id, position),
    FOREIGN KEY (snapshot_id, agent_id) REFERENCES agents(snapshot_id, id) ON DELETE CASCADE
);

-- Observed source-tree files for the snapshot. Audit/debug only; the
-- snapshot identity (commit_sha) is derived from these.
CREATE TABLE IF NOT EXISTS snapshot_files (
    snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
    relative    TEXT NOT NULL,                      -- POSIX relative to source root
    sha256      TEXT NOT NULL,
    size_bytes  INTEGER NOT NULL,
    PRIMARY KEY (snapshot_id, relative)
);
CREATE INDEX IF NOT EXISTS idx_snapshot_files_snapshot_id ON snapshot_files(snapshot_id);

-- Rejected agents from the ingest report. Persisted so the user can
-- inspect why an agent was skipped.
CREATE TABLE IF NOT EXISTS snapshot_rejected_agents (
    snapshot_id  TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
    relative_path TEXT NOT NULL,
    reason       TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, relative_path)
);

UPDATE meta SET value = '2' WHERE key = 'schema_version';
