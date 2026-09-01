-- Skills (TZ Enterprise v2 §7).
--
-- Skills are reusable capability/instruction units that agents depend on.
-- They live next to agents in the source repo (skills/<id>/) and are
-- ingested alongside the agents. This migration adds the persistence
-- tables; the v1 catalog reader (agents/<division>/*.md) is unaffected.
--
-- Design notes:
--  * skills are per-snapshot (snapshot_id is part of the PK) so re-ingest
--    of the same source produces an independent row;
--  * dependencies and permissions are stored as ordered rows so the
--    composition step can render them in the order the manifest declared;
--  * `dependencies` and `permissions` are intentionally typed as TEXT
--    rows (not FK tables) because skills reference other skills only
--    symbolically in MVP — the resolver enforces existence at compose
--    time, not at ingest time.
--  * `body` is stored inline, like `agents.body`. Body is small
--    (Markdown instructions, typically a few KB) and a move to the
--    content store is a follow-up (per ADR-0004 §"CAS layout").

CREATE TABLE IF NOT EXISTS skills (
    id              TEXT NOT NULL,                  -- skill slug
    snapshot_id     TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    version         TEXT NOT NULL,                  -- SemVer string
    description     TEXT NOT NULL,
    body            TEXT NOT NULL,                  -- Markdown body of SKILL.md
    body_hash       TEXT NOT NULL,                  -- sha256 of body
    PRIMARY KEY (snapshot_id, id)
);
CREATE INDEX IF NOT EXISTS idx_skills_snapshot_id ON skills(snapshot_id);

-- Ordered tags per skill. Most skills have zero tags; the index is on
-- (snapshot_id, skill_id) for tag-search backends added in 1.x.
CREATE TABLE IF NOT EXISTS skill_tags (
    snapshot_id TEXT NOT NULL,
    skill_id    TEXT NOT NULL,
    position    INTEGER NOT NULL,
    tag         TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, skill_id, position),
    FOREIGN KEY (snapshot_id, skill_id) REFERENCES skills(snapshot_id, id) ON DELETE CASCADE
);

-- Declared `skill@version` dependencies. The dependency is a free-form
-- `id@version` string; resolution against the snapshot's own skills
-- happens at compose time (not at ingest) so this table is purely
-- declarative.
CREATE TABLE IF NOT EXISTS skill_dependencies (
    snapshot_id TEXT NOT NULL,
    skill_id    TEXT NOT NULL,
    position    INTEGER NOT NULL,
    dependency  TEXT NOT NULL,                      -- "id@version"
    PRIMARY KEY (snapshot_id, skill_id, position),
    FOREIGN KEY (snapshot_id, skill_id) REFERENCES skills(snapshot_id, id) ON DELETE CASCADE
);

-- Declared permissions. Stored as snake_case names matching the
-- `SkillPermission` enum (read_env, spawn_process, network, filesystem).
-- The policy engine (Phase 3) reads these.
CREATE TABLE IF NOT EXISTS skill_permissions (
    snapshot_id TEXT NOT NULL,
    skill_id    TEXT NOT NULL,
    position    INTEGER NOT NULL,
    permission  TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, skill_id, position),
    FOREIGN KEY (snapshot_id, skill_id) REFERENCES skills(snapshot_id, id) ON DELETE CASCADE
);

-- Link table: which agents declared which skill dependencies in their
-- v2 manifest. This is the per-agent view of skill consumption; the
-- `skill_dependencies` table above is the skill's own declared
-- dependencies. Both are useful for the UI ("show me all agents that
-- use this skill" and "what does this skill depend on").
CREATE TABLE IF NOT EXISTS agent_skill_refs (
    snapshot_id TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    position    INTEGER NOT NULL,
    reference   TEXT NOT NULL,                      -- "id@version"
    PRIMARY KEY (snapshot_id, agent_id, position),
    FOREIGN KEY (snapshot_id, agent_id) REFERENCES agents(snapshot_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_agent_skill_refs_snapshot_skill
    ON agent_skill_refs(snapshot_id, reference);

UPDATE meta SET value = '5' WHERE key = 'schema_version';
