-- Initial schema: meta table for tracking applied migrations.
-- Subsequent migrations append to this directory.

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- sqlx records applied migrations in _sqlx_migrations; this `meta` table is
-- our own high-level version tracker.
INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '1');
