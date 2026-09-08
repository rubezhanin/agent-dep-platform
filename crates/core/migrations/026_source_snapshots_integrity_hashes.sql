-- 2.11.0 (P1-G-04b, TZ #1 §7 / G-04
-- follow-up, CWE-494 Download of
-- Code Without Integrity Check) —
-- persist the 3 integrity hashes
-- that P1-G-04 added to
-- `SourceSnapshot` (`tree_hash`,
-- `artifact_manifest_hash`,
-- `scanner_result_hash`).
--
-- Background:
-- P1-G-04 added 3 `Option<String>`
-- fields to the `SourceSnapshot`
-- Rust struct and a comment in
-- `IngestRepository::list_snapshots`
-- / `get_snapshot_detail` that said
-- "the P1-G-04 integrity hashes are
-- not stored in the SQLite
-- `source_snapshots` table yet (a
-- follow-up P1-G-04b commit will
-- add the columns + backfill)".
-- The hydrate code in both read
-- paths returns `None` for all 3
-- fields today.
--
-- P1-G-04b closes the gap:
--
--   1. `tree_hash` — SHA-1 of the
--      git root tree of the cloned
--      commit (populated for git
--      sources via libgit2 in
--      `commit_tree_hash`; stays
--      NULL for filesystem-only
--      `SourceKind::Local` sources
--      that have no `.git` working
--      copy).
--   2. `artifact_manifest_hash` —
--      SHA-256 of the canonical
--      artifact manifest (sorted
--      `<rel-path>\0<file-sha256>`
--      lines, LF-separated). The
--      helper
--      `compute_artifact_manifest_hash`
--      in `application::ingest`
--      already produces this; the
--      P1-G-04 commit simply did
--      not write it to disk.
--   3. `scanner_result_hash` —
--      SHA-256 of the canonical
--      scanner findings list
--      (sorted by
--      `(severity, rule, path,
--      reason)`, serialised as
--      `<severity>\0<rule>\0<path>\0<reason>\n`
--      lines). The helper
--      `compute_scanner_result_hash`
--      in `application::ingest`
--      already produces this; the
--      P1-G-04 commit simply did
--      not write it to disk.
--
-- All 3 are NULL-able so pre-2.11.0
-- snapshots (anything that was
-- `record_snapshot`-ed before this
-- migration ran) keep reading as
-- `None` and do not need a
-- backfill. New snapshots written
-- after this migration populates
-- all 3 fields.
--
-- 2.11.0 (P1-G-04b): bump
-- schema_version 25 -> 26.

ALTER TABLE source_snapshots
    ADD COLUMN tree_hash TEXT;
ALTER TABLE source_snapshots
    ADD COLUMN artifact_manifest_hash TEXT;
ALTER TABLE source_snapshots
    ADD COLUMN scanner_result_hash TEXT;

UPDATE meta
SET value = '26'
WHERE key = 'schema_version';
