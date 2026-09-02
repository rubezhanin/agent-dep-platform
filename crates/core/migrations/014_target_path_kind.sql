-- 2.5.1 fleet path_kind discriminator (ADR-0029).
--
-- Cross-team sharing requires the server to
-- know whether a path is POSIX or Windows so
-- the operator's CLI can render the right
-- hints. The default is 'posix' for backwards
-- compatibility with 2.5.0 rows.
ALTER TABLE targets ADD COLUMN path_kind TEXT NOT NULL DEFAULT 'posix';

UPDATE meta SET value = '14' WHERE key = 'schema_version';
