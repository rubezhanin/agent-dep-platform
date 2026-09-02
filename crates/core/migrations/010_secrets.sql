-- 2.3.0 vault (ADR-0021).
--
-- One row per secret. The `value` is never stored
-- in plain text; only the AES-256-GCM ciphertext
-- with the per-secret 12-byte nonce. The
-- symmetric key is derived from the operator's
-- passphrase via Argon2id (OWASP 2026 defaults)
-- at server startup. The passphrase itself is
-- held in memory only and is not persisted.
--
-- Columns:
--   id            autoincrement PK
--   name          unique name (operator-chosen)
--   ciphertext    AES-256-GCM output
--   nonce         12-byte GCM nonce (per-secret
--                  random, never reused for the
--                  same key)
--   version       KDF version (1 = Argon2id +
--                  AES-256-GCM, the only one in
--                  2.3.0)
--   created_at    ISO 8601 UTC with millis
--   updated_at    ISO 8601 UTC with millis
--   created_by    users.id
--   updated_by    users.id
--
-- The `version` column lets 2.3.1 introduce a new
-- KDF without a migration: 2.3.1 inserts rows
-- with `version = 2`, and the 2.3.x reader falls
-- back to a typed error if it sees an unknown
-- version (the `version` is per-row, so old rows
-- keep working).

CREATE TABLE IF NOT EXISTS secrets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE,
    ciphertext    BLOB NOT NULL,
    nonce         BLOB NOT NULL,
    version       INTEGER NOT NULL CHECK (version IN (1)),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    created_by    INTEGER NOT NULL,
    updated_by    INTEGER NOT NULL,
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_secrets_name
    ON secrets(name);

UPDATE meta SET value = '10' WHERE key = 'schema_version';
