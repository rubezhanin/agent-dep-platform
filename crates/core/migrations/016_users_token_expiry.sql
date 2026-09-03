-- 2.7.8 OIDC token refresh + logout (ADR-0036).
--
-- Adds a nullable `token_expires_at` to
-- `users`. Bearer-token users (2.0.0-2.7.5)
-- keep `token_expires_at = NULL` and never
-- expire. OIDC users get a non-null value
-- on every `provision_user_from_claims` or
-- refresh; the `auth::require_bearer`
-- middleware then enforces the expiry.
ALTER TABLE users ADD COLUMN token_expires_at TEXT;
UPDATE meta SET value = '16' WHERE key = 'schema_version';
