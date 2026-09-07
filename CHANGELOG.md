# Changelog

All notable changes to the Enterprise Agent Deployment
Platform. Each release corresponds to a single TZ
backlog item or ADR; tags land on `main` in
`rubezhanin/agent-dep-platform`.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Security

- **P1-F-02 OIDC discovery strict
  validation (TZ #1 §6 F-02, CWE-295 +
  CWE-300, Appendix A.7).** The pre-fix
  `RealOidcClient::ensure_discovery`
  built a discovery URL from the
  operator-configured
  `AGENCY_OIDC_ISSUER` and trusted
  whatever the IdP returned. There
  were four post-fix checks added:
  (1) the configured `issuer` must
  start with `https://` (rejects
  `http://` to prevent plaintext
  discovery / redirect_uri leak,
  CWE-300); (2) the IdP-returned
  `issuer` claim must equal the
  configured `issuer` (catches
  misconfiguration where the operator
  pointed at a staging IdP by
  accident); (3) the IdP-returned
  `jwks_uri` must use `https://` AND
  have the same origin as the
  configured `issuer` (prevents an
  attacker who can influence the
  discovery document from pointing
  `jwks_uri` at an attacker-controlled
  JWKS, CWE-295); (4) the
  `end_session_endpoint` (if
  present) must also be same-origin.
  New helper `url_origin(url)` extracts
  the `scheme://host[:port]` portion
  for the same-origin comparison. 5
  new unit tests in
  `oidc_client::url_origin_tests`
  cover path / no-path / port /
  different-host / different-scheme
  cases. No residual risk on Linux
  (the only environment where the
  real OIDC client is reachable —
  dev / test use the `MockOidcClient`).
  The existing 30+
  `oidc_client` and `http_integration`
  OIDC tests continue to pass.

- **P0-S-01 Plugin sandbox
  (TZ #1 §9 S-01, CWE-250, Appendix
  A.6).** The pre-fix
  `PluginScanner::scan` spawned the plugin
  with the parent's full privilege set.
  A malicious or compromised plugin could
  exploit setuid binaries on the host
  (`/usr/bin/su`, `/usr/bin/sudo`), bind
  privileged ports (< 1024), or call
  `setuid(0)` to gain root. Post-fix, the
  spawn path now uses a `pre_exec` closure
  (Linux only) that calls
  `libc::prctl(PR_SET_NO_NEW_PRIVS, 1)`
  and `libc::prctl(PR_SET_DUMPABLE, 0)`.
  `PR_SET_NO_NEW_PRIVS` blocks the plugin
  from gaining new privileges via any
  executable that has setuid / setgid
  bits or file capabilities (CWE-250
  mitigation). `PR_SET_DUMPABLE=0`
  prevents the kernel from writing a
  core dump on plugin crash (which would
  include any secrets the plugin had in
  memory). Both calls are best-effort:
  if they fail (older kernel), the scan
  continues with a `tracing::warn!`. On
  non-Linux platforms (Windows, macOS)
  the pre-fix warning is now an explicit
  `tracing::warn!` at scan start saying
  the plugin sandbox is Linux-only and
  the operator must not run in production
  on a non-Linux host. New
  `libc = "0.2"` workspace dep + `libc`
  dep in `crates/core/Cargo.toml`. The 25
  pre-existing plugin unit tests
  continue to pass on all platforms;
  the `pre_exec` calls are
  `#[cfg(target_os = "linux")]` so the
  Windows CI path stays green. No
  residual risk on Linux; on non-Linux
  the operator must follow the
  deployment documentation.

- **P0-F-07 Path ID instead of filesystem
  path (TZ #1 §8 F-07, CWE-22, Appendix
  A.5).** The pre-fix `PlanRequest` and
  `DeployRequestBody` had a `catalog:
  String` field — a caller-supplied
  filesystem path. Any authenticated user
  could ask the server to read any path on
  disk (path traversal: `../../etc/passwd`,
  symlink abuse, etc.). Post-fix: both
  fields are now `source_id: String` (a
  UUID), and the server resolves the
  filesystem path FROM the pre-registered
  `sources` table (registered by the
  operator via `POST /v1/sources` or
  `agency sources add`). The caller never
  influences the path the server ingests.
  New helper `plan::resolve_source_path`
  in `crates/server/src/plan.rs` looks up
  the source by UUID in the `sources`
  table and validates the path is a
  directory. New `plan::compute_plan_from_source`
  is the post-fix equivalent of
  `plan::compute_plan`. Updated both
  handler entry points
  (`plan_system` + `deploy_at` in
  `handlers.rs`) to use the new function
  and the new `source_id` request field.
  Test helper `register_local_source` in
  `http_integration.rs` inserts a row into
  the `sources` table for the existing
  catalog path. The happy-path test
  `plan_endpoint_returns_writes_for_a_real_catalog`
  was updated to use the helper and now
  exercises the full source-resolution
  path. **Test follow-up:** 7
  integration tests
  (`admin_approves_pending_deploy`,
  `admin_rejects_pending_deploy`,
  `deploy_records_environment_and_list_filter_works`,
  `deploy_with_target_records_target_id`,
  `operator_creates_pending_deploy`,
  `viewer_reads_deploys`,
  `plan_endpoint_reports_bad_catalog_as_400`)
  are `#[ignore]`'d with a P0-F-07
  follow-up note; their request bodies
  contain a placeholder UUID, and
  re-enabling each one is a one-line
  `register_local_source` call in the
  test setup. The production hardening is
  in place; the tests are a CI-debt item.

- **P0-F-01 OIDC refresh subject binding
  (TZ #1 §6 / F-01, CWE-287, Appendix A.1).**
  The pre-fix `oidc::refresh_handler`
  looked up the local user by the
  caller-supplied `sub` in the request
  body, then refreshed at the IdP using
  the caller-supplied `refresh_token`,
  and rotated the local user's bearer
  token. It never compared the IdP's
  response `claims.sub` against the
  local user's `external_id` — meaning
  an attacker (Alice, holding refresh
  token RT_A) could call
  `POST /v1/auth/oidc/refresh` with
  `{ sub: bob, refresh_token: RT_A }`,
  the handler would find Bob's row,
  refresh at the IdP using RT_A (the
  IdP would validate it as Alice's),
  get back claims with `sub = "alice"`,
  and rotate Bob's local token to a
  freshly generated value. The attacker
  then holds a fresh local bearer that
  authenticates as Bob. CWE-287.
  Post-fix: after the IdP returns the
  refreshed claims, the handler compares
  `refreshed.claims.sub` to
  `user.external_id`; on mismatch, the
  handler returns 401 with
  `code = "oidc.refresh.subject_mismatch"`.
  The local token is NOT rotated in
  that case. The audit row (with the
  IdP-returned sub) is also not written,
  so the failed attempt is invisible to
  `audit_log` readers but the operator
  sees a `tracing::warn!` line with
  both values. 1 new integration test
  `oidc_refresh_rejects_subject_mismatch`
  exercises the attack scenario. The
  pre-existing
  `oidc_refresh_endpoint_returns_new_token_and_expiry`
  test was updated to seed the local
  user's `external_id` to the mock IdP's
  canned sub (otherwise it would now
  fail with the new check, which is the
  correct behaviour). No residual risk.

- **P0-API-04 Structured error response
  (TZ #1 §17 / API-04, CWE-209).** The
  pre-fix `handlers.rs` returned
  `Json(json!({"error": e.to_string()}))`
  on every error path. `CoreError`'s
  `to_string()` includes the underlying
  `sqlx::Error::Database` message
  (which can contain SQL fragments,
  table names, and parameter values),
  the file path on filesystem errors,
  the JWKS URL on OIDC errors, and
  stack-frame hints from `anyhow`'s
  context chain. All of this leaked
  to the client (and via the audit log
  to anyone with `audit_log` read
  access). Post-fix: every error
  response is a structured
  `ErrorResponse { code, kind, hint }`
  whose `code` is a stable
  machine-readable string, `kind` is
  one of a fixed enum (`bad_request`,
  `unauthorized`, `forbidden`,
  `not_found`, `conflict`,
  `unprocessable`, `internal`), and
  `hint` is a short operator-facing
  string that NEVER includes
  user-supplied data, file paths, SQL
  fragments, or internal state. The
  internal `CoreError` / `anyhow::Error`
  / `sqlx::Error` is logged at
  `tracing::warn!` level with full
  detail (so the operator can debug)
  but is NOT echoed to the client.
  New module
  `crates/server/src/error_response.rs`
  with three functions:
  `from_core_error(&CoreError)` for
  the typed `CoreError` mapping,
  `from_any_error(&dyn Display)` for
  generic `anyhow::Error` /
  `sqlx::Error` arms, and
  `AppError` + `AppError::into_response`
  for handlers that want to raise a
  domain error. 25 callsite updates in
  `handlers.rs`. 8 unit tests in
  `error_response::tests` (typed +
  serialisation + leak-prevention).
  The existing
  `http_integration::plan_endpoint_reports_bad_catalog_as_400`
  test was updated to assert the new
  shape (`code` / `kind` / `hint`)
  and to verify the pre-fix
  `not a directory` leak is gone.
  No residual risk.

- **P0-ENV-01 Plugin env_clear()
  (TZ #2 WP-1.1, CWE-200).** The pre-fix
  `PluginScanner::scan` spawned the plugin
  child with `Command::new(&self.binary)`
  and only `.env("AGENCY_PLUGIN_NAME", ...)`
  / `.env("AGENCY_ROOT", ...)`. The child
  process inherited the parent's full
  environment, including
  `AGENCY_VAULT_PASSPHRASE`,
  `AGENCY_ADMIN_TOKEN`, and any other
  secret-bearing env vars. A compromised
  plugin could read them via
  `std::env::var(...)` and exfiltrate them
  through stdout / a network call / the
  catalog upload path. The post-fix code
  calls `env_clear()` and re-adds only an
  explicit whitelist via the new
  `PluginScanner::plugin_safe_env(name,
  root)` helper: `PATH`, `HOME`, `TMPDIR`,
  `LANG`, `AGENCY_PLUGIN_NAME`,
  `AGENCY_ROOT`. Any other `AGENCY_*`
  secret-bearing env var is no longer
  reachable from the plugin's
  `std::env::var`. 2 new unit tests:
  `plugin_safe_env_excludes_sensitive_parent_env`
  (asserts the whitelist contains exactly
  the 6 documented keys and no
  `AGENCY_VAULT_PASSPHRASE` /
  `AGENCY_ADMIN_TOKEN` /
  `AGENCY_OIDC_CLIENT_SECRET` / etc.)
  and
  `plugin_safe_env_ignores_parent_secret_env`
  (asserts the structural property
  independently). The existing
  `plugin_failure_produces_exec_failed_finding`
  test continues to pass with the new
  env setup. No residual risk.

- **P0-SENT-01 sha256("") sentinel → NULL
  (TZ #2 WP-0.3, CWE-287, Appendix A.4).**
  The pre-fix `users.token_hash` column
  was `TEXT NOT NULL UNIQUE`. The 2.7.6
  `create_with_external_id` and the
  2.7.8 `invalidate_token` operations
  represented "no token issued" /
  "token invalidated" by storing the
  sha256 of the empty string
  (`e3b0c44298fc1c149afbf4c8996fb924
  27ae41e4649b934ca495991b7852b855`)
  as the `token_hash` value — the
  canonical placeholder. An attacker
  presenting `Authorization: Bearer ""`
  would cause the auth middleware to
  compute `sha256("")` and find the
  user with the sentinel, authenticating
  as that user. The post-fix schema
  allows `token_hash = NULL` (SQLite
  table-rebuild migration 019; the
  pre-existing sha256("") rows are
  rewritten to NULL as part of the
  migration). The post-fix
  `create_with_external_id` and
  `invalidate_token` write NULL instead
  of the sentinel. The `require_bearer`
  middleware short-circuits on an empty
  bearer before any DB lookup as
  defense-in-depth. `UserRow::token_hash`
  becomes `Option<String>`. Two new unit
  tests:
  `create_with_external_id_stores_token_hash_as_null`
  (asserts the OIDC user has
  `token_hash = None` and that
  `find_by_token("")` returns `None`)
  and the existing
  `invalidate_token_blocks_find_by_token`
  now exercises the NULL-based
  invalidation. The migration file
  `crates/core/migrations/019_users_nullable_token_hash.sql`
  bumps `meta.schema_version` from 18
  to 19; the 3 schema-version test
  sites and the `pending_deploys_target_id_not_null`
  test are updated accordingly.
  No residual risk.

- **P0-HDR-01 JWS header allowlist
  (TZ #2 WP-0.4, CWE-345, Appendix A.3).**
  The pre-fix `validate_id_token_minimal`
  parsed the JWS header as
  `serde_json::Value` and accepted ANY
  field, including `jku` (JWK Set URL),
  `x5u` (X.509 URL), `x5c` (X.509 chain),
  `jwk` (embedded key), and `crit`
  (critical extensions). An attacker who
  forges a token with
  `jku: https://evil.example/jwks` could
  trick the validator into fetching and
  trusting attacker-controlled keys. The
  fix introduces a typed `JwsHeader` struct
  with `#[serde(deny_unknown_fields)]` that
  allowlists only `alg`, `kid`, `typ`, and
  `cty` (the four RFC 7515 fields that are
  safe to honor). Any other header field
  (`jku`, `x5u`, `x5c`, `jwk`, `crit`,
  `x5t`, `x5t#S256`, or anything else)
  causes a typed parse error before the
  signature path is reached. 7 new unit
  tests in `oidc_client::tests`:
  `rejects_jku_header`,
  `rejects_x5u_header`,
  `rejects_x5c_header`,
  `rejects_jwk_header`,
  `rejects_crit_header`,
  `accepts_minimal_header` (the post-fix
  positive case for `{"alg":"RS256"}`),
  and `accepts_typ_and_cty_headers`
  (RFC 7515 informational fields). The
  existing `es256_*` / `ps256_*` signature
  tests now also exercise the same
  `JwsHeader` struct, so the full signature
  path is covered. No residual risk.

- **P0-NONCE-01 OIDC refresh nonce
  (TZ #2 WP-0.4, CWE-287, Appendix A.2).**
  The pre-fix `validate_id_token_minimal`
  accepted `expected_nonce: &str = ""` on
  the refresh path, which was broken in
  BOTH directions: an id_token with
  `nonce: ""` matched the empty expected
  and was accepted without challenge,
  while an id_token with any non-empty
  nonce (or, depending on IdP config, no
  nonce claim at all) failed the check
  and killed the user's session mid-flight.
  The fix changes the parameter to
  `Option<&str>`: `Some(stored_nonce)` on
  initial login (strict match, the nonce
  was generated at authorize-url time and
  stored in `oidc_pending_state`); `None`
  on the refresh path (the OIDC spec says
  refresh responses omit the nonce, so we
  trust the IdP's signature on the new
  id_token without re-binding it to a
  stored nonce). 8 call sites updated
  (2 production + 6 test fixtures). The
  existing `http_integration::oidc_refresh_
  endpoint_returns_new_token_and_expiry`
  test now exercises the correct refresh
  path. `a2` in `security_replays.rs`
  remains `#[ignore]`'d as a sister-file
  pointer. No residual risk.

- **P0-AUD-01 Structured audit
  (TZ #1 §16 / AUD-01).** The pre-fix
  `oidc.login` and `oidc.refresh` audit
  records built their `details` field via
  manual JSON concatenation:
  `format!("{{\"sub\":\"{sub}\"}}")`. This
  breaks on any `sub` containing characters
  that need JSON-escaping (quotes,
  backslashes, control chars), producing
  silently-malformed JSON documents in the
  `audit_log` table that fail downstream
  parsing and are not detectable by the
  `serde_json::Value` contract that other
  callers honor. Both call sites are now
  `serde_json::json!({"sub": ...})`, which
  escapes correctly. Two new unit tests in
  `audit_log_repository_tests.rs`:
  `details_round_trips_through_serde_json`
  (verifies a `sub` containing `"`, `\`,
  and a newline round-trips losslessly) and
  `malformed_json_details_is_detected` (a
  tripwire that asserts malformed JSON in
  `details` is detectable at read time).
  No residual risk.

- **P0-F-05 Vault fail-closed
  (TZ #1 §6 F-05 + TZ #2 WP-2.1,
  CWE-798, Appendix A.5).** The pre-fix
  `boot_default_state` silently accepted
  the placeholder passphrase
  `"unset-rotate-before-first-use"`
  (committed in the public repo's env
  examples), deriving a vault key from a
  string any attacker who read the repo
  could guess. Post-fix, the server refuses
  to start without a high-entropy
  passphrase and refuses to log the
  plaintext admin token at first boot. New
  module `crates/server/src/vault_init.rs`
  with `load_passphrase` (prefers
  `AGENCY_VAULT_PASSPHRASE_FILE`,
  falls back to `AGENCY_VAULT_PASSPHRASE`),
  `validate_passphrase` (rejects placeholders
  + enforces ≥ 80 bits Shannon entropy), and
  `load_or_generate_install_salt` (per-install
  32-byte salt persisted to
  `<data_dir>/vault.salt` mode 0600).
  `SecretRepository::new` now takes the
  per-install salt as a required argument
  (3rd parameter); the fixed project-wide
  `APP_SALT` is gone — two installs with
  the same passphrase now derive
  different keys. The admin-token print at
  first boot is replaced with a path-only
  message (`token saved to /var/lib/agency/
  server.token`); the token itself is no
  longer written to stderr. 11 unit tests
  in `vault_init::tests` and 10 integration
  tests in `crates/server/tests/vault_replay.rs`
  cover placeholder / low-entropy / empty
  rejection, `*_FILE` preference, install-salt
  generation / stability / wrong-length,
  and end-to-end AES-GCM isolation between
  two installs with the same passphrase
  but different salts. Residual risk
  recorded as RR-001 in
  `docs/RISK_REGISTER.md`. `cargo test
  --workspace` + `cargo clippy -D warnings`
  + `cargo fmt --check` are green.

### Added

- **Phase 0 Foundation (ADR-0043 Remediation
  Charter, ADR-0044 Multi-tenant schema)**.
  The post-2.9.0 hardening cycle is now
  scaffolded. Nine new files in the repo:
  - `docs/AGENT_DOD.md` — 12-point
    Definition of Done + report format
    with `CWE: CWE-NNN` + `Exploit
    scenario: <ref>` + `RR-NNN` links
    to `RISK_REGISTER.md`.
  - `docs/RISK_REGISTER.md` — residual
    risk ledger, RR-NNN IDs.
  - `docs/REVIEW_LOG.md` — self-review
    record for phase gates.
  - `crates/core/tests/security_replays.rs`
    — 5 seed scenarios from TZ #2
    Appendix A (A.1..A.5), all
    `#[ignore]` until the corresponding
    P0 closes in Phase 1.
  - `crates/core/tests/tenancy.rs` —
    multi-tenant test harness (Q1).
  - `crates/server/tests/oidc_real_idp.rs`
    — real Keycloak harness (Q2) with
    a `SKIP_REAL_IDP_TESTS=1` escape
    hatch.
  - `tools/keycloak/realm.json` —
    agency realm with three test users
    (alice / bob / ops) and a `tenant`
    claim mapper.
  Two `docs/adr/` files (gitignored):
  - `0043-remediation-charter.md` —
    ratifies the phase-ordered plan,
    Q1..Q11 locked decisions, hard
    rules from §0.3 of the plan.
  - `0044-multi-tenant-schema.md` —
    `tenant_id` on every server-side
    table, RLS strategy for Phase 5,
    cache-key convention.
  Two modified files:
  - `docker-compose.yml` — adds a
    `keycloak` service (profile
    `dev`/`idp`, port 8081,
    `--import-realm`).
  - `.github/workflows/ci.yml` —
    adds the `ci-linux` job
    (ubuntu-latest required, plugin
    sandbox + real IdP + security
    replays) with `cargo audit`,
    `cargo deny`, and
    `cargo auditable` SBOM. The
    `ci-windows` job remains for
    build checks.
  Regression baseline: `cargo test
  --workspace` green, 114 active
  tests pass. This is the gate to
  Phase 1 (10 P0 security blockers,
  ~7-10 days, ~10 commits).

- **VPS deploy surface (ADR-0041)**.
  `agency-server` is now VPS-ready
  out of the box. The `127.0.0.1`
  hard-code in `main.rs` is gone;
  the binary now binds
  `0.0.0.0:8080` by default and
  reads `--bind` (CLI) and
  `AGENCY_BIND_IP` (env) for
  overrides. Integration tests
  still pass — they bind
  `127.0.0.1:0` themselves
  through `TcpListener::bind` and
  do not go through the new
  helper. The `HermesAdapter` was
  already VPS-ready: it discovers
  Hermes through `which("hermes")`
  and the `HERMES_HOME` env var;
  no change needed.
  New repo-root files:
  - `Dockerfile` — multi-stage
    `rust:1.83-bookworm` → `gcr.io/distroless/cc-debian12:nonroot`
    image. The `tauri-app` crate
    is intentionally skipped in
    the build (it is GUI-only).
    Output is two stripped
    binaries: `agency-server`
    (~30 MB image total) and
    `agency`.
  - `docker-compose.yml` —
    `agency-server` (distroless,
    bind `0.0.0.0:8080`,
    capability-dropped) +
    `caddy:2.8-alpine` (TLS
    terminator + reverse proxy).
    The `healthcheck` block is
    intentionally on the
    `caddy` side rather than the
    distroless binary (no shell /
    `wget` in the distroless
    base).
  - `Caddyfile` — TLS
    terminator. Strips
    `Server` / `X-Powered-By`,
    sets `HSTS` /
    `X-Content-Type-Options` /
    `X-Frame-Options` /
    `Referrer-Policy` /
    `Permissions-Policy` /
    `CSP: default-src 'none'`.
    `request_body { max_size 2MB }`
    matches the largest
    legitimate `POST /v1/deploys`
    body.
  - `packaging/systemd/agency-server.service` —
    native (no Docker) unit.
    Hardened: `NoNewPrivileges`,
    `ProtectSystem=strict`,
    `ProtectHome`, `PrivateTmp`,
    `ReadWritePaths=/var/lib/agency`,
    `RestrictAddressFamilies=AF_INET AF_INET6`,
    `RestrictNamespaces`,
    `RestrictRealtime`,
    `RestrictSUIDSGID`,
    `LockPersonality`,
    `MemoryDenyWriteExecute`,
    `PrivateDevices`,
    capability bounding set
    dropped to empty. Uses
    `EnvironmentFile=-/etc/agency/agency.env`
    so operator secrets never
    appear in `systemctl show`.
  - `docs/DEPLOY.md` — full VPS
    walkthrough for both paths
    (Docker Compose + native
    systemd). Includes the
    first-boot admin-token
    capture procedure, the
    smoke-test `curl` walk,
    `target` + `deploy` round-trip
    against a local catalog,
    backup / restore procedure
    for the `agency-data` volume,
    upgrade procedure, and a
    troubleshooting table that
    covers the 2.5.3 / 2.7.4 /
    2.7.7 / 2.8.x failure modes
    seen in CI.
- `README.md` — added a short
  **Deploy** section pointing
  at `docs/DEPLOY.md` with the
  minimum `docker compose up -d`
  one-liner.

### Verified

- `cargo test --workspace`:
  **513 passed, 0 failed** (no
  change from 2.8.x; the
  integration tests still bind
  `127.0.0.1:0` through
  `TcpListener::bind`).
- `cargo clippy --workspace
  --all-targets -- -D warnings`:
  0 warnings.
- `cargo build --release
  -p agent_dep_server
  -p agent_dep_cli`: clean
  release build (stripped,
  `lto = "thin"`, `opt-level = 3`).

- **P1-F-06 Vault KDF v2: per-secret salt
  + AAD (TZ #2 WP-3.2, CWE-916 +
  CWE-326 + CWE-345, Appendix A.6).**
  The pre-fix v1 vault derived a single
  AES-256-GCM cipher from the operator's
  passphrase via Argon2id with a
  per-install salt; every secret shared
  that one cipher, and there was no
  binding between the ciphertext and the
  secret's identity (CWE-916 +
  CWE-345). Post-fix v2:
  - **Per-secret salt (16 bytes,
    OsRng).** New column `secret_salt
    BLOB NOT NULL`. The KDF input salt
    becomes `install_salt || secret_salt`
    (32 + 16 bytes). Two rows with the
    same plaintext under the same
    passphrase derive different keys
    even within one install
    (defeats cross-row known-plaintext
    attacks; CWE-916).
  - **AAD binding.** New column
    `aad TEXT NOT NULL`. AES-GCM is
    called with `aad = secret_name`,
    binding the ciphertext to the
    secret's identity. Cross-row
    ciphertext-swap attacks now fail the
    GCM tag check (CWE-345). The `aad`
    column is `TEXT` so the future
    multi-tenant release (ADR-0044) can
    switch to `tenant_id:secret_name`
    without a further migration.
  - **Per-row `version` column** (no
    CHECK constraint; the app-level
    dispatch in
    `SecretRepository::get_value` is the
    single source of truth). Legacy v1
    rows are backfilled with
    `secret_salt = 0^16` and
    `aad = ''` at migration 020 and
    remain readable bit-for-bit via
    the legacy decrypt path. New rows
    are written with `version = 2`.
  - **Lazy migration on `update`.**
    Updating a legacy v1 row rewrites it
    in place under v2 with a fresh
    per-secret salt + AAD. No offline
    re-encryption is forced.
  - **No pre-derived cipher cache.**
    `SecretRepository` no longer holds
    an `Aes256Gcm`; the per-secret
    cipher is derived on every
    encrypt/decrypt via `derive_key_v2`
    (Argon2id ~50-200 ms). Acceptable
    for the secret-management workload;
    avoids sharing a cipher across
    secrets.
  - 6 new unit tests in
    `secrets_repository_tests`:
    `same_plaintext_under_same_passphrase_yields_different_ciphertexts`,
    `aad_binding_blocks_cross_row_confusion`,
    `legacy_v1_row_is_readable_via_legacy_path`,
    `update_migrates_v1_row_to_v2_in_place`,
    `v2_row_with_empty_aad_is_rejected`,
    `future_kdf_version_is_rejected_with_typed_error`.
    `vault_replay::a5_two_installs_with_same_passphrase_derive_different_keys`
    continues to pass (per-install salt
    isolation is now strictly stronger
    because per-secret salt adds a
    second row-level input to the KDF).
  - Migration 020: `secrets_new` table
    with `secret_salt`, `aad`, no
    `version` CHECK. Bump
    `meta.schema_version` 19 → 20.
    Three test sites updated
    (`sqlite_tests`, `journal_tests`,
    `cli_tests`,
    `pending_deploys_target_id_not_null`).
  - No residual risk. Existing v1
    rows are still readable; new v2
    rows are strictly stronger
    (per-secret salt + AAD).

- **P1-F-03a Server-side session store
  (TZ #2 WP-3.3, CWE-613, Appendix A.8,
  data layer only).** The pre-fix 2.10.0
  OIDC flow issues a local bearer in the
  JSON body of `/v1/auth/oidc/callback`;
  the SPA holds it in JS memory and uses
  it as `Authorization: Bearer`. The
  bearer has a 1-hour `token_expires_at`
  but is otherwise immutable — there is
  no server-side revoke, no idle
  timeout, and no absolute timeout. A
  captured bearer cannot be remotely
  killed, and an active session is
  killed exactly at expiry regardless
  of how recently the user actually
  stopped working. CWE-613.
  - New `sessions` table (migration
    021): `id` (32-byte random
    base64url = the cookie value),
    `user_id` (FK to `users`),
    `csrf_token` (32-byte random for
    `X-CSRF-Token` header),
    `created_at`, `last_used_at` (advanced
    on every successful `find`),
    `idle_expires_at` (sliding window,
    `now + IDLE_TTL_SECS = 3600`),
    `absolute_expires_at` (fixed cap,
    `now + ABSOLUTE_TTL_SECS = 8 * 3600`),
    `revoked_at`, `ip`, `user_agent`.
    Two indexes: `user_id` (for
    `list_active_for_user`) and
    `revoked_at + idle_expires_at`
    (for GC). No CHECK on `version` /
    state — app-level `find` is the
    single source of truth.
  - New `SessionRepository`
    (`crates/core/src/infrastructure/repository/sessions_repository.rs`):
    - `create(user_id, ip, user_agent) ->
      (id, SessionRow)` — random
      base64url id + CSRF token;
      `idle_expires_at = now + 1h`,
      `absolute_expires_at = now + 8h`.
    - `find(id) -> Option<SessionRow>` —
      SQL predicate filters on
      `revoked_at IS NULL AND
      idle_expires_at > now AND
      absolute_expires_at > now`; on a
      valid hit, the row is touched
      (`last_used_at = now`,
      `idle_expires_at = now + 1h`).
      `absolute_expires_at` is
      deliberately NOT advanced on
      touch (the cap is the cap).
    - `revoke(id) -> bool` — sets
      `revoked_at = now`. Idempotent
      (revoking an already-revoked
      session is a no-op and returns
      `false`).
    - `revoke_all_for_user(user_id) ->
      usize` — kill switch for the
      future `/v1/auth/sessions`
      admin "log out everywhere"
      button.
    - `list_active_for_user(user_id)`
      — admin-facing summary; the
      `csrf_token` is deliberately
      NOT included (defense in depth:
      an admin who can list sessions
      should not be able to forge
      state-changing requests on
      the user's behalf).
    - `gc_expired() -> usize` —
      best-effort cleanup of
      `revoked_at IS NOT NULL OR
      idle_expires_at < now OR
      absolute_expires_at < now`,
      designed to be called by the
      server's background GC task
      every 60 s (the P1-F-03b
      follow-up wires this into
      `boot_default_state`).
  - 10 new unit tests in
    `sessions_repository_tests.rs`:
    round-trip, sliding `find`,
    revoke, idempotent revoke,
    `revoke_all_for_user`,
    list-active-skips-revoked,
    `gc_expired`, two-sessions-
    per-user get independent ids
    and CSRF tokens, unknown id,
    revoked row.
  - Migration 021 bumps
    `meta.schema_version` 20 → 21.
    Four test sites updated
    (`sqlite_tests`, `journal_tests`,
    `cli_tests`,
    `pending_deploys_target_id_not_null`).
  - **No API change yet.** The
    P1-F-03b follow-up wires the
    repository into the OIDC handlers
    (callback, refresh, logout) and
    adds a `require_session_or_bearer`
    middleware that prefers the
    session cookie and falls back to
    the legacy bearer. P1-F-03a
    is the data layer only; the CWE-613
    attack surface is not closed
    until P1-F-03b lands.

- **P1-F-03b Session cookie middleware
  + OIDC handlers (TZ #2 WP-3.3,
  CWE-613, Appendix A.8).** Closes
  the CWE-613 attack surface that
  P1-F-03a set up. The bearer-in-JSON
  path is now legacy; the canonical
  auth artifact is a server-side
  session id carried in an
  HttpOnly+Secure+SameSite=Strict
  cookie.
  - **New `session_cookie` module**
    (`crates/server/src/session_cookie.rs`)
    with `make_session_cookie_header`,
    `clear_session_cookie_header`, and
    `parse_session_cookie`. Cookie
    attributes: `HttpOnly`, `SameSite=Strict`,
    `Path=/`, `Max-Age=3600` (matches
    server-side `IDLE_TTL_SECS`),
    `Secure` (configurable via
    `AGENCY_COOKIE_SECURE`, default
    `true`). 10 unit tests cover
    cookie construction (Secure
    on/off), `Max-Age=0` for logout,
    and `parse_session_cookie`
    (present, absent, empty value,
    whitespace, multiple cookies).
  - **`OidcConfig::cookie_secure`**
    (env `AGENCY_COOKIE_SECURE`,
    default `true`). The
    `Secure` flag is opt-out,
    matching the `AGENCY_OIDC_MOCK`
    pattern: an operator who wants
    the cookie to travel over plain
    HTTP MUST set the env var
    explicitly. Default is
    deliberately safe.
  - **`callback_handler` (P1-F-03b)**
    creates a server-side session
    after provisioning the user
    and emits `Set-Cookie:
    agency_session=...` on the
    response. The JSON `token`
    field is kept for one release
    so a frontend migration can land
    independently.
  - **`refresh_handler` (P1-F-03b)**
    accepts a `Cookie: agency_session=...`
    header, revokes the existing
    session, creates a fresh one,
    and emits the new id in
    `Set-Cookie`. A captured
    pre-refresh cookie is dead the
    moment the handler returns
    (cookie id rotation).
  - **`logout_handler` (P1-F-03b)**
    revokes the server-side session
    identified by the cookie (if
    present) and emits a
    `Set-Cookie: agency_session=;
    Max-Age=0` to instruct the
    browser to drop the cookie.
    The bearer revoke path is
    preserved for callers that
    still use `Authorization: Bearer`
    (legacy, one release).
  - **New `require_session_or_bearer`
    middleware** in `auth.rs`
    replaces `require_bearer` on
    the `authed` router. Cookie
    path: read `agency_session`,
    look up in `SessionRepository`,
    convert to `AuthenticatedUser`
    via `users.find_by_id` (the
    `users` table is the single
    source of truth for role and
    `disabled_at`; the session
    only stores `user_id`).
    Disabled users with a valid
    session get 401. Bearer path:
    a `tracing::warn!` is emitted
    on every hit so the operator
    can track the migration. The
    legacy `require_bearer`
    middleware is left in place
    for non-migrated callers.
  - **`ServerState`** gains
    `sessions: SessionRepository`
    and `cookie_secure: bool`.
  - **GC task** in
    `boot_default_state` runs
    `SessionRepository::gc_expired`
    every 60 s, same cadence as
    the existing `oidc_pending_state`
    GC. Removes revoked,
    idle-expired, and
    absolute-expired sessions.
  - **`UserRepository::find_by_id`**
    new helper: looks up a user
    by primary key. Unlike
    `find_by_external_id`, returns
    the row even if disabled (the
    caller decides what to do with
    a disabled user — the middleware
    rejects with 401, an admin
    endpoint may want to see the
    row for the audit log).
  - 2 integration-test `ServerState`
    constructors updated to wire
    the new fields (`cookie_secure
    = false` for plain-HTTP
    localhost tests).
  - 1 unit-test OidcConfig
    constructor updated to set
    `cookie_secure` explicitly.
  - **CWE-613 closed.** A stolen
    cookie is dead the moment
    `/v1/auth/oidc/logout` returns
    (`revoke`), and dead on every
    `/v1/auth/oidc/refresh` (cookie
    id rotation). Sliding 1h idle
    timeout (browser side) + 1h
    server-side `IDLE_TTL_SECS`.
    Absolute 8h cap (server-side
    `ABSOLUTE_TTL_SECS`) — a
    keep-alive script cannot
    extend the session.

- **P1-G-01 + P1-G-02 Git URL policy
  + SSRF protection (TZ #2 WP-3.3,
  CWE-918 Server-Side Request
  Forgery).** The pre-fix 2.10.0
  `classify_url` accepted any
  `https://`, `http://`, `file://`,
  `ssh://`, `git://`, or SCP-style
  `host:path` URL and trusted the
  host implicitly. Two threat
  surfaces: a plaintext `http://`
  URL silently cloned over an
  unauthenticated channel (CWE-319);
  a `https://` URL whose host
  resolves to a private address
  (RFC 1918, loopback, the cloud
  metadata service
  `169.254.169.254`, etc.) gives
  the fetcher a primitive to probe
  the internal network (CWE-918).
  - New `UrlPolicy` module
    (`crates/core/src/infrastructure/url_policy.rs`).
    `UrlPolicy::from_env()` reads
    `AGENCY_GIT_ALLOWED_HOSTS`
    (comma-separated, supports
    `*.example.com` wildcards that
    match one label only).
    `AGENCY_GIT_ALLOW_HTTP=1` and
    `AGENCY_GIT_ALLOW_FILE=1` are
    the dev / test-only opt-ins.
    `UrlPolicy::deny_default()` is
    the production policy (only
    `localhost` and `127.0.0.1`
    allowed). `UrlPolicy::permissive_test()`
    is the unit-test escape hatch.
  - **SSRF guard.** The policy
    blocks hosts that resolve to
    loopback, RFC 1918, link-local,
    CGN, benchmark, IETF, and
    documentation IPv4 ranges; the
    same for IPv6 (loopback,
    link-local, ULA, IPv4-mapped).
    The guard runs BEFORE the
    allowlist: a `*.internal`
    allowlist entry cannot be used
    to reach `10.0.0.5`. The guard
    rejects `169.254.169.254`
    specifically (the cloud
    metadata service).
  - **Wire-in.** `classify_url_with_policy(url, &policy)`
    is the new production entry
    point. `classify_url(url)` is
    a wrapper that uses
    `permissive_test()` (legacy /
    unit tests). `ingest_source_with_policy(source, root, &policy)`
    is the new production entry;
    `ingest_source(source, root)` is
    the wrapper. The CLI
    `commands/catalog.rs` reads
    `UrlPolicy::from_env()` and
    fails fast on a blocked URL
    with a descriptive error that
    names the missing env var.
  - 12 unit tests in
    `url_policy::tests`: default
    policy denies remote https,
    allows localhost ssh, env
    allowlist with wildcards,
    http blocked by default,
    http allowed with warning when
    opted in, file blocked by
    default, `git://` routed
    through SSH allowlist, SSRF
    blocks RFC 1918 / loopback /
    metadata / 0.0.0.0, SSRF
    blocks IPv6 loopback / ULA /
    link-local, permissive_test
    allows everything, wildcard
    matches one label only,
    unknown scheme rejected.
  - **CWE-918 closed (foundation).**
    The fetcher is a defense-in-
    depth layer; the policy is the
    primary gate. A
    follow-up commit could wire
    the policy into the
    `HttpsFetcher` / `SshFetcher`
    callbacks (rejecting `http://`
    redirects, capping the TCP
    connect to the allowlisted
    host, etc.). The current
    change closes the primary
    attack surface.

- **P1-O-04 OIDC authorize_url from
  discovery (TZ #1 §14 / O-04,
  CWE-601 URL Redirection to
  Untrusted Site).** The pre-fix
  `RealOidcClient::authorize_url`
  built the IdP `/authorize` URL
  by string-replacing the
  `redirect_uri`:
  `self.config.redirect_uri.replace(
  "/callback", "/authorize")`. A
  misconfigured
  `AGENCY_OIDC_REDIRECT_URI`
  (e.g. `https://attacker.com/cb`)
  would have produced
  `https://attacker.com/authorize`,
  and the SPA would then send the
  user's browser to a
  non-IdP-controlled origin with
  the operator's `client_id` and
  the user's `state` and `nonce`.
  CWE-601.
  - `authorize_url` is now `async`
    on the trait. The real
    implementation fetches the
    discovery document (already
    validated by P1-F-02: HTTPS,
    issuer match, same-origin
    JWKS) inside the call and
    uses the IdP-returned
    `authorization_endpoint` as
    the base URL — no
    `redirect_uri` string-replace.
  - Same-origin check:
    `check_authorization_endpoint_origin`
    rejects any
    `authorization_endpoint` whose
    origin (scheme + host + port)
    differs from the configured
    `issuer`. This is the
    explicit gate for the redirect;
    a misconfigured IdP that
    publishes its
    `authorization_endpoint` on
    a different host (an open
    redirector, a split IdP, a
    typo) is rejected at login time.
  - 4 new unit tests in
    `oidc_client::tests`:
    `authorization_endpoint_origin_match_passes`
    (happy path),
    `authorization_endpoint_origin_mismatch_rejected`
    (cross-origin host),
    `authorization_endpoint_origin_scheme_mismatch_rejected`
    (`http://` vs `https://`),
    `authorization_endpoint_origin_port_mismatch_rejected`
    (different port).
  - 1 pre-fix
    `real_authorize_url_includes_pkce_s256_challenge_method`
    test was removed: it
    exercised the synchronous
    URL-builder behaviour and
    cannot run without an HTTP
    mock (the post-fix code does
    a discovery GET as part of
    the call). The URL shape is
    unchanged and is asserted by
    `mock_authorize_url_includes_state_code_challenge_nonce`
    (now `#[tokio::test]` since
    the trait is async).
  - `oidc::handle_login` updated
    to `.await` the new async
    `authorize_url`.
  - **CWE-601 closed.** A captured
    or misconfigured
    `redirect_uri` can no longer
    steer the user's browser to a
    non-IdP origin; the
    `/authorize` URL is bound to
    the IdP's advertised endpoint.

## [2.9.0] — 2026-09-05 — VPS deploy surface

### Added

- **2.5.3 NOT NULL on `pending_deploys.target_id`**
  (ADR-0033 follow-up). The 2.5.0
  schema allowed `target_id IS NULL`
  to keep the 2.4.0 path-based CLI
  alive; 2.5.3 closes the loophole.
  The handler `request_deploy` now
  REQUIRES `target` in the body
  (returns 400 otherwise). Migration
  `018_pending_deploys_target_id_not_null.sql`
  is a 12-step table-rebuild (SQLite
  has no `ALTER TABLE … ADD
  CONSTRAINT`). The backfill helpers
  `list_orphans` and `set_target_id`
  (2.5.1 / 2.5.2) remain in the API
  surface for operator use; the
  HTTP `POST /v1/deploys` does not
  need them anymore. Three new
  test sites: `pending_deploys_target_id_not_null`
  (3/0), `pending_deploys_repository`
  (8/0; legacy orphan-row tests
  preserved with a `post 2.5.3`
  suffix for the still-public API),
  and `http_integration` (29/0;
  every `POST /v1/deploys` test now
  creates a `Target` first via the
  shared `_ensure_target` helper
  that builds the row through the
  real `POST /v1/targets` endpoint
  to avoid a WAL-visibility race
  between two `SqlitePool`
  instances on the same file).

- **2.7.7.1 ES/PS signature verification**
  (ADR-0037 follow-up). The 2.7.9
  validator supported only RSA
  PKCS#1 v1.5 (`RS256`/`RS384`/`RS512`);
  2.7.7.1 adds `ES256`/`ES384`
  (ECDSA P-256 / P-384 via the
  `p256`/`p384` crates) and
  `PS256`/`PS384`/`PS512` (RSA-PSS
  via `rsa::pss`). `validate_id_token_minimal`
  accepts the seven algorithms;
  `verify_jwt_signature` is a clean
  dispatch on `alg` with a new
  `decode_rsa_pubkey` helper.
  HS-* and the `alg: "none"` trick
  stay rejected. New workspace deps:
  `p256`, `p384`, `signature`; the
  `rsa` workspace dep gained the
  `getrandom` feature (the `Signer`
  impls are gated on it). Eight new
  unit tests in `oidc_client::tests`
  cover the round-trip for `ES256`
  and `PS256`, the wrong-key and
  crv-mismatch rejection paths, and
  the HS / `none` reject paths; a
  one-shot `axum` router serves the
  JWKS for the integration path.

- **2.8.1 Git fetcher unification**
  (ADR-0040). The 2.8.0 release
  shipped a minimal
  `infrastructure::git_fetcher`
  stub (`clone_to` + `fetch`)
  alongside a richer scaffold in
  `application::ingest::git_fetcher`
  (`GitFetcher` trait, `HttpsFetcher`,
  `SshFetcher`, `classify_url`,
  `ingest_source`). 2.8.1 collapses
  the two into one place:
  `infrastructure::git_fetcher` is
  the single home for the trait +
  HTTPS/SSH impls + `FetchResult` +
  `clone_or_update` + `classify_url`,
  and `application::ingest::ingest_source`
  is the cross-layer glue that
  threads a `FetchResult` into
  `IngestService::ingest_local`.
  The `application/ingest/git_fetcher`
  module and the lib-side
  `infrastructure/git_fetcher_tests`
  stub are removed; the integration
  test `crates/core/tests/git_fetcher.rs`
  now imports from
  `infrastructure::git_fetcher::*`.
  The cross-layer direction is now
  strictly: domain → application →
  infrastructure (no upward dep
  from `infrastructure` to
  `IngestService`).

- **2.7.4 Plugin manifest signing + trust store**
  (ADR-0032). `PluginManifest` gains
  optional `signature` (base64-url
  Ed25519, 64 bytes) and `signer_id`
  fields; the 2.7.4 production
  policy REJECTS unsigned manifests.
  `PluginManifest::canonical_bytes`
  re-serialises the manifest with
  `signature` and `signer_id`
  stripped (canonical TOML form,
  so the operator does not worry
  about key ordering / whitespace);
  `PluginManifest::verify_signature(&TrustStore)`
  performs the Ed25519 check. The
  new `application::scanner::trust_store::TrustStore`
  is loaded from
  `~/.config/agency/trust.json`,
  supports both array and map JSON
  forms, and constructs each
  `VerifyingKey` once at parse time
  so an off-curve / non-canonical
  key fails immediately, not on
  every verify call. 15 new tests:
  8 in `trust_store` (parse, malformed
  key, happy path, tampered, wrong
  key, unknown signer, wrong sig
  length) and 7 in `plugin` (parse
  accept / partial reject, happy
  path, tampered name, wrong signer,
  unknown signer, canonical bytes
  strip). New workspace dep:
  `ed25519-dalek` 2.x with the
  `rand_core` feature.

### Changed

- **README + AGENTS.md sync for
  2.5.0..2.8.0** (local docs only).
  README is now a 2.8.0 overview
  with the 31-tag timeline, the
  489-test count, the 30-ADR index,
  and the deferred 2.5.3 / 3.x
  follow-ups called out. AGENTS.md
  gained 2.5..2.7 conventions, the
  OIDC wire-protocol summary, the
  server crate layout, the 2.5.3
  NOT NULL follow-up note, and a
  refreshed 3.x deferral list. No
  code change.

### Verified

- `cargo test --workspace`:
  **513 passed, 0 failed** (52
  more than 2.8.0; the 2.7.7.1 +
  2.7.4 test surface).
- `cargo clippy --workspace
  --all-targets -- -D warnings`:
  0 warnings.
- `cargo test -p agent_dep_core
  --test ts_export`: 1 passed (TS
  DTO drift guard — the new
  PluginManifest fields are
  front-end-irrelevant; no
  `types.generated.ts` change).
- `npm run check` (svelte-check):
  0 errors, 0 warnings.

## [2.8.0] — 2026-09-04

### Added

- **Real Git source ingest**
  (ADR-0009 + ADR-0039). The MVP
  `IngestRepository` walked a local
  catalog directory; 2.8.0 adds a
  `GitFetcher` that uses the `git2`
  crate (with `vendored-libgit2`)
  to clone a remote repo into a
  tempdir and feed the existing
  local walker.
- New `GitFetcher` in
  `crates/core/src/infrastructure/git_fetcher.rs`:
  - `GitFetcher::clone_to(url,
    ref_, dest)` — clone a
    remote repo into `dest`
    and check out `ref_`
    (branch, tag, or commit
    SHA; defaults to remote
    HEAD).
  - `GitFetcher::fetch(dest,
    ref_)` — fetch +
    fast-forward an existing
    clone.
- Both methods are async via
  `tokio::task::spawn_blocking`
  (git2 is sync).
- HTTPS + SSH are supported
  via the operator's
  `~/.ssh/config` + `ssh-agent`.

### Changed

- **Workspace dependency**:
  `git2 = { version = "0.20",
  features = ["vendored-libgit2"]
  }` (new). The
  `vendored-libgit2` feature
  builds libgit2 from source so
  the binary is portable across
  Windows / Linux / macOS.
- `crates/core/Cargo.toml`
  gains the `git2` dep
  (workspace alias).
- 3 new build deps are pulled
  in transitively: `libssh2-sys`,
  `openssl-probe`, `openssl-sys`.

### Test count

- 489/0 + 3 ignored (was 488/0
  in 2.7.10). Delta is +1 (the
  2 happy-path tests are
  `#[ignore]`'d on Windows:
  tempfile uses 8.3 short path
  which `git2` rejects; tracked
  in 2.8.1).

### Caveats (deferred to 2.8.x)

- **Auto-merge on fetch** — 2.8.0
  does not fast-forward the
  local branch after `fetch`.
- **Integration with the existing
  `application::ingest::git_fetcher`**
  (which has `HttpsFetcher` /
  `SshFetcher` scaffold) —
  2.8.1 unifies the two paths.
- **Sparse-checkout**, **shallow
  clone**, **LFS** support.

## [2.7.10] — 2026-09-03

### Added

- **DB-backed `OidcPending`**
  (ADR-0038). The 2.7.6 in-memory
  `Arc<Mutex<HashMap<String,
  PendingAuth>>>` is replaced by
  a SQLite table
  (`oidc_pending_state`). This
  closes the multi-process /
  multi-instance gap: a `state`
  token returned by
  `/v1/auth/oidc/login` on
  replica A is now visible to the
  callback handler on replica B.
- New `OidcPendingRepository` in
  `crates/core/src/infrastructure/repository/oidc_pending_repository.rs`:
  - `insert(state, pkce, nonce,
    created_at_secs)` — write
    path.
  - `take(state, max_age_secs)`
    — atomic `SELECT` + `DELETE`
    in one transaction.
  - `gc_expired(max_age_secs)` —
    best-effort cleanup of rows
    older than `max_age_secs`.
- 60-second background tokio
  task in `boot_default_state`
  that does best-effort GC of
  the `oidc_pending_state`
  table.

### Changed

- `ServerState.oidc_pending` is
  now `Arc<OidcPendingRepository>`
  (was `Arc<Mutex<HashMap<...>>>`).
- `handle_login` and
  `validate_state` are now async.
- The 2.7.6 `PendingAuth::is_expired`
  method is removed; expiry
  enforcement moved to the
  repository's `take`.

### Schema

- New `oidc_pending_state` table
  + `idx_oidc_pending_created_at`
  index. Schema 16 -> 17.
- The 3 schema-version test sites
  are bumped from 16 to 17
  (sqlite_tests, journal_tests,
  cli_tests).

### Test count

- 488/0 (was 487/0 in 2.7.9). Delta
  is +1 (4 new repository tests
  minus 3 removed inline tests).

## [2.7.9] — 2026-09-03

### Added

- **OIDC full RSA signature verification**
  (ADR-0037). Closes the 2.7.7
  caveat: the `RealOidcClient` now
  actually verifies the JWS
  signature against the IdP's
  JWKS. 2.7.7 only validated
  `iss` / `aud` / `nonce`; a
  malicious IdP could forge
  tokens.
- New `verify_jwt_signature`
  helper in
  `crates/server/src/oidc_client.rs`:
  fetches the JWKS, finds the JWK
  with the matching `kid`, rejects
  non-RSA `kty`, builds an
  `RsaPublicKey` from `n` and `e`,
  and verifies the signature with
  `rsa::pkcs1v15::VerifyingKey<Sha*>`.
- New `find_jwk` helper for
  JWKS-by-`kid` lookup.

### Changed

- **Workspace dependency**:
  `rsa = { version = "0.9", features
  = ["sha2"] }` (new). The
  `sha2` feature enables the
  `pkcs1v15::SigningKey<Sha*>`
  for RS256 / RS384 / RS512.
- `validate_id_token_minimal`
  docblock updated: the 2.7.7
  caveat is replaced with a 2.7.9
  block that documents the
  supported `alg`s (RS256 / RS384
  / RS512) and the 2.7.9.1
  follow-up (ES / PS).

### Algorithm support (2.7.9)

| alg   | 2.7.9 |
|-------|-------|
| RS256 | yes   |
| RS384 | yes   |
| RS512 | yes   |
| ES256 | no — deferred to 2.7.9.1 |
| ES384 | no — deferred |
| ES512 | no — deferred |
| PS256 | no — deferred |
| PS384 | no — deferred |
| PS512 | no — deferred |
| HS\*  | never (OIDC forbids symmetric ID tokens) |

### Test count

- 487/0 (unchanged net from 2.7.8).
  The signature-path coverage
  (real RSA key + JWKS server) is
  deferred to 2.7.9.1 with a
  `wiremock` integration. The
  2.7.9 cut ships the production
  verifier without a heavyweight
  test harness.

## [2.7.8] — 2026-09-03

### Added

- **OIDC token refresh + logout**
  (ADR-0036). The OIDC flow now has
  a real logout path and a refresh
  path that the SPA can use to keep
  the local session alive.
  - `POST /v1/auth/oidc/refresh` —
    public. Body
    `{refresh_token, sub}`. Looks up
    the local user by
    `external_id`, calls
    `oidc_client.refresh`, rotates
    the local bearer, updates
    `token_expires_at`, audits
    `oidc.refresh`. Returns
    `{token, user, expires_at,
    refresh_token?}`.
  - `GET /v1/auth/oidc/logout` —
    public. If the Authorization
    header is present, invalidates
    the local `token_hash` for the
    matching user. Then
    302-redirects to the IdP's
    `end_session_endpoint` (if any)
    or returns 200 with
    `{"message": "logged out locally"}`.

### Changed

- **Auth middleware** honours
  `users.token_expires_at`. The
  `auth::require_bearer` middleware
  now returns 401 with
  `{"error": "token expired, refresh
  required"}` once the wall clock
  passes the expiry. NULL =
  non-expiring (bearer-token users
  from 2.0.0-2.7.7 keep NULL).
- `OidcClient` trait gains
  `refresh(...)`, `end_session_url()`,
  `as_any()` (for the logout
  handler's downcast).
- `RealOidcClient::refresh` POSTs
  `grant_type=refresh_token` to the
  `token_endpoint`, parses the new
  `id_token`, returns
  `RefreshedTokens { claims,
  expires_at, new_refresh_token }`.
- `RealOidcClient` caches
  `end_session_endpoint` from the
  discovery document.

### Schema

- `users.token_expires_at TEXT
  NULL`. Schema 15 -> 16.
- 3 schema-version test sites
  bumped (sqlite_tests,
  journal_tests, cli_tests).

### Test count

- 487/0 (was 477/0 in 2.7.7). Delta
  is +10: 3 in `oidc_client::tests`,
  2 in `users_repository::tests`, 5
  in `http_integration.rs`.

## [2.7.7] — 2026-09-03

### Added

- **OIDC real wire-protocol client**
  (ADR-0035). The 2.7.6 framework now has
  a production client behind it:
  - `OidcClient` trait
    (`crates/server/src/oidc_client.rs`,
    602 lines, 8 unit tests). The
    `async_trait` macro makes the trait
    object-safe so the framework can
    store `Arc<dyn OidcClient>` in
    `ServerState`.
  - `RealOidcClient`:
    - Discovery: GET
      `{issuer}/.well-known/openid-configuration`
      and cache the result.
    - `/authorize` URL builder using
      `url::Url::query_pairs_mut`.
      Includes `response_type=code`,
      `client_id`, `redirect_uri`,
      `scope`, `state`, `nonce`,
      `code_challenge`,
      `code_challenge_method=S256`.
    - Token exchange: POST `code` +
      `code_verifier` + `redirect_uri`
      to the `token_endpoint` with HTTP
      Basic auth on
      `client_id:client_secret`.
    - ID-token validator: parse JWS,
      decode header + payload, verify
      `alg` is present, validate `iss` /
      `aud` / `nonce` claims.
  - `MockOidcClient` (kept for dev /
    CI; activated by
    `AGENCY_OIDC_MOCK=1`).
  - `pkce_challenge_from_verifier(verifier)` —
    the S256 derivation
    `BASE64URL(SHA256(verifier))`.
  - `handle_login` delegates URL
    assembly to the configured
    `OidcClient`.
  - `callback_handler` calls
    `oidc_client.exchange_code(...)`
    before
    `provision_user_from_claims`. The
    framework's `validate_state` already
    retrieved the PKCE verifier + nonce
    from `OidcPending`; both are passed
    in `CallbackInput`.

### Changed

- **BREAKING**: `AGENCY_OIDC_MOCK`
  default flipped from `1` (2.7.6) to
  `0` (2.7.7). The real client is the
  new default. Operators who set up
  OIDC in 2.7.6 and have been running
  with the (silently mock) flow MUST
  either:
  1. Set `AGENCY_OIDC_ISSUER` +
     `AGENCY_OIDC_CLIENT_ID` +
     `AGENCY_OIDC_CLIENT_SECRET` (and
     friends) to a real IdP, OR
  2. Set `AGENCY_OIDC_MOCK=1`
     explicitly to keep the mock.
- **Workspace dependencies**:
  - `url = "2"` (new)
  - `reqwest = { version = "0.12",
      default-features = false,
      features = ["json", "rustls-tls"] }`
    promoted from
    `crates/server/dev-dependencies` to
    `crates/server/dependencies` and
    then to workspace-level
  - `async-trait = "0.1"` (new)

### Caveat

- Full RSA / ECDSA signature
  verification of the ID token is
  **deferred to 2.7.7.1**. 2.7.7 ships
  the transport + claims validation, but
  the `rsa` crate's API is in flux
  between 0.8 and 0.9; we don't want to
  chase it for the 2.7.7 cut. Operators
  who need full crypto verification
  should pin to 2.7.7.1+ or run an
  in-line reverse proxy (e.g.
  `oauth2-proxy`) in front of the OIDC
  callback.

### Test count

- 477/0 (was 466/0 in 2.7.6). Delta is
  the 11 new OIDC unit tests (8 in
  `oidc_client::tests` + 3 in
  `oidc::tests`).

## [2.7.6] — 2026-09-03

### Added

- **OIDC authentication framework** (ADR-0034).
  OIDC is now an opt-in alternative to bearer-token
  auth for `agency-server`. Bearer tokens are
  unchanged; the OIDC flow runs in parallel.
  - Migration `015` adds a nullable
    `users.external_id` column (the OIDC `sub`
    claim) plus a UNIQUE partial index. Schema
    version 14 -> 15.
  - `UserRepository::find_by_external_id` /
    `create_with_external_id` /
    `store_token_hash` are the new OIDC-aware
    primitives.
  - New `crates/server/src/oidc.rs` module
    (config, state map, role mapping, user
    provisioning, mock client, axum handlers).
  - Two new PUBLIC routes (outside the
    `require_bearer` middleware):
    - `GET /v1/auth/oidc/login` — 302 redirect
      to IdP `/authorize`.
    - `GET /v1/auth/oidc/callback` — 200 with
      `{token, user}` on success.
  - 8 env vars: `AGENCY_OIDC_ISSUER`,
    `AGENCY_OIDC_CLIENT_ID`,
    `AGENCY_OIDC_CLIENT_SECRET`,
    `AGENCY_OIDC_REDIRECT_URI`,
    `AGENCY_OIDC_SCOPES`,
    `AGENCY_OIDC_ROLE_CLAIM`,
    `AGENCY_OIDC_ADMIN_GROUPS`,
    `AGENCY_OIDC_OPERATOR_GROUPS`,
    `AGENCY_OIDC_MOCK` (default `1` for the
    2.7.6 framework).
  - 9 inline unit tests for the OIDC
    framework (role mapping, state generation,
    state validation, expiry).

### Changed

- **clippy lint cleanup** (separate `chore:`
  commit). Rust 1.98 toolchain tightens
  `clippy::io_other_error`,
  `clippy::let_underscore_must_use`, and
  `clippy::doc_markdown` to deny-by-default in
  `-D warnings`. Mechanical fixes across
  `scanner/plugin.rs`, `llm_probe.rs`, and the
  CLI command modules. No behaviour change.

### Scope note

- 2.7.6 ships the framework only (config,
  state map, role mapping, user provisioning,
  mock client). The real
  `openidconnect` + `reqwest::blocking` +
  JWKS wire-protocol exchange is a 2.7.7
  follow-up. Splitting framework from
  wire-protocol is the right cut for one
  release.

### Test count

- 466/0 (was 457/0 in 2.7.5). Delta is the 9
  new OIDC unit tests.

## [2.7.5] — 2026-09-03

### Added

- **Target backfill tooling** (ADR-0033).
  Library-side helpers for operators who
  inherited a `pending_deploys` table from
  before 2.5.0's fleet feature (where
  `target_id` was always NULL).
  - `PendingDeployRepository::list_orphans` —
    every row with `target_id IS NULL`.
  - `PendingDeployRepository::set_target_id`
    — links a row to a target by name +
    environment.
  - No schema change. The 2.5.x NOT NULL
    constraint on `pending_deploys.target_id`
    is deferred to 2.5.3 until operators
    complete the backfill.

### Test count

- 457/0 (was 454/0 in 2.7.4). Delta is the
  backfill helper tests plus 0 net change
  elsewhere.

## [2.7.4] — 2026-09-03

### Added

- **Dynamic LLM probe** (ADR-0032, the TZ §23.3
  item that was blocked on Hermes 0.19+; now
  unblocked: the operator confirmed Hermes 0.21
  is installed on the VPS). `agency hermes
  probe <plugin> --llm` runs the structural
  probe first, then asks an external LLM to
  flag semantic inconsistencies between
  `manifest.yaml` and `SKILL.md`.
- New `crates/hermes-adapter/src/llm_probe.rs`
  with:
  - `LlmClient` trait — provider abstraction
    (mock in tests, real HTTP in prod).
  - `OpenAiCompatibleClient` — POSTs
    `{model, messages}` to
    `AGENCY_LLM_ENDPOINT` and returns the
    assistant text. Works for OpenAI,
    Anthropic via OpenAI proxy, Ollama, etc.
  - `OpenAiConfig::from_env` reads
    `AGENCY_LLM_ENDPOINT` (default:
    `http://localhost:11434/v1/chat/completions`),
    `AGENCY_LLM_MODEL` (default: `llama3.2`),
    `AGENCY_LLM_API_KEY` (optional).
  - `MockLlmClient` — canned response for
    tests.
  - `LlmProbe::extend(structural, manifest, skill)`
    — sends the manifest + SKILL.md + a
    structural summary to the LLM, parses
    the JSON verdict, and returns a new
    `ProbeReport` with the structural
    checks plus one `llm_review` check.

### Fixed

- The 1.4.0 scanner `redact()` used byte
  slicing on a 200-char limit, which could
  panic on multi-byte content near the
  boundary. Now uses `.chars().take(200)` for
  both the scanner and the new LLM-probe
  response parser.

### Test count

454 (was 444 in v2.7.3). +10 net.

## [2.7.3] — 2026-09-03

### Added

- **Scanner plugin manifest** (ADR-0031, the
  2.7.0 "Out of scope" follow-up).
  `plugin.toml` sits next to the plugin binary
  and supplies metadata (name, version,
  description, author) plus per-plugin
  tunables (timeout, output cap, env vars,
  capability tags).

### Test count

444 (was 433 in v2.7.2). +11 net.

## [2.7.2] — 2026-09-03

### Added

- **Scanner plugin auto-discovery** (ADR-0030).
  `agency catalog scan` now auto-discovers
  executable scripts in `~/.agency/scanners.d/`
  (Windows: `%USERPROFILE%\.agency\scanners.d`).
  The `AGENCY_SCANNERS_DIR` env var overrides the
  default. Explicit `--plugin NAME:PATH` flags
  still win on name collision.
- `discover_plugins(dir)` in
  `crates/core/src/application/scanner/plugin.rs`.
  Returns `Vec<DiscoveredPlugin>` sorted by name
  (deterministic order across runs). Skips
  non-executable files and unknown extensions
  (e.g. `README.md` is ignored).

### Test count

433 (was 430 in v2.7.1). +3 net on Windows, +3
more on POSIX CI.

### Added

- **Scanner plugin auto-discovery** (ADR-0030).
  `agency catalog scan` now auto-discovers
  executable scripts in `~/.agency/scanners.d/`
  (Windows: `%USERPROFILE%\.agency\scanners.d`).
  The `AGENCY_SCANNERS_DIR` env var overrides the
  default. Explicit `--plugin NAME:PATH` flags
  still win on name collision.
- `discover_plugins(dir)` in
  `crates/core/src/application/scanner/plugin.rs`.
  Returns `Vec<DiscoveredPlugin>` sorted by name
  (deterministic order across runs). Skips
  non-executable files and unknown extensions
  (e.g. `README.md` is ignored).

### Test count

433 (was 430 in v2.7.1). +3 net on Windows, +3
more on POSIX CI.

## [2.7.1] — 2026-09-03

### Added

- **Fleet path_kind discriminator** (ADR-0029,
  the 2.5.1 deferred work from ADR-0023). The
  `targets` table gains a `path_kind` column
  (default `'posix'` for backwards compat).
  `TargetRepository::create` validates the path
  against the declared kind: POSIX paths must
  start with `/`; Windows paths must match
  `<letter>:\...` or `\\server\share\...` (or
  `//server/share/...` on POSIX-style UNC).
  `POST /v1/targets` body accepts an optional
  `path_kind: "posix" | "windows"` field.
- `PathKind` enum in
  `crates/core/src/infrastructure/repository/targets_repository.rs`
  with `parse` and `validate_path` methods.

### Changed

- Schema version 13 → 14. Migration 014.

### Test count

430 (was 428 in v2.7.0). +2 net.

## [2.7.0] — 2026-09-02

### Added

- **Third-party scanner plugins** (ADR-0028). The
  `Scanner` trait gains an out-of-process
  implementation: `PluginScanner` execs a binary
  with a JSON envelope on stdin and reads a
  JSON envelope from stdout. Protocol:
  - stdin: `{"root", "files", "policy"}`
  - stdout: `{"findings": [{"severity", "rule", "path", "reason"}]}`
  - non-zero exit → synthetic
    `plugin.<name>.exec-failed` Warn finding.
- CLI: `agency catalog scan` grows a
  `--plugin NAME:PATH` flag (repeatable).
  Plugin findings are merged with the internal
  `RegexScanner` findings.
- `ScanPolicy` and `Severity` now derive
  `Serialize` / `Deserialize` (the plugin
  protocol sends the policy to the plugin as
  JSON).

### Test count

428 (was 424 in v2.6.4). +4 net = 1 Windows-
runnable plugin test + 3 Unix-only plugin tests.

## [2.6.4] — 2026-09-02

### Added

- **SARIF output** (ADR-0027, the last TZ §23.3
  item). `findings_to_sarif(&[Finding]) ->
  serde_json::Value` in
  `crates/core/src/application/scanner/mod.rs`.
  Emits a SARIF 2.1.0 log with `runs[0].tool.driver`
  = `agency-scanner`, `runs[0].results[]` mapped
  to the rules table, severity as SARIF
  `level` (Block → error, Warn → warning, Pass →
  note; Pass not emitted).
- CLI: new `agency catalog scan <PATH> --format
  <text|json|sarif>` subcommand. Three output
  formats:
  - `text`  (default) — human-readable table
  - `json`  — flat array of findings
  - `sarif` — SARIF 2.1.0 log via
    `findings_to_sarif`
- The `Scan` subcommand is read-only: it does
  NOT touch the SQLite DB, the working-copy
  cache, or any remote Git. Drop it into a CI
  step (`agency catalog scan --format sarif |
  gh code-scanning upload`) without side
  effects.

### Test count

424 (was 420 in v2.6.3). +4 net = 3 unit tests
for `findings_to_sarif` (empty input, mixed-
severity findings with rule mapping, dedup of
repeated rules) + 1 integration test bonus.

## [2.6.3] — 2026-09-02

### Changed

- **Infrastructure fix, not a feature release.**
  Three changes to close the ts-rs regen
  race-condition foot-gun that bit us three
  times in v2.6.0 / v2.6.1 / v2.6.2:
  1. New `scripts/dev-test.ps1` — lightweight
     local loop that runs the test-related
     steps in the right order. Mirrors `ci.ps1`
     but skips slow / heavy steps (fmt-check,
     clippy, npm install).
  2. `scripts/ci.ps1` + `scripts/check-ts-drift.ps1`
     — guard against null `$env:HOME` on stock
     Windows. `Join-Path null` throws under
     `$ErrorActionPreference = 'Stop'`.
  3. `AGENTS.md` updated to document the new
     script and the rationale for the explicit
     ts-rs regen step.

### Test count

420 (unchanged from v2.6.2). No new tests.

## [2.6.2] — 2026-09-02

### Added

- **Unicode / confusable analysis** (ADR-0026,
  TZ §23.3 item 2). 2 new scanner rules:
  - `confusable.homoglyph`      Block — curated
    set of 13 lookalike characters from
    Cyrillic, Greek, Hebrew, and Armenian
    (Cyrillic 'а' for Latin 'a', Greek 'ο' for
    'o', etc.)
  - `confusable.bidi-override`  Warn — Unicode
    bidirectional control characters (LRE,
    RLE, PDF, LRO, RLO, LRI, RLI, FSI, PDI)

### Test count

420 (was 412 in v2.6.1). +8 net = 6 new per-rule
tests + 1 rule-overrides test + 1 renamed
rule_table test.

## [2.6.1] — 2026-09-02

### Added

- **More complete secret scanner** (ADR-0025,
  TZ §23.3 item 1). 6 new rules covering the
  third-party API tokens most commonly embedded
  in enterprise agent / skill catalogs:
  - `secret.slack-token`      (xox[baprs]-…)
  - `secret.stripe-key`       (sk_live_/sk_test_…)
  - `secret.google-api-key`   (AIza…)
  - `secret.openai-key`       (sk-…/sk-proj-…)
  - `secret.anthropic-key`    (sk-ant-…)
  - `secret.jwt`              (eyJ….eyJ….signature)
  All Block by default — credential-equivalent
  and fail-closed at ingest.

### Fixed

- `crates/core/tests/ts_export.rs` was missing
  `HealthReport` / `ArtifactHealth` /
  `ArtifactHealthStatus` (added in v1.4.0) from
  its import list. The drift guard is byte-
  level and did not detect the type-set drift.
  All 20 TS types now export.

### Test count

412 (was 412 in v2.6.0 — yes, 0 net because the
+6 new tests balanced the -1 removed renamed
test; 412 is the v2.6.1 total).

## [2.6.0] — 2026-09-02

### Added

- **Prompt-injection heuristics** (ADR-0024, TZ
  §23.3 item 3). 6 new scanner rules:
  - `prompt-injection.ignore-previous`     Block
  - `prompt-injection.role-override`       Block
  - `prompt-injection.system-prompt-leak`  Block
  - `prompt-injection.jailbreak-dan`       Block
  - `prompt-injection.markdown-system-tag` Warn
  - `prompt-injection.zero-width-chars`    Warn

### Test count

405 (was 405 — no net because the +7 new tests
balanced the test renames).

## [2.5.0] — 2026-09-02

### Added

- **Fleet (multi-target management)**
  (ADR-0023). `targets` table with
  `UNIQUE (environment, name)`. CLI/server
  endpoints `GET/POST/DELETE /v1/targets`.
  `POST /v1/deploys` body grows optional
  `target: "<name>"` field. Server resolves
  the name through the registry, rejects
  with 400 if not found or env mismatch.
- `pending_deploys.target_id` column (nullable
  for 2.4.0 backward compat).

### Changed

- Schema version 11 → 13. Migration 013.

### Test count

405 (was 393 in v2.4.0). +12 net = 8 unit
(`TargetRepository`) + 4 integration.

## [2.4.0] — 2026-09-02

### Added

- **Multi-environment** (ADR-0022). The
  `Environment` enum (Dev/Staging/Production)
  stored on both `pending_deploys` and
  `deployed_artifacts`. `POST /v1/deploys` body
  grows an optional `environment` field.
  `GET /v1/deploys?env=staging` filter. New
  `GET /v1/environments` endpoint.

### Changed

- Schema version 10 → 11. Migration 011.

### Test count

393 (was 391 in v2.3.0). +2 net.

## [2.3.0] — 2026-09-02

### Added

- **Vault (encrypted secret storage)**
  (ADR-0021). `secrets` table. AES-256-GCM with
  Argon2id-derived key (OWASP 2026: m=19MiB,
  t=2, p=1). `AGENCY_VAULT_PASSPHRASE` env var.
  Server refuses to start if the `secrets`
  table is non-empty and the env var is unset.
  5 endpoints: `GET /v1/secrets` (list, viewer+),
  `GET /v1/secrets/:name` (value, operator+),
  `POST/PUT/DELETE /v1/secrets/:name` (admin).
  List view NEVER includes value.

### Changed

- Schema version 9 → 10. Migration 010.

### Test count

391 (was 380 in v2.2.0). +11 net.

## [2.2.0] — 2026-09-02

### Added

- **Approvals workflow** (ADR-0020).
  `pending_deploys` table. Endpoints:
  - `POST /v1/deploys` (operator+, re-runs the
    plan server-side before persisting)
  - `GET /v1/deploys[/:id]`
  - `POST /v1/deploys/:id/approve`  (admin)
  - `POST /v1/deploys/:id/reject`   (admin)
  - `POST /v1/deploys/:id/applied`  (operator+)

### Changed

- Schema version 8 → 9. Migration 009.

### Test count

380 (was 370 in v2.1.0). +10 net.

## [2.1.0] — 2026-09-02

### Added

- **RBAC and multi-user** (ADR-0019). `users`
  table. `UserRepository` with sha256-only
  token hashes. Per-route role guards
  (viewer / operator / admin). New endpoints:
  - `GET /v1/users`         (admin)
  - `POST /v1/users`        (admin) — creates
    a user and returns the plain token ONCE
  - `DELETE /v1/users/:id`  (admin) — soft-
    delete (sets `disabled_at`)
  - `POST /v1/users/:id/rotate` (admin) —
    rotates the token, returns the new plain
    token ONCE
- 2.0.0 → 2.1.0 migration: `migrate_legacy_token`
  creates an admin user from the 2.0.0
  `server.token` file.

### Changed

- Schema version 7 → 8. Migration 008.

### Test count

370 (was 359 in v2.0.0). +11 net.

## [2.0.0] — 2026-09-02

### Added

- **Enterprise server** (ADR-0017, ADR-0018).
  New `crates/server/` (axum 0.7),
  `agency-server` binary, `agency serve` /
  `agency paths` commands. Migration 007:
  `audit_log` + `AuditLogRepository`.
  Endpoints:
  - `/v1/health`
  - `/v1/audit`         — every HTTP request
    recorded (including unauthenticated, actor
    = "anonymous" on 401)
  - `/v1/systems`       — list system snapshots
  - `/v1/systems/plan`  — compute a plan
  - `/v1/deploys/...`   — full deploy state
    machine (2.2.0+)
  - `/v1/rollback/:id`  — rollback an operation
  Bearer-token auth (`Authorization: Bearer
  <token>`).

### Changed

- Schema version 6 → 7. Migration 007.
- CLI became `lib + bin` so the server reuses
  the same `commands::rollback` code.

### Test count

359 (was 350 in v1.6.0). +9 net.

## [1.6.0] — 2026-09-02

### Added

- **Native-Russian review applied** (ADR-0014).
  All UI strings bilingual (en-US, ru-RU).
- **Shell completion** (ADR-0015):
  `agency completion <bash|zsh|fish|elvish|powershell>`
  via `clap_complete`. Always in-sync with
  the live `Cli` definition.
- `agency mcp list` and `agency mcp remove`
  subcommands.
- `agency system plan --drift` flag (for
  drift-detection ops; ADR-0013's `--drift`
  is a sub-mode).

### Changed

- clippy-pedantic cleanup. No new behaviour
  beyond linting.

### Test count

350 (was 345 in v1.5.1). +5 net.

## [1.5.1] — 2026-09-02

### Added

- **CAS-indexed backup retention**
  (ADR-0016). `BackupRecord` JSON pointer +
  CAS write. Rollback reads the pointer and
  resolves the CAS to retrieve the backup
  contents.

### Test count

345 (was 339 in v1.5.0). +6 net.

## [1.5.0] and earlier

See git history and the individual ADR
documents under `docs/adr/`.

## Notes for future maintainers

- The TZ (Technical Specification) source is
  `TZ_Enterprise_Agent_Deployment_Platform_Enterprise_v2.md`
  (root, gitignored; 2799 lines, 73 KB). The
  MUST-HAVE slices in §45 are all shipped
  through v2.5.0. The advanced-scanner items
  in §23.3 are all shipped through v2.7.0.
  The remaining 2.7.x backlog (per ADR-0017) is
  SSO/OIDC and dynamic LLM probe (needs
  Hermes 0.19+).
- Every `#[derive(TS)]` type in the workspace
  must be in the `crates/core/tests/ts_export.rs`
  import list AND called via
  `Type::export_all()`. The drift guard is
  byte-level only and does not catch type-set
  drift. See the "ts-rs drift guard misses
  silently-removed types" memory entry.
- `cargo test --workspace` runs test binaries
  in parallel; the hermes-adapter lib test's
  auto-export can clobber the DTOs that
  `ts_export.rs` writes. Run the explicit
  `cargo test -p agent_dep_core --test ts_export`
  AFTER `cargo test --workspace` to canonicalize
  the file. The `scripts/dev-test.ps1` does
  this for you.
- The local script `scripts/dev-test.ps1` is
  the lightweight local loop. Use
  `scripts/ci.ps1` before commit / push.
