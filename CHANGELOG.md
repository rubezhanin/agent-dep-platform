# Changelog

All notable changes to the Enterprise Agent Deployment
Platform. Each release corresponds to a single TZ
backlog item or ADR; tags land on `main` in
`rubezhanin/agent-dep-platform`.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

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
