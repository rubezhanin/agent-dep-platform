# Enterprise Agent Deployment Platform

Local-only Tauri 2 + Svelte 5 + Rust desktop application for safely
deploying agent systems from Git repositories into Hermes Agent.

## Status

**v2.8.0 (TZ v2 schema + Hermes router plugin + enterprise
server + OIDC + Real Git ingest)** — 31 tags on main, all TZ
§45 MUST-HAVE slices landed (through v2.5.0), all TZ §23.3
advanced-scanner items landed (through v2.7.0), 2.x enterprise
server (audit / users / approvals / vault / fleet / OIDC
framework + real client + refresh + logout + DB-backed state +
RSA signature verification) closed (through v2.7.10), and
1.x real Git source ingest closed (v2.8.0). **489 tests
passing on Windows**, `svelte-check` 0/0, all CI gates
green. See [`CHANGELOG.md`](./CHANGELOG.md) for the per-release
narrative.

```
$ .\scripts\ci.ps1
==>
==> cargo fmt --check
==> cargo clippy
==> cargo test        (489 passed; 0 failed; 3 ignored)
==> ts-rs regen
==> npm install
==> npm run check     (svelte-check: 0 errors, 0 warnings)
==> ts-rs drift
==>
CI PASSED
```

Source TZ: `TZ_Enterprise_Agent_Deployment_Platform_Enterprise_v2.md`
(root, gitignored; 2799 lines, 73 KB).

## Build

```powershell
cargo build --workspace
cargo test --workspace
.\scripts\ci.ps1
```

## Layout

```
crates/
  core/              domain, application, infrastructure
                     (sqlite, cas, filesystem, git_fetcher, repository)
  hermes-adapter/    RuntimeAdapter trait + HermesAdapter +
                     router plugin + llm_probe
  cli/               agency CLI (clap)
  server/            axum 0.7 HTTP API (audit, systems, deploys,
                     secrets, users, environments, targets) +
                     OIDC (framework + real client + refresh +
                     logout + DB-backed state)
  tauri-app/         Tauri 2 host + IPC commands
src/                 Svelte 5 + Vite frontend
docs/
  superpowers/       specs and plans (gitignored)
  adr/               39 ADRs (ADR-0001 .. ADR-0039) (gitignored)
scripts/             local CI scripts (PowerShell)
```

## What's done

### MVP-0 — Bootstrap skeleton
- Multi-crate Cargo workspace (`core`, `hermes-adapter`, `cli`,
  `tauri-app`, `server`)
- CoreError taxonomy (TZ §35) — 14 variants
- Path safety with proptest property-based tests (3 properties: safe paths
  stay in root, traversal rejected, resolve is idempotent)
- SQLite + sqlx migrations skeleton (WAL / FK / busy-timeout)
- Content-addressed store (sha256 layout, atomic write)
- Hermes adapter skeleton with `RuntimeAdapter` trait
- CLI skeleton (`agency deploy <system>`, `agency status`)
- Tauri 2 app shell with `setup()` initializing tracing, DB, CAS, AppState
- 9 IPC commands, ts-rs drift-CI guard, Svelte 5 + Vite with 8 routes
- `scripts/ci.ps1` runs all gates locally

### MVP-1 — Hermes POC
- **Hermes v0.18.2 router-plugin materialization** (`materialize_router_plugin`):
  writes `manifest.yaml` + `SKILL.md` + `skills/<slug>.md` atomically
  under `<hermes_home>/plugins/<id>/`, byte-deterministic YAML, slug
  regex `^[a-z][a-z0-9_-]{0,63}$`.
- **HermesAdapter** (`RuntimeAdapter` trait) with `deploy` / `plan` /
  `verify` / `health`. `health(plugin_id, baseline)` walks the plugin
  tree, reads sha256 of every file, and emits a `HealthReport` with
  `Current` / `Modified` / `Foreign` / `Missing` / `Error` per file.
- **End-to-end smoke verified** with an isolated `HERMES_HOME`.

### MVP-2 — ADRs (TZ §44 prerequisite for active implementation)
- 39 ADRs accepted; see `docs/adr/`. Key milestones:
  - 0001–0008: MVP-2 + Hermes protocol v2
  - 0009–0016: TZ §23.3 (audit, users, approvals, vault, fleet, plugins)
  - 0017–0022: 2.x enterprise server scope (ADR-0017) and pillars
    (audit, RBAC, approvals, vault)
  - 0023–0029: fleet (PathKind), plugins, scanner (Unicode, secret,
    prompt-injection, SARIF, LLM probe)
  - 0030–0031: plugin auto-discovery + manifest
  - 0032: dynamic LLM probe
  - 0033: target backfill tooling
  - 0034–0038: OIDC framework, real client, refresh + logout, RSA
    signature verification, DB-backed `OidcPending`
  - 0039: real Git source ingest

### MVP-3 — Ingestion, persistence, scanner, journal, composition
- **Local catalog ingest** (`agency catalog update <path>`): parses
  `divisions.json` + per-division `agents/<id>.md` (YAML-frontmatter +
  Markdown body), validates id-matches-stem and version-is-SemVer,
  computes a deterministic sha256 snapshot identity, returns counts +
  per-file records + rejected agents.
- **SQLite persistence** (`IngestRepository`): sources /
  source_snapshots / divisions / agents + ordered link tables for
  tools / activation_phrases / observed files / rejected agents.
  Re-ingest supersedes prior Active in a single transaction.
- **Security scanner** (ADR-0005): 13 rules, PASS / WARN / BLOCK
  severities, `RegexScanner` impl, policy overrides per rule + trusted
  domains with wildcard + `treat_warn_as_block`. Any BLOCK flips the
  snapshot to `Blocked`; `scan_note` summarizes.
- **Recovery journal** (ADR-0006): `operations` table with
  `Prepared -> Writing -> Committing -> Committed | Failed` state
  machine, `RolledBack` exit. `gc_stale(keep=100)` force-fails
  ancient non-terminal rows at startup. Crash-recovery integration
  test (4 cases) covers the state machine end-to-end.
- **Composition + plan** (`agency system plan <file> --catalog <path>`):
  parses `system.yaml` (v1 + v2 auto-detect), resolves refs against
  the ingested snapshot, applies per-agent overrides, emits a
  deployment plan with `Add` / `Noop` / `Update` / `Delete` operations
  against `deployed_artifacts` (TZ v2 §16/§20).

### Phase 1 — TZ v2 schema migration
- **Skill** + **SkillYaml** + **AgentYaml** (TZ v2 §6, §7): strict
  `camelCase` + `deny_unknown_fields` + `$schema:` URL validation.
- **SystemFile v2** + `parse_system_file` auto-detect (v1 / v2 dual
  path). `CompositionService` handles both shapes.
- **IngestV2Service** + `SkillRepository` (migration 005, `skills`
  table family). `IngestResult.skills: Vec<Skill>` exposed.

### Phase 3 — i18n + policy + reconciliation
- **i18n framework** (`Locale`, `Bundle`, `t/tr/from_env/lookup`):
  en-US (mandatory fallback) + ru-RU (mandatory for MVP), CLI strings
  fully translated, Svelte `i18n.ts` mirror with `localStorage`
  persistence + a11y-clean locale picker.
- **Policy engine** (TZ v2 §24): `Policy::source_allowed` /
  `security_decision` / `deployment_decision` with glob suffix/prefix
  rules, security floor (treat_warn_as_block).
- **Reconciliation state model** (TZ v2 §20): `ReconcileState`
  (8 variants) + `DriftReason` (8 variants) + pure `classify()`
  function.

### Phase 4 — Hermes router plugin (the deployment target)
- `materialize_router_plugin(hermes_home, &RouterPluginInputs)`
  writes `manifest.yaml` + `SKILL.md` + `skills/<slug>.md` atomically.
- `HermesAdapter::deploy / verify / plan` are wired end-to-end.
- `agency deploy install [--plugin-id]` CLI command.
- End-to-end smoke verified with isolated `HERMES_HOME`.

### Phase 5 — Lock file + rollback + deployed_artifacts
- **`agency.lock`**: `LockFile` domain with `from_resolved / from_yaml /
  to_yaml / agent_versions`; `examples/agency.lock` checked in.
- **`agency lock generate`**: produces `agency.lock` next to the
  system file with the resolved versions.
- **`agency rollback <operation-id>`**: parses the journal
  `effect_json`, restores each file from `.backups/`, flips the
  journal row to `rolled_back` (only if every entry succeeded).
- **`deployed_artifacts` table** (migration 006): one row per
  `(system_id, target)`, populated by `DeploymentService::apply`,
  read by `PlanService` to compute `Add` / `Noop` / `Update` /
  `Delete` per `deployed_artifacts` diff.

### Phase 6 — UI data binding
- All 8 Svelte routes call real Tauri IPC commands (no more
  `Placeholder` in the data path):
  - `catalog`      -> `list_agents`      (latest active snapshot)
  - `sources`      -> `list_sources`     (sources table, newest first)
  - `systems`      -> `list_systems`     (distinct system_id)
  - `deployments`  -> `list_deployments` (50 most-recent journal ops)
  - `backups`      -> `list_backups`     (walks `hermes_home/plugins/**/.backups`)
  - `logs`         -> `tail`             (reads `app.json`, last 200 lines)
  - `hermes`       -> `detect_hermes`    (definition list view)
  - `security`     -> `scan`             (placeholder; gated on user-supplied path)
- Shared `ListView.svelte` component (Svelte 5 snippet-based).
- Backend additions: `IngestRepository::list_sources` /
  `list_agents_in_latest_snapshot`, `DeployedArtifactsRepository::
  list_distinct_systems`, `JournalService::list_recent(limit)`.

### 1.5..1.7 — TZ §23.3 advanced scanner (closed through v2.7.0)
- **CAS-indexed backup retention** (1.5.1, ADR-0016)
- **i18n review apply** + **clap_complete** (1.6.0, ADR-0014/0015)
- **`mcp list` / `mcp remove` + plan `--drift`** (1.6.0)

### 2.0..2.4 — Enterprise server (TZ §45 + 2.x MUST-HAVE)
- **2.0.0**: `agency-server` (axum 0.7) with bearer auth + audit
  log; `audit_log` table; new ADR-0017/0018 scope.
- **2.1.0**: Per-user RBAC. `users` table, sha256-only token
  storage. `Viewer` / `Operator` / `Admin` roles. Migration from
  2.0.0 single-bearer-token to per-user (ADR-0019).
- **2.2.0**: Approvals workflow. `pending_deploys` state machine;
  server re-runs the plan server-side so the operator cannot
  smuggle in a different plan (ADR-0020).
- **2.3.0**: Vault. AES-256-GCM + Argon2id (OWASP 2026 params:
  m=19MiB, t=2, p=1). App-level salt + per-secret nonce.
  `version` column. List view never includes the value
  (ADR-0021).
- **2.4.0**: Multi-environment. Hard-coded `Dev` / `Staging` /
  `Production` enum. `environments` table. Per-environment
  deployment (ADR-0022).

### 2.5..2.7 — Fleet, plugins, scanner, OIDC (TZ §23.3 + §45 close)
- **2.5.0** Fleet: `targets` table, multi-environment path
  resolution, `pending_deploys.target_id` nullable column for
  backfill compatibility (ADR-0023).
- **2.5.2** Target backfill tooling: `list_orphans` +
  `set_target_id` for operators who inherited a pre-fleet
  `pending_deploys` table (ADR-0033).
- **2.6.0** Prompt-injection heuristics (6 rules) for the
  security scanner (ADR-0024).
- **2.6.1** More complete secret scanner (Slack / Stripe /
  Google / OpenAI / Anthropic / JWT) (ADR-0025).
- **2.6.2** Unicode / confusable (homoglyph Block, bidi-override
  Warn) (ADR-0026).
- **2.6.3** Infrastructure fix: `dev-test.ps1` / `ci.ps1` /
  `check-ts-drift.ps1` null-guard for `$env:HOME` (Windows).
- **2.6.4** SARIF output (ADR-0027) — `findings_to_sarif` +
  `agency catalog scan --format sarif`.
- **2.7.0** Third-party scanner plugins (ADR-0028):
  `PluginScanner`, JSON envelope protocol, `--plugin NAME:PATH`.
- **2.7.1** Fleet `PathKind` discriminator (ADR-0029) —
  `PathKind::validate_path()` does NOT use `Path::is_absolute`
  (cross-platform disagreement). POSIX vs Windows regex.
- **2.7.2** Plugin auto-discovery (ADR-0030) — `discover_plugins`
  reads `~/.agency/scanners.d/`, `AGENCY_SCANNERS_DIR`.
- **2.7.3** Plugin manifest (ADR-0031) — `plugin.toml` with
  name / version / binary / timeout_seconds / max_output_bytes /
  env / capabilities. `toml = "0.8"`.
- **2.7.4** Dynamic LLM probe (ADR-0032) — `LlmClient` trait,
  `OpenAiCompatibleClient`, `MockLlmClient`. `agency hermes
  probe <plugin> --llm`. AGENCY_LLM_ENDPOINT / MODEL / API_KEY /
  MOCK_RESPONSE env vars.
- **2.7.6** OIDC framework (ADR-0034) — `OidcConfig` from 8 env
  vars, `OidcPending` in-memory map, `map_claims_to_role`,
  `provision_user_from_claims`, `mock_oidc_claims`, two new
  public axum routes.
- **2.7.7** OIDC real wire-protocol client (ADR-0035) — discovery,
  PKCE S256 /authorize URL, code exchange, ID-token iss / aud /
  nonce validation. `AGENCY_OIDC_MOCK` default flipped from `1`
  to `0`.
- **2.7.8** OIDC token refresh + logout (ADR-0036) —
  `POST /v1/auth/oidc/refresh` and `GET /v1/auth/oidc/logout`.
  `users.token_expires_at` (schema 15 -> 16). Bearer expiry
  enforced by `auth::require_bearer` middleware.
- **2.7.9** Full RSA signature verification (ADR-0037) — RS256 /
  RS384 / RS512 verified against the JWKS. ES / PS deferred to
  2.7.7.1 (now 2.7.9.1). Closes the 2.7.7 "not safe against a
  malicious IdP" caveat.
- **2.7.10** DB-backed `OidcPending` (ADR-0038) — replaces the
  2.7.6 in-memory `Arc<Mutex<HashMap>>` with a SQLite
  `oidc_pending_state` table. Enables multi-process /
  multi-instance `agency-server` deployments. Schema 16 -> 17.

### 2.8.0 — Real Git source ingest
- (ADR-0009 + ADR-0039) `GitFetcher` in
  `crates/core/src/infrastructure/git_fetcher.rs`. Uses the
  `git2` crate with `vendored-libgit2` (so the binary is
  portable across Windows / Linux / macOS without requiring
  the system `libgit2-dev` package).
  - `clone_to(url, ref_, dest)` — clone a remote repo
  - `fetch(dest, ref_)` — fetch + fast-forward an existing
    clone
  - Both async via `tokio::task::spawn_blocking` (git2 is sync)
  - HTTPS + SSH via `~/.ssh/config` + `ssh-agent`

## Migration from previous state

For users coming from a pre-MVP-1.0 install (schema_version <= 3,
i.e. before `skills` / `deployed_artifacts` were added):

1. **Database schema**: `db.migrate()` is idempotent and runs all
   migrations in order. Opening the old DB on a new build
   automatically picks up migrations 004 (operations_journal was
   already in MVP-3), 005 (skills) and 006 (deployed_artifacts).
   No data loss. `schema_version` advances to 17 on first open.
2. **TS DTOs**: `cargo test -p agent_dep_core --test ts_export`
   regenerates `src/lib/types.generated.ts`. The script
   `scripts/check-ts-drift.ps1` enforces that the file matches
   `git HEAD` so a forgotten regen is caught at CI time.
3. **CLI commands**: `agency deploy install` (Phase 4) and
   `agency lock generate` / `agency rollback` (Phase 5) are new.
   `agency deploy <file>` (MVP-3 file materialization) still
   works the same way. `agency status` and `agency catalog update`
   unchanged.
4. **Svelte IPC contract**: `ipc.ts` grew from one command
   (`detect_hermes`) to eight. Existing callers only need to
   update to the new object shape; the Rust command names are
   backward compatible.
5. **Hermes install**: the contract is unchanged. The first
   `agency deploy install` writes the `agency-agents-router`
   plugin under `<hermes_home>/plugins/`. Hermes 0.18.2 picks
   it up on next start.
6. **`agency-server` 2.x**: the new HTTP API is **additive** —
   the existing 2.0.0 single-bearer-token continues to work for
   scripts. Per-user RBAC + bearer-expiry are opt-in via the
   `users` table; operators can keep using a single
   `AGENCY_SERVER_TOKEN` env var.
7. **OIDC**: opt-in via `AGENCY_OIDC_ISSUER` + `AGENCY_OIDC_CLIENT_ID`
   (and friends). `AGENCY_OIDC_MOCK=1` keeps the dev mock. The
   flow runs alongside bearer-token auth; both work.
8. **Real Git source**: the `agency sources add` flow gains
   `--git-url` + `--ref`. The existing `--local <path>` flow
   is unchanged.

## Local CI

```powershell
.\scripts\ci.ps1
```

Gates: `cargo fmt --check`, `cargo clippy -D warnings`,
`cargo test --workspace`, `ts-rs regen`, `npm install`,
`npm run check` (svelte-check), `ts-rs drift` (git diff guard).

## Conventions for AI agents

See `AGENTS.md` at the repo root.
