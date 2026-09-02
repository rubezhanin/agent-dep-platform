# Enterprise Agent Deployment Platform

Local-only Tauri 2 + Svelte 5 + Rust desktop application for safely
deploying agent systems from Git repositories into Hermes Agent.

## Status

**v2.7.2 (TZ v2 schema + Hermes router plugin + advanced
scanner)** — 22 tags on main, all TZ §45 MUST-HAVE
slices landed (through v2.5.0), all TZ §23.3 advanced-
scanner items landed (through v2.7.0). **433 tests passing
on Windows**, `svelte-check` 0/0, all CI gates green.
See [`CHANGELOG.md`](./CHANGELOG.md) for the per-release
narrative.

```
$ .\scripts\ci.ps1
==>
==> cargo fmt --check
==> cargo clippy
==> cargo test        (433 passed; 0 failed)
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
  core/              domain, application, infrastructure (sqlite, cas, filesystem, repository)
  hermes-adapter/    RuntimeAdapter trait + HermesAdapter + router plugin
  cli/               agency CLI (clap)
  tauri-app/         Tauri 2 host + IPC commands
src/                 Svelte 5 + Vite frontend
docs/
  superpowers/       specs and plans (gitignored)
  adr/               8 ADRs (ADR-0001 .. ADR-0008) (gitignored)
scripts/             local CI scripts (PowerShell)
```

## What's done

### MVP-0 — Bootstrap skeleton
- Multi-crate Cargo workspace (`core`, `hermes-adapter`, `cli`, `tauri-app`)
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
- 8 ADRs accepted; see `docs/adr/`:

| # | File | Topic |
|---|---|---|
| 0001 | `0001-hermes-protocol.md` | Superseded by 0008 |
| 0002 | `0002-deployment-filesystem-semantics.md` | File-level atomic temp+rename, journal for dirs |
| 0003 | `0003-lock-file-and-versioning.md` | Exact versions in MVP, lockfile authoritative |
| 0004 | `0004-local-storage-boundary.md` | SQLite/CAS layout, migration backup policy |
| 0005 | `0005-security-scanner-scope.md` | 13 rules, 3 severities, no NLP heuristics |
| 0006 | `0006-recovery-journal.md` | `operations` table, idempotent recovery, bounded 100 |
| 0007 | `0007-enterprise-server-evolution.md` | Domain frozen across phases, server in 2.x |
| 0008 | `0008-hermes-protocol-v2.md` | Two extension surfaces: Flow A router plugin (agency-agents), Flow B remote MCP (Linear/n8n, deferred to 1.x) |

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

## Migration from previous state

For users coming from a pre-MVP-1.0 install (schema_version <= 3,
i.e. before `skills` / `deployed_artifacts` were added):

1. **Database schema**: `db.migrate()` is idempotent and runs all
   migrations in order. Opening the old DB on a new build
   automatically picks up migrations 004 (operations_journal was
   already in MVP-3), 005 (skills) and 006 (deployed_artifacts).
   No data loss. `schema_version` advances to 6 on first open.
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

## Local CI

```powershell
.\scripts\ci.ps1
```

Gates: `cargo fmt --check`, `cargo clippy -D warnings`,
`cargo test --workspace`, `ts-rs regen`, `npm install`,
`npm run check` (svelte-check), `ts-rs drift` (git diff guard).

## Conventions for AI agents

See `AGENTS.md` at the repo root.
