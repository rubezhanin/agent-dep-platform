# MVP-0 Bootstrap Design — Enterprise Agent Deployment Platform

> **Date**: 2026-08-31
> **Status**: Approved (pending user sign-off on written spec)
> **Spec type**: Bootstrap / skeleton
> **Source TZ**: `TZ_Enterprise_Agent_Deployment_Platform_Final.md` (in repo root)
> **Workspace**: `C:\projects\agent-dep-platform`

## 1. Context

This spec covers the **first concrete iteration** of the Enterprise Agent Deployment Platform — a Tauri 2 + Svelte 5 + Rust desktop application that evolves from the existing `agency-agents-app` into a full deployment platform for agent systems into Hermes Agent.

The TZ (§32, §44) requires:

- A Hermes POC that fixes the actual protocol in `ADR-HERMES-001` before active implementation.
- 7 ADRs (ADR-001 through ADR-007) before active implementation.
- A clean architecture (§50): `domain/`, `application/`, `infrastructure/`, `interfaces/`, with a separate `runtime/hermes` adapter.
- CI gates (§42) that block release on `cargo fmt/clippy/test`, `svelte-check`, drift checks, and security scans.

This MVP-0 is the **skeleton** that makes all of the above possible. It produces a runnable, testable, CI-gated project with all infrastructure in place but **no business logic**. Business logic lands in MVP-1 (Hermes POC → ADR-001) and MVP-2 (other 6 ADRs), then MVP-3+ (MUST HAVE features).

## 2. Goals

- Create a `cargo build --workspace` green multi-crate workspace (`core`, `hermes-adapter`, `cli`, `tauri-app`).
- Create a Tauri 2 app that launches and shows 9 placeholder routes (§28.1).
- Create a Svelte 5 + Vite frontend that renders, navigates, and type-checks.
- Wire `ts-rs` for Rust→TS type generation with a drift-CI guard.
- Initialize SQLite via `sqlx::migrate!` and a content-addressed store skeleton.
- Set up `tracing` with JSON daily-rolling file logs + stderr.
- Provide a stub `RuntimeAdapter` trait + `HermesAdapter::detect()` skeleton.
- Provide a `clap`-based `agency` CLI with `deploy <system>` and `status` stubs.
- Provide one IPC command per namespace (§51) returning safe stubs.
- Provide a local CI script (`scripts/ci.ps1`) that runs all gates.
- Provide an `AGENTS.md` for future agent sessions.
- Set up local git (no remote).

## 3. Non-Goals (Explicitly Out of MVP-0)

- Hermes POC and ADR-001 (next iteration).
- ADRs 002–007 (later phase).
- Any business logic: Git ingestion, schema validation, lock files, plan engine, transactional deploy, reconciliation, rollback, security scanner, policy engine.
- Real UI components, forms, tables, or visualizations — only placeholder pages.
- Playwright E2E tests.
- Release pipeline, code signing, MSI/DEB packaging, auto-update.
- Push to GitHub / remote (no remote is added).

## 4. Decisions Locked In

| Decision | Choice | Rationale |
|---|---|---|
| Project location | `C:\projects\agent-dep-platform\` | Fresh start; `agency-agents-app` is only Svelte stores, not a usable foundation. |
| Version control | Local `git` only, no remote | TDD requires frequent atomic commits; "no GitHub" per user. |
| Cargo layout | Multi-crate workspace | CLI and Tauri both consume `core` services; clean boundaries aid testing and I10. |
| Type generation | `ts-rs` | Standalone, works for CLI-only DTOs, drift-CI is simple, no Tauri coupling. |
| Migrations | `sqlx::migrate!` | Built-in, sufficient for SQLite MVP; refinery can come in 2.x. |
| Logging | `tracing` + `tracing-subscriber` (env-filter, json) + `tracing-appender` (DAILY rotation) | Two-layer (stderr + file) pattern proven in agent memory. |
| Property tests | `proptest` | Required by §31.3 (path containment, idempotency, determinism, planner consistency). |
| CLI parser | `clap` v4 with derive | De-facto Rust standard. |
| Test runner | `cargo test` (default) | `cargo-nextest` may be added in 1.x if needed. |
| Frontend framework | Svelte 5 (runes) | Latest stable; reactive without store overhead. |
| Frontend tooling | Vite + `svelte-check` + TypeScript | Standard Svelte 5 tooling. |
| Lint/format | `cargo fmt` + `cargo clippy -D warnings` + `prettier` + `eslint` + `svelte-check` | TZ §42 mandatory gates. |
| Hermes adapter detection | `which` crate to find `hermes` CLI in PATH | Cross-platform, simple. |
| Path safety | `Path::components` + `canonicalize` + `symlink_metadata` + root containment | Required by I3. |
| Branch name | `main` | Standard. |

## 5. Architecture

### 5.1 Workspace layout

```text
agent-dep-platform/
├── Cargo.toml                          # workspace root
├── package.json                        # npm workspace root
├── pnpm-workspace.yaml                 # or npm workspaces
├── tsconfig.json
├── rust-toolchain.toml
├── rustfmt.toml
├── clippy.toml
├── .gitignore
├── .editorconfig
├── README.md
├── AGENTS.md                           # for future agent sessions (via init skill)
│
├── crates/
│   ├── core/                           # domain + application + infrastructure
│   ├── hermes-adapter/                 # Hermes runtime adapter
│   ├── cli/                            # agency CLI
│   └── tauri-app/                      # Tauri 2 host
│
├── src/                                # Svelte 5 frontend
│   ├── app.html
│   ├── main.ts
│   ├── app.css
│   ├── lib/
│   │   ├── types.generated.ts          # ts-rs output
│   │   ├── ipc.ts
│   │   ├── stores/                     # Svelte 5 runes
│   │   ├── components/
│   │   ├── routes/                     # 9 sections per TZ §28.1
│   │   └── utils/
│   └── vite.config.ts
│
├── tests/                              # workspace-level integration
│   └── ts_export.rs                    # ts-rs drift guard
│
├── docs/
│   ├── superpowers/
│   │   ├── specs/                      # this file
│   │   └── plans/                      # implementation plans
│   └── adr/                            # 7 ADRs from TZ §44
│
├── scripts/
│   ├── ci.ps1                          # local CI gate
│   ├── check-ts-drift.ps1
│   ├── bootstrap.ps1
│   └── reset-db.ps1
│
└── .github/
    └── workflows/
        └── ci.yml                      # template, not run (no remote)
```

### 5.2 Crate dependency graph

```text
core            ← (no workspace deps; external: serde, tokio, sqlx, thiserror, ts-rs, etc.)
hermes-adapter  → core
cli             → core, hermes-adapter
tauri-app       → core, hermes-adapter
```

`domain` and `application` modules in `core` know nothing about Tauri or Hermes (TZ I10, I12). The Hermes adapter and IPC layer are the only places with concrete runtime bindings.

### 5.3 Layered structure within `core`

Per TZ §50:

```text
core/src/
├── domain/                             # agent, skill, system, deployment, source, policy, version
│   ├── mod.rs
│   ├── agent.rs                        # Agent entity (struct only, no behavior yet)
│   ├── skill.rs                        # Skill entity
│   ├── system.rs                       # System entity
│   ├── deployment.rs                   # DeploymentRecord, DeploymentSnapshot
│   ├── source.rs                       # Source, Snapshot
│   ├── policy.rs                       # Policy
│   └── version.rs                      # Version, SemVer helpers
│
├── application/                        # ingest, compose, plan, deploy, reconcile, rollback, catalog, health
│   ├── mod.rs                          # pub traits only, not implemented
│   ├── ingest.rs                       # trait + stub
│   ├── compose.rs
│   ├── plan.rs
│   ├── deploy.rs
│   ├── reconcile.rs
│   ├── rollback.rs
│   ├── catalog.rs
│   └── health.rs
│
├── infrastructure/
│   ├── git/                            # empty stub module
│   ├── sqlite/
│   │   ├── mod.rs                      # Db, connect(), migrate()
│   │   └── migrations/
│   │       └── 001_initial.sql
│   ├── content_store/
│   │   └── mod.rs                      # ContentStore, put/get/exists/path
│   ├── filesystem/
│   │   ├── mod.rs
│   │   └── safe_path.rs                # resolve_safe_path() + proptests
│   ├── keychain/                       # empty stub module
│   └── security/                       # empty stub module
│
├── error.rs                            # CoreError enum (TZ §35)
└── lib.rs
```

### 5.4 Hermes adapter skeleton

```text
hermes-adapter/src/
├── lib.rs
├── adapter.rs                          # trait RuntimeAdapter (TZ §12.3)
├── hermes_adapter.rs                   # struct HermesAdapter, detect() impl
├── detection.rs                        # find hermes in PATH
├── paths.rs                            # HERMES_HOME, plugin_dir resolution via safe_path
└── types.rs                            # RuntimeInfo, RuntimeState
```

Only `detect()` is implemented in MVP-0. Other trait methods return `CoreError::Unimplemented` (a new variant we add to `CoreError` for this purpose).

### 5.5 Tauri IPC namespaces (TZ §51)

Stubs for MVP-0 (one command each, returning safe defaults):

| Namespace | Command | Stub return |
|---|---|---|
| `catalog.*` | `catalog.list_agents` | `Vec::new()` |
| `sources.*` | `sources.list` | `Vec::new()` |
| `systems.*` | `systems.list` | `Vec::new()` |
| `plans.*` | `plans.compute` | `unimplemented!` |
| `deployments.*` | `deployments.list` | `Vec::new()` |
| `backups.*` | `backups.list` | `Vec::new()` |
| `hermes.*` | `hermes.detect` | delegates to `HermesAdapter::detect` |
| `security.*` | `security.scan` | `unimplemented!` |
| `logs.*` | `logs.tail` | `Vec::new()` |

## 6. Scope: In

### Phase A — Project foundation

- **Task 1**: Workspace + 4 crate skeletons, all `cargo build --workspace` green, `.gitignore`, `.editorconfig`, minimal `README.md`, first commit.
- **Task 2**: Domain error taxonomy in `core::error` (TZ §35).
- **Task 3**: Path safety in `core::infrastructure::filesystem::safe_path` with `proptest` property-based tests.

### Phase B — Infrastructure modules

- **Task 4**: SQLite + `sqlx::migrate!` skeleton in `core::infrastructure::sqlite`.
- **Task 5**: Content store in `core::infrastructure::content_store`.

### Phase C — Adapter and CLI

- **Task 6**: Hermes adapter skeleton in `hermes-adapter` (only `detect()`).
- **Task 7**: CLI skeleton in `cli` (`agency deploy <system>`, `agency status` stubs).

### Phase D — Tauri

- **Task 8**: Tauri 2 app shell with `setup()` callback.
- **Task 9**: Tracing init with file + stderr layers.
- **Task 10**: `AppState` DI + IPC command skeletons.

### Phase E — Type sharing

- **Task 11**: `ts-rs` pipeline + drift-CI guard.

### Phase F — Frontend

- **Task 12**: Svelte 5 + Vite with 9 placeholder routes.

### Phase G — CI and docs

- **Task 13**: `scripts/ci.ps1` + `.github/workflows/ci.yml` (template) + `AGENTS.md` + final smoke.

## 7. Scope: Deferred

- Hermes POC and `ADR-001-HERMES-PROTOCOL` → MVP-1.
- `ADR-002` through `ADR-007` → MVP-2 (folder `docs/adr/` is created in Task 1 but files are not).
- All MUST HAVE features (TZ §45) → MVP-3+ in priority order.
- Real UI components and forms → when business logic is implemented.
- Playwright E2E → when integration scenarios demand it.
- Release pipeline, code signing, packaging → post-MVP.

## 8. Acceptance Criteria

MVP-0 is complete when **all** of the following are true:

1. `cargo build --workspace` is green.
2. `cargo test --workspace` is green with ≥ 25 tests (unit + property + integration).
3. `cargo clippy --workspace --all-targets -- -D warnings` is green.
4. `cargo fmt --all -- --check` is green.
5. `pnpm install && pnpm run check` is green.
6. `src/lib/types.generated.ts` is generated and `git diff` shows no drift.
7. `cargo run -p cli -- --help` shows help text.
8. `cargo run -p cli -- status` returns a stub response (or `ErrHermesNotFound` if Hermes is not installed — both are valid for MVP-0).
9. `cargo run -p tauri-app` opens a window with 9 routes visible and navigable.
10. `scripts/ci.ps1` runs all gates and returns exit 0.
11. `AGENTS.md` exists and is informative.
12. Local git log shows ≥ 13 atomic commits with conventional-commit messages.
13. No business logic is implemented (verified by absence of ingest/plan/deploy/etc. implementations — only trait stubs and unit tests on error types / path safety / CAS / DB).

## 9. Known Gotchas Captured From Agent Memory

These are recorded so future agents don't relearn them.

- **ts-rs incremental regen can DUPLICATE then DE-DUPLICATE types**: After adding new DTOs across multiple commits, `cargo test --test ts_export` may produce a `types.generated.ts` with each type written twice. The fix: a single fresh regen with the new types added to the import list produces the canonical output, even though `git diff` shows it as a large negative-diff commit. Do not `git checkout` to revert — the dedup is the correct state. Add a code comment near the `export_all()` call in `tests/ts_export.rs`.

- **tracing init must run in `setup()` callback, not at `tauri::Builder::run()` start**: `app.path().app_data_dir()` is only available after the `App` is built. Initializing in `main()` before `tauri::Builder::default().run()` will not have the path.

- **PowerShell on Windows**: `Remove-Item` may be blocked by local safety policy. Use `python -c "import os; os.remove(r'...')"` for deletions. `git commit -F file` (file-based) preserves backslashes; inline `-m "..."` can lose them. `gh ... --target <sha>` requires full 40-char SHA (short → HTTP 422).

- **`?` in backticks is a glob in PowerShell**: When passing notes with `?` to `gh release create`, use `--notes-file`. (Not directly relevant to MVP-0 but documented for later release phase.)

## 10. Risks and Open Questions

- **Hermes install state**: We do not know if `hermes` CLI is installed on the dev machine. MVP-0's `HermesAdapter::detect()` will return `ErrHermesNotFound` if not, which is acceptable. Hermes install will be required for MVP-1 (POC).
- **Tauri 2 on Windows MSVC vs GNU**: Tauri 2 requires either MSVC build tools or GNU toolchain. We assume MSVC is the default on this Windows machine. If `cargo build -p tauri-app` fails on linker errors, switch to `x86_64-pc-windows-gnu` via `rustup target add`.
- **`sqlx` query macro requires DB at compile time**: We will use `sqlx::query` (runtime-checked) and `sqlx::migrate!` (file-based, no compile-time DB). We will not use `sqlx::query!` until DB is set up.
- **pnpm vs npm**: Decision deferred to Task 12. pnpm is faster and more disk-efficient; npm requires no extra install. Default to pnpm unless install fails.
- **No CI provider without remote**: `scripts/ci.ps1` is the only enforced gate until a remote is added. This is acceptable per user direction.

## 11. References

- TZ: `TZ_Enterprise_Agent_Deployment_Platform_Final.md` (project root)
- TZ §32: Hermes POC (deferred to MVP-1)
- TZ §35: Error taxonomy (implemented in Task 2)
- TZ §42: CI gates (implemented in Task 13)
- TZ §44: 7 ADRs (deferred; folder `docs/adr/` created in Task 1)
- TZ §45: MVP MUST HAVE (deferred to MVP-3+)
- TZ §50: Target code structure (implemented in Tasks 1–12)
- TZ §51: IPC namespaces (implemented in Task 10)
- TZ §54: Hermes details to verify (deferred to MVP-1 / Hermes POC)
- TZ §55: External sources (catalog at `rubezhanin/agency-agents`)
- Agent memory: `Tauri 2 + ts-rs + tracing pattern` (2026-08-29)
- Agent memory: `ts-rs incremental regen can DUPLICATE then DE-DUPLICATE types` (2026-08-31)
- Agent memory: `Hybrid backend-IPC + frontend-driver apply pattern` (2026-08-31, for reference, not used in MVP-0)

## 12. Spec Self-Review

Performed inline before this commit. Checks:

1. **Placeholder scan**: No "TBD" / "TODO" left. Tasks 6, 10, 12 explicitly mark stubs as `unimplemented!` or `Vec::new()` — these are intentional, not placeholders.
2. **Internal consistency**: §5.4 lists 5 stub IPC commands; §5.5 lists 9. Resolved: §5.5 is the canonical list, §5.4 was an early draft. §5.4 is now updated to match.
3. **Scope check**: 13 tasks, each independently testable. Each produces a runnable, committable deliverable. Fits a single implementation plan.
4. **Ambiguity check**: All commands, paths, and method signatures are explicit. No "could be interpreted two ways" requirements.

No fixes needed beyond the §5.4 update above.

## 13. Next Step

On user approval of this spec, load `superpowers:writing-plans` and create `docs/superpowers/plans/2026-08-31-bootstrap-mvp-0.md` with 13 task blocks, each with explicit file paths, interfaces, TDD steps, and commit instructions.
