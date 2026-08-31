# Enterprise Agent Deployment Platform

Local-only Tauri 2 + Svelte 5 + Rust desktop application for safely
deploying agent systems from Git repositories into Hermes Agent.

## Status

**MVP-0 (Bootstrap skeleton)** — complete, all CI gates green.

```
$ .\scripts\ci.ps1
==>
==>
... (cargo fmt, clippy, test, npm check, ts-rs drift)
==>
CI PASSED
```

See `docs/superpowers/specs/2026-08-31-bootstrap-mvp-0-design.md` for the
design, `docs/superpowers/plans/2026-08-31-bootstrap-mvp-0.md` for the
13-task implementation plan, and `AGENTS.md` for AI agent conventions.

Source TZ: `TZ_Enterprise_Agent_Deployment_Platform_Final.md` (root).

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
  hermes-adapter/    RuntimeAdapter trait + HermesAdapter
  cli/               agency CLI (clap)
  tauri-app/         Tauri 2 host + IPC commands
src/                 Svelte 5 + Vite frontend
docs/                specs, plans, ADRs (deferred to MVP-2)
scripts/             local CI scripts (PowerShell)
```

## What's in MVP-0

- **Workspace + 4 crate skeletons** with correct dependency graph
- **CoreError taxonomy** (TZ §35) — 14 variants
- **Path safety** with proptest property-based tests (3 unit + 3 property)
- **SQLite + sqlx migrations** skeleton with WAL/FK/busy-timeout
- **Content-addressed store** with sha256 layout, atomic write, defense-in-depth path validation
- **Hermes adapter** with `RuntimeAdapter` trait + `HermesAdapter::detect()`
- **CLI** with `agency deploy <system>` and `agency status` (stubs)
- **Tauri 2 app shell** with setup() initializing tracing, DB, CAS, Hermes adapter, AppState
- **9 IPC commands** (one per namespace) returning safe stubs
- **ts-rs** with drift-CI guard — 11 generated TypeScript types
- **Svelte 5 + Vite** with 9 placeholder routes and IPC wrappers
- **`scripts/ci.ps1`** runs all gates locally; same checks as the
  unactivated `.github/workflows/ci.yml` template

## What's deferred

- Hermes POC + ADR-001 → MVP-1
- ADRs 002–007 → MVP-2
- All MUST HAVE features (TZ §45) → MVP-3+

## Local CI

```powershell
.\scripts\ci.ps1
```

Gates: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`,
`ts-rs regen`, `npm install`, `npm run check` (svelte-check), `ts-rs drift` (git diff guard).
