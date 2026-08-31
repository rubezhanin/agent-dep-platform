# AGENTS.md

Conventions and context for AI agent sessions working on this repository.

## Project

**Enterprise Agent Deployment Platform** — Tauri 2 + Svelte 5 + Rust desktop
app that safely deploys agent systems from Git repositories into Hermes Agent.

- Spec: `docs/superpowers/specs/`
- Plans: `docs/superpowers/plans/`
- ADRs (when written): `docs/adr/`
- Source TZ: `TZ_Enterprise_Agent_Deployment_Platform_Final.md` (root)

## Layout

Multi-crate Cargo workspace. Domain/application lives in `core`; Tauri and CLI
are thin consumers. See `docs/superpowers/specs/2026-08-31-bootstrap-mvp-0-design.md`
§5 for the full layout.

```
crates/
  core/              domain, application, infrastructure (sqlite, cas, filesystem)
  hermes-adapter/    RuntimeAdapter trait + HermesAdapter
  cli/               agency CLI (clap)
  tauri-app/         Tauri 2 host + IPC commands
src/                 Svelte 5 + Vite frontend
docs/                specs, plans, ADRs
scripts/             local CI scripts (PowerShell)
```

## Build / Test

```powershell
cargo build --workspace
cargo test --workspace
.\scripts\ci.ps1
```

## Conventions

- **Path safety**: every user-supplied path goes through
  `agent_dep_core::infrastructure::filesystem::safe_path::resolve_safe_path`.
  Never use raw `Path::join` for write operations.
- **Error handling**: every fallible function returns `Result<T, CoreError>`.
  No `unwrap()` outside tests. `expect()` in tests with a clear message.
- **Type sharing**: DTOs that cross IPC get `#[derive(TS)] #[ts(export,
  export_to = "../../../src/lib/types.generated.ts")]`. Run
  `.\scripts\check-ts-drift.ps1` before committing IPC changes. The
  three-`..` path is required: from `crates/<crate>/src/<file>.rs` we
  go up to `crates/`, up to repo root, into `src/lib/`.
- **ts-rs gotcha**: incremental regen can DUPLICATE types. After adding new
  DTOs across multiple commits, `cargo test --test ts_export` may produce
  a `types.generated.ts` with each type written twice. The fix: a single
  fresh regen with the new types added to the import list produces the
  canonical (non-duplicated) output, even though `git diff` shows it as
  a large negative diff. Do not `git checkout` to revert — the dedup is
  the correct state. See `crates/core/tests/ts_export.rs` for the
  recorded warning.
- **Tracing init**: must run in Tauri `setup()` callback, not in `main()`.
  `app.path().app_data_dir()` is only available after the `App` is built.
- **Async work in Tauri setup()**: use `tauri::async_runtime::block_on`,
  not `tokio::runtime::Handle::current().block_on` (the latter would
  panic with "Cannot drop a runtime in a context where blocking is not
  allowed" because Tauri already runs on a tokio runtime).
- **PowerShell on Windows**: see memory note in Mavis profile —
  `Remove-Item` may be blocked, use `python -c "import os; os.remove(...)"`.
  Commit messages use `git commit -F <file>` (file-based), never inline
  `-m "..."` (preserves backslashes).
- **Cargo on PowerShell session**: not in PATH by default. The CI script
  prepends `C:\Users\Администратор\.cargo\bin;` to `$env:PATH`. When
  running cargo manually from a fresh PowerShell, do the same.
- **Tauri command names**: `#[tauri::command]` generates a global
  `__cmd__<name>` symbol. If two commands in different modules share
  the same function name (`list`), the macro fails. Use unique names
  (e.g. `list_sources`, `list_systems`).

## Deferred to later milestones

- Hermes POC + ADR-001 → MVP-1
- ADRs 002–007 → MVP-2
- All MUST HAVE features (TZ §45) → MVP-3+
- See spec §7 for full deferral list.

## When you are stuck

1. Read the relevant spec in `docs/superpowers/specs/`.
2. Read the relevant plan in `docs/superpowers/plans/`.
3. Read the matching ADR if it exists in `docs/adr/`.
4. Load the appropriate superpowers skill (`superpowers:systematic-debugging`
   for bugs, `superpowers:test-driven-development` for new features).
5. Run `.\scripts\ci.ps1` to see the current state.
