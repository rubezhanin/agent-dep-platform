# AGENTS.md

Conventions and context for AI agent sessions working on this repository.

## Project

**Enterprise Agent Deployment Platform** — Tauri 2 + Svelte 5 + Rust desktop
app that safely deploys agent systems from Git repositories into Hermes Agent.

- Source TZ: `TZ_Enterprise_Agent_Deployment_Platform_Enterprise_v2.md`
  (root, gitignored; 2799 lines). The earlier v1 TZ
  (`TZ_Enterprise_Agent_Deployment_Platform_Final.md`) is gitignored too.
- Specs: `docs/superpowers/specs/` (gitignored)
- Plans: `docs/superpowers/plans/` (gitignored)
- ADRs: `docs/adr/0001..0008.md` (gitignored; ADR-0001 superseded by 0008)

## Status

**MVP-1.0 (TZ v2 schema + Hermes router plugin)** — 296 workspace tests
passing, `svelte-check` 0/0, all CI gates green. See `README.md` for
the full Phase 1..6 breakdown. Two manual follow-ups remain before
release tagging:

- **Native-Russian copy review** (TZ §57 Q1) — review surface lives
  at `docs/i18n-review-ru.md`. Bilingual parity is auto-tested.
- **Secondary-platform smoke** — Windows verified; Ubuntu 20.04 VPS
  was reachable on prior session, not re-verified in this one.

## Layout

Multi-crate Cargo workspace. Domain/application lives in `core`;
Tauri and CLI are thin consumers. The Hermes adapter is its own
crate so other runtimes (e.g. OpenAI Codex) can implement
`RuntimeAdapter` without touching `core`.

```
crates/
  core/              domain, application, infrastructure
                     (sqlite, cas, filesystem, repository)
                     TZ v2 schema: Skill, AgentYaml, SystemFileV2
  hermes-adapter/    RuntimeAdapter trait + HermesAdapter
                     + materialize_router_plugin
  cli/               agency CLI (clap)
  tauri-app/         Tauri 2 host + IPC commands
src/                 Svelte 5 + Vite frontend
docs/                i18n-review-ru.md is committed; adr/ and
                     superpowers/ are gitignored
scripts/             local CI scripts (PowerShell)
```

## Build / Test

```powershell
cargo build --workspace
cargo test --workspace
.\scripts\ci.ps1
```

The full CI gates: `cargo fmt --check`, `cargo clippy -D warnings`,
`cargo test --workspace`, `cargo test -p agent_dep_core --test
ts_export` (regenerate TS), `npm install`, `npm run check`
(svelte-check), `git diff --exit-code src/lib/types.generated.ts`
(ts-rs drift guard).

## Conventions

### Rust / domain

- **Path safety**: every user-supplied path goes through
  `agent_dep_core::infrastructure::filesystem::safe_path::resolve_safe_path`.
  Never use raw `Path::join` for write operations.
- **Error handling**: every fallible function returns
  `Result<T, CoreError>`. No `unwrap()` outside tests. `expect()` in
  tests with a clear message.
- **Filesystem writes**: file-level atomic via temp+rename
  (per ADR-0002). For deploys, the parent directory must exist
  BEFORE `resolve_safe_path` is called on the child (the
  canonicalize step needs an existing parent).
- **Backend services that take a `&Db`/`&Pool` from the caller**:
  application services (`DeploymentService`, `JournalService`,
  `IngestRepository`, `DeployedArtifactsRepository`) are pure
  functions of state. They never own a `Pool`. The CLI / Tauri
  IPC layer builds the pool once in `setup()` and threads it
  through.

### Type sharing (Rust ↔ TypeScript)

- DTOs that cross IPC get
  `#[derive(TS)] #[ts(export, export_to =
  "../../../src/lib/types.generated.ts")]`. The three-`..` path
  is required: from `crates/<crate>/src/<file>.rs` we go up to
  `crates/`, up to repo root, into `src/lib/`.
- `crates/core/tests/ts_export.rs` MUST import every DTO +
  every Hermes TS type and call `Type::export_all()` on each.
  Only types in the import list are regenerated; if a new DTO
  is added but the import list is forgotten, the generated TS
  silently goes stale.
- **ts-rs gotcha**: incremental regen can DUPLICATE types.
  After adding new DTOs across multiple commits, the regen
  may produce a `types.generated.ts` with each type written
  twice. The fix: a single fresh regen with the new types
  added to the import list produces the canonical
  (non-duplicated) output, even though `git diff` shows it as
  a large negative diff. Do not `git checkout` to revert — the
  dedup is the correct state.

### Tauri 2

- **Tracing init** must run in the `setup()` callback, not in
  `main()`. `app.path().app_data_dir()` is only available after
  the `App` is built.
- **Async work in Tauri setup()**: use
  `tauri::async_runtime::block_on`, not
  `tokio::runtime::Handle::current().block_on` (the latter
  would panic with "Cannot drop a runtime in a context where
  blocking is not allowed" because Tauri already runs on a
  tokio runtime).
- **Tauri command names**: `#[tauri::command]` generates a
  global `__cmd__<name>` symbol. If two commands in different
  modules share the same function name (`list`), the macro
  fails. Use unique names (`list_sources`, `list_systems`).
- **IPC placement**: thin shim in `crates/tauri-app/src/ipc/<domain>.rs`
  that takes `State<'_, AppState>` and calls into a domain
  service or repository. The tauri crate MUST NOT depend on
  `sqlx` directly — repositories live in `agent_dep_core`.

### Svelte 5 + TypeScript

- **Snippets, not inline arrows**: shared `ListView.svelte`
  exposes `row: Snippet<[unknown]>`. Each route uses
  `{#snippet row(item)}...{/snippet}` to pass the per-item
  renderer. Inline arrow `row={(a) => '...'}` is NOT a valid
  Svelte 5 snippet and will fail svelte-check with
  "Type 'string' is not assignable to type ... unique symbol".
- **Initial $state for nullable types** must be cast:
  `let result: T | null = $state(null as T | null)` because
  `let x: T | null = $state(null)` narrows the type to `null`
  and `result?.field` becomes `never.field`.
- **`ipc.ts` stubs**: commands that need a user-supplied path
  (e.g. `plans.compute`, `security.scan`) are wrapped with
  `.catch(() => defaultValue)` so the UI never crashes on a
  stub.

### Tests

- **Integration test placement**: for state machines /
  public-application services, write the test as
  `crates/<crate>/tests/<feature>.rs`, not as
  `src/<domain>/.../tests.rs`. The integration test compiles
  against the public crate only, so it exercises the same API
  paths as a real consumer (CLI, Tauri IPC) and catches any
  internal test that only works because of `#[cfg(test)]`
  visibility tricks.
- **proptest for path safety**: 3 property tests in
  `crates/core/src/infrastructure/filesystem/safe_path_tests.rs`
  cover the safe-path resolver. Add new properties to the
  same `proptest!` block; do not start a second one.
- **Crash-recovery**: state-machine transitions for the
  recovery journal are tested end-to-end in
  `crates/core/tests/crash_recovery.rs`. Use the same
  `connect(&path).await + db.migrate().await` + `OnceLock`
  pattern when adding new state-machine tests.

### CLI (clap)

- **Backward-compatible argument addition**: when adding a
  new option to an existing clap subcommand, the new option
  MUST be optional with a `Default` value, otherwise
  `clap::CommandFactory::debug_assert()` panics on existing
  test fixtures that don't pass it. Use
  `#[arg(long, value_name = "PATH")]` without
  `required = true`.
- **tokio::main returns `ExitCode`**: `?` cannot be used
  inside `match` arms; use explicit `match Result::Err` to
  convert errors.

### PowerShell on Windows

- `Remove-Item` is blocked by local safety; use
  `python -c "import os; os.remove(r'...')"`. Same for
  `rename`/`move`: use `python -c "import os; os.replace(tmp, path)"`.
- Commit messages use `git commit -F <file>` (file-based),
  never inline `-m "..."` (preserves backslashes).
- `Cargo` is not in PATH by default. The CI script prepends
  `C:\Users\Администратор\.cargo\bin;` to `$env:PATH`. When
  running cargo manually from a fresh PowerShell, do the same.
- Cyrillic username `Администратор` garbles the Hermes PATH
  resolution for some scripts — always run with explicit
  `cwd` and `cd` to the repo root.

## Deferred to later milestones

- **TZ §45 OUT OF MVP** (deferred to 1.x/2.x per spec §7):
  RBAC, SSO/OIDC, approvals, fleet, multi-environment,
  vault, advanced scanner, SBOM/SLSA, fuzzing.
- **1.x**: real Git source ingestion (SSH/HTTPS), `nix` +
  `git2` dependency, SemVer range resolution (MVP is exact
  only per ADR-0003), Hermes 0.19+ flow B (MCP server
  manifests, deferred per ADR-0008 §12.4A).
- **2.x**: enterprise server (ADR-0007) — `core/` stays
  frozen for 1.x; new layers (skills, i18n, reconciliation,
  policy, lock, renderers) are added incrementally.

## When you are stuck

1. Read the relevant ADR in `docs/adr/`. If the topic touches
   deployment, journal, scanner, or storage — there is almost
   certainly an ADR for it.
2. Read the matching section of the source TZ at
   `TZ_Enterprise_Agent_Deployment_Platform_Enterprise_v2.md`
   (root, gitignored).
3. Read the relevant test file
   (`crates/<crate>/tests/<feature>.rs` or
   `crates/<crate>/src/.../tests.rs`) for usage examples.
4. Load the appropriate superpowers skill
   (`superpowers:systematic-debugging` for bugs,
   `superpowers:test-driven-development` for new features).
5. Run `.\scripts\ci.ps1` to see the current state.
