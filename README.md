# Enterprise Agent Deployment Platform

Local-only Tauri 2 + Svelte 5 + Rust desktop application for safely
deploying agent systems from Git repositories into Hermes Agent.

## Status

**MVP-3 (Ingestion, persistence, scanner, journal, composition)** —
in progress; 5 of 6 MUST HAVE slices landed. 169 tests passing,
all CI gates green.

```
$ .\scripts\ci.ps1
==>
==> cargo fmt --check
==> cargo clippy
==> cargo test        (169 passed; 0 failed)
==> ts-rs regen
==> npm install
==> npm run check     (svelte-check: 0 errors, 0 warnings)
==> ts-rs drift
==>
CI PASSED
```

Source TZ: `TZ_Enterprise_Agent_Deployment_Platform_Final.md` (root,
gitignored).

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
  hermes-adapter/    RuntimeAdapter trait + HermesAdapter
  cli/               agency CLI (clap)
  tauri-app/         Tauri 2 host + IPC commands
src/                 Svelte 5 + Vite frontend
docs/
  superpowers/       specs and plans
  adr/               7 ADRs (ADR-0001 .. ADR-0007)
scripts/             local CI scripts (PowerShell)
```

## What's done

### MVP-0 — Bootstrap skeleton
- Multi-crate Cargo workspace (`core`, `hermes-adapter`, `cli`, `tauri-app`)
- CoreError taxonomy (TZ §35) — 14 variants
- Path safety with proptest property-based tests
- SQLite + sqlx migrations skeleton (WAL / FK / busy-timeout)
- Content-addressed store (sha256 layout, atomic write)
- Hermes adapter skeleton with `RuntimeAdapter` trait
- CLI skeleton (`agency deploy <system>`, `agency status`)
- Tauri 2 app shell with `setup()` initializing tracing, DB, CAS, AppState
- 9 IPC commands, ts-rs drift-CI guard, Svelte 5 + Vite with 9 routes
- `scripts/ci.ps1` runs all gates locally

### MVP-1 — Hermes POC
- **Parked per user decision 2026-08-31** (no router-plugin spec in
  Hermes v0.18.2; ADR-0001 documents the MCP-server alternative)

### MVP-2 — ADRs (TZ §44 prerequisite for active implementation)
- 7 ADRs written and accepted; see `docs/adr/`:

| # | File | Topic |
|---|---|---|
| 0001 | `0001-hermes-protocol.md` | Hermes v0.18.2 protocol — MCP servers, not dashboard plugins |
| 0002 | `0002-deployment-filesystem-semantics.md` | File-level atomic temp+rename, journal for dirs |
| 0003 | `0003-lock-file-and-versioning.md` | Exact versions in MVP, lockfile authoritative |
| 0004 | `0004-local-storage-boundary.md` | SQLite/CAS layout, migration backup policy |
| 0005 | `0005-security-scanner-scope.md` | 13 rules, 3 severities, no NLP heuristics |
| 0006 | `0006-recovery-journal.md` | `operations` table, idempotent recovery, bounded 100 |
| 0007 | `0007-enterprise-server-evolution.md` | Domain frozen across phases, server in 2.x |

### MVP-3 — Ingestion, persistence, scanner, journal, composition
- **Local catalog ingest** (`agency catalog update <path>`):
  parses `divisions.json` + per-division `agents/<id>.md`
  (YAML-frontmatter + Markdown body), validates id-matches-stem and
  version-is-SemVer, computes a deterministic sha256 snapshot
  identity, returns counts + per-file records + rejected agents.
- **SQLite persistence** (`IngestRepository`):
  sources / source_snapshots / divisions / agents + ordered link
  tables for tools and activation_phrases / observed files /
  rejected agents. Schema migrations 001, 002, 003 (schema_version=4).
  Re-ingest supersedes prior Active in a single transaction.
- **Security scanner** (ADR-0005): 13 rules, PASS / WARN / BLOCK
  severities, `RegexScanner` impl, policy overrides per rule +
  trusted domains with wildcard + `treat_warn_as_block`. Any BLOCK
  flips the snapshot to `Blocked`; `scan_note` summarizes.
- **Recovery journal** (ADR-0006): `operations` table with
  `Prepared -> Writing -> Committing -> Committed | Failed` state
  machine, `RolledBack` exit. `gc_stale(keep=100)` force-fails
  ancient non-terminal rows at startup.
- **Composition + plan** (`agency system plan <file> --catalog <path>`):
  parses `system.yaml` (`apiVersion: agent-dep/v1`, `kind: System`,
  `spec.agents[].ref: <id>@<version>`), resolves refs against the
  ingested snapshot, applies per-agent overrides, emits a
  deployment plan (every resolved agent becomes one ADD
  operation; risk is `low`). The diff against a real deployment
  state lands in 1.x.

## What's still in MVP-3 (and beyond)

- **Real deploy step** — `agency deploy <file>` that actually applies
  the plan via the journal and writes agent files to Hermes (or its
  MCP-server location per ADR-0001).
- **Hermes adapter wiring** — the existing `HermesAdapter` is
  detected-only; the `agency mcp add` / `agency mcp list` flow
  that materializes the four router tools from ADR-0001.
- **Tauri UI** — current pages are placeholders that call
  placeholder IPCs. MVP-3 wires the real data through the existing
  IPC surface.
- **Backup / restore** + **update flows** (TZ §19, §21).
- **TZ §12.2 / §54 / §55 wording** updates to match ADR-0001.
- **ADR-0008** — bridge between the upstream `agency-agents`
  format (YAML frontmatter) and the TZ §6 apiVersion/kind/metadata/spec shape.

## Local CI

```powershell
.\scripts\ci.ps1
```

Gates: `cargo fmt --check`, `cargo clippy -D warnings`,
`cargo test --workspace`, `ts-rs regen`, `npm install`,
`npm run check` (svelte-check), `ts-rs drift` (git diff guard).

## Conventions for AI agents

See `AGENTS.md` at the repo root.
