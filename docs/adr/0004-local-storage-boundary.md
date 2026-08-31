# ADR-0004: Local Storage Boundary

- **Status**: Accepted
- **Date**: 2026-08-31
- **Supersedes**: TZ §11 ("Local storage model") and §26 ("Storage and
  migration") by fixing the on-disk layout and the migration safety
  contract.

## Context and Problem Statement

The TZ §11 says:

> SQLite stores metadata only (sources, snapshots, agents, skills,
> systems, deployments, operations, audit, policy). Immutable content
> lives in the content-addressed store (CAS). SQLite MUST NOT be a
> source of truth for System definitions (TZ §26.2) — those are
> YAML/JSON in Git.

And §26.1 requires migration-based schema with up + rollback + test +
backup-before-migration.

This ADR fixes:

- The exact on-disk layout under `app_data_dir` on each OS.
- The boundary between "mutated by our app" and "immutable / system".
- The migration safety contract (backup, up-only MVP, down = restore
  from backup).
- The relationship between SQLite metadata and CAS content.

## Decision

### On-disk layout

All app-managed state lives under one root: `$app_data_dir`.

| OS | Default `$app_data_dir` |
|---|---|
| Windows | `%APPDATA%\com.agentdep.platform` |
| macOS | `~/Library/Application Support/com.agentdep.platform` |
| Linux | `~/.config/com.agentdep.platform` |

The app uses the `tauri::path::app_data_dir()` resolution, so the
exact path is whatever Tauri returns. We do **not** override it
without explicit policy.

Layout under `$app_data_dir`:

```
$app_data_dir/
├── data/
│   ├── agent-dep.db              # SQLite: source/snapshot/agent/skill/system/
│   │                            # deployment/operation/audit/policy meta
│   ├── agent-dep.db-wal         # SQLite WAL (WAL journal mode)
│   ├── agent-dep.db-shm         # SQLite shared memory
│   └── backups/
│       ├── pre-migration-2026-08-31-173000.db
│       └── pre-migration-2026-08-31-180000.db
├── cas/
│   ├── sha256/                  # content-addressed immutable content
│   │   ├── ab/
│   │   │   └── cd/
│   │   │       └── abcdef...    # actual file (sha256 of contents)
│   │   └── ...
│   └── staging/                 # in-flight content, journal-managed
├── logs/
│   └── app.json.YYYY-MM-DD      # rotating daily JSON logs (TZ §34)
├── cache/                       # non-authoritative, safe to delete
│   └── remote-catalogs/         # mirror of fetched source snapshots
└── config.json                  # user-visible runtime config
```

### What is mutable vs immutable

| Path | Mutable? | Owner | Notes |
|---|---|---|---|
| `data/agent-dep.db*` | Yes (in-place) | our app | SQLite, FK on, WAL mode |
| `cas/sha256/**` | **No** (immutable) | our app | Content-addressed, deduplicated |
| `cas/staging/**` | Yes (temp) | our app | Journal-managed; cleaned on commit |
| `logs/*.json` | Append-only | our app | Rotated daily, not deleted in MVP |
| `cache/**` | Yes | our app | Recreatable, deleted freely |
| `config.json` | Yes (in-place via atomic rename) | our app | User config; survives upgrades |
| Hermes home | Yes (via Hermes CLI) | Hermes | We configure, Hermes writes |

### SQLite is metadata, not source of truth

Per TZ §26.2, system definitions (`system.yaml`) are YAML files in
the user's source Git repository. The app reads them, validates them,
and stores hashes + extracted metadata in SQLite, but it does not
write back the source-of-truth `system.yaml` into the local store.
The user can delete the entire `data/` directory and the app will
rebuild metadata by re-reading the source — the only thing lost is
local audit history and the in-progress operation journal
(recoverable from logs and CAS until next launch).

### Migrations are irreversible in MVP

Per TZ §26.3, every migration has up + rollback + test + backup. In
MVP, "rollback" means "restore from the pre-migration backup copy":
the app keeps the last 5 pre-migration SQLite backups under
`data/backups/`. The app never auto-downgrades a schema. If a
migration is interrupted, the next launch detects this and either
completes the up or restores from the pre-migration backup.

The backup is created immediately before `sqlx::migrate!` runs:

```rust
// Pseudocode
let backup = current_db_snapshot()?;
save_to(&backup, &data_dir.join("backups").join(format!("pre-migration-{}.db", now())))?;
sqlx::migrate!().run().await?;
// If this fails, next launch's recovery restores from `backups/pre-migration-*.db`.
```

### Migration compatibility

- Forward-only: a v0.1 app cannot read a v0.2 database.
- A v0.2 app **can** read a v0.1 database (it runs the v0.1→v0.2
  migration on launch).
- A v0.2 app **can** also recover a v0.1 database from the
  pre-migration backup, then re-apply v0.1 migrations, then re-apply
  the v0.1→v0.2 migration. This round-trip is tested.

### CAS content is portable across OS but not across machines

CAS content is content-addressed (sha256 of bytes). The same bytes
on any OS hash to the same CAS path. So:

- Moving the `cas/` directory between machines preserves all
  content.
- Moving between OSes on the same machine preserves all content.
- The `data/` SQLite is OS-portable but not architecture-portable
  (an x86_64 SQLite is fine to move; an ARM SQLite to x86_64 works
  only if `pragma journal_mode = wal` is set; we set WAL on first
  connect).

### Backups are not in the CAS

Backups in `data/backups/` are full SQLite snapshots, not CAS
references. They are byte-for-byte database copies, used only for
schema-rollback. Application content backups (TZ §21) live in
`cas/sha256/` and are addressed by their original content hash.
These are two different concepts; the file-system layout makes the
distinction explicit.

### Cache directory is not authoritative

`cache/remote-catalogs/` may hold mirrors of fetched source
snapshots. The app must function correctly after a fresh start
with an empty `cache/` — every cached file is recreatable by
re-fetching the source. The cache is purely a performance
optimization.

## Consequences

### Positive

- One root, predictable layout. Users (and the app's uninstaller)
  can wipe the entire app by deleting `$app_data_dir`.
- Content integrity: CAS is immutable and dedup'd by sha256.
- Migration safety: every schema change has a 1-click rollback via
  the pre-migration backup.
- Portability: CAS content travels; SQLite travels (with WAL
  caveat).

### Negative

- Disk usage can grow without bound if backups and CAS are not
  pruned. MVP policy: keep last 5 SQLite backups, keep all CAS
  content referenced by the current or last 5 deployment records
  (the rest is pruneable but not auto-pruned in MVP).
- The pre-migration backup doubles disk usage during the migration
  window. For small databases (kilobytes) this is negligible; for
  multi-GB databases this is noticeable but still fine.
- `cache/remote-catalogs/` re-downloads on first use after wipe;
  this is by design but means cold-start after uninstall is slow.

### Neutral

- Tauri determines the exact `app_data_dir` path. If the user
  overrides it via `tauri::path`, the layout above still applies
  under whatever path they chose.
- We do not encrypt the SQLite or the CAS in MVP. 1.x can add
  at-rest encryption; for now the security model assumes disk
  encryption (FileVault, BitLocker, LUKS) at the OS level.

## Alternatives considered

1. **Use a single SQLite file for everything (data + blobs).**
   - Rejected. SQLite blobs work but are less efficient than the
     filesystem for the CAS volume we expect (10s of MB to GB
     across deployments). The CAS-on-filesystem pattern is also
     easier to back up incrementally and to reason about.

2. **Store the source-of-truth `system.yaml` in SQLite, treat Git
   as a sync source only.**
   - Rejected. TZ §26.2 is explicit: Git is the source of truth.
     SQLite is metadata. Re-deriving SQLite from Git is part of the
     design contract.

3. **Use the user's Documents folder instead of OS-managed
   `app_data_dir`.**
   - Rejected. `app_data_dir` is OS-managed (hidden on Windows,
   excluded from Spotlight on macOS, in `~/.config/` on Linux).
     Storing in Documents would clutter the user's view and expose
     state to accidental deletion.

4. **Auto-prune CAS on every deploy.**
   - Rejected. Pruning is hard to make safe (we'd need to know which
     deployment records still reference which CAS entries, plus
     backups and audit). MVP: manual `agency cas gc` command.

## References

- TZ §11 (Local storage model)
- TZ §11.1 (SQLite metadata)
- TZ §11.2 (CAS content)
- TZ §11.3 (Consistency rule)
- TZ §21 (Backup)
- TZ §26 (Storage and migration)
- TZ §26.1 (Migrations)
- TZ §26.2 (JSON snapshots / Git as source of truth)
- TZ §26.3 (Migration principle)
- ADR-0001 (Hermes protocol) — the Hermes home boundary
- ADR-0002 (filesystem semantics) — backup-before-overwrite
- ADR-0006 (recovery journal) — backup interaction
