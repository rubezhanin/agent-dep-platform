# ADR-0002: Deployment Filesystem Semantics

- **Status**: Accepted
- **Date**: 2026-08-31
- **Supersedes**: TZ §17.2 ("Cross-platform rule") by formalizing the
  underlying guarantees and trade-offs.

## Context and Problem Statement

The TZ §17 ("Transactional deployment engine") and §17.2
("Cross-platform rule") say:

> Do not claim "atomic directory rename" globally.
> For files use file-level temp+atomic rename where guaranteed by the OS.
> For directories and Windows use journal-and-replay / versioned snapshot
> strategy. Absolute guarantee of atomic tree replacement is not assumed.

This ADR makes that policy concrete: what our app commits to, what it
does not commit to, and how we recover from partial failure on each
supported platform.

## Decision

### File-level: atomic temp + rename within OS guarantees

For every file write (config, manifest, plugin entry, skill file):

1. Compute the target path inside the Hermes-controlled subtree.
2. Write content to `<target>.tmp.<random>` in the **same parent
   directory** (so rename stays on a single filesystem).
3. `fsync` the temp file.
4. `rename(temp, target)` — atomic on POSIX and on NTFS for same-volume
   renames.
5. Optionally `fsync` the parent directory (best effort on Windows).

Consumers either see the old file or the new file, never a partial
write. The `.tmp.<random>` suffix is cleaned up on next deploy or by
the next app launch's recovery sweep.

### Directory-level: never assume atomic tree replacement

We do **not** rely on rename of a directory tree as an atomic
operation. Instead:

- Directory *contents* are updated file-by-file using the file-level
  rule above.
- New subdirectories are created with `mkdir -p` semantics; if
  creation fails partway, recovery sees the partial subtree and
  completes or undoes it (see ADR-0006 recovery journal).
- Removed subdirectories are first renamed to `<name>.staging-removal`
  and only deleted after the operation is committed in the journal
  (deletes become atomic via the journal, not via fs).

### Backup-before-overwrite for modified/foreign state

Per TZ §21 ("Backup — technical implementation of rollback, not a
separate user-facing concept"), before overwriting any file in the
target tree whose previous hash is not the one we wrote, we push the
old content into the content store (CAS) and record a backup
reference. The reference is part of the deployment record; rollback
restores from CAS.

This is the only context in which backup is implicit and not gated by
user confirmation. Wiping user-written files is never implicit; it
requires explicit policy (TZ §20.3) and surfaces in the plan UI as
"modified" / "foreign" before any delete.

### Cross-platform reality

| Platform | rename(file) same dir | rename(dir) | atomic tree swap |
|---|---|---|---|
| Linux ext4/btrfs | atomic | atomic | not atomic across fs |
| macOS APFS | atomic | atomic | not atomic across fs |
| Windows NTFS | atomic same vol | atomic same vol | not atomic across vol |
| Windows FAT/exFAT | atomic | not atomic | not atomic |

Our app is honest about this: it provides file-level atomicity
**within a single volume** and directory-level recovery via the
journal (ADR-0006). It does **not** claim atomicity across volumes,
network mounts, or kernel-level filesystems with no rename support.

### Bounded retries for transient errors

For transient errors (`ERROR_SHARING_VIOLATION` on Windows, `EBUSY`
on Linux), retry with exponential backoff up to 5 attempts, total
budget 10 seconds per file. Beyond that, the operation is marked
`failed` in the journal and surfaced to the user; recovery is manual
(ADR-0006).

## Consequences

### Positive

- Honest, testable contract: every write is either durably old or
  durably new.
- Crash mid-deploy is recoverable: any committed (journaled) step has
  either fully happened or not; unjournaled files may be partial but
  are quarantined on startup.
- The CAS doubles as the backup store; no separate "backup disk"
  architecture.

### Negative

- A power loss between journal-write and rename leaves a "prepared
  but not committed" state. The journal records this; the next
  launch's recovery detects it and rolls back the prepared file
  (uses the previous hash to restore the prior content from CAS).
- Cross-volume moves (e.g., Hermes config on `C:` while we write to
  `D:`) are not atomic. Our app refuses cross-volume deploys in MVP
  and surfaces an error; 1.x can add explicit two-phase commit if
  the use case appears.
- File-level atomic rename does not protect against the *file
  content* being wrong (a corrupt upstream catalog). That's the
  scanner's job (ADR-0005).

### Neutral

- Backups accumulate in the CAS until pruned. Retention policy is
  "keep the most recent 5 deployments per system, plus the one
  currently in `CURRENT`" in MVP; this is a follow-up
  operationalization, not in this ADR.
- The `.tmp.<random>` files are auto-cleaned on next app launch and on
  successful journal commit; they never accumulate in a healthy
  system.

## Alternatives considered

1. **Always copy-rename-verify.** A third "verify" pass hashes the
   result and retries if mismatch.
   - Rejected. Adds latency and an extra IO per file. We rely on
     per-OS atomic rename which is verified by the OS vendor; the
     journal + recovery handle the rest.

2. **Use a CoW filesystem overlay (e.g., btrfs subvolume snapshot,
   ZFS snapshot, APFS clone) when available.**
   - Rejected for MVP. Adds platform-specific code paths and
     requires admin/root for some operations. Can be added in 1.x as
     an optimization, not a correctness primitive.

3. **Refuse all overwrites; require the user to manually delete
   first.**
   - Rejected. Breaks the "one-click apply" UX the TZ §1.1.1 calls
     out as a hard requirement.

## References

- TZ §17 ("Transactional deployment engine")
- TZ §17.2 ("Cross-platform rule")
- TZ §17.3 ("Operation journal")
- TZ §20.3 ("Remediation policy")
- TZ §21 ("Backup")
- ADR-0001 (Hermes protocol) — the target tree shape
- ADR-0004 (local storage boundary) — where CAS and journal live
- ADR-0006 (recovery journal) — consumes this ADR's guarantees
