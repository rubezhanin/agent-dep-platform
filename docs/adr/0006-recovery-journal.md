# ADR-0006: Recovery Journal

- **Status**: Accepted
- **Date**: 2026-08-31
- **Supersedes**: TZ §17.3 ("Operation journal") and §18 ("Crash
  recovery") by formalizing the journal schema, the recovery
  algorithm, and the safety properties the implementation must
  preserve.

## Context and Problem Statement

The TZ §17.3 mandates:

> Every mutation gets:
> ```yaml
> operationId: ...
> type: deploy
> status: prepared|writing|committing|committed|rolled_back|failed
> planHash: ...
> startedAt: ...
> ```
>
> If the app terminated after `prepared/writing/committing`, on the
> next launch recovery is run.

And TZ §18 describes startup recovery:

> Open DB → find non-terminal operations → inspect filesystem →
> validate snapshot / journal → finish commit OR rollback →
> reconcile → mark operation terminal.

The TZ is clear about *what* must happen but not about exactly *how*
the implementation distinguishes "the operation completed but
the journal-commit was lost" from "the operation was interrupted
mid-write". This ADR fixes that.

## Decision

### Journal schema (SQLite)

A new table `operations`:

```sql
CREATE TABLE operations (
    operation_id   TEXT PRIMARY KEY,        -- uuid v4
    type           TEXT NOT NULL,           -- 'deploy' | 'rollback' | 'plan' | 'audit'
    status         TEXT NOT NULL,           -- 'prepared' | 'writing' | 'committing'
                                            -- | 'committed' | 'rolled_back' | 'failed'
    plan_hash      TEXT NOT NULL,           -- sha256 of the plan that produced this op
    started_at     TEXT NOT NULL,           -- ISO 8601
    finished_at    TEXT,                    -- ISO 8601, set on terminal status
    -- The plan's effect, snapshotted at prepare time, so recovery
    -- can finish or roll back without re-reading external state.
    -- JSON blob; size capped at 1 MB per op (we split big ops).
    effect_json    TEXT NOT NULL,
    -- Free-form error message, set on `failed`.
    error          TEXT
);
```

A non-terminal op is any row with `status IN ('prepared','writing','committing')`.
Terminal statuses are `committed`, `rolled_back`, `failed`. The
recovery process only touches non-terminal rows; terminal rows are
history.

### State machine

```
                    prepare
   (nothing)  ---------------->  prepared
        ^                              |
        |                              | begin-write
        |                              v
        |                            writing
        |                              |
        |                       (one of: commit-success | commit-fail | crash)
        |                              |
        |                              v
        |                          committing
        |                              |
        |              +---------------+---------------+
        |              |               |               |
        |              v               v               v
        |          committed       failed        (crash leaves non-terminal)
        |              |               |
        |              | rollback      | (terminal; no further work)
        |              v               |
        |          rolled_back         |
        |              |               |
        +--------------+---------------+
              (terminal; no further work)
```

The key invariant: **the journal row is written *before* the
mutation starts**, and the *terminal* status is written *after* the
mutation completes successfully (or after rollback completes on
failure). A crash leaves the row non-terminal; the next launch's
recovery is the only path to a terminal state.

### Recovery algorithm (TZ §18)

On app launch, the recovery runs before any other startup work:

1. Open DB.
2. `SELECT * FROM operations WHERE status IN ('prepared','writing','committing')`.
3. For each non-terminal op, classify:
   - **`prepared`**: nothing was written to disk. Just mark `rolled_back`
     (or `failed` if the effect_json indicates a policy violation that
     would have stopped the op from starting).
   - **`writing`**: some files may have been written or partially
     written. The `effect_json` contains the full list of intended
     writes (target path + expected sha256). For each intended write:
     - If the file exists and its hash matches the expected hash →
       the write completed; carry on.
     - If the file exists and its hash does NOT match → it's a
       partial write; restore from CAS (the previous version is in
       CAS, key by the prior content hash if the op recorded it;
       otherwise just delete the partial file and treat it as
       "missing").
     - If the file does not exist → never written; carry on.
   - **`committing`**: all files were written and the journal is
     about to flip to `committed`. The DB INSERT of the
     `committed` status is missing. We re-attempt the commit by
     verifying every intended write is in place and hashes match,
     then mark `committed`.
4. After all non-terminal ops are resolved, mark the operation
   `rolled_back` (if we did restore) or `committed` (if we did
   finish). Record `finished_at` and any `error`.
5. Run reconciliation (TZ §20): compare the current `deployed` system
   against the desired state from the latest committed op; surface
   drift in the UI (MVP: a log line + a status badge).

### What recovery never does

- It does not retry a `failed` op. Failures are terminal; the user
  inspects the error and starts a new op.
- It does not auto-rollback a `committed` op. The user invokes
  rollback explicitly via `agency rollback <deployment-id>` (TZ §19).
- It does not modify file contents that the op did not own. If
  another op or the user wrote to a path that the current op
  intended to write, recovery notices (the prior hash in the
  effect_json does not match) but does not overwrite without user
  policy.

### Idempotency

Every recovery step is idempotent. Re-running recovery on a system
that was already recovered is a no-op (terminal rows are not
touched). This matters because:

- The user may force-quit the app multiple times during recovery.
- A power loss during a SQLite WAL flush leaves the recovery
  itself in a half-done state; the next launch must redo it
  safely.

### Audit log vs. operation journal

The TZ §34 audit log records every state-changing event (success or
failure). The operation journal records state-changing
**operations** with enough info to resume or roll back. The audit
log is append-only; the journal is the authoritative state for
recovery.

A write may produce several audit entries (one per file) but is one
operation. Recovery reads the journal, not the audit log.

### Bounded recovery time

Recovery is bounded: each non-terminal op is resolved in O(writes)
time, and we keep the last 100 non-terminal ops (anything older is
forced to `failed` at startup with a clear "stale operation
aborted" message). The cap is configurable but 100 is a generous
default for a single-app, single-user MVP.

## Consequences

### Positive

- The journal makes "what happened last time the app died" a
  computable question: list the non-terminal ops, look at the
  filesystem, finish or roll back each one.
- The schema is small, additive, and migrates cleanly (each version
  is a separate `ALTER TABLE`).
- Recovery is idempotent; running it twice is safe.
- The `effect_json` is the key: it captures the full intent at
  prepare time, so recovery does not need to re-read external state
  (the Git source might be unreachable, the lock might be edited,
  etc.).

### Negative

- `effect_json` is a JSON blob in SQLite; it's not as queryable as
  normalized columns. We accept this; the journal is write-once per
  op, and reading it is rare (only on crash recovery).
- The 100-op cap is somewhat arbitrary; if a user runs 100+ ops
  without closing the app, very old non-terminal ops are
  forcibly-failed. In practice this is never an issue (a single
  user is unlikely to leave the app open for 100 deploys), but it's
  worth noting.
- Recovery time grows with op count and per-op writes. For a
  multi-GB deploy with millions of files, this could become slow.
  1.x will need to batch.

### Neutral

- The journal is local (in `$app_data_dir/data/agent-dep.db`). It
  does not sync to a server. In 2.x the enterprise control plane
  has a central audit log (TZ §34.2) which is a separate concern;
  the local journal remains the source of truth for crash recovery.
- We do not write the journal to CAS. The journal is metadata
  (small, structured, SQLite-friendly), not content.

## Alternatives considered

1. **Use a write-ahead log at the file system level (e.g.,
   `intent.log` in the target tree).**
   - Rejected. The target tree is owned by Hermes or the user's
     other apps; we do not write files into it. The journal lives
     in our app's data dir, where it belongs.

2. **Use `git` as the journal.**
   - Rejected. Git is the source of truth for system definitions,
     not for the app's runtime state. Using Git for the journal
     would couple the app to Git in a way that's hard to undo.

3. **Skip the journal, rely on atomic file rename + "never
   interrupted" property.**
   - Rejected. TZ §18 explicitly requires recovery from interrupted
     operations; the journal is the only way to satisfy that
     contract on real hardware (laptop sleep, power loss, user
     kill).

4. **Use CRDT-like mergeable state for concurrent ops.**
   - Rejected. MVP is single-user, single-process; no concurrent
     ops. CRDTs are 2.x complexity.

## References

- TZ §17 (Transactional deployment engine)
- TZ §17.3 (Operation journal)
- TZ §18 (Crash recovery)
- TZ §19 (Rollback)
- TZ §20 (Reconciliation)
- TZ §34 (Observability / audit log)
- ADR-0002 (filesystem semantics) — the `effect_json` matches the file-level rules
- ADR-0004 (local storage boundary) — `data/agent-dep.db` is where the table lives
- ADR-0001 (Hermes protocol) — what kinds of operations are tracked (deploy, rollback, plan)
