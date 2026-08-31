# ADR-0007: Enterprise Server Evolution

- **Status**: Accepted
- **Date**: 2026-08-31
- **Supersedes**: TZ §37 ("Enterprise evolution") by formalizing what
  the desktop app must preserve (and what it must not do) to enable
  the 2.x server mode without a rewrite.

## Context and Problem Statement

The TZ §37 describes three phases:

- **A (MVP, this ADR's scope)**: local-only single-user desktop.
- **B (1.x)**: signed source snapshots, stronger scanner, version/lock
  resolution, advanced reconciliation, deployment history, expanded
  CLI, policy packs, migration tooling, independent updates of
  Hermes / app / catalog.
- **C (2.x)**: server mode with org/tenant, RBAC, SSO/OIDC, approval
  workflows, environments, central audit, remote catalog registry,
  fleet management, policy-as-code, remote deployment, CI/CD
  integration, enterprise secret providers.

The TZ also requires (§1.2, §37.1) that the **domain model survives
unchanged** into 2.x: `Source`, `Snapshot`, `Agent`, `Skill`,
`System`, `DeploymentPlan`, `DeploymentSnapshot`, `Policy`,
`Operation` are the same concepts in 1.x and 2.x.

The risk this ADR mitigates: making decisions in MVP that lock the
desktop app out of a clean 2.x evolution. We want a 2.x server-mode
re-uses the desktop app's domain, not a parallel implementation.

## Decision

### The desktop app's domain crate is the canonical domain

`crates/core` (and the `core::domain` submodule structure) is the
canonical implementation of the domain model. It MUST NOT contain:

- Tauri types
- CLI parsing
- SQLite connection management (the `infrastructure::sqlite` module
  is fine, but a 2.x server will replace it with Postgres; the
  *domain* must not depend on the SQL flavor)
- Hermes-specific types (Hermes lives behind `hermes-adapter`)
- File-system specifics behind `infrastructure::filesystem`
- Auth, RBAC, sessions, OIDC (those are 2.x surface concerns)

The boundary check: if a module in `core` imports `tauri::*` or
`diesel::*` or `oauth2::*` or anything in `crates/hermes-adapter/*`,
that's a layer violation. The CI script runs a `cargo metadata` /
`cargo tree`-based check (or a simpler `cargo build -p core` with
explicit deny-lists) in a follow-up to enforce this; for now it's
discipline plus a TODO in `core/README.md` (1.x).

### Server-mode 2.x is a separate workspace member, not a feature flag

A 2.x server mode is **not** a `#[cfg(feature = "server")]` on the
desktop binary. It is a separate binary `agent-dep-server` (or a
separate workspace member `crates/server` in 2.x) that depends on
`core` and `hermes-adapter` exactly the same way the desktop app
does. This avoids a class of bugs where the server accidentally
links in Tauri or the desktop UI.

The 2.x server's deployment surface (HTTP API, RBAC, audit) is in
its own crates. The domain is shared.

### Hermes adapter is the only place with runtime specifics

The `RuntimeAdapter` trait (MVP, ADR-0001) is the seam. In 2.x, a
server may want to deploy to *remote* Hermes instances (TZ §40 "Fleet
/ remote deployment"). That is a `RemoteHermesAdapter` that
implements the same `RuntimeAdapter` trait and uses SSH/HTTP to
control a remote Hermes. The domain code is unchanged.

### Auth and identity are 2.x-only

The desktop app has a single implicit user (the local OS user) and
no auth surface. 2.x adds OIDC, RBAC, sessions, and approvals. None
of these touch the domain. The desktop app stays single-user in
1.x; we do **not** add a "log in" screen.

### Audit log schema is frozen at 2.0

The TZ §34.2 says: "Local audit log MUST NOT allow silent rewrite of
history in the regular UI. 2.x central audit will be immutable
server-side log."

This means: the audit log schema we ship in 1.x IS the schema the
2.x server ingests. We commit to a stable audit event format
(JSON, with versioned event type names) so a 1.x desktop can
optionally push events to a 2.x server for central aggregation.
Adding fields to events is allowed (1.x server reads them as
"unknown fields, ignored"); removing or renaming is a 2.0-only
breaking change.

### Multi-environment in 1.x is per-workspace, not per-server

In 1.x, the user can have multiple workspaces (separate
`$app_data_dir` instances via Tauri's profile system) and treat
each as an "environment" (dev / staging / prod) by hand. There's
no 1.x feature for "same workspace, multiple environments";
that's a 2.x concept with a server.

The 1.x plan UI shows a "environment" label that defaults to
`Default` (TZ §38). It's purely informational; the user picks a
deployment target manually.

### Approvals are 2.x-only

TZ §37.5: "Production deployment may require approval policy.
Desktop v1 this flow is not simulated."

In 1.x, "approval" is the user clicking Apply in the plan UI. The
state of the operation is "approved by the human who has the
keyboard." There is no second party, no queued approval, no
delegation. 2.x adds those.

### The desktop app remains useful in 2.x

The 2.x server does not replace the desktop app. The desktop app
becomes "an admin client for the 2.x server" plus "an offline
deploy tool for air-gapped systems." The same `core` domain is used
by both. A user can run 2.x server with zero desktop apps, or
multiple desktop apps talking to one server, or one desktop app
talking to no server (current behavior). All three modes share the
same `core` code.

### What is explicitly out of scope for this ADR

- The exact list of fields in the 2.x audit event format
  (deferred to 2.x design).
- Whether the 2.x server uses Postgres, MySQL, or something else
  (deferred; ADR-0004 says SQLite is the MVP store; 2.x replaces
  the `infrastructure::sqlite` module with an `infrastructure::pg`
  module that exposes the same trait surface).
- Whether the 2.x server uses the desktop app's binary or is
  written from scratch (deferred; this ADR only constrains the
  shared *domain* layer).

## Consequences

### Positive

- Domain survives from MVP to 2.x unchanged, so the 2.x server
  inherits all the bug fixes and improvements from 1.x.
- The desktop app keeps working in 2.x (it can be a client of the
  server, or run standalone). No forced migration.
- The Hermes adapter trait is the runtime seam; 2.x can add
  remote/fleet adapters without touching the domain.

### Negative

- MVP may have to do a small amount of "2.x-shape" thinking to
  avoid painting into a corner (e.g., audit events with versioned
  names). This is a discipline cost, not a code cost.
- 1.x will not get a "preview of 2.x" server features (no sneak
  peek). We commit to 1.x being a desktop product, period.

### Neutral

- The "remote catalog registry" (TZ §37) is a 2.x concept. The
  1.x app reads catalogs from local clones of Git repos; 2.x
  might add a way to share catalogs across users via a central
  registry. This is independent of the domain model.
- We are not committing to any specific web framework or HTTP
  server. 2.x is free to pick whatever.

## Alternatives considered

1. **Build the desktop app as a 2.x server from day one.**
   - Rejected. The TZ §2.1 is explicit: MVP is local-only.
     "Simulating enterprise" in desktop mode creates the illusion
     of enterprise without the substance (TZ §0).

2. **Build a single binary with feature flags for "server mode".**
   - Rejected. A single binary with two modes means the server
     inherits the Tauri dependency (dead code on the server) and
     the desktop inherits whatever the server needs (RBAC code
     paths that never fire). Two binaries share `core` and
     `hermes-adapter`; that's enough.

3. **Defer the domain-stability commitment to "we'll figure it
   out in 2.x".**
   - Rejected. The cost of getting the domain wrong now is
     catastrophic (rewrite at 2.x). The cost of the discipline
     now is small (a few "this module imports nothing from
     outside `core`" reviews). We pay the small cost.

## References

- TZ §0 (Resume / scope statement)
- TZ §1.2 (non-goals; no enterprise IAM in MVP)
- TZ §2 (Evolutionary model)
- TZ §2.2 / §2.3 (1.x and 2.x phase lists)
- TZ §34.2 (audit log; central audit in 2.x)
- TZ §37 (Enterprise evolution)
- TZ §37.1 (Domain model unchanged across phases)
- TZ §37.2 (What 2.x adds)
- TZ §37.5 (Approvals in 2.x only)
- TZ §38 (Environment model; Default in MVP, multiple in 1.x)
- TZ §40 (Fleet / remote deployment in 2.x)
- ADR-0001 (Hermes protocol; seam for runtime adapter)
- ADR-0004 (local storage boundary; SQLite → Postgres in 2.x)
- ADR-0006 (recovery journal; same on server, different transport)
