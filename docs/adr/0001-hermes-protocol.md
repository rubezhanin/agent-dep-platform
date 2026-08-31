# ADR-0001: Hermes v0.18.2 Integration Protocol

- **Status**: Accepted
- **Date**: 2026-08-31
- **Author**: Mavis (drafted during MVP-1 discovery)
- **Supersedes**: TZ §12.2 (router-plugin description) and TZ §55 (rubezhanin/agency-agents reference) — both found to be aspirational, not descriptive of the actual v0.18.2 protocol.

## Context and Problem Statement

The TZ presumes an "Enterprise Agent Deployment Platform" that deploys agent
systems into Hermes Agent. The TZ §12.2 describes a "lazy-router plugin"
mechanism that exposes four LLM-callable tools
(`agency_agents_search`, `agency_agents_inspect`, `agency_agents_load`,
`agency_agents_delegate`) from a plugin installed at
`~/.hermes/plugins/agency-agents-router/`.

Before active implementation, the TZ §32 and §44 require:

1. A Hermes PoC that fixes the actual integration protocol.
2. `ADR-0001-HERMES-PROTOCOL` recording the verified facts.

This ADR fulfils item 2 for the Hermes version installed on the development
host (Hermes v0.18.2 (2026.7.7.2), installed at
`C:\Users\Администратор\AppData\Local\hermes\hermes-agent`, Python 3.11.15,
OpenAI SDK 2.24.0, install method `git`).

## Decision

**Use MCP (Model Context Protocol) servers, not dashboard plugins, for
exposing agent-routing tools to Hermes.**

The four router tools from TZ §12.2 will be re-implemented as a single
MCP server that our app deploys alongside the agent catalog. The MCP server
is a Python process spawned by Hermes; it reads its agent roster from a
frozen config file written by our app at install time.

## Forces / Findings

### Hermes v0.18.2 architecture (verified 2026-08-31 on the host)

| Integration surface | Mechanism | CLI / API | Used for |
|---|---|---|---|
| Dashboard UI tabs | Plugin (Python `plugin_api.py` + JS `dist/index.js` + `manifest.json`) | `hermes plugins install <git-url>` | UI extensions (achievements, browser tabs) |
| **LLM-callable tools** | **MCP server (separate Python process, stdio or HTTP)** | **`hermes mcp add`** | **Tool surfaces (linear, n8n, etc.)** |
| Knowledge / behaviors | Skill (`SKILL.md` with YAML frontmatter) | `hermes skills install` | Procedural knowledge loaded into context |
| Built-in tools | Python modules in `hermes-agent/tools/` | Bundled with Hermes | Core toolset (file ops, web search, etc.) |
| Skill aliases | Bundle | `hermes bundles` | Group multiple skills under a single name |
| Bundled with the app | None of the above | Built into `hermes-agent` itself | `hermes` CLI, TUI, gateway, dashboard |

### Two integration mechanisms are commonly confused

1. **Plugins** (`hermes plugins install`): for **UI tabs** in the Hermes
   dashboard. The `manifest.json` declares a tab with `entry: dist/index.js`
   and `api: plugin_api.py`. The Python `plugin_api.py` is the backend
   for the tab, **not** an LLM-callable tool. Example: `hermes-achievements`
   has a tab at `/achievements` powered by `dashboard/dist/index.js`.

2. **MCP servers** (`hermes mcp add`): for **LLM-callable tools**. Each
   MCP server is a separate process that speaks the Model Context Protocol;
   Hermes discovers the tools it exposes and registers them in the agent's
   tool surface. The `hermes mcp add` command walks through discovery and
   registration. Examples: `linear`, `n8n`, `unreal-engine` in
   `hermes-agent/optional-mcps/`.

The TZ §12.2 description of a "lazy-router plugin with router tools"
does not match v0.18.2: plugins are UI, not tools. The TZ was written
based on a planned protocol that was never implemented in Hermes.

### Upstream reference (TZ §55) does not exist

The TZ cites `rubezhanin/agency-agents` on GitHub as the source of the
router-plugin description. As of 2026-08-31, `https://github.com/rubezhanin/agency-agents`
returns HTTP 404. The local copy at `C:\projects\agency-agents` is the
**template repo** (per its README: "the version you are looking at is the
template to fork") and contains only persona Markdown files plus a
`hermes-kit-manifest.json` template — no router-plugin implementation.

The TZ §12.2 description is **aspirational**, not descriptive of a
deployable upstream.

## Decision details

### Architecture: agent catalog → MCP server (one per catalog)

```
┌─────────────────────────┐
│ our-app                 │
│  ┌─────────────────────┐ │
│  │ source snapshot     │ │  (frozen git SHA + rendered manifests)
│  │ agent roster        │ │
│  │ system definitions  │ │
│  └─────────────────────┘ │
│           │             │
│           ▼             │
│  ┌─────────────────────┐ │
│  │ router.json         │ │  (frozen, written to HERMES_HOME/router/<id>/)
│  │   catalog_id,       │ │
│  │   catalog_ref,      │ │
│  │   agents[],         │ │
│  │   install_id        │ │
│  └─────────────────────┘ │
│           │             │
│           ▼             │
│  generate               │
│           │             │
│           ▼             │
│  ┌─────────────────────┐ │
│  │ MCP config entry    │ │  (written to hermes config.yaml MCP section
│  │   name, cmd, args,  │ │   or registered via `hermes mcp add`)
│  │   env, tools        │ │
│  └─────────────────────┘ │
└─────────┬───────────────┘
          │
          ▼
┌─────────────────────────┐
│ Hermes (v0.18.2)         │
│  ┌─────────────────────┐ │
│  │ router-mcp server   │ │  (Python process spawned by Hermes;
│  │   reads router.json │ │   one process per deployed catalog)
│  │   exposes 4 tools   │ │
│  └─────────────────────┘ │
│           │             │
│           ▼             │
│  agent tool surface     │
│   (visible to LLM)      │
└─────────────────────────┘
```

### Tool mapping (TZ §12.2 → MCP)

| TZ §12.2 router tool | MCP tool (proposed) | Behavior |
|---|---|---|
| `agency_agents_search` | `router_search` | Search the catalog by id/name/tags/description. Returns matching agent ids. |
| `agency_agents_inspect` | `router_inspect` | Return metadata (name, version, description, tags, required skills) for an agent id. |
| `agency_agents_load` | `router_load` | Load the agent's full body (instructions.md) and return to the LLM context. |
| `agency_agents_delegate` | `router_delegate` | Switch the active agent persona (load instructions into the system prompt) for the current session. |

Names are placeholders; final names TBD in MVP-1 PoC. The semantics
preserve TZ §13 ("load agents on demand, not all at once"): the roster
is read from `router.json` on every tool call; the agent body is
streamed to the LLM only on `router_load` / `router_delegate`.

### Install path

Our app, after rendering and freezing a deployment snapshot, runs:

```
hermes mcp add --name <id> --command <python> --args <router-mcp.py> --env-var CATALOG=<HERMES_HOME>/router/<id>/router.json
```

(or, equivalently, writes the entry directly into Hermes's MCP config
section; both are valid and `hermes mcp add` is the documented path).

The user can verify the install with `hermes mcp list`.

### HERMES_HOME

Multiple Hermes installs on the same host are supported via the
`HERMES_HOME` env var (TZ §12.5). Default is `%LOCALAPPDATA%\hermes\hermes-agent`
on Windows. Our app writes the frozen `router.json` to
`$HERMES_HOME/router/<catalog-id>/router.json` and the MCP server reads
from that absolute path passed via the `CATALOG` env var.

For PoC, we will use a **separate `HERMES_HOME` in a temp directory**
to avoid touching the user's live Hermes. The PoC spawns its own Hermes
process pointing at the temp home, installs the MCP server there, and
exercises the four tools end-to-end.

## Consequences

### Positive

- We use a real, supported integration surface (MCP) that exists in v0.18.2.
- The four tools map cleanly to MCP's `tools/list` and `tools/call`.
- MCP server lifecycle (start, stop, health) is owned by Hermes; our app
  only configures.
- Future Hermes versions (1.x, 2.x) almost certainly keep MCP (it's a
  standard); the abstraction travels.

### Negative

- TZ §12.2 text is now wrong. We must update the TZ to reflect the
  actual v0.18.2 protocol (deferred to a follow-up edit; tracked as a
  side note in this ADR).
- The "lazy-router plugin" framing in TZ §12.2 will need to be reframed
  as "MCP server". Any future contributor reading the TZ in isolation
  will be confused unless we also update it.
- The PoC requires Python (Hermes already requires Python, so this is
  not a new dependency for the host, but our repo gains a Python
  subdirectory).
- The PoC requires a separate `HERMES_HOME` (or a v0.18.2-compatible
  Hermes with a different version, which we are NOT attempting in MVP-1).
  The user must either point at their existing v0.18.2 home (the user has
  consented) or we run in a sandboxed temp home.

### Neutral

- Skills (TZ §7 "tags / full-text search / explicit metadata") and
  capabilities ontology are still valid; v0.18.2's `SKILL.md` format
  maps cleanly to agent `instructions.md` and skill discovery.
- Hermes's own skill-bundling and lazy loading are still the right
  primitive for "load on demand"; we just use MCP tools (not plugin
  tabs) as the surface.

## Alternatives considered

1. **Use a dashboard plugin (`hermes plugins install`) and put the four
   tools behind the plugin's `api: plugin_api.py`.**
   - Rejected. `plugin_api.py` is the backend for the dashboard tab UI;
     it does not register LLM-callable tools. We confirmed this by
     reading `hermes-agent/plugins/hermes-achievements/dashboard/manifest.json`
     and the plugin entry point. To add LLM tools from a plugin we'd
     have to patch Hermes itself, which violates TZ §11 (don't modify
     upstream).

2. **Build a custom Python tool module inside `hermes-agent/tools/`.**
   - Rejected. Modifying `hermes-agent/tools/` is also a Hermes
     modification, breaks the upgrade path, and complicates the
     "declarative install" model.

3. **Wait for the upstream `rubezhanin/agency-agents` to publish a
   router-plugin spec; implement against that.**
   - Rejected. The repo does not exist on GitHub. We have no way to
     predict when (or if) the spec will be published. The TZ does not
     give a target date.

4. **Adopt Hermes's `optional-mcps` model: ship a Python package the
   user installs via `pip install` (or `uv tool install`) and reference
   from `config.yaml`.**
   - Rejected for MVP-1 because it requires user-side pip/uv work
     outside Hermes's own install/upgrade story. The MCP-server path
     keeps the entire install under Hermes's own CLI
     (`hermes mcp add`), which matches TZ §1.1.3 "the platform —
     control plane".

## TZ updates required (out of scope for this ADR; tracked separately)

- §12.2: reframe as "agent router is an MCP server" (not a plugin).
- §12.3: reframe `RuntimeAdapter` to support MCP-server deploy (in
  addition to or instead of plugin deploy).
- §54 item 1 ("plugin manifest format"): replace with "MCP server
  config schema".
- §54 item 2 ("plugin discovery rules"): replace with "MCP discovery
  via `hermes mcp add` and `hermes mcp list`".
- §54 item 3 ("exact Hermes home semantics"): unchanged; `HERMES_HOME`
  env var already works.
- §54 items 4–7 (config format, plugin lifecycle, reload/restart,
  health/doctor): keep `config.yaml` references; the MCP server
  configuration is a sub-section of `config.yaml`.
- §54 items 8–12 (sandbox, safe write root, secret redaction, skill
  guard, version compat): these are Hermes-level properties unchanged by
  this ADR; verify each against v0.18.2 docs in MVP-1 PoC.

## PoC scope for MVP-1 (next milestone)

To validate this ADR end-to-end, MVP-1 must produce:

1. A reference MCP server (`router-mcp.py`, Python) that implements the
   four router tools and reads its roster from a frozen `router.json`.
2. A PoC harness (likely a new binary in `crates/cli` or a new
   crate `crates/hermes-adapter/src/mcp_server/`) that:
   - generates `router.json` from a sample source snapshot (the local
     `C:\projects\agency-agents` catalog is the realistic example);
   - invokes `hermes mcp add` to install the router;
   - exercises the four tools via `hermes mcp test` (or directly via
     `mcp_serve.py` to bypass Hermes's tool gating for the PoC);
   - captures the diff between "fresh install" and "re-install after
     source change" to demonstrate reproducibility (TZ §1.1.5).
3. An updated `HermesAdapter::deploy` (MVP-3) that wraps the above
   PoC harness.

The MVP-1 PoC is a *deferred* work item; per user decision (2026-08-31),
MVP-1 is parked pending a future Hermes release that supports a
cleaner router-plugin protocol. The PoC will be revived when the
deferred trigger fires.

Until then, this ADR is the binding contract: the four TZ §12.2
router tools are MCP tools, the install path is `hermes mcp add`, and
the catalog is a frozen `router.json` written by our app.

## References

- TZ §12.2 — the section this ADR supersedes (needs follow-up edit).
- TZ §12.5 — `HERMES_HOME` semantics, unchanged.
- TZ §32 — PoC requirement that produced this ADR.
- TZ §44 — ADR-0001 requirement satisfied by this document.
- TZ §54 — items to verify in MVP-1 PoC; mostly transferable except
  plugin-related items (see "TZ updates required" above).
- TZ §55 — upstream reference, now known to be unavailable.
- v0.18.2 sources inspected 2026-08-31 on the dev host:
  - `hermes --version` → `Hermes Agent v0.18.2 (2026.7.7.2) · upstream 6abf1956`
  - `hermes plugins list` output (browser-*, achievements, etc.)
  - `hermes mcp --help` output
  - `hermes plugins install --help` output
  - `hermes-agent/plugins/hermes-achievements/dashboard/manifest.json`
  - `hermes-agent/skills/software-development/spike/SKILL.md`
  - `hermes-agent/optional-mcps/{linear,n8n,unreal-engine}/`
  - `C:\Users\Администратор\AppData\Local\hermes\hermes-agent\venv\Scripts\hermes.exe`
- `https://github.com/rubezhanin/agency-agents` → HTTP 404
  (verified 2026-08-31).
- `C:\projects\agency-agents` (local template repo) — confirmed to be
  the fork-template, not the populated upstream.
