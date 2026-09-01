# Examples

This directory contains ready-to-run example inputs for the
`agency` CLI. Each example is a `system.yaml` (a `SystemFile`) that
references agents from a local catalog.

## `saas-stack.yaml`

A two-agent system: `backend-engineer@1.0.0` +
`frontend-architect@1.0.0`. Pairs well with the
[`agency-agents`](https://github.com/rubezhanin/agency-agents)
reference catalog.

### End-to-end demo (against a local `agency-agents` clone)

```powershell
# 1. Clone a reference catalog (or point at any local dir with
#    divisions.json + agents/<division>/*.md).
git clone https://github.com/rubezhanin/agency-agents C:\projects\agency-agents

# 2. Ingest the catalog into the default SQLite DB.
agency catalog update C:\projects\agency-agents

# 3. Preview the plan (no writes).
agency system plan examples\saas-stack.yaml --catalog C:\projects\agency-agents

# 4. Apply the plan to a target directory.
agency deploy apply examples\saas-stack.yaml `
    --catalog C:\projects\agency-agents `
    --target C:\tmp\agency-target
```

After step 4, `C:\tmp\agency-target` will contain:

```
agents/
  backend-engineer@1.0.0/
    backend-engineer.md
  frontend-architect@1.0.0/
    frontend-architect.md
```

Each `.md` is the Markdown **body** (no frontmatter); the YAML
metadata stays in the catalog DB. A second run with the same
`system.yaml` is a no-op (`skipped=2`).

### Editing the deployed copy

If you hand-edit a deployed `.md`, the next `agency deploy apply`
backups the old content to
`<target>/agents/<id>@<version>/.backups/<name>.<unix_ts>.<rand8>`
before overwriting. The backup directory is the only on-disk
recovery path in MVP-3; the journal row is the DB-side recovery
path.
