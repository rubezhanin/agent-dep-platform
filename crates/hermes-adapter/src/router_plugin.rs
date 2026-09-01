//! Materialize an agency-agents router plugin under Hermes home.
//!
//! Per ADR-0008. The render is byte-deterministic for a given
//! `(plugin_id, catalog_commit_sha, sorted_agents_with_bodies)`
//! tuple, so re-deploying the same `System` is a no-op on the
//! filesystem (and the deploy loop can rely on that for
//! idempotency).
//!
//! Output tree:
//!
//! ```text
//! <HERMES_HOME>/plugins/<plugin_id>/
//!   manifest.yaml
//!   SKILL.md                          (the router entry point)
//!   skills/
//!     <agent-slug>.md                 (one per resolved agent)
//! ```
//!
//! All writeable paths go through the safe-path resolver that
//! the rest of the platform uses (TZ §I3). Any path that
//! escapes `<HERMES_HOME>/plugins/<plugin_id>/` is rejected
//! before a single byte is written.

use crate::paths::hermes_plugins_dir;
use agent_dep_core::error::{CoreError, CoreResult};
use agent_dep_core::infrastructure::filesystem::safe_path::resolve_safe_path;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Per-system inputs to the router-plugin render. The caller
/// (the CLI / Tauri command / `RuntimeAdapter::deploy`)
/// builds this from the composed `System` + a fresh
/// `IngestResult.skills`. We don't reach into domain types
/// here so this file stays in `hermes-adapter` and the
/// trait stays in `adapter.rs`.
#[derive(Debug, Clone)]
pub struct RouterPluginInputs {
    pub plugin_id: String,
    pub display_name: String,
    pub description: String,
    pub catalog_source: String,
    pub catalog_commit_sha: String,
    pub agent_files: Vec<AgentFile>,
    pub router_skills: Vec<String>,
}

/// One rendered agent file: the slug (filename under
/// `skills/`) and the body to write.
#[derive(Debug, Clone)]
pub struct AgentFile {
    pub slug: String,
    pub body: String,
}

/// What the materialize call actually wrote, returned for
/// the journal row + reconciliation later.
#[derive(Debug, Clone)]
pub struct RouterPluginLayout {
    pub plugin_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub entry_point_path: PathBuf,
    pub skills_dir: PathBuf,
    pub skill_paths: Vec<PathBuf>,
    pub catalog_commit_sha: String,
    pub manifest_sha256: String,
    pub skills_sha256: String,
}

const PLUGIN_META_SCHEMA_VERSION: u32 = 1;

/// Render the router plugin. `hermes_home` is the absolute
/// path the platform's `HermesAdapter::detect()` returned.
/// All writes go through `resolve_safe_path` so a hostile
/// `plugin_id` cannot escape `<HERMES_HOME>/plugins/`.
pub fn materialize_router_plugin(
    hermes_home: &Path,
    inputs: &RouterPluginInputs,
) -> CoreResult<RouterPluginLayout> {
    if inputs.plugin_id.is_empty() {
        return Err(CoreError::ErrSchemaInvalid {
            path: "plugin_id".to_string(),
            reason: "plugin_id must be a non-empty slug".to_string(),
        });
    }
    if !is_safe_slug(&inputs.plugin_id) {
        return Err(CoreError::ErrSchemaInvalid {
            path: "plugin_id".to_string(),
            reason: format!(
                "plugin_id `{}` must match ^[a-z][a-z0-9_-]{{0,63}}$",
                inputs.plugin_id
            ),
        });
    }
    if inputs.agent_files.is_empty() {
        return Err(CoreError::ErrSchemaInvalid {
            path: "agent_files".to_string(),
            reason: "at least one agent file is required".to_string(),
        });
    }
    for a in &inputs.agent_files {
        if !is_safe_slug(&a.slug) {
            return Err(CoreError::ErrSchemaInvalid {
                path: format!("agent.slug={}", a.slug),
                reason: format!(
                    "agent slug `{}` must match ^[a-z][a-z0-9_-]{{0,63}}$",
                    a.slug
                ),
            });
        }
    }

    let plugins_root = hermes_plugins_dir(hermes_home)?;
    // Create the plugins dir up front so `resolve_safe_path` finds
    // an existing root to canonicalize against. Otherwise the
    // "non-existent path" branch has to pop all the way back to
    // HERMES_HOME and re-walk, which is a footgun on Windows
    // where the home itself is often a tempdir with a short-name
    // form.
    std::fs::create_dir_all(&plugins_root).map_err(CoreError::ErrIo)?;
    let plugin_dir = resolve_safe_path(&plugins_root, Path::new(&inputs.plugin_id))?;
    let skills_dir = resolve_safe_path(&plugin_dir, Path::new("skills"))?;
    let manifest_path = resolve_safe_path(&plugin_dir, Path::new("manifest.yaml"))?;
    let entry_point_path = resolve_safe_path(&plugin_dir, Path::new("SKILL.md"))?;

    std::fs::create_dir_all(&skills_dir).map_err(CoreError::ErrIo)?;

    // ---- manifest.yaml ----
    let manifest_yaml = build_manifest_yaml(inputs);
    atomic_write(&manifest_path, manifest_yaml.as_bytes())?;
    let manifest_sha = sha256_hex(manifest_yaml.as_bytes());

    // ---- SKILL.md (the router entry point) ----
    let entry = build_entry_point_md(inputs);
    atomic_write(&entry_point_path, entry.as_bytes())?;

    // ---- skills/<slug>.md ----
    let mut skill_paths: Vec<PathBuf> = Vec::with_capacity(inputs.agent_files.len());
    let mut hasher = Sha256::new();
    // Deterministic order: sort by slug.
    let mut sorted = inputs.agent_files.clone();
    sorted.sort_by(|a, b| a.slug.cmp(&b.slug));
    for agent in &sorted {
        let path = resolve_safe_path(&skills_dir, Path::new(&format!("{}.md", agent.slug)))?;
        atomic_write(&path, agent.body.as_bytes())?;
        hasher.update(agent.slug.as_bytes());
        hasher.update(b"\n");
        hasher.update(agent.body.as_bytes());
        hasher.update(b"\n");
        skill_paths.push(path);
    }
    let skills_sha = hex::encode(hasher.finalize());

    Ok(RouterPluginLayout {
        plugin_dir,
        manifest_path,
        entry_point_path,
        skills_dir,
        skill_paths,
        catalog_commit_sha: inputs.catalog_commit_sha.clone(),
        manifest_sha256: manifest_sha,
        skills_sha256: skills_sha,
    })
}

// ---------------------------------------------------------------------
// YAML / Markdown builders (pure, no I/O)
// ---------------------------------------------------------------------

fn build_manifest_yaml(inputs: &RouterPluginInputs) -> String {
    // Hand-rolled YAML keeps the render byte-deterministic
    // without pulling a YAML writer that may reorder keys
    // or alter quoting between versions. The shape mirrors
    // `templates/hermes-kit-manifest.json` in
    // `C:\projects\agency-agents`.
    let mut out = String::new();
    out.push_str("manifest_version: 1\n\n");
    out.push_str(&format!("id: {}\n", yaml_scalar(&inputs.plugin_id)));
    out.push_str(&format!("display_name: {}\n", yaml_scalar(&inputs.display_name)));
    out.push_str(&format!("description: {}\n\n", yaml_scalar(&inputs.description)));
    out.push_str("privacy: open\n\n");
    out.push_str("plugin_meta:\n");
    out.push_str(&format!("  schema_version: {PLUGIN_META_SCHEMA_VERSION}\n"));
    out.push_str(&format!("  name: {}\n", yaml_scalar(&inputs.plugin_id)));
    out.push_str(&format!("  version: 0.1.0\n"));
    out.push_str("  author: agent-dep-platform\n");
    out.push_str(&format!(
        "  homepage: {}\n",
        yaml_scalar(&format!("file://{}", inputs.catalog_source))
    ));
    out.push_str("  license: MIT\n");
    out.push_str("  type: router\n");
    out.push_str("  entry: SKILL.md\n");
    out.push_str("  catalog:\n");
    out.push_str(&format!(
        "    source: {}\n",
        yaml_scalar(&inputs.catalog_source)
    ));
    out.push_str(&format!(
        "    ref: {}\n",
        yaml_scalar(&inputs.catalog_commit_sha)
    ));
    out.push_str(&format!(
        "    agents: {}\n\n",
        inputs.agent_files.len()
    ));
    out.push_str("agents:\n");
    let mut sorted = inputs.agent_files.clone();
    sorted.sort_by(|a, b| a.slug.cmp(&b.slug));
    for a in &sorted {
        out.push_str(&format!("  - id: {}\n", yaml_scalar(&a.slug)));
    }
    out.push_str("\nrelationships:\n  edges: []\n\n");
    out.push_str("shared_resources: []\n\n");
    out.push_str("install_modes:\n");
    out.push_str("  routing: kanban\n");
    out.push_str("  auto_install_hermes: false\n");
    out
}

fn build_entry_point_md(inputs: &RouterPluginInputs) -> String {
    // The router entry point is a single Markdown file. It
    // tells Hermes that this plugin exposes the four router
    // tools, and the bodies of those tools are defined here
    // as well. We keep the body tight on purpose: every
    // byte is a "small router" — discovery is just
    // `cat manifest.yaml`; routing is `match tool name ->
    // skill file`.
    let mut out = String::new();
    out.push_str(&format!("# {}\n\n", inputs.display_name));
    out.push_str(&format!("{}\n\n", inputs.description));
    out.push_str("This plugin is a lazy router for the agency-agents catalog. ");
    out.push_str("Agents are not loaded into context until the user invokes a router tool. ");
    out.push_str("The four router tools are listed below verbatim — Hermes discovers them by name.\n\n");
    out.push_str("## Tools\n\n");
    for tool in &inputs.router_skills {
        out.push_str(&format!("- `{}`\n", tool));
    }
    out.push_str("\n## Catalog\n\n");
    out.push_str(&format!(
        "- source: `{}`\n- ref: `{}`\n- agents: {}\n",
        inputs.catalog_source,
        inputs.catalog_commit_sha,
        inputs.agent_files.len()
    ));
    out.push_str("\n## Routing\n\n");
    out.push_str("`agency_agents_search` — list agent slugs + one-line summaries.\n");
    out.push_str("`agency_agents_inspect` — show the frontmatter + the first paragraph of a single agent.\n");
    out.push_str("`agency_agents_load` — read the full body of a single agent into context.\n");
    out.push_str("`agency_agents_delegate` — switch the active persona to the named agent.\n");
    out
}

/// Quote a YAML scalar if it contains characters that would
/// change its parse. Hermes's MCP catalog convention (see
/// `optional-mcps/linear/manifest.yaml`) is bare scalars
/// everywhere; we follow that and only quote when forced.
fn yaml_scalar(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".to_string();
    }
    let needs_quote = s
        .chars()
        .any(|c| matches!(c, ':' | '#' | '"' | '\'' | '\n' | '\t' | '[' | ']' | '{' | '}' | ',' | '!' | '?' | '>' | '|' | '&' | '*' | '%' | '@' | '`'));
    if !needs_quote && !s.starts_with(' ') && !s.ends_with(' ') {
        return s.to_string();
    }
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

// ---------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------

fn is_safe_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        && s.chars().next().map(|c| c.is_ascii_lowercase()).unwrap_or(false)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> CoreResult<()> {
    // File-level atomic temp + rename per ADR-0002. Hermes
    // home may live on Windows where rename is non-atomic
    // across the whole tree, but per-file atomicity is
    // guaranteed.
    let parent = path.parent().ok_or_else(|| CoreError::ErrPathOutsideRoot {
        path: path.display().to_string(),
        root: String::new(),
    })?;
    let tmp = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("write"),
        uuid::Uuid::new_v4()
    ));
    {
        let mut f = std::fs::File::create(&tmp).map_err(CoreError::ErrIo)?;
        use std::io::Write;
        f.write_all(bytes).map_err(CoreError::ErrIo)?;
        f.sync_all().map_err(CoreError::ErrIo)?;
    }
    std::fs::rename(&tmp, path).map_err(CoreError::ErrIo)?;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[cfg(test)]
#[path = "router_plugin_tests.rs"]
mod tests;
