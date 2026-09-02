//! `agency mcp ...` — install/remove Flow B MCP server
//! manifests under `<hermes_home>/optional-mcps/<name>/`
//! (1.3.0, ADR-0011).
//!
//! 1.3.0 ships only the `add` subcommand. The spec
//! is a JSON file the operator points at with
//! `--spec <path>`. A future 1.3.x may add a
//! `~/.config/agency/mcp-specs.d/` overlay and
//! a `default` template for `linear` / `notion` /
//! `n8n`; for now the user provides their own spec.

use std::path::{Path, PathBuf};

use agent_dep_hermes_adapter::mcp_server::{materialize_mcp_server, McpServerSpec};
use anyhow::{Context, Result};

/// Summary returned from `add_at` so tests can assert
/// without re-parsing stdout.
#[derive(Debug, Clone)]
pub struct McpAddSummary {
    pub name: String,
    pub server_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub manifest_sha256: String,
}

/// CLI entry point.
pub async fn add(name: String, spec_path: &Path) -> Result<()> {
    let summary = add_at(&name, spec_path)?;
    print_summary(&summary);
    Ok(())
}

/// Pure orchestration: parse the spec file, materialize
/// the manifest under `<hermes_home>/optional-mcps/<name>/`.
/// Returns the layout so tests can verify the on-disk
/// sha against the spec.
pub fn add_at(name: &str, spec_path: &Path) -> Result<McpAddSummary> {
    if !spec_path.is_file() {
        anyhow::bail!("not a file: {}", spec_path.display());
    }
    let text = std::fs::read_to_string(spec_path)
        .with_context(|| format!("read {}", spec_path.display()))?;
    let mut spec: McpServerSpec = serde_json::from_str(&text)
        .with_context(|| format!("parse {} as McpServerSpec JSON", spec_path.display()))?;
    // The CLI subcommand is the source of truth for
    // the directory name; the spec's `name` field is
    // informational. This matches the user mental
    // model: `agency mcp add linear` is what they
    // typed, and the manifest's `name:` field
    // should agree.
    if spec.name != name {
        spec.name = name.to_string();
    }
    let hermes_home = crate::data_dir::default_hermes_home();
    std::fs::create_dir_all(&hermes_home)
        .with_context(|| format!("create_dir_all {}", hermes_home.display()))?;
    let layout = materialize_mcp_server(&hermes_home, &spec)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(McpAddSummary {
        name: layout
            .server_dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(name)
            .to_string(),
        server_dir: layout.server_dir,
        manifest_path: layout.manifest_path,
        manifest_sha256: layout.manifest_sha256,
    })
}

fn print_summary(s: &McpAddSummary) {
    use crate::output;
    let i = agent_dep_core::i18n::I18n::from_env();
    output::header(&i.tr("cli.mcp.add.header", &[("name", &s.name)]));
    output::kv(&i.t("cli.mcp.kv.server_dir"), &s.server_dir.display().to_string());
    output::kv(
        &i.t("cli.mcp.kv.manifest_path"),
        &s.manifest_path.display().to_string(),
    );
    output::kv(
        &i.t("cli.mcp.kv.manifest_sha256"),
        &s.manifest_sha256,
    );
}
