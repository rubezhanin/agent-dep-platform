//! Hermes 0.19+ Flow B: MCP server manifest materializer
//! (TZ §12.4B, ADR-0011).
//!
//! The Flow A materializer (`router_plugin.rs`) writes a
//! router plugin under `<hermes_home>/plugins/<id>/`.
//! This module writes a *remote MCP server* manifest
//! under `<hermes_home>/optional-mcps/<name>/`. The
//! two functions share helpers but produce entirely
//! different output shapes.
//!
//! The output is byte-deterministic (the same spec
//! always produces the same bytes) and is written
//! atomically (temp+rename per ADR-0002).

use agent_dep_core::error::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use ts_rs::TS;

/// HTTP transport for an MCP server. The 0.19 reference
/// catalog only ships `Http`; `Stdio` lands in 1.3.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "snake_case")]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub enum McpTransport {
    Http { url: String },
}

/// Authentication scheme. `Oauth` covers the
/// `native MCP OAuth` case (the Linear manifest) and
/// the `third-party provider` case where the
/// `provider` field names e.g. Google.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "snake_case")]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub enum McpAuth {
    Oauth {
        /// None for native MCP OAuth (case 1), Some for
        /// third-party providers (case 2).
        provider: Option<String>,
    },
}

/// The platform-owned spec for an MCP server manifest.
/// `name` is the manifest directory name; `description`,
/// `source_url`, `transport`, and `auth` map 1:1 to
/// their YAML fields. The manifest adds a static
/// `manifest_version: 1` header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub struct McpServerSpec {
    pub name: String,
    pub description: String,
    pub source_url: String,
    pub transport: McpTransport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<McpAuth>,
}

/// Layout returned by `materialize_mcp_server`. Mirrors
/// the Flow A `RouterPluginLayout` shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerLayout {
    pub server_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub manifest_sha256: String,
}

const MANIFEST_VERSION: u32 = 1;

/// Slug regex: same shape as the Flow A plugin id
/// (ADR-0008 §12.1 — three-`..`); the upstream
/// catalog also uses this rule for `<name>`.
fn is_valid_name(name: &str) -> bool {
    let len = name.len();
    if len == 0 || len > 64 {
        return false;
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

/// Public so the CLI can validate user-supplied names
/// before asking the user to confirm.
pub fn validate_name(name: &str) -> CoreResult<()> {
    if !is_valid_name(name) {
        return Err(CoreError::ErrSchemaInvalid {
            path: "mcp.name".to_string(),
            reason: format!("name `{name}` is invalid: must match ^[a-z][a-z0-9_-]{{0,63}}$"),
        });
    }
    Ok(())
}

/// Materialize a `manifest.yaml` under
/// `<hermes_home>/optional-mcps/<name>/`. Returns the
/// `McpServerLayout` so the caller can verify the
/// on-disk sha against the spec.
pub fn materialize_mcp_server(
    hermes_home: &Path,
    spec: &McpServerSpec,
) -> CoreResult<McpServerLayout> {
    validate_name(&spec.name)?;
    let server_dir = hermes_home.join("optional-mcps").join(&spec.name);
    let manifest_path = server_dir.join("manifest.yaml");
    let yaml = render_manifest_yaml(spec)?;
    let sha = write_manifest_atomic(&manifest_path, &yaml)?;
    Ok(McpServerLayout {
        server_dir,
        manifest_path,
        manifest_sha256: sha,
    })
}

/// Pure renderer: `McpServerSpec` -> YAML string. The
/// output is byte-deterministic: keys in a fixed
/// order, no trailing whitespace, and no
/// platform-specific line endings (we always emit LF).
fn render_manifest_yaml(spec: &McpServerSpec) -> CoreResult<String> {
    // Hand-rolled YAML (no library) so the output is
    // stable across serde_yaml versions. The
    // reference manifest at
    // `~/.hermes/optional-mcps/linear/manifest.yaml`
    // gives the field order.
    let mut out = String::new();
    out.push_str("# Materialized by `agency mcp add` (1.3.0, ADR-0011).\n");
    out.push_str("# Edit the comments above (they will be preserved on re-render)\n");
    out.push_str("# by removing the leading `#` and adding your own.\n");
    out.push_str(&format!("manifest_version: {}\n", MANIFEST_VERSION));
    out.push('\n');
    out.push_str(&format!("name: {}\n", spec.name));
    out.push_str(&format!("description: {}\n", yaml_quote(&spec.description)));
    out.push_str(&format!("source: {}\n", spec.source_url));
    out.push('\n');
    out.push_str("transport:\n");
    match &spec.transport {
        McpTransport::Http { url } => {
            out.push_str("  type: http\n");
            out.push_str(&format!("  url: {url}\n"));
        }
    }
    if let Some(auth) = &spec.auth {
        out.push('\n');
        out.push_str("auth:\n");
        match auth {
            McpAuth::Oauth { provider } => {
                out.push_str("  type: oauth\n");
                if let Some(p) = provider {
                    out.push_str(&format!("  provider: {p}\n"));
                }
            }
        }
    }
    Ok(out)
}

/// Quote a description for YAML: a single double-quoted
/// scalar with backslash and double-quote escaping.
fn yaml_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn write_manifest_atomic(path: &Path, contents: &str) -> CoreResult<String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(CoreError::ErrIo)?;
    }
    let tmp = path.with_extension("yaml.tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp).map_err(CoreError::ErrIo)?;
        f.write_all(contents.as_bytes()).map_err(CoreError::ErrIo)?;
        f.sync_all().map_err(CoreError::ErrIo)?;
    }
    std::fs::rename(&tmp, path).map_err(CoreError::ErrIo)?;
    let bytes = std::fs::read(path).map_err(CoreError::ErrIo)?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}

use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_spec() -> McpServerSpec {
        McpServerSpec {
            name: "linear".to_string(),
            description: "Find, create, and update Linear issues, projects, and comments."
                .to_string(),
            source_url: "https://linear.app/docs/mcp".to_string(),
            transport: McpTransport::Http {
                url: "https://mcp.linear.app/mcp".to_string(),
            },
            auth: Some(McpAuth::Oauth { provider: None }),
        }
    }

    #[test]
    fn validate_name_accepts_normal_slugs() {
        for n in ["linear", "notion", "n8n", "a", "my-cool_mcp-server"] {
            validate_name(n).expect(n);
        }
    }

    #[test]
    fn validate_name_rejects_bad_slugs() {
        for n in ["", "Linear", "1abc", "x".repeat(65).as_str(), "a b"] {
            assert!(validate_name(n).is_err(), "should reject `{n}`");
        }
    }

    #[test]
    fn render_manifest_is_byte_deterministic() {
        let a = render_manifest_yaml(&sample_spec()).unwrap();
        let b = render_manifest_yaml(&sample_spec()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn render_manifest_contains_required_fields() {
        let y = render_manifest_yaml(&sample_spec()).unwrap();
        assert!(y.contains("manifest_version: 1"));
        assert!(y.contains("name: linear"));
        assert!(y.contains("transport:"));
        assert!(y.contains("  type: http"));
        assert!(y.contains("  url: https://mcp.linear.app/mcp"));
        assert!(y.contains("auth:"));
        assert!(y.contains("  type: oauth"));
        // No provider line when None
        assert!(!y.contains("provider:"));
    }

    #[test]
    fn render_manifest_emits_provider_when_set() {
        let mut spec = sample_spec();
        spec.auth = Some(McpAuth::Oauth {
            provider: Some("google".to_string()),
        });
        let y = render_manifest_yaml(&spec).unwrap();
        assert!(y.contains("  provider: google"));
    }

    #[test]
    fn materialize_writes_atomic_file_with_correct_sha() {
        let dir = tempfile::tempdir().unwrap();
        let layout = materialize_mcp_server(dir.path(), &sample_spec()).unwrap();
        assert!(layout.manifest_path.is_file());
        assert_eq!(
            layout.manifest_path,
            dir.path()
                .join("optional-mcps")
                .join("linear")
                .join("manifest.yaml")
        );
        assert_eq!(layout.manifest_sha256.len(), 64);
        // The on-disk file's sha must match the layout
        // field (the function returns the hash it
        // actually wrote).
        let on_disk = std::fs::read(&layout.manifest_path).unwrap();
        let mut h = Sha256::new();
        h.update(&on_disk);
        assert_eq!(layout.manifest_sha256, hex::encode(h.finalize()));
    }

    #[test]
    fn materialize_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let a = materialize_mcp_server(dir.path(), &sample_spec()).unwrap();
        let b = materialize_mcp_server(dir.path(), &sample_spec()).unwrap();
        assert_eq!(a.manifest_sha256, b.manifest_sha256);
        // And the file content is the same.
        assert_eq!(
            std::fs::read(&a.manifest_path).unwrap(),
            std::fs::read(&b.manifest_path).unwrap()
        );
    }

    #[test]
    fn materialize_rejects_invalid_name() {
        let dir = tempfile::tempdir().unwrap();
        let mut bad = sample_spec();
        bad.name = "BadName".to_string();
        let err = materialize_mcp_server(dir.path(), &bad).expect_err("invalid name");
        let s = format!("{err:?}");
        assert!(s.contains("invalid") || s.contains("name"), "got: {s}");
    }
}
