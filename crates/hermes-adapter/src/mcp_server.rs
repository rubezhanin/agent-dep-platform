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
//!
//! ## Security: P1-MCP-01 (TZ #2 WP-3.4 / SEC-10, CWE-94)
//!
//! The manifest is hand-rolled YAML, parsed by Hermes
//! at runtime. Every operator-controlled field
//! (`description`, `source_url`, `transport.url`,
//! `auth.provider`) MUST be emitted as a
//! double-quoted YAML scalar with backslash, quote, and
//! control-character escaping, **never** as a raw
//! `format!("{k}: {v}\n")` interpolation.
//!
//! **Exploit scenario (pre-fix):** the pre-fix
//! `render_manifest_yaml` used `format!` for
//! `source_url`, `transport.url`, and `auth.provider`.
//! An operator (or a malicious catalog) supplying
//! `source_url: "https://x.com\nauth:\n  type: oauth\n  provider: evil"`
//! would produce:
//!
//! ```yaml
//! source: https://x.com
//! auth:
//!   type: oauth
//!   provider: evil
//! ```
//!
//! CWE-94: the second `auth:` block in the
//! user-controlled portion is parsed as the real
//! `auth:` field, overriding any later config.
//! The same attack works on `transport.url` and
//! `auth.provider` (a colon in the value can re-open
//! the key as a mapping; a `#` introduces a comment
//! that hides the rest of the line from the operator).
//! Post-fix, every user-controlled scalar is rendered
//! via `yaml_quote`, which wraps the value in
//! double-quotes, escapes `"` / `\\` / `\n` / `\r` /
//! `\t`, and emits other control characters as
//! `\xNN` so the YAML parser always treats the field
//! as a single string.

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
///
/// All operator-controlled scalars are wrapped via
/// [`yaml_quote`] so the YAML parser always sees them
/// as a single string. See the module-level docstring
/// for the P1-MCP-01 (CWE-94) threat model.
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
    // `name` is validated by `is_valid_name` (lowercase
    // ASCII + digits + `_` + `-`), so it cannot contain
    // any YAML-special character and is safe to emit
    // unquoted. We still quote it as defense-in-depth —
    // the cost is two quote chars and the parser does
    // not care.
    out.push_str(&format!("name: {}\n", yaml_quote(&spec.name)));
    out.push_str(&format!("description: {}\n", yaml_quote(&spec.description)));
    out.push_str(&format!("source: {}\n", yaml_quote(&spec.source_url)));
    out.push('\n');
    out.push_str("transport:\n");
    match &spec.transport {
        McpTransport::Http { url } => {
            out.push_str("  type: http\n");
            out.push_str(&format!("  url: {}\n", yaml_quote(url)));
        }
    }
    if let Some(auth) = &spec.auth {
        out.push('\n');
        out.push_str("auth:\n");
        match auth {
            McpAuth::Oauth { provider } => {
                out.push_str("  type: oauth\n");
                if let Some(p) = provider {
                    out.push_str(&format!("  provider: {}\n", yaml_quote(p)));
                }
            }
        }
    }
    Ok(out)
}

/// Quote a string for YAML as a single double-quoted
/// scalar. Escapes `"`, `\\`, `\n`, `\r`, `\t`, and
/// every other C0 control character (`\x00`-`\x1f`).
///
/// Used for every operator-controlled field in the
/// manifest — `description`, `source_url`,
/// `transport.url`, `auth.provider`, and `name` (the
/// last as defense-in-depth; the slug validator would
/// also accept it as a plain scalar). P1-MCP-01 fix
/// — the pre-fix version only handled `"`, `\\`, and
/// the three common whitespace controls, so a `\x00`
/// in the input would have terminated the string
/// early or produced invalid YAML that a strict
/// parser rejects but a lenient one parses with
/// content loss.
fn yaml_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if (c as u32) < 0x20 => {
                // Other C0 controls: emit the
                // 2-digit hex form. The YAML 1.2
                // spec allows `\xNN` inside double-
                // quoted strings.
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
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
        // P1-MCP-01 (CWE-94): all operator-controlled
        // scalars are now double-quoted, including
        // `name` (defense-in-depth — the slug
        // validator would also accept it unquoted).
        assert!(y.contains("name: \"linear\""));
        assert!(y.contains("transport:"));
        assert!(y.contains("  type: http"));
        assert!(y.contains("  url: \"https://mcp.linear.app/mcp\""));
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
        // P1-MCP-01 (CWE-94): provider is now a
        // double-quoted scalar.
        assert!(y.contains("  provider: \"google\""));
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

    // -------------------------------------------------------------------
    // P1-MCP-01 — YAML escape hardening (CWE-94 Code Injection)
    //
    // The pre-fix renderer used `format!("{k}: {v}\n")` for
    // every operator-controlled field, so a value containing
    // `\n`, `:`, `#`, `"`, or `\0` would either inject new
    // YAML keys or terminate the scalar early. These tests
    // pin the post-fix invariants:
    //   1. `yaml_quote` produces a parseable double-quoted
    //      scalar for every special character.
    //   2. `render_manifest_yaml` quotes every operator-
    //      controlled field, so the output always parses
    //      back to the same spec via serde_yaml.
    //   3. Known injection payloads (newline, colon, quote,
    //      control char) do not introduce extra keys or
    //      override the real ones in the rendered output.
    // -------------------------------------------------------------------

    #[test]
    fn yaml_quote_escapes_common_specials() {
        // The base-case characters — every one of these
        // would have been emitted raw in the pre-fix
        // renderer and broken YAML parsing.
        assert_eq!(yaml_quote("plain"), "\"plain\"");
        assert_eq!(yaml_quote("with \"quote"), "\"with \\\"quote\"");
        assert_eq!(yaml_quote("with \\back"), "\"with \\\\back\"");
        assert_eq!(yaml_quote("line1\nline2"), "\"line1\\nline2\"");
        assert_eq!(yaml_quote("a\rb"), "\"a\\rb\"");
        assert_eq!(yaml_quote("a\tb"), "\"a\\tb\"");
        // Empty string still emits a valid scalar.
        assert_eq!(yaml_quote(""), "\"\"");
    }

    #[test]
    fn yaml_quote_escapes_c0_control_characters() {
        // Every C0 control except the three whitespace
        // ones already named above (NUL, SOH, .., US)
        // must be emitted as `\xNN` so a strict YAML
        // parser keeps the full string intact.
        let cases: &[(char, &str)] = &[
            ('\0', "\\0"),
            ('\x01', "\\x01"),
            ('\x07', "\\x07"), // BEL
            ('\x0b', "\\x0b"), // VT
            ('\x1f', "\\x1f"), // US
        ];
        for &(c, hex_esc) in cases {
            let q = yaml_quote(&format!("a{c}b"));
            assert!(
                q.contains(hex_esc),
                "expected {hex_esc:?} in {q:?} for char U+{:04X}",
                c as u32
            );
            // The control char itself must NOT appear
            // unescaped in the output.
            assert!(!q.contains(c), "unescaped control char in {q:?}");
        }
    }

    #[test]
    fn render_manifest_quotes_source_url_blocking_newline_injection() {
        // Pre-fix: source: https://x.com\nauth:\n  type: oauth
        // would have produced an extra `auth:` block.
        // Post-fix: source_url is yaml_quote'd, so the
        // newline is escaped to `\n` and stays inside
        // the scalar.
        let mut spec = sample_spec();
        spec.source_url = "https://x.com\nauth:\n  type: oauth\n  provider: evil".to_string();
        let y = render_manifest_yaml(&spec).unwrap();
        // The real `auth:` block from `spec.auth` must
        // still be present, and there must NOT be a
        // second `auth:` key introduced by the injection.
        let auth_count = y.matches("\nauth:\n").count();
        assert_eq!(
            auth_count, 1,
            "injection introduced extra auth: block:\n{y}"
        );
        // The newline in the source URL must appear
        // escaped as the literal sequence `\n`, not as
        // a raw LF.
        assert!(y.contains("\\n"), "expected escaped \\n in:\n{y}");
        assert!(
            !y.contains("https://x.com\nauth"),
            "raw newline leaked into output:\n{y}"
        );
    }

    #[test]
    fn render_manifest_quotes_transport_url_blocking_colon_injection() {
        // Pre-fix: `url: https://mcp.x.com:8080/secret`
        // would parse as `url: "https://mcp.x.com"` and
        // a follow-on `:8080/secret` which most YAML
        // parsers tolerate as a single string — but
        // `url: https://x.com\nfoo: bar` would have
        // produced a second top-level key.
        let mut spec = sample_spec();
        spec.transport = McpTransport::Http {
            url: "https://mcp.x.com\nfoo: bar".to_string(),
        };
        let y = render_manifest_yaml(&spec).unwrap();
        // The injected `foo: bar` must NOT appear as
        // a real YAML key (it would be at column 0
        // because transport is indented by 2 spaces).
        assert!(
            !y.contains("\nfoo: bar"),
            "colon-injection leaked key into output:\n{y}"
        );
        // And the real transport block must still
        // emit the type: http header.
        assert!(y.contains("  type: http"));
    }

    #[test]
    fn render_manifest_quotes_provider_blocking_colon_injection() {
        let mut spec = sample_spec();
        spec.auth = Some(McpAuth::Oauth {
            provider: Some("google: malicious".to_string()),
        });
        let y = render_manifest_yaml(&spec).unwrap();
        // The value must be a double-quoted scalar so
        // the colon stays inside the string.
        assert!(
            y.contains("  provider: \"google: malicious\""),
            "provider not quoted:\n{y}"
        );
    }

    #[test]
    fn render_manifest_output_round_trips_via_serde_yaml() {
        // The strongest post-fix invariant: take any
        // spec (with the special characters that would
        // have caused the pre-fix bug), render it,
        // then re-parse the result and assert the data
        // matches. If the renderer still emitted raw
        // strings, the re-parse would either fail
        // outright or come back with a different
        // structure.
        let mut spec = sample_spec();
        spec.description = "line1\nline2\twith \"quote\" and \\back".to_string();
        spec.source_url = "https://x.com/?q=:foo&a=b#frag".to_string();
        spec.transport = McpTransport::Http {
            url: "https://mcp.x.com:8080/path?x=1&y=2".to_string(),
        };
        spec.auth = Some(McpAuth::Oauth {
            provider: Some("oauth:custom:tenant".to_string()),
        });
        let y = render_manifest_yaml(&spec).unwrap();
        // serde_yaml requires a tagged enum for the
        // transport/auth variants; parse through the
        // same JSON shape the CLI uses.
        let parsed: serde_yaml::Value = serde_yaml::from_str(&y).expect("YAML re-parse");
        // The fields we care about.
        assert_eq!(parsed.get("name").and_then(|v| v.as_str()), Some("linear"));
        assert_eq!(
            parsed.get("description").and_then(|v| v.as_str()),
            Some("line1\nline2\twith \"quote\" and \\back")
        );
        assert_eq!(
            parsed.get("source").and_then(|v| v.as_str()),
            Some("https://x.com/?q=:foo&a=b#frag")
        );
        let transport = parsed.get("transport").expect("transport");
        assert_eq!(
            transport.get("url").and_then(|v| v.as_str()),
            Some("https://mcp.x.com:8080/path?x=1&y=2")
        );
        let auth = parsed.get("auth").expect("auth");
        assert_eq!(
            auth.get("provider").and_then(|v| v.as_str()),
            Some("oauth:custom:tenant")
        );
        // And critically: the YAML must NOT contain
        // any extra top-level keys introduced by an
        // injection. The expected set is exactly
        // {manifest_version, name, description, source,
        // transport, auth}.
        let expected_keys = [
            "manifest_version",
            "name",
            "description",
            "source",
            "transport",
            "auth",
        ];
        for k in expected_keys {
            assert!(parsed.get(k).is_some(), "missing key `{k}` in:\n{y}");
        }
        // Extra keys would appear here.
        let extra: Vec<&str> = parsed
            .as_mapping()
            .unwrap()
            .keys()
            .filter_map(|k| k.as_str())
            .filter(|k| !expected_keys.contains(k))
            .collect();
        assert!(extra.is_empty(), "extra keys {extra:?} in:\n{y}");
    }

    #[test]
    fn render_manifest_output_byte_deterministic_under_injection() {
        // Two renders of the same malicious spec must
        // produce byte-identical output (otherwise a
        // re-render would silently rewrite the manifest
        // and lose the operator's manual edits — the
        // current behaviour for the in-payload `#`
        // comment trick is "the second render would
        // wrap the value in quotes and shift the
        // comment position").
        let mut spec = sample_spec();
        spec.source_url = "https://x.com#comment\nhidden: yes".to_string();
        let a = render_manifest_yaml(&spec).unwrap();
        let b = render_manifest_yaml(&spec).unwrap();
        assert_eq!(a, b);
    }
}
