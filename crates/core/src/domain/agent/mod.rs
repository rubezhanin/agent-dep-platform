//! Agent: a persona in a catalog. Mirrors the upstream
//! `agency-agents/agents/<division>/<slug>.md` YAML-frontmatter + body
//! format.
//!
//! Diverges from TZ §6 (which describes an `apiVersion/kind/metadata/spec`
//! shape) — see ADR-0008 backlog. The actual upstream is just YAML
//! frontmatter (id, name, division, role, description, ...) followed
//! by a Markdown body.

use super::version::Version;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Raw upstream `agents/<division>/<slug>.md` frontmatter. Parsed
/// straight from the file before any normalization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamAgentFrontmatter {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub division: String,
    pub role: String,
    pub description: String,
    #[serde(default)]
    pub activation_phrases: Vec<String>,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub sensitive: bool,
    pub version: Version,
}

/// One parsed agent as our domain sees it. The body is stored as a
/// string (Markdown); the `body_hash` references its CAS entry.
#[derive(Debug, Clone)]
pub struct Agent {
    pub snapshot_id: Uuid,
    pub id: String,
    pub division: String,
    pub name: String,
    pub display_name: Option<String>,
    pub role: String,
    pub description: String,
    pub version: Version,
    pub sensitive: bool,
    pub tools: Vec<String>,
    pub activation_phrases: Vec<String>,
    pub body: String,
    /// sha256 of the body. The body is stored in the CAS at this hash
    /// (see `infrastructure::content_store`). For MVP we keep `body` in
    /// memory at ingest time and rely on the snapshot identity to
    /// deduplicate on re-ingest.
    pub body_hash: String,
}

impl Agent {
    /// The `system.yaml` can reference an agent as `<id>@<version>`;
    /// the body of this references is `<id>`. `version` is a separate
    /// field for lock-file resolution (see ADR-0003).
    pub fn reference_id(&self) -> &str {
        &self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_frontmatter() {
        let yaml = r#"
id: backend-engineer
name: Backend Engineer
division: engineering
role: builds APIs
description: backend person
version: 1.0.0
"#;
        let parsed: UpstreamAgentFrontmatter = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(parsed.id, "backend-engineer");
        assert_eq!(parsed.division, "engineering");
        assert_eq!(parsed.version, Version::new(1, 0, 0));
        assert!(parsed.tools.is_empty());
        assert!(!parsed.sensitive);
    }

    #[test]
    fn parse_full_frontmatter() {
        let yaml = r#"
id: backend-engineer
name: Backend Engineer
display_name: Backend Engineer
division: engineering
role: builds APIs
description: backend
activation_phrases:
  - design an API
tools: [claude-code, hermes]
sensitive: true
version: 2.1.0
"#;
        let parsed: UpstreamAgentFrontmatter = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(parsed.activation_phrases.len(), 1);
        assert_eq!(parsed.tools, vec!["claude-code", "hermes"]);
        assert!(parsed.sensitive);
    }

    #[test]
    fn reject_missing_required_field() {
        let yaml = r#"
id: backend-engineer
name: Backend Engineer
# division missing
role: builds APIs
description: backend
version: 1.0.0
"#;
        let parsed: Result<UpstreamAgentFrontmatter, _> = serde_yaml::from_str(yaml);
        assert!(parsed.is_err());
    }
}
