//! System: a named bundle of agent references drawn from a single
//! source snapshot.
//!
//! A `System` is what the user actually deploys: it pins a set of
//! `AgentRef`s (id + version) against a specific snapshot, plus
//! optional per-agent overrides. Systems live next to the catalog
//! in the user's Git repo (TZ §10) as `system.yaml` files.
//!
//! MVP-3 only models the read-side (compose + plan). Mutations and
//! rollback are added in 1.x once a real deployment state table lands.

use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use super::agent::Agent;

/// Reference to a specific `(id, version)` of an agent in a
/// snapshot. The textual form is `<id>@<version>` (e.g.
/// `backend-engineer@1.0.0`).
///
/// `Deserialize` is implemented manually below to accept the
/// `id@version` string form. `Serialize` uses the same form via
/// the derive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentRef {
    pub id: String,
    pub version: super::version::Version,
}

impl AgentRef {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (id, version) = s
            .split_once('@')
            .ok_or_else(|| format!("agent ref must be `<id>@<version>`, got `{s}`"))?;
        let id = id.trim();
        if id.is_empty() {
            return Err(format!("empty agent id in `{s}`"));
        }
        let version = super::version::Version::parse(version.trim())
            .map_err(|e| format!("bad version in `{s}`: {e}"))?;
        Ok(Self {
            id: id.to_string(),
            version,
        })
    }
}

impl std::fmt::Display for AgentRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.id, self.version)
    }
}

/// Accept the textual form `id@version` (e.g. `backend-engineer@1.2.3`)
/// in YAML/JSON. This makes `system.yaml` look like:
/// ```yaml
/// agents:
///   - ref: backend-engineer@1.0.0
/// ```
/// instead of a nested struct.
impl<'de> Deserialize<'de> for AgentRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Per-agent override applied on top of the snapshot's agent. Used
/// to specialize an agent without forking the upstream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AgentOverride {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemAgentRef {
    #[serde(rename = "ref")]
    pub agent_ref: AgentRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#override: Option<AgentOverride>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemMetadata {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemSpec {
    /// Logical source identifier (the user's catalog name or path).
    /// The composer resolves it against a concrete `Source` at run
    /// time.
    pub source: String,
    pub agents: Vec<SystemAgentRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemFile {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: SystemMetadata,
    pub spec: SystemSpec,
}

/// A composed system: metadata + spec + the resolved `Agent`s from
/// a snapshot. The composer fills `resolved`; everything else is
/// carried straight from the `SystemFile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct System {
    pub metadata: SystemMetadata,
    pub spec: SystemSpec,
    /// The `Source.id` that supplied the resolved agents. Set by
    /// the composer; not present in the on-disk file.
    pub source_id: Uuid,
    /// The `SourceSnapshot.id` (commit-pinned) that was used to
    /// resolve. Set by the composer; not present in the on-disk file.
    pub snapshot_id: Uuid,
    /// One entry per `SystemAgentRef`, in spec order. The composer
    /// looks each ref up in the snapshot, applies any override, and
    /// produces a flat `Agent` ready for the planner.
    pub resolved: Vec<ResolvedAgent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAgent {
    pub agent: Agent,
    /// The `AgentRef` that was used to look up this agent. Echoed
    /// back so the planner / deployer can report which ref produced
    /// which on-disk artifact.
    pub from_ref: AgentRef,
    /// The override that was applied, if any. None means "snapshot
    /// values as-is".
    pub applied_override: Option<AgentOverride>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_ref_parse_valid() {
        let r = AgentRef::parse("backend-engineer@1.2.3").unwrap();
        assert_eq!(r.id, "backend-engineer");
        assert_eq!(r.version, super::super::version::Version::new(1, 2, 3));
        // Use the Display impl (not the removed inherent to_string).
        assert_eq!(format!("{r}"), "backend-engineer@1.2.3");
    }

    #[test]
    fn agent_ref_parse_rejects_no_at() {
        assert!(AgentRef::parse("nope").is_err());
    }

    #[test]
    fn agent_ref_parse_rejects_empty_id() {
        assert!(AgentRef::parse("@1.0.0").is_err());
    }

    #[test]
    fn agent_ref_parse_rejects_bad_version() {
        assert!(AgentRef::parse("x@not-a-version").is_err());
    }

    #[test]
    fn system_file_deserialize_minimal() {
        let yaml = r#"
apiVersion: agent-dep/v1
kind: System
metadata:
  id: saas-platform
  name: SaaS Platform
spec:
  source: agency-agents
  agents:
    - ref: backend-engineer@1.0.0
    - ref: frontend-architect@1.0.0
"#;
        let f: SystemFile = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(f.metadata.id, "saas-platform");
        assert_eq!(f.kind, "System");
        assert_eq!(f.spec.agents.len(), 2);
        assert_eq!(f.spec.agents[0].agent_ref.id, "backend-engineer");
    }
}
