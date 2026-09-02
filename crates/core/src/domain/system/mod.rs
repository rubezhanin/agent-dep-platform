//! System: a named bundle of agent (and, in v2, skill) references
//! drawn from a single source snapshot.
//!
//! TZ Enterprise v2 §8. A `System` is what the user actually
//! deploys: it pins a set of agent refs and (optionally) skill
//! refs against a specific snapshot, plus optional per-agent
//! overrides. The MVP-3 on-disk file was `apiVersion:
//! agent-dep/v1`; v2 uses `apiVersion: agency/v1` and adds
//! `spec.runtime.type`, `spec.skills[]`, and `spec.project.root`.
//!
//! Both formats are accepted by `SystemFile::from_yaml_auto`:
//! the choice is driven by `apiVersion` (v1 = `agent-dep/v1`,
//! v2 = `agency/v1`). The resolved `System` domain object is
//! the same in both cases — only the on-disk shape differs.

use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use super::agent::Agent;

/// `apiVersion` of the MVP-3 system file. Kept here so the v1
/// parser can still pin the right value when a legacy
/// `system.yaml` shows up.
pub const SYSTEM_FILE_API_VERSION_V1: &str = "agent-dep/v1";
/// `apiVersion` of the TZ v2 system file. Required for v2.
pub const SYSTEM_FILE_API_VERSION_V2: &str = "agency/v1";
/// `$schema:` URL we expect on v2 manifests. Used by the
/// `SchemaRegistry` to find the schema document.
pub const SYSTEM_FILE_SCHEMA_URL_V2: &str = "https://schemas.agent-dep.platform/system/v1.json";
/// `kind` discriminator on every system manifest.
pub const SYSTEM_FILE_KIND: &str = "System";
/// The only MVP runtime type. Other values are rejected until
/// we add another runtime adapter.
pub const RUNTIME_TYPE_HERMES: &str = "hermes";

// =====================================================================
// Shared domain objects (AgentRef, AgentOverride, ResolvedAgent, System)
// =====================================================================

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

impl<'de> Deserialize<'de> for AgentRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Reference to a specific `(id, version)` of a skill in a
/// snapshot. Same textual form as `AgentRef`; distinct type so
/// the composer and the planner can tell agents and skills
/// apart without an extra flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkillRef {
    pub id: String,
    pub version: super::version::Version,
}

impl SkillRef {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (id, version) = s
            .split_once('@')
            .ok_or_else(|| format!("skill ref must be `<id>@<version>`, got `{s}`"))?;
        let id = id.trim();
        if id.is_empty() {
            return Err(format!("empty skill id in `{s}`"));
        }
        let version = super::version::Version::parse(version.trim())
            .map_err(|e| format!("bad version in `{s}`: {e}"))?;
        Ok(Self {
            id: id.to_string(),
            version,
        })
    }
}

impl std::fmt::Display for SkillRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.id, self.version)
    }
}

impl<'de> Deserialize<'de> for SkillRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Per-agent override applied on top of the snapshot's agent.
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

// =====================================================================
// v1 system file (legacy MVP-3 format)
// =====================================================================

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
pub struct SystemSpecV1 {
    /// Logical source identifier (the user's catalog name or path).
    pub source: String,
    pub agents: Vec<SystemAgentRef>,
}

/// MVP-3 on-disk format. Still supported by `from_yaml_auto` so
/// legacy `system.yaml` files keep working during the v1→v2
/// transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemFile {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: SystemMetadata,
    pub spec: SystemSpecV1,
}

// =====================================================================
// v2 system file (TZ Enterprise v2 §8)
// =====================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemAgentRefV2 {
    #[serde(rename = "ref")]
    pub agent_ref: AgentRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#override: Option<AgentOverride>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemSkillRefV2 {
    #[serde(rename = "ref")]
    pub skill_ref: SkillRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemRuntimeV2 {
    #[serde(rename = "type")]
    pub runtime_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemProjectV2 {
    /// Project root path on the user's machine. Free-form string
    /// (no canonicalization at parse time; the deploy step is
    /// the only place that opens files under it).
    pub root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemMetadataV2 {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemSpecV2 {
    pub runtime: SystemRuntimeV2,
    #[serde(default)]
    pub agents: Vec<SystemAgentRefV2>,
    #[serde(default)]
    pub skills: Vec<SystemSkillRefV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<SystemProjectV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemFileV2 {
    #[serde(rename = "$schema")]
    pub schema_url: String,
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: SystemMetadataV2,
    pub spec: SystemSpecV2,
}

// =====================================================================
// Resolved System (post-composition; format-agnostic)
// =====================================================================

/// A composed system: metadata + spec + the resolved `Agent`s
/// from a snapshot. The composer fills `resolved`; everything
/// else is carried straight from the on-disk file.
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
    /// One entry per `SystemAgentRef`, in spec order.
    pub resolved: Vec<ResolvedAgent>,
    /// Resolved skills (v2 only). Empty for v1 systems.
    pub resolved_skills: Vec<ResolvedSkill>,
}

/// v2-aware `spec` view. The composer always produces this,
/// regardless of the on-disk format, so downstream code (planner,
/// deployer, UI) does not need to handle two shapes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemSpec {
    /// Runtime type. Always `hermes` in MVP.
    pub runtime_type: String,
    /// Logical source identifier. Resolved to a `Source.id` at
    /// compose time.
    pub source: String,
    /// Agent refs in spec order.
    pub agents: Vec<SystemAgentRef>,
    /// Skill refs in spec order (v2 only; empty for v1).
    pub skills: Vec<SkillRef>,
    /// Optional project root, when the system file declared one.
    pub project_root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAgent {
    pub agent: Agent,
    /// The `AgentRef` that was used to look up this agent.
    pub from_ref: AgentRef,
    /// The override that was applied, if any.
    pub applied_override: Option<AgentOverride>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSkill {
    pub skill: super::skill::Skill,
    pub from_ref: SkillRef,
}

// =====================================================================
// Format detection + auto-load
// =====================================================================

/// Marker of which on-disk format produced a `System`. Stored
/// alongside the `System` so audit / deployment-snapshot rows
/// can show which dialect they came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemFileFormat {
    V1,
    V2,
}

/// Parsed-once representation of a system file. Either the v1
/// `SystemFile` or the v2 `SystemFileV2`. The composer (in
/// `application::compose`) consumes this and produces a
/// canonical `System` for the planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedSystemFile {
    V1(SystemFile),
    V2(SystemFileV2),
}

impl ParsedSystemFile {
    pub fn format(&self) -> SystemFileFormat {
        match self {
            ParsedSystemFile::V1(_) => SystemFileFormat::V1,
            ParsedSystemFile::V2(_) => SystemFileFormat::V2,
        }
    }
}

impl SystemFile {
    /// Parse a v1 system file. Validates the structural contract
    /// (apiVersion, kind, non-empty id, ≥1 agent).
    pub fn from_yaml_v1(text: &str) -> Result<Self, String> {
        let f: SystemFile = serde_yaml::from_str(text).map_err(|e| format!("yaml parse: {e}"))?;
        if f.api_version != SYSTEM_FILE_API_VERSION_V1 {
            return Err(format!(
                "unsupported apiVersion: got `{}`, expected `{}`",
                f.api_version, SYSTEM_FILE_API_VERSION_V1
            ));
        }
        if f.kind != SYSTEM_FILE_KIND {
            return Err(format!(
                "unsupported kind: got `{}`, expected `{}`",
                f.kind, SYSTEM_FILE_KIND
            ));
        }
        if f.metadata.id.is_empty() || f.metadata.name.is_empty() {
            return Err("metadata.id and metadata.name must be non-empty".to_string());
        }
        if f.spec.agents.is_empty() {
            return Err("spec.agents must contain at least one entry (v1)".to_string());
        }
        Ok(f)
    }
}

impl SystemFileV2 {
    /// Parse a v2 system file. Validates the structural contract
    /// ($schema, apiVersion, kind, runtime.type, non-empty id).
    pub fn from_yaml(text: &str) -> Result<Self, String> {
        let f: SystemFileV2 = serde_yaml::from_str(text).map_err(|e| format!("yaml parse: {e}"))?;
        if f.schema_url != SYSTEM_FILE_SCHEMA_URL_V2 {
            return Err(format!(
                "unsupported $schema: got `{}`, expected `{}`",
                f.schema_url, SYSTEM_FILE_SCHEMA_URL_V2
            ));
        }
        if f.api_version != SYSTEM_FILE_API_VERSION_V2 {
            return Err(format!(
                "unsupported apiVersion: got `{}`, expected `{}`",
                f.api_version, SYSTEM_FILE_API_VERSION_V2
            ));
        }
        if f.kind != SYSTEM_FILE_KIND {
            return Err(format!(
                "unsupported kind: got `{}`, expected `{}`",
                f.kind, SYSTEM_FILE_KIND
            ));
        }
        if f.metadata.id.is_empty() || f.metadata.name.is_empty() {
            return Err("metadata.id and metadata.name must be non-empty".to_string());
        }
        if let Some(v) = &f.metadata.version {
            super::version::Version::parse(v)
                .map_err(|_| "metadata.version is not a valid SemVer".to_string())?;
        }
        if f.spec.runtime.runtime_type != RUNTIME_TYPE_HERMES {
            return Err(format!(
                "unsupported spec.runtime.type: got `{}`, expected `{}`",
                f.spec.runtime.runtime_type, RUNTIME_TYPE_HERMES
            ));
        }
        if f.spec.agents.is_empty() && f.spec.skills.is_empty() {
            return Err("spec must include at least one agent or one skill".to_string());
        }
        Ok(f)
    }
}

/// Auto-detect the on-disk format from `apiVersion` and dispatch
/// to the right parser. Both v1 (`agent-dep/v1`) and v2
/// (`agency/v1`) are accepted. This is the only entry point
/// the CLI / Tauri / TUI use.
pub fn parse_system_file(text: &str) -> Result<ParsedSystemFile, String> {
    // Cheap textual probe to avoid parsing the whole document
    // twice. `apiVersion:` is a top-level scalar so a regex-less
    // line search is enough.
    let api_version = text
        .lines()
        .find_map(|l| {
            let l = l.trim();
            l.strip_prefix("apiVersion:").map(|v| v.trim().to_string())
        })
        .ok_or_else(|| "system file is missing top-level `apiVersion:` field".to_string())?;
    match api_version.as_str() {
        SYSTEM_FILE_API_VERSION_V1 => {
            let f = SystemFile::from_yaml_v1(text)?;
            Ok(ParsedSystemFile::V1(f))
        }
        SYSTEM_FILE_API_VERSION_V2 => {
            let f = SystemFileV2::from_yaml(text)?;
            Ok(ParsedSystemFile::V2(f))
        }
        other => Err(format!(
            "unsupported system file apiVersion: `{other}` (expected `{}` or `{}`)",
            SYSTEM_FILE_API_VERSION_V1, SYSTEM_FILE_API_VERSION_V2
        )),
    }
}

#[cfg(test)]
#[path = "system_tests.rs"]
mod tests;
