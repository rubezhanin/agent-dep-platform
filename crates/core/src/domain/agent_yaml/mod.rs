//! Canonical Agent YAML manifest parser (TZ Enterprise v2 §6).
//!
//! Placeholder — populated in the next steps of Phase 1.

use serde::{Deserialize, Serialize};

use super::version::Version;

pub const AGENT_API_VERSION: &str = "agency/v1";
pub const AGENT_KIND: &str = "Agent";
pub const AGENT_SCHEMA_URL: &str = "https://schemas.agent-dep.platform/agent/v1.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentYaml {
    #[serde(rename = "$schema")]
    pub schema_url: String,
    pub api_version: String,
    pub kind: String,
    pub metadata: AgentMetadataYaml,
    pub spec: AgentSpecYaml,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentMetadataYaml {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentSpecYaml {
    /// Path to the body file, relative to the manifest's directory.
    /// Always `instructions.md` in MVP.
    pub instructions: String,
    #[serde(default)]
    pub skills: Vec<AgentSkillRefYaml>,
    pub runtime: AgentRuntimeYaml,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentSkillRefYaml {
    /// `skill-id@version` form. We accept the structured form here
    /// and let the composition step split / validate.
    #[serde(rename = "ref")]
    pub reference: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentRuntimeYaml {
    pub hermes: AgentHermesRuntimeYaml,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentHermesRuntimeYaml {
    pub supported: bool,
}

pub fn parse_agent_yaml(text: &str) -> Result<AgentYaml, String> {
    let y: AgentYaml = serde_yaml::from_str(text).map_err(|e| format!("yaml parse: {e}"))?;
    if y.schema_url != AGENT_SCHEMA_URL {
        return Err(format!(
            "unsupported $schema: got `{}`, expected `{}`",
            y.schema_url, AGENT_SCHEMA_URL
        ));
    }
    if y.api_version != AGENT_API_VERSION {
        return Err(format!(
            "unsupported apiVersion: got `{}`, expected `{}`",
            y.api_version, AGENT_API_VERSION
        ));
    }
    if y.kind != AGENT_KIND {
        return Err(format!(
            "unsupported kind: got `{}`, expected `{}`",
            y.kind, AGENT_KIND
        ));
    }
    if y.metadata.id.is_empty() || y.metadata.name.is_empty() || y.metadata.description.is_empty() {
        return Err(
            "metadata.id, metadata.name, metadata.description must be non-empty".to_string(),
        );
    }
    Version::parse(&y.metadata.version)
        .map_err(|_| "metadata.version is not a valid SemVer".to_string())?;
    if y.spec.instructions.is_empty() {
        return Err("spec.instructions must be a non-empty path".to_string());
    }
    for s in &y.spec.skills {
        if !s.reference.contains('@') {
            return Err(format!(
                "spec.skills[].ref must be `id@version`, got `{}`",
                s.reference
            ));
        }
    }
    Ok(y)
}

#[cfg(test)]
#[path = "agent_yaml_tests.rs"]
mod tests;
