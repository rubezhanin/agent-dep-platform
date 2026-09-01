//! Canonical Skill YAML manifest parser (TZ Enterprise v2 §7).
//!
//! A skill lives on disk as:
//!
//! ```text
//! skills/<id>/
//!   skill.yaml
//!   SKILL.md
//! ```
//!
//! `skill.yaml` carries the metadata; `SKILL.md` is the human-
//! readable body that the deploy pipeline renders. This separation
//! follows TZ §5.2 ("metadata / prompt/instructions / runtime-
//! specific artifacts are stored separately").
//!
//! The parser is intentionally strict: a missing or wrong
//! `$schema:` URL, a wrong `apiVersion`, or a wrong `kind` is a
//! hard error. The struct here is the *manifest* view; the
//! resolved `Skill` domain object (with parsed body, computed
//! hashes, etc.) lives in `crate::domain::skill`.

use serde::{Deserialize, Serialize};

use super::skill::SkillPermission;
use super::version::Version;

/// `apiVersion` value required on every v2 skill manifest. Bumping
/// this value is a breaking change.
pub const SKILL_API_VERSION: &str = "agency/v1";

/// `kind` discriminator on every v2 skill manifest.
pub const SKILL_KIND: &str = "Skill";

/// `$schema:` URL we expect for v2 skill manifests. The
/// `SchemaRegistry` resolves the actual document at validation
/// time; the URL is the contract.
pub const SKILL_SCHEMA_URL: &str =
    "https://schemas.agent-dep.platform/skill/v1.json";

/// Canonical YAML shape of a skill manifest. Serialized in
/// `examples/fixtures/v2/` and in tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillYaml {
    #[serde(rename = "$schema")]
    pub schema_url: String,
    pub api_version: String,
    pub kind: String,
    pub metadata: SkillMetadataYaml,
    pub spec: SkillSpecYaml,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillMetadataYaml {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillSpecYaml {
    /// Path to the body file, relative to the manifest's directory.
    /// Always `SKILL.md` in MVP.
    pub body: String,
    #[serde(default)]
    pub dependencies: Vec<SkillDependencyYaml>,
    #[serde(default)]
    pub permissions: Vec<SkillPermissionYaml>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillDependencyYaml {
    pub id: String,
    pub version: String,
}

/// String form of a permission. We accept the snake_case name
/// and convert to the typed `SkillPermission` enum in the
/// composition step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillPermissionYaml {
    ReadEnv,
    SpawnProcess,
    Network,
    Filesystem,
}

impl From<SkillPermissionYaml> for SkillPermission {
    fn from(p: SkillPermissionYaml) -> Self {
        match p {
            SkillPermissionYaml::ReadEnv => SkillPermission::ReadEnv,
            SkillPermissionYaml::SpawnProcess => SkillPermission::SpawnProcess,
            SkillPermissionYaml::Network => SkillPermission::Network,
            SkillPermissionYaml::Filesystem => SkillPermission::Filesystem,
        }
    }
}

/// Parse a v2 skill manifest from a YAML string. Returns a
/// structured error on any structural or contract violation.
pub fn parse_skill_yaml(text: &str) -> Result<SkillYaml, String> {
    let y: SkillYaml =
        serde_yaml::from_str(text).map_err(|e| format!("yaml parse: {e}"))?;
    if y.schema_url != SKILL_SCHEMA_URL {
        return Err(format!(
            "unsupported $schema: got `{}`, expected `{}`",
            y.schema_url, SKILL_SCHEMA_URL
        ));
    }
    if y.api_version != SKILL_API_VERSION {
        return Err(format!(
            "unsupported apiVersion: got `{}`, expected `{}`",
            y.api_version, SKILL_API_VERSION
        ));
    }
    if y.kind != SKILL_KIND {
        return Err(format!(
            "unsupported kind: got `{}`, expected `{}`",
            y.kind, SKILL_KIND
        ));
    }
    if y.metadata.id.is_empty()
        || y.metadata.name.is_empty()
        || y.metadata.description.is_empty()
    {
        return Err("metadata.id, metadata.name, metadata.description must be non-empty".to_string());
    }
    Version::parse(&y.metadata.version)
        .map_err(|_| "metadata.version is not a valid SemVer".to_string())?;
    if y.spec.body.is_empty() {
        return Err("spec.body must be a non-empty path".to_string());
    }
    for dep in &y.spec.dependencies {
        Version::parse(&dep.version).map_err(|_| {
            format!("dependency `{}` version is not a valid SemVer", dep.id)
        })?;
    }
    Ok(y)
}

#[cfg(test)]
#[path = "skill_yaml_tests.rs"]
mod tests;
