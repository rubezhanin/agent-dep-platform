//! Composition service (TZ v2 §14, §15).
//!
//! Takes a parsed `SystemFile` (either v1 `agent-dep/v1` or v2
//! `agency/v1`) plus a snapshot's agents and (for v2) skills,
//! validates that every ref resolves to a real `(id, version)`
//! in the snapshot, applies any per-agent override, and produces
//! a canonical `System` with resolved agents and skills ready
//! for planning.
//!
//! MVP-3 only supports the `Local` source kind. Git is 1.x.

use crate::domain::agent::Agent;
use crate::domain::skill::Skill;
use crate::domain::system::{
    AgentOverride, ParsedSystemFile, ResolvedAgent, ResolvedSkill, SkillRef,
    System, SystemAgentRef, SystemMetadata, SystemSpec,
    RUNTIME_TYPE_HERMES, SYSTEM_FILE_API_VERSION_V1,
};
use crate::error::{CoreError, CoreResult};
use uuid::Uuid;

pub struct CompositionService;

impl CompositionService {
    pub fn new() -> Self {
        Self
    }

    /// Compose a `System` from a parsed system file and the
    /// agents/skills of a single snapshot. `source_id` and
    /// `snapshot_id` are recorded on the result so downstream
    /// steps (planner, deployer) can trace provenance.
    pub fn compose(
        &self,
        source_id: Uuid,
        snapshot_id: Uuid,
        agents: &[Agent],
        skills: &[Skill],
        file: &ParsedSystemFile,
    ) -> CoreResult<System> {
        match file {
            ParsedSystemFile::V1(f) => {
                self.compose_v1(source_id, snapshot_id, agents, f)
            }
            ParsedSystemFile::V2(f) => {
                self.compose_v2(source_id, snapshot_id, agents, skills, f)
            }
        }
    }

    fn compose_v1(
        &self,
        source_id: Uuid,
        snapshot_id: Uuid,
        agents: &[Agent],
        f: &crate::domain::system::SystemFile,
    ) -> CoreResult<System> {
        // Redundant with `SystemFile::from_yaml_v1` but kept as a
        // defense-in-depth check in case the caller skips the
        // parser.
        if f.api_version != SYSTEM_FILE_API_VERSION_V1 {
            return Err(CoreError::ErrSchemaInvalid {
                path: "apiVersion".to_string(),
                reason: format!(
                    "unsupported apiVersion `{}` (only `{}` is recognized)",
                    f.api_version, SYSTEM_FILE_API_VERSION_V1
                ),
            });
        }
        if f.metadata.id.trim().is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "metadata.id".to_string(),
                reason: "metadata.id must not be empty".to_string(),
            });
        }
        if f.spec.agents.is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "spec.agents".to_string(),
                reason: "spec.agents must contain at least one ref".to_string(),
            });
        }

        let mut resolved: Vec<ResolvedAgent> = Vec::with_capacity(f.spec.agents.len());
        let mut seen_ids: Vec<&str> = Vec::with_capacity(f.spec.agents.len());

        for entry in &f.spec.agents {
            if seen_ids.contains(&entry.agent_ref.id.as_str()) {
                return Err(CoreError::ErrSchemaInvalid {
                    path: "spec.agents[].ref".to_string(),
                    reason: format!(
                        "duplicate agent ref `{}` (each agent may appear at most once)",
                        entry.agent_ref.id
                    ),
                });
            }
            seen_ids.push(entry.agent_ref.id.as_str());

            let candidate = agents
                .iter()
                .find(|a| a.id == entry.agent_ref.id && a.version == entry.agent_ref.version);
            let Some(agent) = candidate else {
                let known: Vec<String> = agents
                    .iter()
                    .filter(|a| a.id == entry.agent_ref.id)
                    .map(|a| a.version.to_string())
                    .collect();
                let requested =
                    format!("agent:{}@{}", entry.agent_ref.id, entry.agent_ref.version);
                let dependency = if known.is_empty() {
                    requested
                } else {
                    format!("{requested} (known versions: {})", known.join(", "))
                };
                return Err(CoreError::ErrDependencyMissing {
                    dependency,
                    required_by: format!("system:{}", f.metadata.id),
                });
            };

            let applied = apply_override(agent, entry.r#override.as_ref());
            resolved.push(ResolvedAgent {
                agent: applied,
                from_ref: entry.agent_ref.clone(),
                applied_override: entry.r#override.clone(),
            });
        }

        Ok(System {
            metadata: f.metadata.clone(),
            spec: SystemSpec {
                runtime_type: RUNTIME_TYPE_HERMES.to_string(),
                source: f.spec.source.clone(),
                agents: f.spec.agents.clone(),
                skills: Vec::new(),
                project_root: None,
            },
            source_id,
            snapshot_id,
            resolved,
            resolved_skills: Vec::new(),
        })
    }

    fn compose_v2(
        &self,
        source_id: Uuid,
        snapshot_id: Uuid,
        agents: &[Agent],
        skills: &[Skill],
        f: &crate::domain::system::SystemFileV2,
    ) -> CoreResult<System> {
        // Structural checks are already enforced by
        // `SystemFileV2::from_yaml`; we re-validate non-empty id
        // and at-least-one-ref-or-skill here for defense in depth.
        if f.metadata.id.trim().is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "metadata.id".to_string(),
                reason: "metadata.id must not be empty".to_string(),
            });
        }
        if f.spec.agents.is_empty() && f.spec.skills.is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "spec".to_string(),
                reason: "spec must include at least one agent or one skill"
                    .to_string(),
            });
        }
        if f.spec.runtime.runtime_type != RUNTIME_TYPE_HERMES {
            return Err(CoreError::ErrSchemaInvalid {
                path: "spec.runtime.type".to_string(),
                reason: format!(
                    "unsupported runtime.type `{}` (only `{}` is recognized in MVP)",
                    f.spec.runtime.runtime_type, RUNTIME_TYPE_HERMES
                ),
            });
        }

        // Resolve agents.
        let mut resolved: Vec<ResolvedAgent> = Vec::with_capacity(f.spec.agents.len());
        let mut seen_agent_ids: Vec<&str> = Vec::with_capacity(f.spec.agents.len());
        for entry in &f.spec.agents {
            if seen_agent_ids.contains(&entry.agent_ref.id.as_str()) {
                return Err(CoreError::ErrSchemaInvalid {
                    path: "spec.agents[].ref".to_string(),
                    reason: format!(
                        "duplicate agent ref `{}` (each agent may appear at most once)",
                        entry.agent_ref.id
                    ),
                });
            }
            seen_agent_ids.push(entry.agent_ref.id.as_str());

            let candidate = agents.iter().find(|a| {
                a.id == entry.agent_ref.id && a.version == entry.agent_ref.version
            });
            let Some(agent) = candidate else {
                let known: Vec<String> = agents
                    .iter()
                    .filter(|a| a.id == entry.agent_ref.id)
                    .map(|a| a.version.to_string())
                    .collect();
                let requested =
                    format!("agent:{}@{}", entry.agent_ref.id, entry.agent_ref.version);
                let dependency = if known.is_empty() {
                    requested
                } else {
                    format!("{requested} (known versions: {})", known.join(", "))
                };
                return Err(CoreError::ErrDependencyMissing {
                    dependency,
                    required_by: format!("system:{}", f.metadata.id),
                });
            };

            let applied = apply_override(agent, entry.r#override.as_ref());
            resolved.push(ResolvedAgent {
                agent: applied,
                from_ref: entry.agent_ref.clone(),
                applied_override: entry.r#override.clone(),
            });
        }

        // Resolve skills. v2 systems may declare skills without
        // declaring agents; skill-only systems are valid in MVP.
        let mut resolved_skills: Vec<ResolvedSkill> =
            Vec::with_capacity(f.spec.skills.len());
        let mut seen_skill_ids: Vec<&str> = Vec::with_capacity(f.spec.skills.len());
        for skill_ref in &f.spec.skills {
            if seen_skill_ids.contains(&skill_ref.skill_ref.id.as_str()) {
                return Err(CoreError::ErrSchemaInvalid {
                    path: "spec.skills[].ref".to_string(),
                    reason: format!(
                        "duplicate skill ref `{}`",
                        skill_ref.skill_ref.id
                    ),
                });
            }
            seen_skill_ids.push(skill_ref.skill_ref.id.as_str());

            let candidate = skills.iter().find(|s| {
                s.id == skill_ref.skill_ref.id
                    && s.version == skill_ref.skill_ref.version
            });
            let Some(skill) = candidate else {
                let known: Vec<String> = skills
                    .iter()
                    .filter(|s| s.id == skill_ref.skill_ref.id)
                    .map(|s| s.version.to_string())
                    .collect();
                let requested = format!(
                    "skill:{}@{}",
                    skill_ref.skill_ref.id, skill_ref.skill_ref.version
                );
                let dependency = if known.is_empty() {
                    requested
                } else {
                    format!("{requested} (known versions: {})", known.join(", "))
                };
                return Err(CoreError::ErrDependencyMissing {
                    dependency,
                    required_by: format!("system:{}", f.metadata.id),
                });
            };
            resolved_skills.push(ResolvedSkill {
                skill: skill.clone(),
                from_ref: SkillRef {
                    id: skill_ref.skill_ref.id.clone(),
                    version: skill_ref.skill_ref.version.clone(),
                },
            });
        }

        // Build the canonical metadata block. v2 metadata may
        // carry an extra `version` field that we drop on the
        // floor here; it is preserved in the on-disk `SystemFileV2`
        // and surfaced via audit rows. The canonical `System` is
        // version-agnostic w.r.t. the system itself — its
        // provenance is the snapshot's `commit_sha`.
        let metadata = SystemMetadata {
            id: f.metadata.id.clone(),
            name: f.metadata.name.clone(),
            description: f.metadata.description.clone(),
        };

        // Lift v2 agent refs into the v1-shaped `SystemAgentRef`
        // (same `AgentRef` text, same `AgentOverride` type) so
        // downstream planner/deployer code can keep one shape.
        let agents_v1: Vec<SystemAgentRef> = f
            .spec
            .agents
            .iter()
            .map(|a| SystemAgentRef {
                agent_ref: a.agent_ref.clone(),
                r#override: a.r#override.clone(),
            })
            .collect();
        let skills_v1: Vec<SkillRef> = f
            .spec
            .skills
            .iter()
            .map(|s| s.skill_ref.clone())
            .collect();

        Ok(System {
            metadata,
            spec: SystemSpec {
                runtime_type: f.spec.runtime.runtime_type.clone(),
                // v2 systems do not carry an explicit `source:`
                // string; the CLI resolves the catalog root to a
                // `Source` row and passes the resulting id in.
                // The composer preserves that id here for audit
                // and rollback; downstream code reads it from
                // `source_id` on the `System` itself, not from
                // this string. We store the literal `"v2"` so
                // audit rows can show the format was v2 without
                // having to look at the file.
                source: "v2".to_string(),
                agents: agents_v1,
                skills: skills_v1,
                project_root: f.spec.project.as_ref().map(|p| p.root.clone()),
            },
            source_id,
            snapshot_id,
            resolved,
            resolved_skills,
        })
    }
}

impl Default for CompositionService {
    fn default() -> Self {
        Self::new()
    }
}

fn apply_override(agent: &Agent, ovr: Option<&AgentOverride>) -> Agent {
    let Some(o) = ovr else {
        return agent.clone();
    };
    let mut a = agent.clone();
    if let Some(name) = &o.display_name {
        a.display_name = Some(name.clone());
    }
    if let Some(role) = &o.role {
        a.role = role.clone();
    }
    if let Some(description) = &o.description {
        a.description = description.clone();
    }
    a
}

// Re-export the v2-only types for callers that don't want to
// reach into the deeply-nested `system` module path.
pub use crate::domain::system::SystemRuntimeV2 as RuntimeSpec;

#[cfg(test)]
#[path = "compose_tests.rs"]
mod compose_tests;
