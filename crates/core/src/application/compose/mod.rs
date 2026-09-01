//! Composition service (TZ §10).
//!
//! Takes a `SystemFile` (read from `system.yaml`) plus a snapshot's
//! agents, validates that every `AgentRef` resolves to a real
//! `(id, version)` in the snapshot, applies any per-agent override,
//! and produces a `System` with the resolved `Agent`s ready for
//! planning.
//!
//! MVP-3 only supports `Local` source kind. Git is 1.x.

use crate::domain::agent::Agent;
use crate::domain::system::{AgentOverride, ResolvedAgent, System, SystemFile};
use crate::error::{CoreError, CoreResult};
use uuid::Uuid;

pub struct CompositionService;

impl CompositionService {
    pub fn new() -> Self {
        Self
    }

    /// Compose a `System` from a `SystemFile` and the agents of a
    /// single snapshot. `source_id` and `snapshot_id` are recorded
    /// on the result so downstream steps (planner, deployer) can
    /// trace provenance.
    pub fn compose(
        &self,
        source_id: Uuid,
        snapshot_id: Uuid,
        agents: &[Agent],
        file: &SystemFile,
    ) -> CoreResult<System> {
        // Basic shape checks.
        if file.api_version != "agent-dep/v1" {
            return Err(CoreError::ErrSchemaInvalid {
                path: "apiVersion".to_string(),
                reason: format!(
                    "unsupported apiVersion `{}` (only `agent-dep/v1` is recognized)",
                    file.api_version
                ),
            });
        }
        if file.kind != "System" {
            return Err(CoreError::ErrSchemaInvalid {
                path: "kind".to_string(),
                reason: format!("expected kind `System`, got `{}`", file.kind),
            });
        }
        if file.metadata.id.trim().is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "metadata.id".to_string(),
                reason: "metadata.id must not be empty".to_string(),
            });
        }
        if file.spec.agents.is_empty() {
            return Err(CoreError::ErrSchemaInvalid {
                path: "spec.agents".to_string(),
                reason: "spec.agents must contain at least one ref".to_string(),
            });
        }

        let mut resolved: Vec<ResolvedAgent> = Vec::with_capacity(file.spec.agents.len());
        let mut seen_ids: Vec<&str> = Vec::with_capacity(file.spec.agents.len());

        for entry in &file.spec.agents {
            // Reject duplicate refs in the same system.
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

            // Find the agent in the snapshot. Match on id AND version
            // (per ADR-0003: MVP uses exact versions only).
            let candidate = agents
                .iter()
                .find(|a| a.id == entry.agent_ref.id && a.version == entry.agent_ref.version);
            let Some(agent) = candidate else {
                // Build a useful "known versions" list for the error.
                let known: Vec<String> = agents
                    .iter()
                    .filter(|a| a.id == entry.agent_ref.id)
                    .map(|a| a.version.to_string())
                    .collect();
                let requested = format!("agent:{}@{}", entry.agent_ref.id, entry.agent_ref.version);
                let dependency = if known.is_empty() {
                    requested
                } else {
                    format!("{requested} (known versions: {})", known.join(", "))
                };
                return Err(CoreError::ErrDependencyMissing {
                    dependency,
                    required_by: format!("system:{}", file.metadata.id),
                });
            };

            let applied_agent = apply_override(agent, entry.r#override.as_ref());
            resolved.push(ResolvedAgent {
                agent: applied_agent,
                from_ref: entry.agent_ref.clone(),
                applied_override: entry.r#override.clone(),
            });
        }

        Ok(System {
            metadata: file.metadata.clone(),
            spec: file.spec.clone(),
            source_id,
            snapshot_id,
            resolved,
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

#[cfg(test)]
#[path = "compose_tests.rs"]
mod compose_tests;
