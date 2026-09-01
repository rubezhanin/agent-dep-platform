//! Plan service (TZ §16).
//!
//! MVP-1.0 supports two of the six TZ §16.1 plan
//! operations:
//!
//! * `Add`  — a resolved agent has no on-disk counterpart
//!   in the target tree.
//! * `Noop` — the agent's body hash already matches the
//!   on-disk file, so the deploy loop skips the write.
//!
//! The remaining four (`Update`, `Delete`, `Backup`,
//! `Verify`) are 1.x once we have a `deployed_artifacts`
//! table to read the "current" state from. The plan
//! service here is a pure function: the caller passes
//! in the on-disk sha256s (when known) and gets back a
//! typed `Plan`.
//!
//! `risk` is `low` for a plan that only contains `Add` /
//! `Noop`. A future `High` risk (e.g. deletes against
//! non-empty trees) lands together with `Update` /
//! `Delete`.

use crate::domain::plan::{Plan, PlanOperation, PlanOperationKind, PlanRisk};
use crate::domain::system::System;

pub struct PlanService;

impl PlanService {
    pub fn new() -> Self {
        Self
    }

    /// Compute a deployment plan for a composed `System`.
    ///
    /// `actual_sha256_by_ref` is an optional map from
    /// `agent:id@version` to the sha256 of the file that
    /// already exists at the target. When the map is
    /// provided and the entry matches the desired body
    /// hash, the operation is `Noop`; otherwise it is
    /// `Add`. When the map is `None` (or the entry is
    /// missing), the plan is the old "always add" path.
    ///
    /// The map is keyed by `id@version` so a system that
    /// references the same agent id at two different
    /// versions emits two distinct operations, each
    /// classified against its own current state.
    pub fn plan_for(
        &self,
        system: &System,
        actual_sha256_by_ref: Option<&std::collections::HashMap<String, String>>,
    ) -> Plan {
        let mut operations = Vec::with_capacity(system.resolved.len());
        for r in &system.resolved {
            let agent_ref = format!("{}@{}", r.agent.id, r.agent.version);
            let desired_sha = r.agent.body_hash.clone();

            let kind = match actual_sha256_by_ref
                .and_then(|m| m.get(&agent_ref))
            {
                Some(actual) if actual == &desired_sha => PlanOperationKind::Noop,
                _ => PlanOperationKind::Add,
            };
            let reason = match kind {
                PlanOperationKind::Noop => {
                    format!(
                        "agent `{agent_ref}` already at desired content; nothing to write"
                    )
                }
                _ => format!("agent in system `{}`", system.metadata.id),
            };
            operations.push(PlanOperation {
                kind,
                target: format!("agent:{agent_ref}"),
                reason,
            });
        }
        Plan {
            system_id: system.metadata.id.clone(),
            operations,
            risk: PlanRisk::Low,
        }
    }
}

impl Default for PlanService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod plan_tests;
