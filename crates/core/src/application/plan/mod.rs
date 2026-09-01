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
    ///
    /// `previously_deployed_targets` is the set of target
    /// paths that exist in `deployed_artifacts` for this
    /// system but are **not** referenced by the current
    /// `System`. Each one becomes a `Delete` op — the
    /// deploy loop will route it through
    /// `RuntimeAdapter::verify` (or the rollback path)
    /// before the actual removal. Pass `None` to skip
    /// delete detection (the old behavior).
    pub fn plan_for(
        &self,
        system: &System,
        actual_sha256_by_ref: Option<&std::collections::HashMap<String, String>>,
        previously_deployed_targets: Option<&std::collections::HashSet<String>>,
    ) -> Plan {
        let mut operations = Vec::with_capacity(system.resolved.len());
        let mut planned_targets: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for r in &system.resolved {
            let agent_ref = format!("{}@{}", r.agent.id, r.agent.version);
            let target = format!("agents/{}/{}.md", agent_ref, r.agent.id);
            planned_targets.insert(target.clone());

            let desired_sha = r.agent.body_hash.clone();
            let kind = match actual_sha256_by_ref.and_then(|m| m.get(&agent_ref)) {
                Some(actual) if actual == &desired_sha => PlanOperationKind::Noop,
                Some(actual) => {
                    // Hash differs: content drift. The deploy
                    // service backs up the previous bytes and
                    // writes the new ones.
                    PlanOperationKind::Update
                }
                None => PlanOperationKind::Add,
            };
            let reason = match kind {
                PlanOperationKind::Noop => format!(
                    "agent `{agent_ref}` already at desired content; nothing to write"
                ),
                PlanOperationKind::Update => format!(
                    "agent `{agent_ref}` content changed (actual != desired); back up + write"
                ),
                _ => format!("agent in system `{}`", system.metadata.id),
            };
            operations.push(PlanOperation {
                kind,
                target: format!("agent:{agent_ref}"),
                reason,
            });
        }

        // Deletes: anything in `previously_deployed_targets`
        // that the current system no longer references.
        if let Some(prev) = previously_deployed_targets {
            for old in prev {
                if !planned_targets.contains(old) {
                    operations.push(PlanOperation {
                        kind: PlanOperationKind::Delete,
                        target: format!("path:{old}"),
                        reason: format!(
                            "previously deployed at `{old}` but no longer in system `{}`",
                            system.metadata.id
                        ),
                    });
                }
            }
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
