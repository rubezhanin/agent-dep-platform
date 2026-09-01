//! Plan service (TZ §16).
//!
//! MVP-3 produces a flat `Add` plan: every resolved agent in the
//! system becomes one `PlanOperation { kind: Add, target: agent:... }`.
//! 1.x adds the diff against a real deployment state (then
//! `Update`, `Delete`, `Noop` come into play).

use crate::domain::plan::{Plan, PlanOperation, PlanOperationKind, PlanRisk};
use crate::domain::system::System;

pub struct PlanService;

impl PlanService {
    pub fn new() -> Self {
        Self
    }

    /// Compute a deployment plan for a composed `System`. For MVP-3
    /// the plan is `Add` per resolved agent; risk is `low`.
    pub fn plan_for(&self, system: &System) -> Plan {
        let mut operations = Vec::with_capacity(system.resolved.len());
        for r in &system.resolved {
            operations.push(PlanOperation {
                kind: PlanOperationKind::Add,
                target: format!("agent:{}@{}", r.agent.id, r.agent.version),
                reason: format!("agent in system `{}`", system.metadata.id),
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
