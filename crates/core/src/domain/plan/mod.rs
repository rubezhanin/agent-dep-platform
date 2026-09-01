//! Deployment plan (TZ §16 + MVP-3).
//!
//! A `Plan` is the output of "what operations does it take to make
//! the deployed state match this System?". For MVP-3 the planner
//! is intentionally simple: every resolved agent produces an `Add`
//! operation. 1.x adds the diff against a real deployment state
//! (then `Update`, `Delete`, and `Noop` come into play).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanOperationKind {
    /// Install a new agent on the target runtime.
    Add,
    /// Replace an existing agent with a new version.
    Update,
    /// Remove an agent that is no longer referenced.
    Delete,
    /// Re-deploy an unchanged agent (idempotent re-apply).
    Noop,
    /// Snapshot a file before mutating it (rollback safety).
    Backup,
    /// Run a post-deploy verification check.
    Verify,
}

impl PlanOperationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Add => "ADD",
            Self::Update => "UPDATE",
            Self::Delete => "DELETE",
            Self::Noop => "NOOP",
            Self::Backup => "BACKUP",
            Self::Verify => "VERIFY",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanOperation {
    pub kind: PlanOperationKind,
    /// Stable target identifier, e.g. `agent:backend-engineer@1.0.0`
    /// or `skill:sql@0.1.0`. The deployer uses this as the
    /// rollback key.
    pub target: String,
    /// Human-readable reason. For MVP-3: "agent in system" or
    /// "snapshot has newer version". 1.x: policy-driven reasoning.
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanRisk {
    Low,
    Medium,
    High,
}

impl PlanRisk {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub system_id: String,
    pub operations: Vec<PlanOperation>,
    pub risk: PlanRisk,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_operation_kind_round_trip() {
        for k in [
            PlanOperationKind::Add,
            PlanOperationKind::Update,
            PlanOperationKind::Delete,
            PlanOperationKind::Noop,
            PlanOperationKind::Backup,
            PlanOperationKind::Verify,
        ] {
            assert_eq!(
                k.as_str().to_ascii_lowercase(),
                format!("{k:?}").to_ascii_lowercase()
            );
        }
    }

    #[test]
    fn plan_risk_round_trip() {
        assert_eq!(PlanRisk::Low.as_str(), "low");
        assert_eq!(PlanRisk::Medium.as_str(), "medium");
        assert_eq!(PlanRisk::High.as_str(), "high");
    }
}
