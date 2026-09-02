//! Plan service (TZ §16).
//!
//! MVP-1.0 / 1.4.x support four of the six TZ §16.1
//! plan operations: `Add`, `Noop`, `Update`,
//! `Delete`. 1.5.0 (ADR-0013) adds the remaining two
//! as *drift-detection* read-only operations:
//!
//! * `Verify` — for every file that *should* be on disk
//!   per the previous `deployed_artifacts` snapshot,
//!   check that the on-disk sha256 still matches the
//!   expected one. A mismatch means the operator
//!   (or some external process) edited the file after
//!   deployment.
//! * `Backup` — for every file that *should* have a
//!   backup under `<parent>/.backups/`, check that
//!   the backup is actually there.
//!
//! The plan service is a pure function: the caller
//! passes in the on-disk sha256s (when known) and gets
//! back a typed `Plan`. `Verify` and `Backup` are
//! emitted only when the caller provides the
//! `previously_deployed_observations` argument
//! (4th parameter, optional).
//!
//! `risk` is `low` for a plan that only contains `Add` /
//! `Noop` / `Verify` / `Backup`. A future `High` risk
//! (e.g. deletes against non-empty trees) lands
//! together with `Update` / `Delete` if we ever decide
//! to upgrade the risk model.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::domain::plan::{Plan, PlanOperation, PlanOperationKind, PlanRisk};
use crate::domain::system::System;

/// What the plan service needs to know about a single
/// previously-deployed file in order to emit `Verify`
/// and `Backup` ops for it (1.5.0, ADR-0013).
///
/// `target` is the relative path recorded in
/// `deployed_artifacts.target` (e.g.
/// `agents/be@1.0.0/be.md`). `expected_sha256` is what
/// the row says the file *should* be. `observed_sha256`
/// is what the filesystem actually has right now, or
/// `None` if the file is missing.
#[derive(Debug, Clone)]
pub struct DeployedObservation {
    pub target: String,
    pub expected_sha256: String,
    pub observed_sha256: Option<String>,
    /// Whether `<parent>/.backups/<target>` exists on
    /// disk. The CLI populates this by a `read_dir`
    /// walk before calling `plan_for`.
    pub backup_present: bool,
}

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
    ///
    /// `previously_deployed_observations` (1.5.0+) is the
    /// richer view that powers `Verify` and `Backup` ops.
    /// Pass `None` for the 1.4.x behaviour (no
    /// drift-detection ops).
    #[allow(clippy::too_many_arguments)]
    pub fn plan_for(
        &self,
        system: &System,
        actual_sha256_by_ref: Option<&HashMap<String, String>>,
        previously_deployed_targets: Option<&HashSet<String>>,
        previously_deployed_observations: Option<&BTreeMap<String, DeployedObservation>>,
    ) -> Plan {
        let mut operations = Vec::with_capacity(system.resolved.len());
        let mut planned_targets: HashSet<String> = HashSet::new();

        for r in &system.resolved {
            let agent_ref = format!("{}@{}", r.agent.id, r.agent.version);
            let target = format!("agents/{}/{}.md", agent_ref, r.agent.id);
            planned_targets.insert(target.clone());

            let desired_sha = r.agent.body_hash.clone();
            let kind = match actual_sha256_by_ref.and_then(|m| m.get(&agent_ref)) {
                Some(actual) if actual == &desired_sha => PlanOperationKind::Noop,
                Some(_actual) => {
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

        // Drift detection: for every file the previous
        // deployment tracked, emit `Verify` (sha mismatch
        // or missing) and/or `Backup` (backup missing).
        if let Some(obs) = previously_deployed_observations {
            for (target, o) in obs {
                // `target` is the relative path (e.g.
                // `agents/be@1.0.0/be.md`). Match it
                // against the planned-target set so we
                // don't double-emit a `Verify` for a file
                // that the new system is also going to
                // touch with an `Add` / `Update`.
                if planned_targets.contains(target) {
                    continue;
                }
                if let Some(observed) = &o.observed_sha256 {
                    if observed != &o.expected_sha256 {
                        operations.push(PlanOperation {
                            kind: PlanOperationKind::Verify,
                            target: format!("path:{target}"),
                            reason: format!(
                                "drift: expected sha `{}`, on-disk sha `{}`",
                                short(&o.expected_sha256),
                                short(observed)
                            ),
                        });
                    }
                } else {
                    operations.push(PlanOperation {
                        kind: PlanOperationKind::Verify,
                        target: format!("path:{target}"),
                        reason: format!(
                            "drift: expected sha `{}` but file is missing on disk",
                            short(&o.expected_sha256)
                        ),
                    });
                }
                if !o.backup_present {
                    operations.push(PlanOperation {
                        kind: PlanOperationKind::Backup,
                        target: format!("path:{target}"),
                        reason: format!(
                            "no backup under `<parent>/.backups/{target}`; \
                             next deploy cannot roll back this file"
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

fn short(sha: &str) -> &str {
    if sha.len() >= 12 {
        &sha[..12]
    } else {
        sha
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
