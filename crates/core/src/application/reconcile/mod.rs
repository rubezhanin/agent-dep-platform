//! Reconciliation (TZ v2 §20).
//!
//! MVP-1.0 ships the *value object* half of reconciliation:
//! the state model, the drift-reason taxonomy, and a pure
//! function that classifies a single deployed artifact
//! against the desired-state hash. The full reconcile
//! loop (read deployed_artifacts table, classify each
//! row, emit drift reports) lands in 1.x once we have a
//! `deployed_artifacts` table to read from.
//!
//! The model mirrors §20.1 / §20.2 verbatim:
//!
//! * `ReconcileState` — what we observed.
//! * `DriftReason` — why we observed it.
//! * `classify(desired, actual, modified_by_user)` — pure
//!   function: `desired == actual` → `Current`; otherwise
//!   one of the non-CURRENT states.

use serde::{Deserialize, Serialize};

/// The state of a single deployed artifact relative to
/// the desired state recorded in the system file +
/// `agency.lock`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileState {
    /// The on-disk artifact byte-matches the desired hash.
    Current,
    /// The desired hash has changed since this artifact
    /// was last deployed.
    Outdated,
    /// The on-disk file's content has been modified by
    /// the user since deployment. Backup-before-overwrite
    /// is mandatory.
    Modified,
    /// The file is not tracked by any system. Either the
    /// user added it manually or a previous system left
    /// it behind. MVP-1.0 does not delete foreign files
    /// without an explicit user override.
    Foreign,
    /// The file is expected by the system but absent on
    /// disk. The deploy loop creates it.
    Missing,
    /// The runtime refuses to run the artifact (Hermes
    /// version mismatch, plugin lifecycle error, etc.).
    /// MVP-1.0 treats this as a separate state from
    /// `Error` so the user can still update via the
    /// standard flow.
    Incompatible,
    /// A catch-all for unexpected failure modes. The
    /// caller is expected to read `error_code` to know
    /// what to do.
    Error,
    /// The deploy has not yet been run for this artifact.
    /// This is the "no row in deployed_artifacts" case
    /// and is distinct from `Missing` (which means the
    /// file is gone).
    Unknown,
}

/// Why an artifact drifted. The list is small on
/// purpose: a long taxonomy is hard to test and harder
/// to surface in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftReason {
    SourceChanged,
    RendererChanged,
    UserModified,
    TargetMoved,
    TargetMissing,
    VersionIncompatible,
    PolicyViolation,
    Unknown,
}

/// A single classified row. The `target` is the
/// relative path under the deployment root. The
/// `expected_sha256` and `actual_sha256` are both
/// sha256-hex strings (64 chars); they are equal iff
/// the file is `Current`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileRow {
    pub target: String,
    pub expected_sha256: Option<String>,
    pub actual_sha256: Option<String>,
    pub state: ReconcileState,
    pub reason: DriftReason,
}

/// Pure classifier. Pass the desired sha256 (from the
/// system file + lock) and the actual sha256 (from the
/// target filesystem) and a `user_modified` flag
/// (heuristic: stat mtime, or a future explicit marker),
/// and the function returns the right state + reason.
///
/// The `desired.is_none()` and `actual.is_none()`
/// shapes cover the boundary cases (no row vs. file
/// missing) without forcing the caller to encode the
/// difference at the call site.
pub fn classify(
    desired: Option<&str>,
    actual: Option<&str>,
    user_modified: bool,
) -> (ReconcileState, DriftReason) {
    match (desired, actual) {
        (None, None) => (ReconcileState::Unknown, DriftReason::Unknown),
        (None, Some(_)) => (ReconcileState::Foreign, DriftReason::Unknown),
        (Some(_), None) => (ReconcileState::Missing, DriftReason::TargetMissing),
        (Some(d), Some(a)) if d == a => {
            (ReconcileState::Current, DriftReason::Unknown)
        }
        (Some(_), Some(_)) if user_modified => (
            ReconcileState::Modified,
            DriftReason::UserModified,
        ),
        (Some(_), Some(_)) => (
            ReconcileState::Outdated,
            DriftReason::SourceChanged,
        ),
    }
}

#[cfg(test)]
#[path = "reconcile_tests.rs"]
mod tests;
