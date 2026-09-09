//! Source: a catalog repository (local directory or Git repo) that we
//! ingest and snapshot.
//!
//! MVP supports `Local` (filesystem clone). Git is planned for 1.x
//! (ADR-0001). Both kinds produce the same downstream artifact: a
//! `SourceSnapshot` with a stable commit-pinned identity.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

use super::version::Version;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceKind {
    /// A local directory on disk. We treat it as a snapshot with a
    /// content-derived identity (sha256 of the canonicalized file
    /// manifest) until the user points us at a Git repository.
    Local { path: PathBuf },
    /// Git via HTTPS. Planned for 1.x.
    GitHttps { url: String },
    /// Git via SSH. Planned for 1.x.
    GitSsh { url: String },
}

impl SourceKind {
    pub fn local(path: PathBuf) -> Self {
        Self::Local { path }
    }

    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub id: Uuid,
    pub kind: SourceKind,
    /// For Git kinds: the pinned commit SHA (or branch/tag for
    /// unstaged dev work). For Local: the SHA256 of the canonicalized
    /// root manifest, which doubles as the snapshot identity.
    pub pinned_ref: Option<String>,
    pub display_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_indexed_at: Option<DateTime<Utc>>,
    /// 3.0.0 (B7, audit, CWE-345
    /// Insufficient Verification
    /// of Data Authenticity):
    /// when `true`, the Git
    /// fetcher rejects any
    /// `pinned_ref` that is
    /// NOT an annotated tag
    /// (lightweight tags
    /// cannot carry a GPG
    /// signature, so they're
    /// not eligible for
    /// signed-only sources).
    ///
    /// Default `false` for
    /// back-compat with
    /// pre-3.0.0 sources.
    /// New sources created
    /// via the API for a
    /// security-sensitive
    /// pipeline (e.g.
    /// production
    /// catalog pulls)
    /// should set this to
    /// `true`.
    ///
    /// The check is
    /// STRUCTURAL (the ref
    /// must be an annotated
    /// tag object, not a
    /// lightweight
    /// commit-pointer);
    /// cryptographic GPG
    /// signature verification
    /// is a 3.1 follow-up
    /// (requires
    /// `pgp` / `gpgme`
    /// integration +
    /// a trust-store of
    /// allowed key
    /// fingerprints).
    #[serde(default)]
    pub require_signed_refs: bool,
}

impl Source {
    pub fn new(kind: SourceKind) -> Self {
        Self {
            id: Uuid::new_v4(),
            kind,
            pinned_ref: None,
            display_name: None,
            created_at: Utc::now(),
            last_indexed_at: None,
            require_signed_refs: false,
        }
    }

    /// 3.0.0 (B7, audit):
    /// builder-style setter.
    /// Returns `self` so
    /// callers can chain
    /// `Source::new(kind).require_signed_refs(true)`.
    pub fn require_signed_refs(mut self, value: bool) -> Self {
        self.require_signed_refs = value;
        self
    }
}

/// A single ingestion result. Stable identity is the `commit_sha`
/// (or, for non-git locals, a content-derived hash). Once written, a
/// snapshot is immutable; re-ingesting the same content produces a
/// new row with `status = 'superseded'` pointing at the same commit.
///
/// Future 1.x: `superseded` snapshots stay in the DB for history
/// (TZ §20). MVP: kept for 5 most-recent per source, older are GC'd.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSnapshot {
    pub id: Uuid,
    pub source_id: Uuid,
    /// 2.11.0 (P1-G-04, TZ #1 §7 /
    /// G-04, CWE-494 Download of
    /// Code Without Integrity
    /// Check): the resolved HEAD
    /// commit SHA (40 hex chars).
    /// Pre-P1-G-04 the snapshot
    /// was pinned to a mutable
    /// branch; P1-G-04 pins it
    /// to a specific commit SHA
    /// (the agent-dep-core
    /// `clone_or_update` already
    /// resolves the branch to a
    /// SHA at clone time, so this
    /// is a re-affirmation that
    /// the field is treated as
    /// immutable for downstream
    /// consumers).
    pub commit_sha: String,
    /// 2.11.0 (P1-G-04, CWE-494):
    /// SHA-1 of the root tree of
    /// the cloned commit (40 hex
    /// chars, lowercase). The
    /// tree hash uniquely
    /// identifies the directory
    /// structure of the source at
    /// this commit. A different
    /// tree hash means the source
    /// content changed; a same
    /// tree hash across two
    /// commits means the source
    /// content is bit-identical.
    /// `None` for non-git sources
    /// (the pre-P1-G-04 path).
    pub tree_hash: Option<String>,
    /// 2.11.0 (P1-G-04, CWE-494):
    /// SHA-256 of the canonical
    /// artifact manifest
    /// (sorted `<rel-path>\0<file-sha256>`
    /// lines, LF-separated).
    /// The manifest is the
    /// byte-stable identity of
    /// the working-copy contents
    /// — equivalent to the
    /// `pending_deploys.artifact_manifest_hash`
    /// from P1-D-01c but for
    /// the source side. A
    /// different manifest hash
    /// means a different set of
    /// files (or different
    /// contents) was ingested.
    /// `None` if the snapshot
    /// predates P1-G-04 or the
    /// scanner was skipped.
    pub artifact_manifest_hash: Option<String>,
    /// 2.11.0 (P1-G-04, CWE-494):
    /// SHA-256 of the canonical
    /// scanner findings list
    /// (sorted
    /// `<severity>\0<rule>\0<path>\0<reason>`,
    /// LF-separated). The scanner
    /// result hash is the
    /// byte-stable identity of
    /// the scanner verdict at
    /// snapshot time. A different
    /// hash means the scanner
    /// produced a different
    /// findings list (different
    /// rules, different paths,
    /// different reasons). `None`
    /// if the scanner was
    /// skipped or the snapshot
    /// predates P1-G-04.
    pub scanner_result_hash: Option<String>,
    pub status: SnapshotStatus,
    pub agent_count: u32,
    pub division_count: u32,
    pub created_at: DateTime<Utc>,
    /// `Version` of the source's `agency-agents` template at snapshot
    /// time. None for first-time ingestion or when the upstream
    /// doesn't expose one.
    pub upstream_template_version: Option<Version>,
    /// Free-form note from the scanner (BLOCK summary, or just an
    /// audit marker for PASS).
    pub scan_note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    /// All good. This snapshot is the active one for its source.
    Active,
    /// Re-ingestion produced a newer active snapshot. This one is
    /// kept for history (1.x+).
    Superseded,
    /// Scanner BLOCK-ed. Ingested but not eligible for active use.
    Blocked,
    /// Ingester failed mid-flight; partial state preserved for
    /// recovery (see ADR-0006).
    Failed,
}

impl SnapshotStatus {
    pub fn is_active_or_superseded(&self) -> bool {
        matches!(self, Self::Active | Self::Superseded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_kind_local_helper() {
        let k = SourceKind::local(PathBuf::from("/tmp/agency-agents"));
        assert!(k.is_local());
    }

    #[test]
    fn snapshot_status_flags() {
        assert!(SnapshotStatus::Active.is_active_or_superseded());
        assert!(SnapshotStatus::Superseded.is_active_or_superseded());
        assert!(!SnapshotStatus::Blocked.is_active_or_superseded());
        assert!(!SnapshotStatus::Failed.is_active_or_superseded());
    }
}
