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
        }
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
    pub commit_sha: String,
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
