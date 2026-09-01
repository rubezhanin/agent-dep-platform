//! Types shared between adapter trait and concrete implementations.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub struct RuntimeInfo {
    pub version: String,
    pub home: PathBuf,
    pub plugin_dir: PathBuf,
}

/// Per-plugin verification report (TZ §12.3 + ADR-0008).
///
/// One `HealthReport` per Hermes plugin id. Each `ArtifactHealth`
/// describes one file inside the plugin tree relative to
/// `hermes_home` (e.g. `plugins/agency-agents-router/manifest.yaml`).
///
/// `expected_sha256` is `None` for files that the operator
/// never deployed through us (e.g. a hand-written `README.md`).
/// `observed_sha256` is `None` when the file is missing on disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub struct HealthReport {
    pub plugin_id: String,
    pub hermes_home: PathBuf,
    pub artifacts: Vec<ArtifactHealth>,
    /// `true` iff every `ArtifactHealth` is `Current` (i.e. the
    /// on-disk state matches what we last deployed).
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub struct ArtifactHealth {
    /// Path relative to `hermes_home` (POSIX style).
    pub target: String,
    /// sha256 we expected on disk, or `None` if the file is
    /// not tracked in our baseline.
    pub expected_sha256: Option<String>,
    /// sha256 we actually read, or `None` if the file is
    /// missing or unreadable.
    pub observed_sha256: Option<String>,
    pub status: ArtifactHealthStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub enum ArtifactHealthStatus {
    /// File present and sha matches the baseline.
    Current,
    /// File present but sha differs from the baseline
    /// (someone edited it after our last deploy).
    Modified,
    /// File present, but we have no baseline for it —
    /// it was not part of the last deploy output.
    Foreign,
    /// Tracked in the baseline, but the file is gone.
    Missing,
    /// IO error reading the file (permission, etc.).
    Error,
}
