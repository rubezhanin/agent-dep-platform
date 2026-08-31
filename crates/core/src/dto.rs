//! Data Transfer Objects (DTOs) shared across IPC and CLI.
//!
//! Each DTO derives `TS` for codegen into TypeScript. Keep this file
//! additive — appending types is fine, renaming is breaking.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub struct AgentSummary {
    pub id: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub struct SourceSummary {
    pub id: String,
    pub url: String,
    pub commit_sha: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub struct SystemSummary {
    pub id: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub struct DeploymentSummary {
    pub id: String,
    pub system_id: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub struct BackupSummary {
    pub id: String,
    pub path: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub struct Plan {
    pub system_id: String,
    pub operations: Vec<PlanOperation>,
    pub risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub struct PlanOperation {
    pub kind: String, // ADD, UPDATE, DELETE, NOOP, BACKUP, VERIFY
    pub target: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub struct ScanResult {
    pub source_id: String,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub struct Finding {
    pub severity: String, // PASS, WARN, BLOCK
    pub rule: String,
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub struct LogLine {
    pub ts: String,
    pub level: String,
    pub target: String,
    pub message: String,
}
