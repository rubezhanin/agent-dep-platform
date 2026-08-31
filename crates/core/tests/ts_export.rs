//! ts-rs drift guard.
//!
//! Generates TypeScript bindings for every `#[derive(TS)]` type into
//! `src/lib/types.generated.ts`. Run `scripts/check-ts-drift.ps1` to
//! verify the generated file matches git HEAD.
//!
//! GOTCHA (recorded in AGENTS.md): incremental regen can DUPLICATE types
//! when adding new DTOs across commits. The fix is a single fresh regen
//! with the new types added to this import list. The resulting diff may
//! look like a large negative change — that's correct.

use agent_dep_core::dto::{
    AgentSummary, BackupSummary, DeploymentSummary, Finding, LogLine, Plan, PlanOperation,
    ScanResult, SourceSummary, SystemSummary,
};
use agent_dep_hermes_adapter::types::RuntimeInfo;
use ts_rs::TS;

#[test]
fn export_all_types() {
    // Export each type once. ts-rs writes them all into the same file
    // (export_to path) and dedupes by type name.
    AgentSummary::export_all().expect("export AgentSummary");
    SourceSummary::export_all().expect("export SourceSummary");
    SystemSummary::export_all().expect("export SystemSummary");
    DeploymentSummary::export_all().expect("export DeploymentSummary");
    BackupSummary::export_all().expect("export BackupSummary");
    Plan::export_all().expect("export Plan");
    PlanOperation::export_all().expect("export PlanOperation");
    ScanResult::export_all().expect("export ScanResult");
    Finding::export_all().expect("export Finding");
    LogLine::export_all().expect("export LogLine");
    RuntimeInfo::export_all().expect("export RuntimeInfo");
}
