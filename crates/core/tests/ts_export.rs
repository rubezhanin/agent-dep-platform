//! ts-rs drift guard.
//!
//! Generates TypeScript bindings for every `#[derive(TS)]` type into
//! `src/lib/types.generated.ts`. Run `scripts/check-ts-drift.ps1` to
//! verify the generated file matches git HEAD.

use agent_dep_core::dto::{
    AgentSummary, BackupSummary, DeploymentSummary, Finding, LogLine, Plan, PlanOperation,
    ScanResult, SourceSummary, SystemSummary,
};
use agent_dep_hermes_adapter::types::RuntimeInfo;
use ts_rs::TS;

#[test]
fn export_all_types() {
    // Call export_all() on each type. ts-rs writes to the file
    // associated with each type's `export_to` path. Each type has the
    // same path, so they all write to the same file and accumulate.
    let _ = AgentSummary::export_all();
    let _ = SourceSummary::export_all();
    let _ = SystemSummary::export_all();
    let _ = DeploymentSummary::export_all();
    let _ = BackupSummary::export_all();
    let _ = Plan::export_all();
    let _ = PlanOperation::export_all();
    let _ = ScanResult::export_all();
    let _ = Finding::export_all();
    let _ = LogLine::export_all();
    let _ = RuntimeInfo::export_all();
}
