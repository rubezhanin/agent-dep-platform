//! Types shared between adapter trait and concrete implementations.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../../src/lib/types.generated.ts")]
pub struct RuntimeInfo {
    pub version: String,
    pub home: PathBuf,
    pub plugin_dir: PathBuf,
}
