//! Concrete HermesAdapter (only `detect` implemented in MVP-0).

use crate::adapter::RuntimeAdapter;
use crate::detection::detect_hermes;
use crate::types::RuntimeInfo;
use agent_dep_core::error::CoreResult;
use std::path::{Path, PathBuf};

pub struct HermesAdapter {
    hermes_home: PathBuf,
}

impl HermesAdapter {
    pub fn new(hermes_home: PathBuf) -> Self {
        Self { hermes_home }
    }

    pub fn hermes_home(&self) -> &Path {
        &self.hermes_home
    }
}

impl RuntimeAdapter for HermesAdapter {
    fn detect(&self) -> CoreResult<RuntimeInfo> {
        detect_hermes(&self.hermes_home)
    }
}
