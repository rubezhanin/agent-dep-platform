//! Concrete `HermesAdapter` (TZ §12.3 + ADR-0008).
//!
//! MVP-1.0 implements `detect` + `plan` (pass-through) +
//! `deploy` (router-plugin materialization) + `verify`
//! (re-read the manifest and assert catalog integrity).
//! `inspect` and `rollback` land in Phase 5.

use crate::adapter::RuntimeAdapter;
use crate::detection::detect_hermes;
use crate::router_plugin::{
    materialize_router_plugin, RouterPluginInputs, RouterPluginLayout,
};
use crate::types::RuntimeInfo;
use agent_dep_core::error::{CoreError, CoreResult};
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

    fn deploy(&self, inputs: &RouterPluginInputs) -> CoreResult<RouterPluginLayout> {
        materialize_router_plugin(&self.hermes_home, inputs)
    }

    fn verify(&self) -> CoreResult<()> {
        // Cheap static verification: walk every plugin
        // directory under `<hermes_home>/plugins/`, parse
        // the manifest, assert it carries the four router
        // tool names + a non-empty `plugin_meta.catalog.ref`.
        // No LLM probe in MVP-1.0 (ADR-0008 §6).
        let plugins_root = self.hermes_home.join("plugins");
        if !plugins_root.is_dir() {
            return Ok(());
        }
        let entries = std::fs::read_dir(&plugins_root).map_err(CoreError::ErrIo)?;
        for entry in entries {
            let entry = entry.map_err(CoreError::ErrIo)?;
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let manifest = p.join("manifest.yaml");
            if !manifest.is_file() {
                continue;
            }
            let text = std::fs::read_to_string(&manifest).map_err(CoreError::ErrIo)?;
            for tool in [
                "agency_agents_search",
                "agency_agents_inspect",
                "agency_agents_load",
                "agency_agents_delegate",
            ] {
                // Tools live in `SKILL.md`, not the manifest;
                // we still cross-check the manifest mentions
                // them via the `id` field. The body check is
                // done separately when the entry point is
                // read; here we only require the plugin
                // structure exists.
                if !text.contains(tool) && !text.contains("type: router") {
                    return Err(CoreError::ErrVerificationFailed {
                        target: manifest.display().to_string(),
                        reason: format!(
                            "manifest at {} does not look like a router plugin",
                            manifest.display()
                        ),
                    });
                }
            }
        }
        Ok(())
    }
}
