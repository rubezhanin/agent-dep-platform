//! RuntimeAdapter trait (TZ §12.3 + ADR-0008).
//!
//! Domain layer MUST NOT import concrete adapters. The
//! `RuntimeAdapter` abstraction is owned by `hermes-adapter`
//! because hermes-adapter is the first concrete implementation;
//! future adapters (e.g. for OpenAI Codex) would live in their
//! own crates and implement this same trait.
//!
//! MVP-1.0 only implements the Hermes flow:
//!
//! 1. `detect`  — locate the Hermes install, return its
//!    `RuntimeInfo` (version, home, plugin dir).
//! 2. `plan`    — accept a `RouterPluginInputs` (id, name,
//!    description, catalog source/ref, agents, four router
//!    tools) and produce an identical-shape plan. For
//!    Hermes the "plan" is currently a no-op pass-through;
//!    the contract is in place so 1.x can layer a real
//!    `ReversePlan` for rollback on top.
//! 3. `deploy`  — write the router plugin tree to disk
//!    (`manifest.yaml` + `SKILL.md` + `skills/<slug>.md`),
//!    atomic temp+rename per ADR-0002, all paths through
//!    `resolve_safe_path` per TZ §I3.
//! 4. `verify`  — re-read the on-disk manifest and assert
//!    the catalog `commit_sha` + the four router tool
//!    names are present (cheap static check; the LLM-driven
//!    probe is out of MVP scope per ADR-0008 §6).
//! 5. `rollback` — restore a previous `RouterPluginLayout`
//!    from a content-addressed backup. Not implemented in
//!    MVP-1.0; lands with Phase 5 (`agency.lock` + 6 plan
//!    operations + rollback flow).
//! 6. `inspect` — read the on-disk plugin tree and return
//!    a structured `RuntimeState`. Stub for now; the CLI
//!    uses `hermes mcp list` for the user-facing read in
//!    MVP-1.0.

use crate::router_plugin::{RouterPluginInputs, RouterPluginLayout};
use crate::types::RuntimeInfo;
use agent_dep_core::error::{CoreError, CoreResult};
use std::path::Path;

pub trait RuntimeAdapter: Send + Sync {
    fn detect(&self) -> CoreResult<RuntimeInfo>;

    fn inspect(&self) -> CoreResult<()> {
        Err(CoreError::Unimplemented {
            feature: "RuntimeAdapter::inspect".into(),
        })
    }

    /// Accept the deploy inputs and (optionally) decorate
    /// them — e.g. fill in a default router_skills list,
    /// validate plugin_id against policy, or attach a
    /// fallback router strategy. MVP-1.0 returns the
    /// inputs unchanged.
    fn plan(&self, inputs: &RouterPluginInputs) -> CoreResult<RouterPluginInputs> {
        Ok(RouterPluginInputs {
            plugin_id: inputs.plugin_id.clone(),
            display_name: inputs.display_name.clone(),
            description: inputs.description.clone(),
            catalog_source: inputs.catalog_source.clone(),
            catalog_commit_sha: inputs.catalog_commit_sha.clone(),
            agent_files: inputs.agent_files.clone(),
            router_skills: inputs.router_skills.clone(),
        })
    }

    /// Materialize the router plugin tree on disk. The
    /// returned `RouterPluginLayout` carries the on-disk
    /// paths + content hashes for the journal row.
    fn deploy(&self, inputs: &RouterPluginInputs) -> CoreResult<RouterPluginLayout> {
        let _ = inputs;
        Err(CoreError::Unimplemented {
            feature: "RuntimeAdapter::deploy".into(),
        })
    }

    fn verify(&self) -> CoreResult<()> {
        Err(CoreError::Unimplemented {
            feature: "RuntimeAdapter::verify".into(),
        })
    }

    fn rollback(&self, _snapshot: &Path) -> CoreResult<()> {
        Err(CoreError::Unimplemented {
            feature: "RuntimeAdapter::rollback".into(),
        })
    }
}
