//! RuntimeAdapter trait (TZ §12.3).
//!
//! Domain layer MUST NOT import concrete adapters. The `RuntimeAdapter`
//! abstraction is owned by `hermes-adapter` because hermes-adapter is the
//! first concrete implementation; future adapters (e.g. for OpenAI Codex)
//! would live in their own crates and implement this same trait.

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

    fn plan(&self, _system: &()) -> CoreResult<()> {
        Err(CoreError::Unimplemented {
            feature: "RuntimeAdapter::plan".into(),
        })
    }

    fn deploy(&self, _plan: &()) -> CoreResult<()> {
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
