//! `Skill` domain — TZ Enterprise v2 §7.
//!
//! Skills are reusable capability/instruction units. They are not
//! agents: an agent *uses* skills, a skill does not run on its own.
//! Skills carry a Markdown body (`SKILL.md`), declared dependencies
//! (other skills), and a permissions list that a policy engine
//! inspects before deployment.
//!
//! This module owns the *domain* representation only. The canonical
//! on-disk YAML manifest is parsed in `crate::domain::skill_yaml`
//! and validated against the JSON Schema in
//! `crate::infrastructure::schema::SKILL_SCHEMA_ID`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// A resolved skill, persisted as part of a catalog snapshot.
///
/// `body_hash` references the canonical bytes in the content store
/// (`crate::infrastructure::content_store`). The body itself is held
/// in memory at ingest time so the deploy pipeline can render
/// without re-reading disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skill {
    pub snapshot_id: Uuid,
    pub id: String,
    pub name: String,
    pub version: super::version::Version,
    pub description: String,
    pub tags: Vec<String>,
    pub body: String,
    pub body_hash: String,
    pub dependencies: Vec<SkillDependency>,
    pub permissions: Vec<SkillPermission>,
}

/// A declared `skill@version` reference. Used both inside a skill's
/// own `dependencies` list and inside a `System`'s `spec.skills`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillDependency {
    pub id: String,
    pub version: super::version::Version,
}

/// Permission declared on a skill. The set is intentionally small in
/// MVP — just enough to drive the policy engine in Phase 3 and to
/// be inspectable in the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillPermission {
    /// Read environment variables (resolved at runtime through
    /// `env:` / `secret:` references; never persisted in cleartext).
    ReadEnv,
    /// Spawn child processes. Always subject to Hermes sandbox
    /// policy in MVP; the skill manifest declares intent only.
    SpawnProcess,
    /// Access the network. Always subject to Hermes network policy.
    Network,
    /// Read/write the local filesystem under the declared safe root.
    Filesystem,
}

impl Skill {
    /// Compute the canonical sha256 hex digest of `bytes`. Used by
    /// the content store as the immutable key.
    pub fn sha256_hex(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        hex::encode(h.finalize())
    }
}

#[cfg(test)]
#[path = "skill_tests.rs"]
mod tests;
