//! `agency.lock` — exact-version pin file (TZ Enterprise v2 §9).
//!
//! A lock file freezes the resolved set of (agent, skill,
//! renderer) versions for a given `System` and snapshot. It
//! is the deterministic input to the deploy pipeline: the
//! same lock + the same renderer versions reproduce
//! byte-identical artifacts.
//!
//! ## Format
//!
//! ```yaml
//! lockVersion: 1
//! source:
//!   repository: git@github.com:company/agents.git
//!   commit: abc123...
//! agents:
//!   backend-architect: 2.4.0
//!   database-engineer: 1.3.0
//! skills:
//!   observability: 2.0.1
//! renderers:
//!   hermes-router: 1.0.0
//! ```
//!
//! SemVer ranges (TZ §9 MVP) are NOT supported in MVP-1.0 —
//! exact versions only. That keeps the parser trivial and
//! matches ADR-0003.
//!
//! The file is a sibling of the system definition in the
//! user's Git repo (per TZ §26.2 — SQLite is *not* the
//! source of truth for System definitions or lock files).
//!
//! ## Note on `Version` serialization
//!
//! `Version` has a derived `Serialize` that emits a
//! `{"major":..,"minor":..,"patch":..}` map. We want the
//! lock-file to look like the YAML above (scalar `2.4.0`),
//! so `LockFile` keeps versions as `String` internally and
//! converts at the `from_resolved` / `from_yaml` boundary.
//! `Version` validation still happens; we just store the
//! canonical form in YAML.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::version::Version;

/// Current lock-file format version. Bump on any
/// backwards-incompatible change.
pub const LOCK_FILE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockSource {
    pub repository: String,
    pub commit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockFile {
    pub lock_version: u32,
    pub source: LockSource,
    /// Pinned (id, SemVer-string) per agent. BTreeMap for
    /// stable serialization order (TZ §I5 determinism).
    pub agents: BTreeMap<String, String>,
    /// Pinned (id, SemVer-string) per skill. Empty for v1
    /// systems.
    pub skills: BTreeMap<String, String>,
    /// Renderer version pins. For MVP-1.0 the only
    /// renderer is `hermes-router@1.0.0`; future renderers
    /// (Codex, etc.) add entries here.
    pub renderers: BTreeMap<String, String>,
}

impl LockFile {
    /// Build a `LockFile` from a snapshot's `commit_sha` and
    /// the resolved agents/skills. Renderer pins are
    /// defaulted to `hermes-router@1.0.0`.
    pub fn from_resolved(
        catalog_repository: &str,
        catalog_commit: &str,
        agents: &[(String, Version)],
        skills: &[(String, Version)],
    ) -> Self {
        let mut agent_map: BTreeMap<String, String> = BTreeMap::new();
        for (id, v) in agents {
            agent_map.insert(id.clone(), v.to_string());
        }
        let mut skill_map: BTreeMap<String, String> = BTreeMap::new();
        for (id, v) in skills {
            skill_map.insert(id.clone(), v.to_string());
        }
        let mut renderers: BTreeMap<String, String> = BTreeMap::new();
        renderers.insert("hermes-router".to_string(), "1.0.0".to_string());
        Self {
            lock_version: LOCK_FILE_VERSION,
            source: LockSource {
                repository: catalog_repository.to_string(),
                commit: catalog_commit.to_string(),
            },
            agents: agent_map,
            skills: skill_map,
            renderers,
        }
    }

    /// Parse a lock file from a YAML string. Validates the
    /// lockVersion, non-empty source fields, and that every
    /// version string is a valid SemVer (zero parts are
    /// rejected).
    pub fn from_yaml(text: &str) -> Result<Self, String> {
        let f: LockFile = serde_yaml::from_str(text)
            .map_err(|e| format!("yaml parse: {e}"))?;
        if f.lock_version != LOCK_FILE_VERSION {
            return Err(format!(
                "unsupported lockVersion: got `{}`, expected `{}`",
                f.lock_version, LOCK_FILE_VERSION
            ));
        }
        if f.source.repository.is_empty() {
            return Err("source.repository must be non-empty".to_string());
        }
        if f.source.commit.is_empty() {
            return Err("source.commit must be non-empty".to_string());
        }
        for (id, raw) in &f.agents {
            if id.is_empty() {
                return Err("agents key must be non-empty".to_string());
            }
            Version::parse(raw).map_err(|_| {
                format!("agents.{id} has an invalid SemVer (`{raw}`)")
            })?;
        }
        for (id, _raw) in &f.skills {
            if id.is_empty() {
                return Err("skills key must be non-empty".to_string());
            }
        }
        for (id, raw) in &f.renderers {
            Version::parse(raw).map_err(|_| {
                format!("renderers.{id} has an invalid SemVer (`{raw}`)")
            })?;
        }
        Ok(f)
    }

    /// Serialize to a deterministic YAML string.
    pub fn to_yaml(&self) -> Result<String, String> {
        serde_yaml::to_string(self).map_err(|e| format!("yaml serialize: {e}"))
    }

    /// Convenience accessor for the typed `(id, Version)`
    /// agent pins. Useful for the deploy loop.
    pub fn agent_versions(&self) -> Result<Vec<(String, Version)>, String> {
        self.agents
            .iter()
            .map(|(id, raw)| {
                Version::parse(raw)
                    .map(|v| (id.clone(), v))
                    .map_err(|_| format!("agents.{id} has an invalid SemVer"))
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "lock_tests.rs"]
mod tests;
