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
//!   database-engineer: ^1.3.0       # SemVer range (1.2.0+)
//! skills:
//!   observability: 2.0.1
//! renderers:
//!   hermes-router: 1.0.0
//! ```
//!
//! MVP-1.0 stored exact versions only (ADR-0003). 1.2.0
//! (ADR-0010) lifts that to `VersionReq` strings: the
//! value is whatever `semver::VersionReq::parse` accepts,
//! including exact pins (`=1.0.0`), carets (`^1.0.0`),
//! tildes (`~1.0.0`), and compound ranges
//! (`>=1.0.0, <2.0.0`). A bare `1.0.0` is treated as
//! `^1.0.0` by the `semver` 1.x parser (the same input
//! can also be written as `>=1.0.0, <2.0.0`).
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
    /// Build a fresh `LockFile` with the given source
    /// metadata and the default renderer pin. The agent
    /// and skill maps are empty; the caller populates
    /// them (used by `generate_at_with_range`, which
    /// wants to insert SemVer range strings rather than
    /// the exact-pinned strings `from_resolved`
    /// produces).
    pub fn new_for_test(catalog_repository: &str, catalog_commit: &str) -> Self {
        let mut renderers: BTreeMap<String, String> = BTreeMap::new();
        renderers.insert("hermes-router".to_string(), "=1.0.0".to_string());
        Self {
            lock_version: LOCK_FILE_VERSION,
            source: LockSource {
                repository: catalog_repository.to_string(),
                commit: catalog_commit.to_string(),
            },
            agents: BTreeMap::new(),
            skills: BTreeMap::new(),
            renderers,
        }
    }

    /// Build a `LockFile` from a snapshot's `commit_sha` and
    /// the resolved agents/skills. Renderer pins are
    /// defaulted to `hermes-router@=1.0.0` (explicit
    /// exact pin — the `=` is required for true exact
    /// pinning in `semver` 1.x, see ADR-0010).
    pub fn from_resolved(
        catalog_repository: &str,
        catalog_commit: &str,
        agents: &[(String, Version)],
        skills: &[(String, Version)],
    ) -> Self {
        let mut agent_map: BTreeMap<String, String> = BTreeMap::new();
        for (id, v) in agents {
            agent_map.insert(id.clone(), format!("={v}"));
        }
        let mut skill_map: BTreeMap<String, String> = BTreeMap::new();
        for (id, v) in skills {
            skill_map.insert(id.clone(), format!("={v}"));
        }
        let mut renderers: BTreeMap<String, String> = BTreeMap::new();
        renderers.insert("hermes-router".to_string(), "=1.0.0".to_string());
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
    /// version string is a valid `semver::VersionReq`
    /// (1.2.0+, supports exact pins, carets, tildes, and
    /// compound ranges).
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
            semver::VersionReq::parse(raw).map_err(|_| {
                format!("agents.{id} has an invalid SemVer req (`{raw}`)")
            })?;
        }
        for (id, raw) in &f.skills {
            if id.is_empty() {
                return Err("skills key must be non-empty".to_string());
            }
            semver::VersionReq::parse(raw).map_err(|_| {
                format!("skills.{id} has an invalid SemVer req (`{raw}`)")
            })?;
        }
        for (id, raw) in &f.renderers {
            semver::VersionReq::parse(raw).map_err(|_| {
                format!("renderers.{id} has an invalid SemVer req (`{raw}`)")
            })?;
        }
        Ok(f)
    }

    /// Serialize to a deterministic YAML string.
    pub fn to_yaml(&self) -> Result<String, String> {
        serde_yaml::to_string(self).map_err(|e| format!("yaml serialize: {e}"))
    }

    /// Convenience accessor for the typed `(id, Version)`
    /// agent pins. **Only** succeeds for exact versions
    /// (a `VersionReq` of the form `=X.Y.Z`). A range
    /// like `^1.0.0` returns an error pointing the
    /// caller at `agent_version_reqs`. Used by the
    /// deploy loop, which only knows how to install one
    /// concrete version of each agent.
    pub fn agent_versions(&self) -> Result<Vec<(String, Version)>, String> {
        self.agents
            .iter()
            .map(|(id, raw)| {
                let req = semver::VersionReq::parse(raw).map_err(|_| {
                    format!("agents.{id} has an invalid SemVer req (`{raw}`)")
                })?;
                let req_str = req.to_string();
                let exact = req_str.strip_prefix('=').unwrap_or(&req_str);
                let v = Version::parse(exact).map_err(|_| {
                    format!(
                        "agents.{id} is a range (`{raw}`); deploy needs an exact version"
                    )
                })?;
                Ok((id.clone(), v))
            })
            .collect()
    }

    /// Range-aware accessor (1.2.0+). Returns the typed
    /// `(id, VersionReq)` so callers like the plan
    /// service can resolve against a snapshot.
    pub fn agent_version_reqs(&self) -> Result<Vec<(String, semver::VersionReq)>, String> {
        self.agents
            .iter()
            .map(|(id, raw)| {
                semver::VersionReq::parse(raw)
                    .map(|r| (id.clone(), r))
                    .map_err(|_| format!("agents.{id} has an invalid SemVer req (`{raw}`)"))
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "lock_tests.rs"]
mod tests;
