//! Local policy engine (TZ v2 §24, MVP MUST HAVE #18).
//!
//! MVP-1.0 ships a typed, file-driven policy. The shape
//! is fixed (per §24.2 example) and the engine exposes
//! three decisions: `Allow`, `Warn`, `Block`.
//!
//! ```yaml
//! policyVersion: 1
//! sources:
//!   allowedRepositories:
//!     - git@github.com:company/*
//! security:
//!   unknownExternalUrls: block
//!   plaintextSecrets: block
//!   executableFiles: block
//! deployment:
//!   modifiedFiles: requireExplicitConfirmation
//! ```
//!
//! Policy application: each MVP-1.0 check site
//! (deploy / install / ingest) loads a `Policy` once
//! and asks `evaluate(...)` for each gate. Failures
//! are surfaced as `CoreError::ErrPolicyBlocked` so the
//! deploy loop can fail closed (TZ §I13).
//!
//! We do **not** run an OPA / Rego engine in MVP-1.0
//! (per §24.4 — that is 2.x). The local typed policy
//! is enough for the MUST HAVE.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::{CoreError, CoreResult};

/// Bumped on backwards-incompatible policy changes.
pub const POLICY_FILE_VERSION: u32 = 1;

/// Three-way verdict. Matches TZ §24.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    #[default]
    Allow,
    Warn,
    Block,
}

/// Source-side gates.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourcePolicy {
    /// Glob patterns of accepted Git URLs / local paths.
    /// Empty means "no constraint" (TZ §24.1 — the
    /// constraint is opt-in).
    #[serde(default)]
    pub allowed_repositories: Vec<String>,
}

/// Security-side gates. Each field is the *minimum*
/// severity the engine emits if the rule is hit; the
/// scanner's per-finding severity is then re-evaluated
/// against this baseline.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityPolicy {
    #[serde(default = "default_block")]
    pub unknown_external_urls: PolicyDecision,
    #[serde(default = "default_block")]
    pub plaintext_secrets: PolicyDecision,
    #[serde(default = "default_block")]
    pub executable_files: PolicyDecision,
}

/// Deployment-side gates.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentPolicy {
    /// `RequireExplicitConfirmation` = `Block` (the
    /// deploy loop refuses to overwrite modified or
    /// foreign files without a user override).
    /// `AllowOverwrite` = `Warn` (the deploy loop
    /// logs and continues). `RefuseOverwrite` = `Block`.
    #[serde(default = "default_block")]
    pub modified_files: PolicyDecision,
}

fn default_block() -> PolicyDecision {
    PolicyDecision::Block
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub policy_version: u32,
    #[serde(default)]
    pub sources: SourcePolicy,
    #[serde(default)]
    pub security: SecurityPolicy,
    #[serde(default)]
    pub deployment: DeploymentPolicy,
}

impl Policy {
    /// Parse from a YAML string. Validates the version
    /// and the structural contract.
    pub fn from_yaml(text: &str) -> CoreResult<Self> {
        let p: Policy = serde_yaml::from_str(text).map_err(|e| CoreError::ErrSchemaInvalid {
            path: "policy".to_string(),
            reason: format!("yaml parse: {e}"),
        })?;
        if p.policy_version != POLICY_FILE_VERSION {
            return Err(CoreError::ErrSchemaInvalid {
                path: "policyVersion".to_string(),
                reason: format!(
                    "unsupported policyVersion: got `{}`, expected `{}`",
                    p.policy_version, POLICY_FILE_VERSION
                ),
            });
        }
        Ok(p)
    }

    pub fn from_path(path: &Path) -> CoreResult<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| CoreError::ErrSchemaInvalid {
            path: path.display().to_string(),
            reason: format!("read: {e}"),
        })?;
        Self::from_yaml(&text)
    }

    /// Is a given catalog location allowed by
    /// `sources.allowedRepositories`? An empty list
    /// means "no constraint".
    pub fn source_allowed(&self, location: &str) -> bool {
        if self.sources.allowed_repositories.is_empty() {
            return true;
        }
        for pat in &self.sources.allowed_repositories {
            if glob_match(pat, location) {
                return true;
            }
        }
        false
    }

    /// Combine a scanner finding's rule + default
    /// severity with the policy's per-rule floor. We
    /// return the *stricter* of the two so a `Warn`
    /// scanner default + a `Block` policy floor becomes
    /// `Block`.
    pub fn security_floor(&self, rule_id: &str) -> PolicyDecision {
        // Hard-coded mapping per MVP-1.0: the three
        // security rule families from §23.1 + §24.2.
        if rule_id == "url.unknown-download-endpoint"
            || rule_id == "url.suspicious-download-endpoint"
        {
            return self.security.unknown_external_urls;
        }
        if rule_id.starts_with("secret.") {
            return self.security.plaintext_secrets;
        }
        if rule_id == "executable.unexpected-extension" {
            return self.security.executable_files;
        }
        PolicyDecision::Allow
    }

    /// What to do when a file in the target tree is
    /// MODIFIED or FOREIGN (TZ §8 / §20).
    pub fn modified_file_decision(&self) -> PolicyDecision {
        self.deployment.modified_files
    }
}

/// `*` matches any run of non-`/` chars; `**` matches
/// any run including `/`. We only support the subset
/// we actually need in MVP-1.0: a leading `*` wildcard
/// and a trailing `*` wildcard. Everything else is an
/// exact match.
fn glob_match(pattern: &str, candidate: &str) -> bool {
    if pattern == candidate {
        return true;
    }
    if let Some(suffix) = pattern.strip_suffix('*') {
        if candidate.starts_with(suffix) {
            return true;
        }
    }
    if let Some(prefix) = pattern.strip_prefix('*') {
        if candidate.ends_with(prefix) {
            return true;
        }
    }
    false
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
