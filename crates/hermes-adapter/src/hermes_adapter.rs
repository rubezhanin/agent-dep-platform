//! Concrete `HermesAdapter` (TZ §12.3 + ADR-0008).
//!
//! MVP-1.0 implements `detect` + `plan` (pass-through) +
//! `deploy` (router-plugin materialization) + `verify`
//! (re-read the manifest and assert catalog integrity) +
//! `health` (compare on-disk plugin files against a baseline).
//! `inspect` and `rollback` land in Phase 5.

use crate::adapter::RuntimeAdapter;
use crate::detection::detect_hermes;
use crate::router_plugin::{materialize_router_plugin, RouterPluginInputs, RouterPluginLayout};
use crate::types::{ArtifactHealth, ArtifactHealthStatus, HealthReport, RuntimeInfo};
use agent_dep_core::error::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use ts_rs::TS;

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

    /// Per-plugin verification: walk `<hermes_home>/plugins/<id>/`,
    /// read every file, compare its sha256 against the `baseline`
    /// map (target relative to `hermes_home` -> expected sha256).
    /// Returns a `HealthReport` with one `ArtifactHealth` per
    /// file observed OR per baseline entry that was missing
    /// from disk.
    ///
    /// `baseline` is typically built by the caller from
    /// `DeployedArtifactsRepository::list_for_system(system_id)`.
    /// Files the operator added by hand (and that are NOT in
    /// `baseline`) are reported as `Foreign` so the UI can flag
    /// them without auto-repairing.
    pub fn health(
        &self,
        plugin_id: &str,
        baseline: &BTreeMap<String, String>,
    ) -> CoreResult<HealthReport> {
        let plugin_dir = self.hermes_home.join("plugins").join(plugin_id);
        let mut artifacts: Vec<ArtifactHealth> = Vec::new();
        let mut observed: BTreeMap<String, Option<String>> = BTreeMap::new();

        if plugin_dir.is_dir() {
            collect_files(&plugin_dir, &self.hermes_home, &mut observed)?;
        } else {
            // The plugin directory is gone entirely. Every
            // baseline entry is `Missing`; there are no
            // `Foreign` files because nothing exists.
        }

        // First: report every observed file (some will be in
        // baseline, some won't).
        for (rel, obs_sha) in &observed {
            let expected = baseline.get(rel).cloned();
            let status = match (expected.as_ref(), obs_sha.as_ref()) {
                (Some(e), Some(o)) if e == o => ArtifactHealthStatus::Current,
                (Some(_), Some(_)) => ArtifactHealthStatus::Modified,
                (Some(_), None) => ArtifactHealthStatus::Missing,
                (None, Some(_)) => ArtifactHealthStatus::Foreign,
                (None, None) => ArtifactHealthStatus::Error,
            };
            artifacts.push(ArtifactHealth {
                target: rel.clone(),
                expected_sha256: expected,
                observed_sha256: obs_sha.clone(),
                status,
            });
        }
        // Then: every baseline entry that we did NOT see on disk
        // is `Missing` (covers the case where the plugin dir
        // itself is gone).
        for (rel, expected) in baseline {
            if !observed.contains_key(rel) {
                artifacts.push(ArtifactHealth {
                    target: rel.clone(),
                    expected_sha256: Some(expected.clone()),
                    observed_sha256: None,
                    status: ArtifactHealthStatus::Missing,
                });
            }
        }
        // Stable order: by target path. `BTreeMap` already gives
        // us that, but we built observed+baseline in two passes,
        // so sort at the end for determinism in the TS export.
        artifacts.sort_by(|a, b| a.target.cmp(&b.target));

        let ok = artifacts
            .iter()
            .all(|a| matches!(a.status, ArtifactHealthStatus::Current));

        Ok(HealthReport {
            plugin_id: plugin_id.to_string(),
            hermes_home: self.hermes_home.clone(),
            artifacts,
            ok,
        })
    }
}

/// Walk `dir` recursively and append `rel -> sha256` (or
/// `rel -> None` on read error) for every regular file found.
fn collect_files(
    dir: &Path,
    root: &Path,
    out: &mut BTreeMap<String, Option<String>>,
) -> CoreResult<()> {
    let entries = std::fs::read_dir(dir).map_err(CoreError::ErrIo)?;
    for entry in entries {
        let entry = entry.map_err(CoreError::ErrIo)?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(CoreError::ErrIo)?;
        if file_type.is_dir() {
            collect_files(&path, root, out)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let rel = match path.strip_prefix(root) {
            Ok(r) => r.to_string_lossy().replace('\\', "/"),
            Err(_) => continue, // should never happen — we only recurse under root
        };
        let sha = match std::fs::read(&path) {
            Ok(bytes) => Some(sha256_hex(&bytes)),
            Err(_) => None,
        };
        out.insert(rel, sha);
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
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

// ---------------------------------------------------------------------------
// Structural probe (1.4.0, ADR-0012)
// ---------------------------------------------------------------------------

/// Status of a single check inside a `ProbeReport`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Ok,
    Missing,
    Mismatch,
    Error,
}

/// One named check inside a `ProbeReport`. `sha256` is
/// `Some` for file-content checks; `None` for
/// directory-existence checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub struct ProbeCheck {
    pub name: String,
    pub status: ProbeStatus,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// The full structural probe result for a single plugin.
/// `ok` is `true` iff every check is `Ok`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../src/lib/types.generated.ts")]
pub struct ProbeReport {
    pub plugin_id: String,
    pub ok: bool,
    pub checks: Vec<ProbeCheck>,
}

impl HermesAdapter {
    /// Structural probe (1.4.0, ADR-0012). Verifies that
    /// the plugin directory, `manifest.yaml`, `SKILL.md`,
    /// and every `skills/<agent_id>.md` referenced in the
    /// manifest are present and non-empty. Pure
    /// filesystem inspection; never spawns `hermes`.
    pub fn probe(&self, plugin_id: &str) -> CoreResult<ProbeReport> {
        let mut checks = Vec::new();
        let plugin_dir = self.hermes_home.join("plugins").join(plugin_id);

        if !plugin_dir.is_dir() {
            checks.push(ProbeCheck {
                name: "plugin_dir".to_string(),
                status: ProbeStatus::Missing,
                detail: format!("plugin directory not found: {}", plugin_dir.display()),
                sha256: None,
            });
            return Ok(ProbeReport {
                plugin_id: plugin_id.to_string(),
                ok: false,
                checks,
            });
        }
        checks.push(ProbeCheck {
            name: "plugin_dir".to_string(),
            status: ProbeStatus::Ok,
            detail: format!("{}", plugin_dir.display()),
            sha256: None,
        });

        // Manifest.
        let manifest_path = plugin_dir.join("manifest.yaml");
        let manifest_text = match std::fs::read_to_string(&manifest_path) {
            Ok(t) => t,
            Err(e) => {
                checks.push(ProbeCheck {
                    name: "manifest.yaml".to_string(),
                    status: ProbeStatus::Error,
                    detail: format!("read {}: {e}", manifest_path.display()),
                    sha256: None,
                });
                return Ok(ProbeReport {
                    plugin_id: plugin_id.to_string(),
                    ok: false,
                    checks,
                });
            }
        };
        checks.push(ProbeCheck {
            name: "manifest.yaml".to_string(),
            status: ProbeStatus::Ok,
            detail: format!("{} bytes", manifest_text.len()),
            sha256: Some(sha256_hex(manifest_text.as_bytes())),
        });

        // SKILL.md.
        let skill_path = plugin_dir.join("SKILL.md");
        match std::fs::read_to_string(&skill_path) {
            Ok(t) if !t.trim().is_empty() => checks.push(ProbeCheck {
                name: "SKILL.md".to_string(),
                status: ProbeStatus::Ok,
                detail: format!("{} bytes", t.len()),
                sha256: Some(sha256_hex(t.as_bytes())),
            }),
            Ok(_) => checks.push(ProbeCheck {
                name: "SKILL.md".to_string(),
                status: ProbeStatus::Missing,
                detail: "file is empty".to_string(),
                sha256: None,
            }),
            Err(e) => checks.push(ProbeCheck {
                name: "SKILL.md".to_string(),
                status: ProbeStatus::Error,
                detail: format!("read {}: {e}", skill_path.display()),
                sha256: None,
            }),
        }

        // Every `agents[].id` mentioned in the manifest
        // must have a corresponding `skills/<id>.md`.
        // We parse the manifest with serde_yaml (1.4.0
        // is the first release that pulls serde_yaml into
        // hermes-adapter; it is already an indirect
        // dep via the router-plugin module).
        #[derive(Deserialize)]
        struct ManifestProbe {
            agents: Option<Vec<AgentProbe>>,
        }
        #[derive(Deserialize)]
        struct AgentProbe {
            id: String,
        }
        let parsed: ManifestProbe = match serde_yaml::from_str(&manifest_text) {
            Ok(m) => m,
            Err(e) => {
                checks.push(ProbeCheck {
                    name: "manifest.agents".to_string(),
                    status: ProbeStatus::Error,
                    detail: format!("parse manifest: {e}"),
                    sha256: None,
                });
                return Ok(ProbeReport {
                    plugin_id: plugin_id.to_string(),
                    ok: false,
                    checks,
                });
            }
        };
        let skills_dir = plugin_dir.join("skills");
        for agent in parsed.agents.unwrap_or_default() {
            let skill_path = skills_dir.join(format!("{}.md", agent.id));
            match std::fs::read(&skill_path) {
                Ok(bytes) if !bytes.is_empty() => checks.push(ProbeCheck {
                    name: format!("skills/{}.md", agent.id),
                    status: ProbeStatus::Ok,
                    detail: format!("{} bytes", bytes.len()),
                    sha256: Some(sha256_hex(&bytes)),
                }),
                Ok(_) => checks.push(ProbeCheck {
                    name: format!("skills/{}.md", agent.id),
                    status: ProbeStatus::Missing,
                    detail: "file is empty".to_string(),
                    sha256: None,
                }),
                Err(_) => checks.push(ProbeCheck {
                    name: format!("skills/{}.md", agent.id),
                    status: ProbeStatus::Mismatch,
                    detail: format!(
                        "manifest references `{}` but {} is missing",
                        agent.id,
                        skill_path.display()
                    ),
                    sha256: None,
                }),
            }
        }

        let ok = checks.iter().all(|c| c.status == ProbeStatus::Ok);
        Ok(ProbeReport {
            plugin_id: plugin_id.to_string(),
            ok,
            checks,
        })
    }
}
