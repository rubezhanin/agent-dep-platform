//! 2.7.4 dynamic LLM probe (ADR-0032).
//!
//! Extends the 1.4.0 structural probe with a
//! semantic review by an external LLM. The
//! LLM is hidden behind a `LlmClient` trait
//! so tests can mock it.

use agent_dep_core::error::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};

use crate::hermes_adapter::{ProbeCheck, ProbeReport, ProbeStatus};

/// Provider abstraction. Tests supply a
/// `MockLlmClient`; production uses
/// `OpenAiCompatibleClient`.
pub trait LlmClient: Send + Sync {
    /// Send `prompt` and return the assistant
    /// text. Implementations are expected to
    /// be synchronous from the probe's POV;
    /// `OpenAiCompatibleClient` uses a
    /// blocking `reqwest::blocking` client
    /// internally so the probe can run
    /// without a tokio runtime.
    fn complete(&self, prompt: &str) -> CoreResult<String>;
}

/// Configuration for the OpenAI-compatible
/// client. All fields can be overridden via
/// env vars: `AGENCY_LLM_ENDPOINT`,
/// `AGENCY_LLM_MODEL`, `AGENCY_LLM_API_KEY`.
#[derive(Debug, Clone)]
pub struct OpenAiConfig {
    pub endpoint: String,
    pub model: String,
    pub api_key: Option<String>,
}

impl OpenAiConfig {
    /// Read config from environment variables,
    /// falling back to Ollama's defaults.
    pub fn from_env() -> Self {
        Self {
            endpoint: std::env::var("AGENCY_LLM_ENDPOINT").unwrap_or_else(|_| {
                "http://localhost:11434/v1/chat/completions".to_string()
            }),
            model: std::env::var("AGENCY_LLM_MODEL")
                .unwrap_or_else(|_| "llama3.2".to_string()),
            api_key: std::env::var("AGENCY_LLM_API_KEY").ok(),
        }
    }
}

/// Blocking OpenAI-compatible client. The
/// `endpoint` must accept POST
/// `{endpoint}` with body
/// `{"model": ..., "messages": [{"role":
/// "user", "content": ...}]}` and return
/// `{"choices": [{"message": {"content":
/// "..."}}]}`. Works for OpenAI, Anthropic
/// (via openai-compat proxy), and Ollama.
pub struct OpenAiCompatibleClient {
    http: reqwest::blocking::Client,
    cfg: OpenAiConfig,
}

impl OpenAiCompatibleClient {
    pub fn new(cfg: OpenAiConfig) -> Self {
        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .expect("reqwest client builder");
        Self { http, cfg }
    }
}

impl LlmClient for OpenAiCompatibleClient {
    fn complete(&self, prompt: &str) -> CoreResult<String> {
        let body = serde_json::json!({
            "model": self.cfg.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0,
        });
        let mut req = self.http.post(&self.cfg.endpoint).json(&body);
        if let Some(key) = &self.cfg.api_key {
            req = req.bearer_auth(key);
        }
        let resp = req
            .send()
            .map_err(|e| CoreError::ErrIo(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("LLM POST: {e}"),
            )))?
            .error_for_status()
            .map_err(|e| CoreError::ErrIo(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("LLM status: {e}"),
            )))?;
        let v: serde_json::Value = resp.json().map_err(|e| {
            CoreError::ErrIo(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("LLM JSON: {e}"),
            ))
        })?;
        v.get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c0| c0.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| CoreError::ErrSchemaInvalid {
                path: "llm.response".to_string(),
                reason: format!(
                    "LLM response missing choices[0].message.content: {v}"
                ),
            })
    }
}

/// A canned LLM response for tests.
pub struct MockLlmClient {
    pub response: String,
}

impl LlmClient for MockLlmClient {
    fn complete(&self, _prompt: &str) -> CoreResult<String> {
        Ok(self.response.clone())
    }
}

/// Dynamic LLM probe. Takes the structural
/// `ProbeReport` plus the manifest and
/// SKILL.md text, asks the LLM, and returns
/// a new `ProbeReport` with the structural
/// checks plus one `llm_review` check.
pub struct LlmProbe {
    client: Box<dyn LlmClient>,
}

impl LlmProbe {
    pub fn new(client: Box<dyn LlmClient>) -> Self {
        Self { client }
    }

    /// Build the prompt sent to the LLM. Pure
    /// function — exposed for tests.
    pub fn build_prompt(structural: &ProbeReport, manifest: &str, skill: &str) -> String {
        let summary = if structural.ok {
            "PASSED".to_string()
        } else {
            let mut s = String::from("FAILED:\n");
            for c in &structural.checks {
                if c.status != ProbeStatus::Ok {
                    s.push_str(&format!("  - {} [{}]: {}\n", c.name, status_str(c.status), c.detail));
                }
            }
            s
        };
        format!(
            "You are auditing a Hermes 0.21+ router plugin \
             (manifest.yaml + SKILL.md).\n\
             Identify ONLY these problems:\n\
             1. Manifest references an agent that SKILL.md does not document.\n\
             2. SKILL.md contradicts the manifest's stated role / tools.\n\
             3. Any other obvious inconsistency between manifest and SKILL.md.\n\
             Do NOT duplicate the structural checks below.\n\
             Respond with strict JSON only:\n\
             {{\"ok\": bool, \"detail\": \"<=200 chars\"}}\n\
             No prose outside the JSON.\n\n\
             === manifest.yaml ===\n{manifest}\n\n\
             === SKILL.md ===\n{skill}\n\n\
             === structural probe ===\n{summary}\n"
        )
    }

    /// Parse the LLM response. Returns a
    /// `ProbeCheck` reflecting the verdict.
    /// Malformed JSON → `Error` check with a
    /// short excerpt of the bad response.
    pub fn parse_response(response: &str) -> ProbeCheck {
        // Try to find a JSON object in the
        // response. The LLM is told to respond
        // with strict JSON only, but a real LLM
        // might wrap the JSON in prose.
        let trimmed = response.trim();
        let json_start = trimmed.find('{');
        let json_end = trimmed.rfind('}');
        let candidate = match (json_start, json_end) {
            (Some(s), Some(e)) if e > s => &trimmed[s..=e],
            _ => trimmed,
        };
        match serde_json::from_str::<LlmVerdict>(candidate) {
            Ok(v) => {
                if v.ok {
                    ProbeCheck {
                        name: "llm_review".to_string(),
                        status: ProbeStatus::Ok,
                        detail: truncate(&v.detail, 200),
                        sha256: None,
                    }
                } else {
                    ProbeCheck {
                        name: "llm_review".to_string(),
                        status: ProbeStatus::Error,
                        detail: truncate(&v.detail, 200),
                        sha256: None,
                    }
                }
            }
            Err(_) => ProbeCheck {
                name: "llm_review".to_string(),
                status: ProbeStatus::Error,
                detail: format!("LLM returned non-JSON: {}", truncate(trimmed, 200)),
                sha256: None,
            },
        }
    }

    /// Extend the structural report with the
    /// LLM check. The new report has all
    /// structural checks plus the
    /// `llm_review` check.
    pub fn extend(
        &self,
        structural: ProbeReport,
        manifest: &str,
        skill: &str,
    ) -> CoreResult<ProbeReport> {
        let prompt = Self::build_prompt(&structural, manifest, skill);
        let response = self.client.complete(&prompt)?;
        let check = Self::parse_response(&response);
        let mut checks = structural.checks.clone();
        let llm_ok = check.status == ProbeStatus::Ok;
        checks.push(check);
        let ok = structural.ok && llm_ok;
        Ok(ProbeReport {
            plugin_id: structural.plugin_id,
            ok,
            checks,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct LlmVerdict {
    ok: bool,
    #[serde(default)]
    detail: String,
}

fn truncate(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max).collect();
        format!("{truncated}…")
    }
}

fn status_str(s: ProbeStatus) -> &'static str {
    match s {
        ProbeStatus::Ok => "OK",
        ProbeStatus::Missing => "MISSING",
        ProbeStatus::Mismatch => "MISMATCH",
        ProbeStatus::Error => "ERROR",
    }
}

#[cfg(test)]
#[path = "llm_probe_tests.rs"]
mod tests;
