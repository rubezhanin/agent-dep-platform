//! `agency hermes ...` — Flow A plugin lifecycle on a
//! Hermes install. 1.4.0 ships only the `probe`
//! subcommand (ADR-0012 structural probe).
//! 2.7.4 (ADR-0032) extends it with an LLM-based
//! semantic review via the `--llm` flag.

use std::path::PathBuf;

use agent_dep_hermes_adapter::hermes_adapter::{HermesAdapter, ProbeReport, ProbeStatus};
use agent_dep_hermes_adapter::llm_probe::{
    LlmProbe, MockLlmClient, OpenAiCompatibleClient, OpenAiConfig,
};
use anyhow::{Context, Result};

use crate::output;

/// Summary returned from `probe_at` so tests can assert
/// without re-parsing stdout.
#[derive(Debug, Clone)]
pub struct ProbeSummary {
    pub plugin_id: String,
    pub ok: bool,
    pub report: ProbeReport,
    pub hermes_home: PathBuf,
}

/// CLI entry point.
pub async fn probe(plugin_id: String, with_llm: bool) -> Result<()> {
    let hermes_home = crate::data_dir::default_hermes_home();
    let summary = if with_llm {
        probe_at_with_llm(&plugin_id, &hermes_home)?
    } else {
        probe_at(&plugin_id, &hermes_home)?
    };
    print_report(&summary);
    if summary.ok {
        Ok(())
    } else {
        // Surface a non-zero exit code so CI / cron can
        // detect a degraded install. The actual error
        // message was already printed by `print_report`.
        std::process::exit(1);
    }
}

/// Pure orchestration: build the adapter, run the
/// structural probe, return the summary.
pub fn probe_at(plugin_id: &str, hermes_home: &PathBuf) -> Result<ProbeSummary> {
    if !hermes_home.exists() {
        std::fs::create_dir_all(hermes_home)
            .with_context(|| format!("create_dir_all {}", hermes_home.display()))?;
    }
    let adapter = HermesAdapter::new(hermes_home.clone());
    let report = adapter
        .probe(plugin_id)
        .with_context(|| format!("probe `{}`", plugin_id))?;
    Ok(ProbeSummary {
        plugin_id: plugin_id.to_string(),
        ok: report.ok,
        report,
        hermes_home: hermes_home.clone(),
    })
}

/// 2.7.4 (ADR-0032): structural probe +
/// LLM-based semantic review. Reads the
/// manifest.yaml and SKILL.md from the plugin
/// directory and asks the LLM to flag
/// semantic inconsistencies.
pub fn probe_at_with_llm(plugin_id: &str, hermes_home: &PathBuf) -> Result<ProbeSummary> {
    let structural_summary = probe_at(plugin_id, hermes_home)?;
    let plugin_dir = hermes_home.join("plugins").join(plugin_id);
    let manifest_path = plugin_dir.join("manifest.yaml");
    let skill_path = plugin_dir.join("SKILL.md");
    let manifest_text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("read manifest {}", manifest_path.display()))?;
    let skill_text = std::fs::read_to_string(&skill_path)
        .with_context(|| format!("read SKILL.md {}", skill_path.display()))?;
    // The LLM client is chosen at runtime by
    // env vars. `OpenAiConfig::from_env` reads
    // `AGENCY_LLM_ENDPOINT`,
    // `AGENCY_LLM_MODEL`, `AGENCY_LLM_API_KEY`.
    // A test override is also supported via
    // `AGENCY_LLM_MOCK_RESPONSE`.
    let mock_response = std::env::var("AGENCY_LLM_MOCK_RESPONSE").ok();
    let client: Box<dyn agent_dep_hermes_adapter::llm_probe::LlmClient> = match mock_response {
        Some(r) => Box::new(MockLlmClient { response: r }),
        None => Box::new(OpenAiCompatibleClient::new(OpenAiConfig::from_env())),
    };
    let probe = LlmProbe::new(client);
    let extended = probe
        .extend(
            structural_summary.report.clone(),
            &manifest_text,
            &skill_text,
        )
        .map_err(|e| anyhow::anyhow!("LLM probe failed: {e}"))?;
    Ok(ProbeSummary {
        plugin_id: plugin_id.to_string(),
        ok: extended.ok,
        report: extended,
        hermes_home: hermes_home.clone(),
    })
}

fn print_report(s: &ProbeSummary) {
    let i = agent_dep_core::i18n::I18n::from_env();
    output::header(&i.tr("cli.hermes.probe.header", &[("name", &s.plugin_id)]));
    output::kv(
        &i.t("cli.hermes.kv.hermes_home"),
        &s.hermes_home.display().to_string(),
    );
    output::kv(&i.t("cli.hermes.kv.ok"), &s.ok.to_string());
    for c in &s.report.checks {
        let status = match c.status {
            ProbeStatus::Ok => "OK",
            ProbeStatus::Missing => "MISSING",
            ProbeStatus::Mismatch => "MISMATCH",
            ProbeStatus::Error => "ERROR",
        };
        let sha = c
            .sha256
            .as_ref()
            .map(|s| format!("  sha={}", &s[..16]))
            .unwrap_or_default();
        println!("  [{}] {} — {}{}", status, c.name, c.detail, sha);
    }
    if !s.ok {
        eprintln!("{}", i.t("cli.hermes.probe.failed"));
    }
}
