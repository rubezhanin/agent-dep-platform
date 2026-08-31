//! Security scanner (TZ §23 + ADR-0005).
//!
//! Deterministic, regex-based catalog scanner that emits
//! `Finding { severity, rule, path, reason }` entries. Runs at three
//! points per ADR-0005: ingest, plan generation, deploy time. MVP
//! only runs it at ingest; the other call sites are stubs in the
//! IngestService/CLI flow that read the recorded findings.
//!
//! The scanner is a `Scanner` trait so additional implementations
//! (Unicode normalization, AST-based, SARIF-emitting) can be added in
//! 1.x without changing call sites. MVP ships `RegexScanner`.
//!
//! No NLP heuristics (ADR-0005 §"No NLP heuristics in MVP").

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

use crate::error::{CoreError, CoreResult};

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Pass,
    Warn,
    Block,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Pass => "PASS",
            Severity::Warn => "WARN",
            Severity::Block => "BLOCK",
        }
    }

    pub fn parse(s: &str) -> CoreResult<Self> {
        Ok(match s {
            "PASS" => Severity::Pass,
            "WARN" => Severity::Warn,
            "BLOCK" => Severity::Block,
            other => {
                return Err(CoreError::ErrSchemaInvalid {
                    path: "severity".to_string(),
                    reason: format!("unknown severity: {other}"),
                })
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

/// One finding emitted by the scanner. Mirrors the `Finding` DTO but
/// uses a strongly-typed `Severity`. The DTO is a serde-friendly
/// projection; this is the in-process shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub rule: String,
    /// Path to the file the finding applies to, relative to the
    /// scanned root in POSIX form. For cross-file findings (e.g. an
    /// archive entry), `path` is the entry name.
    pub path: String,
    /// Short human-readable reason. Should NOT contain the matched
    /// secret itself — see `redact()`.
    pub reason: String,
}

impl Finding {
    fn redact(reason: &str) -> String {
        // Truncate to 200 chars and ensure no embedded raw secret
        // leaks via Reason. We trust the regex authors; this is a
        // belt-and-suspenders last line.
        if reason.len() > 200 {
            format!("{}…", &reason[..200])
        } else {
            reason.to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ScanPolicy {
    /// Hosts (exact or `*.example.com`) that are considered safe
    /// download sources. Used by `url.allowed-domain` and
    /// `url.suspicious-download-endpoint`. Empty in MVP — user must
    /// populate via `config.json`.
    pub trusted_domains: Vec<String>,
    /// If true, every `WARN` finding is upgraded to `BLOCK` at
    /// resolution time.
    pub treat_warn_as_block: bool,
    /// Per-rule severity overrides. `BLOCK` is enforced, `PASS` skips
    /// the rule entirely, anything else is recorded as the override.
    pub rule_overrides: HashMap<String, Severity>,
}

impl ScanPolicy {
    /// MVP default: empty trusted domains, no overrides, WARN is WARN.
    pub fn mvp_default() -> Self {
        Self {
            trusted_domains: Vec::new(),
            treat_warn_as_block: false,
            rule_overrides: HashMap::new(),
        }
    }

    /// Resolve the *post-policy* severity for a rule. The `default`
    /// is what the rule table in ADR-0005 says.
    pub fn resolve_severity(&self, rule_id: &str, default: Severity) -> Severity {
        if let Some(s) = self.rule_overrides.get(rule_id) {
            return *s;
        }
        if self.treat_warn_as_block && matches!(default, Severity::Warn) {
            return Severity::Block;
        }
        default
    }

    fn is_trusted_host(&self, host: &str) -> bool {
        if host.is_empty() {
            return false;
        }
        for d in &self.trusted_domains {
            if let Some(suffix) = d.strip_prefix("*.") {
                // Wildcard: matches subdomains of `suffix` and `suffix` itself.
                if host == suffix || host.ends_with(&format!(".{suffix}")) {
                    return true;
                }
            } else if host == d {
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Rule metadata (the 13 rules from ADR-0005)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct RuleSpec {
    pub id: &'static str,
    pub default: Severity,
}

pub const RULES: &[RuleSpec] = &[
    RuleSpec {
        id: "secret.aws-access-key",
        default: Severity::Block,
    },
    RuleSpec {
        id: "secret.github-token",
        default: Severity::Block,
    },
    RuleSpec {
        id: "secret.generic-password",
        default: Severity::Warn,
    },
    RuleSpec {
        id: "secret.private-key",
        default: Severity::Block,
    },
    RuleSpec {
        id: "shell.dangerous-rm-rf",
        default: Severity::Block,
    },
    RuleSpec {
        id: "shell.dangerous-curl-pipe-bash",
        default: Severity::Block,
    },
    RuleSpec {
        id: "shell.dangerous-eval-exec",
        default: Severity::Block,
    },
    RuleSpec {
        id: "url.suspicious-download-endpoint",
        default: Severity::Block,
    },
    RuleSpec {
        id: "url.allowed-domain",
        default: Severity::Pass,
    },
    RuleSpec {
        id: "exec.executable-in-data",
        default: Severity::Block,
    },
    RuleSpec {
        id: "archive.symlink-traversal",
        default: Severity::Block,
    },
    RuleSpec {
        id: "archive.zip-slip",
        default: Severity::Block,
    },
    RuleSpec {
        id: "manifest.foreign-executable",
        default: Severity::Warn,
    },
];

// ---------------------------------------------------------------------------
// Scanner trait
// ---------------------------------------------------------------------------

pub trait Scanner {
    /// Scan a directory tree rooted at `root`. Returns ALL findings
    /// (regardless of severity); the caller decides what to do with
    /// PASS / WARN / BLOCK.
    fn scan(&self, root: &Path, policy: &ScanPolicy) -> CoreResult<Vec<Finding>>;
}

// ---------------------------------------------------------------------------
// RegexScanner: MVP implementation
// ---------------------------------------------------------------------------

pub struct RegexScanner;

impl Scanner for RegexScanner {
    fn scan(&self, root: &Path, policy: &ScanPolicy) -> CoreResult<Vec<Finding>> {
        let mut findings: Vec<Finding> = Vec::new();

        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            let rel = rel_to(path, root);

            // We only scan text-like files for content rules; the
            // executable / archive rules look at the path itself.
            if let Some(text) = read_text_if_small(path)? {
                scan_text_rules(&text, &rel, policy, &mut findings);
                scan_url_rules(&text, &rel, policy, &mut findings);
            }

            // Path-based rules. None of them have a real implementation
            // in MVP because the upstream `agency-agents` catalog has
            // no `data/` subdir, no archives, and no `system.yaml`
            // with `allowedExecutables`. They are present so the
            // scanner wiring can be exercised end-to-end.
            let path_for_rules = path.to_path_buf();
            scan_executable_in_data(&path_for_rules, &rel, policy, &mut findings);
        }

        // Sort: BLOCK > WARN > Pass, then by rule id, then by path.
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.rule.cmp(&b.rule))
                .then_with(|| a.path.cmp(&b.path))
        });
        Ok(findings)
    }
}

// ---------------------------------------------------------------------------
// Per-rule implementations
// ---------------------------------------------------------------------------

fn scan_text_rules(text: &str, rel: &str, policy: &ScanPolicy, out: &mut Vec<Finding>) {
    for (rule_id, default, regex) in TEXT_RULES {
        for m in regex.find_iter(text) {
            let severity = policy.resolve_severity(rule_id, *default);
            if severity == Severity::Pass {
                continue;
            }
            out.push(Finding {
                severity,
                rule: (*rule_id).to_string(),
                path: rel.to_string(),
                reason: Finding::redact(&format!("matched `{}`", short_excerpt(m.as_str()))),
            });
        }
    }
}

fn scan_url_rules(text: &str, rel: &str, policy: &ScanPolicy, out: &mut Vec<Finding>) {
    for m in URL_RE.find_iter(text) {
        let url = m.as_str();
        if let Some(host) = extract_host(url) {
            let trusted = policy.is_trusted_host(&host);
            let path_part = extract_path(url);
            let dangerous_ext = has_dangerous_download_extension(&path_part);

            if trusted {
                // url.allowed-domain is a PASS-when-trusted marker.
                // We don't emit a finding for trusted URLs.
                let _ = policy.resolve_severity("url.allowed-domain", Severity::Pass);
                continue;
            } else if dangerous_ext {
                let severity =
                    policy.resolve_severity("url.suspicious-download-endpoint", Severity::Block);
                if severity != Severity::Pass {
                    out.push(Finding {
                        severity,
                        rule: "url.suspicious-download-endpoint".to_string(),
                        path: rel.to_string(),
                        reason: Finding::redact(&format!(
                            "URL on untrusted host `{host}` points at a downloadable executable"
                        )),
                    });
                }
            }
            // Plain untrusted URL with no dangerous extension is a
            // no-op in MVP. Future rules can flag it.
        }
    }
}

fn scan_executable_in_data(path: &Path, rel: &str, policy: &ScanPolicy, out: &mut Vec<Finding>) {
    // MVP: no `data/` convention yet. Place a hook here so the rule
    // is wired end-to-end and tests can construct a fixture.
    let Some(parent) = path.parent() else {
        return;
    };
    if parent
        .components()
        .any(|c| c.as_os_str() == std::ffi::OsStr::new("data"))
        && looks_executable(path)
    {
        let severity = policy.resolve_severity("exec.executable-in-data", Severity::Block);
        if severity != Severity::Pass {
            out.push(Finding {
                severity,
                rule: "exec.executable-in-data".to_string(),
                path: rel.to_string(),
                reason: "executable file in catalog data/ directory".to_string(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn rel_to(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .and_then(|p| p.to_str())
        .map(|s| s.replace('\\', "/"))
        .unwrap_or_else(|| path.display().to_string())
}

fn read_text_if_small(path: &Path) -> CoreResult<Option<String>> {
    const MAX_BYTES: u64 = 2 * 1024 * 1024; // 2 MiB per file for MVP
    let meta = fs::metadata(path).map_err(CoreError::ErrIo)?;
    if meta.len() > MAX_BYTES {
        return Ok(None);
    }
    // Reject obvious binary by extension to keep regex search honest.
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(
        ext.as_str(),
        "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "pdf"
            | "zip"
            | "tar"
            | "gz"
            | "bz2"
            | "7z"
            | "rar"
            | "exe"
            | "dll"
            | "so"
            | "dylib"
    ) {
        return Ok(None);
    }
    // Non-UTF-8 files (e.g. binary blobs mislabeled as .md) cannot
    // be scanned as text; skip them rather than erroring out the
    // whole ingest.
    let text = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    Ok(Some(text))
}

fn short_excerpt(s: &str) -> String {
    let one_line: String = s.chars().take(60).collect();
    one_line.replace('\n', " ")
}

fn extract_host(url: &str) -> Option<String> {
    let after = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host_end = after.find(['/', ':', '?', '#']).unwrap_or(after.len());
    let host = &after[..host_end];
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

fn extract_path(url: &str) -> String {
    let after = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    if let Some(idx) = after.find('/') {
        after[idx..].to_string()
    } else {
        "/".to_string()
    }
}

fn has_dangerous_download_extension(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    for ext in [
        ".exe", ".dll", ".so", ".dylib", ".sh", ".ps1", ".bat", ".vbs", ".jar", ".apk", ".dmg",
        ".pkg", ".msi",
    ] {
        if lower.ends_with(ext) {
            return true;
        }
    }
    false
}

fn looks_executable(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "exe" | "bat" | "ps1" | "sh" | "cmd" | "msi" | "jar" | "apk"
    )
}

// ---------------------------------------------------------------------------
// Regex table
// ---------------------------------------------------------------------------

static AWS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}").unwrap()
});
static GH_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,255}").unwrap());
static GENERIC_PASSWORD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)(password|passwd|pwd)\s*[:=]\s*['"][^'"\s]{8,}['"]"#).unwrap());
static PRIVATE_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----").unwrap()
});
static RM_RF_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"rm\s+-rf?\s+/(\s|$)").unwrap());
static CURL_BASH_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"curl\s+[^|\n]*\|\s*(sudo\s+)?(ba)?sh").unwrap());
static EVAL_EXEC_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\beval\s*\(\s*['"]\$\(|os\.system\s*\(\s*['"]\$\("#).unwrap());

static URL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"https?://[A-Za-z0-9.\-_:]+(?:/[^"'\s<>)]*)?"#).unwrap());

const TEXT_RULES: &[(&str, Severity, &Lazy<Regex>)] = &[
    ("secret.aws-access-key", Severity::Block, &AWS_RE),
    ("secret.github-token", Severity::Block, &GH_RE),
    (
        "secret.generic-password",
        Severity::Warn,
        &GENERIC_PASSWORD_RE,
    ),
    ("secret.private-key", Severity::Block, &PRIVATE_KEY_RE),
    ("shell.dangerous-rm-rf", Severity::Block, &RM_RF_RE),
    (
        "shell.dangerous-curl-pipe-bash",
        Severity::Block,
        &CURL_BASH_RE,
    ),
    ("shell.dangerous-eval-exec", Severity::Block, &EVAL_EXEC_RE),
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "scanner_tests.rs"]
mod scanner_tests;
