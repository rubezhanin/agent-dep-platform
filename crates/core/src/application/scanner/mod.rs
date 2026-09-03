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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

use crate::error::{CoreError, CoreResult};

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
        // belt-and-suspenders last line. Counts chars (not bytes)
        // so the limit is stable across multi-byte content.
        if reason.chars().count() > 200 {
            let truncated: String = reason.chars().take(200).collect();
            format!("{truncated}…")
        } else {
            reason.to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    // 2.6.0 prompt-injection heuristics (ADR-0024).
    // Block: unambiguous English/Russian patterns
    // that almost never appear in legitimate
    // agent / skill content.
    // Warn:   patterns that are sometimes
    // legitimate (a documentation file can have
    // a ZWJ emoji sequence, a markdown file can
    // have a "## System prompt" heading); the
    // operator reviews.
    RuleSpec {
        id: "prompt-injection.ignore-previous",
        default: Severity::Block,
    },
    RuleSpec {
        id: "prompt-injection.role-override",
        default: Severity::Block,
    },
    RuleSpec {
        id: "prompt-injection.system-prompt-leak",
        default: Severity::Block,
    },
    RuleSpec {
        id: "prompt-injection.jailbreak-dan",
        default: Severity::Block,
    },
    RuleSpec {
        id: "prompt-injection.markdown-system-tag",
        default: Severity::Warn,
    },
    RuleSpec {
        id: "prompt-injection.zero-width-chars",
        default: Severity::Warn,
    },
    // 2.6.1 more complete secret scanner (ADR-0025).
    // All Block — these tokens are
    // credential-equivalent and fail-closed at
    // ingest (ADR-0005 §"fail-closed").
    RuleSpec {
        id: "secret.slack-token",
        default: Severity::Block,
    },
    RuleSpec {
        id: "secret.stripe-key",
        default: Severity::Block,
    },
    RuleSpec {
        id: "secret.google-api-key",
        default: Severity::Block,
    },
    RuleSpec {
        id: "secret.openai-key",
        default: Severity::Block,
    },
    RuleSpec {
        id: "secret.anthropic-key",
        default: Severity::Block,
    },
    RuleSpec {
        id: "secret.jwt",
        default: Severity::Block,
    },
    // 2.6.2 Unicode / confusable analysis
    // (ADR-0026). The homoglyph rule is Block;
    // the bidi-override rule is Warn because
    // some legitimate content (Arabic / Hebrew
    // text in skill descriptions) uses bidi
    // control characters by design.
    RuleSpec {
        id: "confusable.homoglyph",
        default: Severity::Block,
    },
    RuleSpec {
        id: "confusable.bidi-override",
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

// 2.6.0 prompt-injection heuristics (ADR-0024).
// All case-insensitive. The English patterns
// are well-known from public AI red-team
// datasets; the Cyrillic transliterations
// (e.g. "игнорируй" for "ignore") are NOT
// included in 2.6.0 — the ADR defers
// multilingual coverage to 2.7.x because
// adding a Cyrillic block per language
// doubles the regex table.
static PI_IGNORE_PREVIOUS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(ignore|disregard|forget)\s+(all\s+)?(the\s+)?(above|previous|prior|earlier)\s+(instructions?|prompts?|messages?|context)",
    )
    .unwrap()
});
static PI_ROLE_OVERRIDE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b(you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as|pretend\s+(to\s+be|you\s+are)|roleplay\s+as)\b",
    )
    .unwrap()
});
static PI_SYSTEM_PROMPT_LEAK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(reveal|show|print|leak|dump|expose)\s+(your\s+|the\s+)?(system\s+prompt|hidden\s+instructions?|internal\s+prompt|secret\s+instructions?)",
    )
    .unwrap()
});
static PI_JAILBREAK_DAN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b(do\s+anything\s+now|DAN\s+mode|jailbreak\s+mode|developer\s+mode\s+(enabled|on)|unlock\s+mode)\b",
    )
    .unwrap()
});
static PI_MARKDOWN_SYSTEM_TAG_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?im)(^|\n)\s*(\[system\]|###\s*system|<\|system\|>|\[\[system\]\]|##\s*system\s*prompt)",
    )
    .unwrap()
});
static PI_ZERO_WIDTH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[\u{200B}-\u{200F}\u{2028}-\u{202F}\u{205F}-\u{206F}\u{FEFF}]").unwrap()
});

// 2.6.1 more complete secret scanner (ADR-0025).
// All vendor-published formats as of 2026-09.
// Each regex is anchored on the vendor's
// documented prefix to keep false-positive
// surface minimal. Note: the `regex` crate
// forbids variable-width lookbehind after
// `{N,}`, so we disambiguate the OpenAI vs
// Stripe overlap via the `sk-` (dash) vs `sk_`
// (underscore) prefix rather than `(?<!_)`.
static SECRET_SLACK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"xox[baprs]-[A-Za-z0-9-]{10,}").unwrap());
static SECRET_STRIPE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk_(?:live|test)_[A-Za-z0-9]{20,}").unwrap());
static SECRET_GOOGLE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"AIza[A-Za-z0-9_-]{35}").unwrap());
// OpenAI new-format `sk-…` (post-Mar 2024) and
// `sk-proj-…` (project keys). The `sk-` (dash)
// prefix is the discriminator vs. Stripe's
// `sk_` (underscore) — no overlap, no
// lookbehind needed. We allow `-` in the body
// so `sk-proj-…` (the project-key form) matches.
static SECRET_OPENAI_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"sk-[A-Za-z0-9-]{20,}").unwrap());
static SECRET_ANTHROPIC_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk-ant-[A-Za-z0-9_-]{32,}").unwrap());
static SECRET_JWT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap());

// 2.6.2 Unicode / confusable analysis
// (ADR-0026). The homoglyph set is curated to
// the 13 most-common lookalikes from Cyrillic,
// Greek, Hebrew, and Armenian. Full coverage
// of confusables.txt is a 2.7.x release.
static CONFUSABLE_HOMOGLYPH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        "[\u{0430}\u{0435}\u{043E}\u{0440}\u{0441}\u{0445}\u{03BF}\u{03B1}\u{0399}\u{04B0}\u{04CF}\u{05E2}\u{0578}\u{057C}]",
    )
    .unwrap()
});
// Bidi control characters: LRE/RLE/PDF/LRO/RLO
// (U+202A-U+202E) and LRI/RLI/FSI/PDI
// (U+2066-U+2069).
static CONFUSABLE_BIDI_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new("[\u{202A}-\u{202E}\u{2066}-\u{2069}]").unwrap());

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
    (
        "prompt-injection.ignore-previous",
        Severity::Block,
        &PI_IGNORE_PREVIOUS_RE,
    ),
    (
        "prompt-injection.role-override",
        Severity::Block,
        &PI_ROLE_OVERRIDE_RE,
    ),
    (
        "prompt-injection.system-prompt-leak",
        Severity::Block,
        &PI_SYSTEM_PROMPT_LEAK_RE,
    ),
    (
        "prompt-injection.jailbreak-dan",
        Severity::Block,
        &PI_JAILBREAK_DAN_RE,
    ),
    (
        "prompt-injection.markdown-system-tag",
        Severity::Warn,
        &PI_MARKDOWN_SYSTEM_TAG_RE,
    ),
    (
        "prompt-injection.zero-width-chars",
        Severity::Warn,
        &PI_ZERO_WIDTH_RE,
    ),
    // 2.6.1 more complete secret scanner (ADR-0025).
    ("secret.slack-token", Severity::Block, &SECRET_SLACK_RE),
    ("secret.stripe-key", Severity::Block, &SECRET_STRIPE_RE),
    ("secret.google-api-key", Severity::Block, &SECRET_GOOGLE_RE),
    ("secret.openai-key", Severity::Block, &SECRET_OPENAI_RE),
    (
        "secret.anthropic-key",
        Severity::Block,
        &SECRET_ANTHROPIC_RE,
    ),
    ("secret.jwt", Severity::Block, &SECRET_JWT_RE),
    // 2.6.2 Unicode / confusable analysis
    // (ADR-0026).
    (
        "confusable.homoglyph",
        Severity::Block,
        &CONFUSABLE_HOMOGLYPH_RE,
    ),
    (
        "confusable.bidi-override",
        Severity::Warn,
        &CONFUSABLE_BIDI_RE,
    ),
];

// ---------------------------------------------------------------------------
// 2.6.4 SARIF output (ADR-0027)
// ---------------------------------------------------------------------------

/// Map our internal `Severity` to the SARIF
/// `level` enum. We do NOT emit `note` (Pass)
/// findings in the SARIF output — they would
/// inflate the result count without providing
/// signal to CI / IDE consumers.
fn severity_to_sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Block => "error",
        Severity::Warn => "warning",
        Severity::Pass => "note",
    }
}

/// Convert a slice of findings into a SARIF 2.1.0
/// log. The output is a `serde_json::Value` so
/// the caller can serialize it as JSON to stdout,
/// to a file, or to an HTTP response. The
/// `tool.driver` is `agency-scanner`; the version
/// is the `CARGO_PKG_VERSION` of the crate.
///
/// Each unique `rule` becomes one entry in
/// `runs[0].tool.driver.rules[]` with a stable
/// `index`. Each `Finding` becomes one entry in
/// `runs[0].results[]` whose `ruleIndex` points
/// back into the rules table. The `locations`
/// array uses a placeholder
/// `physicalLocation.artifactLocation.uri` (the
/// relative path) and a stub
/// `physicalLocation.region` (line 1) — exact
/// line tracking is a 2.6.x enhancement.
pub fn findings_to_sarif(findings: &[Finding]) -> serde_json::Value {
    // Build a stable (de-duplicated) rule table.
    // The first finding for a given rule id sets
    // the index; later findings for the same rule
    // reference the same index.
    let mut rule_index_by_id: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut rules: Vec<serde_json::Value> = Vec::new();
    for f in findings {
        if rule_index_by_id.contains_key(&f.rule) {
            continue;
        }
        let idx = rules.len();
        rule_index_by_id.insert(f.rule.clone(), idx);
        rules.push(serde_json::json!({
            "id": f.rule,
            "name": f.rule,
            "shortDescription": { "text": f.rule },
            "fullDescription": { "text": f.rule },
            "defaultConfiguration": { "level": severity_to_sarif_level(f.severity) },
        }));
    }
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let rule_index = rule_index_by_id.get(&f.rule).copied().unwrap_or(0);
            serde_json::json!({
                "ruleId": f.rule,
                "ruleIndex": rule_index,
                "level": severity_to_sarif_level(f.severity),
                "message": { "text": f.reason },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.path },
                        "region": { "startLine": 1, "endLine": 1 }
                    }
                }]
            })
        })
        .collect();
    serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "agency-scanner",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/rubezhanin/agent-dep-platform",
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}

// ---------------------------------------------------------------------------
// 2.7.0 third-party scanner plugins (ADR-0028)
// ---------------------------------------------------------------------------

pub mod plugin;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "scanner_tests.rs"]
mod scanner_tests;
