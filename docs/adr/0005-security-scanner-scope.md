# ADR-0005: Security Scanner Scope

- **Status**: Accepted
- **Date**: 2026-08-31
- **Supersedes**: TZ §23 ("Security scanning") by fixing the rule set,
  severity model, and what we explicitly do **not** do in MVP.

## Context and Problem Statement

The TZ §23.1 enumerates six MVP "deterministic static checks":

1. plaintext credential patterns
2. private key markers
3. explicit dangerous shell execution patterns
4. suspicious external URLs
5. executable files in places where they aren't allowed by the manifest
6. malformed archive / symlink traversal

Severity is three-valued: `PASS`, `WARN`, `BLOCK` (TZ §23.1).

Trusted domains (TZ §23.2): external URLs are `allowed by explicit
policy` or `WARN` or `BLOCK`; default for enterprise-oriented profile
is `BLOCK` unknown external download endpoints.

Advanced scanning (TZ §23.3, deferred to 1.x/2.x): fuller secret
scanner, Unicode/confusable analysis, prompt-injection heuristics,
SARIF output, third-party scanner plugins.

This ADR fixes:

- The rule set (what is `PASS` / `WARN` / `BLOCK` by default).
- Where the scanner runs (catalog ingestion vs. plan generation vs.
  deploy time).
- The extensibility story for 1.x and 2.x.

## Decision

### The scanner runs at three points

1. **Catalog ingestion** (when a source snapshot is first read):
   fast, surface-level checks to reject obviously-malicious catalogs
   *before* they're indexed. Findings are recorded; BLOCK prevents
   the snapshot from being marked `active`.
2. **Plan generation** (before a deploy): same checks re-run against
   the *resolved* content (after lock and CAS), so a fresh finding
   blocks the plan with a clear "rejected by security scanner" line.
3. **Deploy time** (commit): BLOCK findings are enforced. WARN
   findings are surfaced but do not block unless the policy says
   `treat_warn_as_block: true`.

The same engine runs at all three points. The difference is
strictness: ingestion can be strict (we don't want bad data in the
catalog), deploy can be the strictest (we're about to execute it).

### MVP rule set

The following is the MVP rule set, with default severity. Policy can
override each rule's severity in `config.json`.

| # | Rule id | Pattern / check | Default severity |
|---|---|---|---|
| 1 | `secret.aws-access-key` | `(A3T[A-Z0-9]\|AKIA\|AGPA\|AIDA\|AROA\|AIPA\|ANPA\|ANVA\|ASIA)[A-Z0-9]{16}` | BLOCK |
| 2 | `secret.github-token` | `gh[pousr]_[A-Za-z0-9_]{36,255}` | BLOCK |
| 3 | `secret.generic-password` | `(password\|passwd\|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]` (heuristic, high false-positive) | WARN |
| 4 | `secret.private-key` | `-----BEGIN (RSA \|EC \|DSA \|OPENSSH \|PGP )?PRIVATE KEY( BLOCK)?-----` | BLOCK |
| 5 | `shell.dangerous-rm-rf` | `rm\s+-rf?\s+/\s` (rm -rf / variants) | BLOCK |
| 6 | `shell.dangerous-curl-pipe-bash` | `curl\s+[^|]*\|\s*(sudo\s+)?(ba)?sh` | BLOCK |
| 7 | `shell.dangerous-eval-exec` | `\beval\s*\(\s*['\"]\$\(` or `os\.system\s*\(\s*['\"]\$\(` | BLOCK |
| 8 | `url.suspicious-download-endpoint` | URL on a TLD/host NOT in `config.json:security.trustedDomains` AND path ends in `.(exe\|dll\|so\|dylib\|sh\|ps1\|bat\|vbs\|jar\|apk\|dmg\|pkg\|msi)` | BLOCK (default enterprise profile) |
| 9 | `url.allowed-domain` | URL on a TLD/host IN `config.json:security.trustedDomains` | PASS |
| 10 | `exec.executable-in-data` | Path matches `<catalog>/data/**` and file is executable (Unix `+x` or Windows extension `.exe`/`.bat`/`.ps1`/`.sh`/`.cmd`) | BLOCK |
| 11 | `archive.symlink-traversal` | Archive entry whose name is `../` or absolute path | BLOCK |
| 12 | `archive.zip-slip` | Archive entry whose extracted path escapes the extraction root (the classic zip-slip; we canonicalize and check) | BLOCK |
| 13 | `manifest.foreign-executable` | File with executable bit set but NOT in `system.yaml:spec.allowedExecutables` | WARN |

### Severity override policy

`config.json`:

```json
{
  "security": {
    "trustedDomains": [
      "github.com",
      "raw.githubusercontent.com",
      "*.ghe.local"
    ],
    "treatWarnAsBlock": false,
    "rules": {
      "secret.generic-password": "WARN",
      "url.suspicious-download-endpoint": "BLOCK"
    }
  }
}
```

Rules that the user sets to BLOCK are enforced; rules set to PASS
are skipped entirely. The default is what the rule table above
shows; user overrides are merged on top.

### Output

Findings are emitted as `ScanResult` (already in `core::dto`):

```rust
pub struct Finding {
    pub severity: String, // "PASS" | "WARN" | "BLOCK"
    pub rule: String,
    pub path: String,
    pub reason: String,
}
```

The `severity` is the *post-policy* severity (the user's override
applied), not the rule's default. The `rule` field carries the rule
id for traceability.

### No NLP heuristics in MVP

The TZ §23.3 lists "prompt-injection heuristics" as 1.x/2.x. We do
**not** ship any of these in MVP. A scanning pass that uses an LLM
to "summarize a file looking for prompt injection" is:

- non-deterministic (different runs of the same file can produce
  different results),
- expensive (one LLM call per file),
- opaque (no audit trail beyond the LLM's output).

The MVP scanner is fully deterministic, regex/AST-based, and has
tests for every rule. If a real prompt-injection vector makes it
through, that's a 1.x feature with proper test coverage, not a
silent MVP risk.

### Extensibility

The scanner is implemented as a trait `Scanner` with one method
`scan(&Path) -> Vec<Finding>`. MVP ships a `RegexScanner` implementing
this trait. 1.x can ship additional `Scanner` impls (Unicode
normalization, AST-based, SARIF-emitting) without changing the call
sites. The policy + severity logic is shared.

## Consequences

### Positive

- Clear, auditable, deterministic: every finding has a rule id and a
  pattern (or a description for AST-based rules). Users can audit
  the scanner.
- Three integration points (ingest, plan, deploy) catch issues at
  the earliest possible time, and the deploy-time check is the last
  gate.
- Severity is policy-driven and overrideable; an enterprise can
  raise the floor (more BLOCK) or lower it (more PASS) without
  recompiling.

### Negative

- Regex-based detection is brittle. AWS access key regexes are
  well-known; generic-password is heuristic and noisy. We accept
  false positives (WARN) and accept false negatives (a determined
  attacker can obscure a key in base64 or in a comment block).
- Default trusted-domains list is empty in MVP; the user must
  populate it for the scanner to allow any URL. This is safe but
  creates friction on first run; we mitigate with a single prompt
  during initial setup.
- No SARIF output in MVP; security teams that consume SARIF in their
  CI cannot integrate directly. 1.x.

### Neutral

- The scanner runs on our app's process; for a 100MB catalog the
  scan completes in seconds. For 1GB+ catalogs, we may need to move
  to a streaming scanner (1.x).
- The rule set is closed in MVP; adding rules is a code change, not
  a config change. A future version may support user-defined rules
  via a JSON DSL (deferred).

## Alternatives considered

1. **Skip the scanner entirely in MVP, defer to 1.x.**
   - Rejected. The TZ §23.1 lists it as a MUST HAVE, and the BLOCK
     severity is a load-bearing safety guarantee for the "fail
     closed" principle (TZ principle I13).

2. **Ship a "use a third-party scanner like `osv-scanner`" integration.**
   - Rejected for MVP. Adds an external dependency, platform-specific
     binaries, supply-chain surface. We can add it in 1.x as an
     optional plug-in scanner (the `Scanner` trait above).

3. **Use an LLM for scanning (call the user's configured model).**
   - Rejected. See "No NLP heuristics" above. The MVP scanner is
     deterministic; the LLM scanner is 2.x and is opt-in, behind a
     per-source policy.

4. **Make the scanner run in a separate process for isolation.**
   - Rejected for MVP. The scanner is a regex pass over file
     contents; the security boundary is the FS sandbox (TZ §25).
     For 1.x, a separate process becomes interesting only when we
     start running untrusted catalog code in a sandbox; not the
     case in MVP.

## References

- TZ §23.1 (MVP deterministic checks)
- TZ §23.2 (Trusted domains)
- TZ §23.3 (Advanced scanning, deferred)
- TZ §25 (Hermes security integration)
- TZ §1.1.13 (Fail closed)
- TZ §20.3 (Remediation policy)
- ADR-0001 (Hermes protocol)
- ADR-0004 (local storage boundary)
- `crates/core/src/dto.rs` (`ScanResult`, `Finding`)
