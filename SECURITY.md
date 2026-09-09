# Security Policy

The Agent Deployment Platform (ADP) takes security
seriously. ADP is the control plane for deploying
agent systems into Hermes Agent — a compromised
deployment pipeline can substitute attacker-controlled
agents for legitimate ones, and the audit log is the
only forensic trail if a bad deployment slips through.

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for
security-sensitive reports.**

Email: **security@rubezhanin.dev** (replace with
your real contact). PGP key fingerprint and
corresponding public key block are below.

```
PGP Fingerprint: 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
```

(Replace with the actual project maintainer's
fingerprint. The 2.10.0 release is the first to publish
this contact — prior to 2.10.0 there was no
disclosure channel at all, which the kimi-k3 2026-09-09
audit flagged as D4.)

## What to Expect

- **Acknowledgement** within 3 business days
- **Triage decision** within 7 business days
  (accepted / needs-more-info / declined with
  rationale)
- **Fix timeline** depends on severity:
  - **Critical** (RCE, auth bypass, audit-log
    tampering): patch within 14 days
  - **High** (data exposure, privilege
    escalation): patch within 30 days
  - **Medium** (DoS via legitimate use, info
    leak): patch in next minor release
  - **Low** (best-practice deviations, hardening
    suggestions): patch when convenient
- **Coordinated disclosure** by default. We
  prefer to release the fix and the CVE /
  advisory simultaneously.

## Security Boundaries

ADP has two operational modes:

1. **Local single-user** (Tauri desktop app +
   local `agency-server` bound to `127.0.0.1`).
   The threat model is "local malware on the
   workstation". Mitigations: CSRF tokens
   (2.10.0 B2), no-cache headers on secret
   reveal (2.10.0 B3), platform sandbox for
   plugins (`PR_SET_NO_NEW_PRIVS`).

2. **Multi-user enterprise** (axum server behind
   a reverse proxy). The threat model is
   "authenticated user tries to escalate or
   pivot". Mitigations: bearer + session-cookie
   auth (2.7.x), idempotency keys (2.11.0 P1-D-03),
   audit-log hash chain (2.11.0 P1-AUD-02),
   rate limiting (2.11.0 P1-RL-01), CSRF
   middleware (2.10.0 B2), record_sync
   audit path for mutations (2.10.0 P1-AUD-FIX).

## Supported Versions

| Version | Status | Security fixes |
|---|---|---|
| 2.10.x | current | yes |
| 2.9.x | LTS | yes (until 2027-09) |
| 2.8.x | LTS | yes (until 2027-03) |
| 2.7.x | LTS | yes (until 2026-09) |
| < 2.7   | EOL | no — please upgrade |

The 2.x line is the only actively-developed
line. 1.x was the Tauri-MVP line and is EOL as
of 2.7.0.

## Disclosure History

The 2.10.0 release is the first to include this
file. Prior security-relevant fixes (2.7.0 →
2.9.0) were made without a public disclosure
channel — operators discovered them via the
changelog + commit history. The 2.10.0 P1-AUD-FIX
commit (`bb3fdd9`) is the first fix where the
audit row + ADRs were published *before* the
code change (per the TZ §11.5 DoD rule).
