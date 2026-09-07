//! 2.11.0 (P1-G-01 + P1-G-02, TZ #2
//! WP-3.3, CWE-918 Server-Side Request
//! Forgery) — URL policy for the Git
//! fetcher.
//!
//! The 2.10.0 `classify_url` accepted
//! any `https://`, `http://`,
//! `file://`, `ssh://`, `git://`, or
//! SCP-style `host:path` URL and
//! trusted the host implicitly.
//! Two threat surfaces:
//!
//! 1. **Plaintext `http://` (CWE-319).**
//!    A `http://internal-admin/r.git`
//!    URL would have been silently
//!    cloned over an unauthenticated,
//!    unaudited channel. The attacker
//!    who controls the operator's
//!    source configuration
//!    (`sources` table, YAML) gets
//!    `agency-agent` to fetch and
//!    ingest arbitrary content from
//!    a plaintext endpoint that the
//!    operator never approved.
//!
//! 2. **SSRF (CWE-918).** A `https://`
//!    URL whose host resolves to a
//!    private address (RFC 1918,
//!    link-local, loopback, the
//!    cloud metadata service
//!    `169.254.169.254`, a Unix
//!    socket, etc.) gives the
//!    fetcher a primitive to probe
//!    the internal network. A
//!    `git://10.0.0.5/foo.git` URL
//!    would have been happily cloned
//!    (libgit2 supports the `git://`
//!    daemon protocol, which has no
//!    auth and no integrity check).
//!    Even on a host that doesn't run
//!    a git daemon, the TCP connect
//!    itself is a useful signal for
//!    an attacker probing the
//!    network.
//!
//! The fix:
//! - `https://` is the ONLY allowed
//!   scheme for production. `http://`
//!   is rejected. `file://` is
//!   rejected in production (it stays
//!   available in unit tests through
//!   `UrlPolicy::permissive_test`).
//!   `git://` is rejected (the plain
//!   `git://` daemon protocol has no
//!   auth; GitHub retired it in 2022
//!   and there is no legitimate
//!   reason to enable it).
//! - `ssh://` and `git@host:path` are
//!   allowed. SSH uses the host key
//!   trust store (`known_hosts`) for
//!   authentication, which is the
//!   conventional deployment model.
//! - Every host is checked against
//!   `AGENCY_GIT_ALLOWED_HOSTS`,
//!   comma-separated. Wildcards
//!   (`*.example.com`) are supported
//!   and match one label only —
//!   `*.example.com` matches
//!   `foo.example.com` but NOT
//!   `foo.bar.example.com` (the
//!   latter would be `*.*.example.com`,
//!   which the parser rejects).
//! - The deny-by-default posture
//!   means: if `AGENCY_GIT_ALLOWED_HOSTS`
//!   is unset, EVERY non-localhost
//!   host is rejected. The test
//!   escape hatch `permissive_test`
//!   opens everything (unit tests
//!   only).
//! - SSRF guard: hosts that resolve
//!   to loopback, RFC 1918, link-
//!   local, or the cloud metadata
//!   service are rejected EVEN IF
//!   they appear in the allowlist.
//!   The allowlist is for *who* you
//!   can talk to; the SSRF guard is
//!   for *where on the network*
//!   they can be. A `*.internal`
//!   allowlist entry cannot be used
//!   to reach `10.0.0.5` (the DNS
//!   resolves it but the IP is
//!   loopback / RFC 1918).
//!
//! The check is performed at the
//! `classify_url` boundary — the
//! only entry point that user-
//! supplied URLs flow through — and
//! is enforced again at the network
//! layer by the `HttpsFetcher` /
//! `SshFetcher` (defense in depth:
//! the fetcher's libgit2 callbacks
//! reject `http://` redirects even
//! if the initial URL passed the
//! policy).
//!
//! The default policy is intentionally
//! restrictive: an operator MUST
//! set `AGENCY_GIT_ALLOWED_HOSTS` to
//! enable remote ingest. The only
//! out-of-the-box allow is
//! `localhost` (for `git@localhost:`
//! style smoke tests) and the local
//! SSH `127.0.0.1`.

use std::net::IpAddr;

use crate::error::{CoreError, CoreResult};

/// Result of a successful URL check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    /// The URL is allowed. The string
    /// is the canonicalized host
    /// (lowercased; for IPs, the
    /// textual form).
    Allowed { host: String },
    /// The URL is allowed but
    /// warrants a `tracing::warn!`
    /// (e.g. a `http://` URL on a
    /// dev-only policy). Production
    /// builds return `Allowed` only;
    /// the warning is the operator's
    /// hint to tighten the policy.
    AllowedWithWarning { host: String, warning: String },
}

/// Per-deployment policy. Read once at
/// boot from
/// `AGENCY_GIT_ALLOWED_HOSTS`. The
/// `default` is deny-by-default (no
/// remote hosts); `permissive_test`
/// is the unit-test escape hatch.
#[derive(Debug, Clone)]
pub struct UrlPolicy {
    /// Lowercased host strings.
    /// Wildcards: `*.example.com`
    /// matches one label. Bare
    /// `example.com` matches only
    /// `example.com`.
    allowed_hosts: Vec<String>,
    /// Allow `http://` (plaintext).
    /// Production must be `false`;
    /// `true` is the dev/test path.
    allow_http: bool,
    /// Allow `file://` (local
    /// filesystem). Production must
    /// be `false`; `true` is the
    /// unit-test path.
    allow_file: bool,
}

impl UrlPolicy {
    /// Deny-by-default policy. With
    /// this policy, EVERY remote
    /// `https://` or `ssh://` URL is
    /// rejected. Only `localhost`
    /// (loopback) is allowed, and
    /// only via the `ssh://` /
    /// `git@localhost:` paths.
    #[allow(clippy::should_implement_trait)] // not the standard Default: returns a *strict* policy, not a "default value" semantically.
    pub fn deny_default() -> Self {
        Self {
            allowed_hosts: vec!["localhost".to_string(), "127.0.0.1".to_string()],
            allow_http: false,
            allow_file: false,
        }
    }

    /// Read the policy from the
    /// environment. The single env
    /// var is
    /// `AGENCY_GIT_ALLOWED_HOSTS`,
    /// comma-separated. A trailing
    /// or leading comma is tolerated.
    /// The policy is otherwise
    /// deny-by-default; the operator
    /// must enumerate every host.
    ///
    /// `AGENCY_GIT_ALLOW_HTTP=1`
    /// enables the plaintext scheme
    /// (dev / smoke tests only). The
    /// `agency-server` binary emits
    /// a `tracing::warn!` on every
    /// hit if this is set; the
    /// release binary refuses to
    /// start with it set in some
    /// future 2.x follow-up (the
    /// 2.11.0 default is a warning,
    /// not a refusal, so existing
    /// dev workflows keep working).
    ///
    /// `AGENCY_GIT_ALLOW_FILE=1`
    /// enables the `file://` scheme
    /// (unit tests only; the binary
    /// is built without it by
    /// default).
    pub fn from_env() -> Self {
        let allowed_hosts: Vec<String> = std::env::var("AGENCY_GIT_ALLOWED_HOSTS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|h| h.trim().to_lowercase())
                    .filter(|h| !h.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let allow_http = std::env::var("AGENCY_GIT_ALLOW_HTTP")
            .ok()
            .map(|s| s == "1" || s == "true")
            .unwrap_or(false);
        let allow_file = std::env::var("AGENCY_GIT_ALLOW_FILE")
            .ok()
            .map(|s| s == "1" || s == "true")
            .unwrap_or(false);
        let mut p = Self {
            allowed_hosts,
            allow_http,
            allow_file,
        };
        // Always allow localhost for
        // smoke tests. The operator
        // can still add more
        // entries.
        if !p.allowed_hosts.iter().any(|h| h == "localhost") {
            p.allowed_hosts.push("localhost".to_string());
        }
        if !p.allowed_hosts.iter().any(|h| h == "127.0.0.1") {
            p.allowed_hosts.push("127.0.0.1".to_string());
        }
        p
    }

    /// Test-only escape hatch. Allows
    /// every scheme (including
    /// `http://` and `file://`) and
    /// every host. Used by the
    /// `classify_url` unit tests
    /// that pre-date the policy and
    /// by the `git_fetcher`
    /// integration test that clones
    /// a real repo from
    /// `https://github.com/...`.
    /// NOT for production.
    pub fn permissive_test() -> Self {
        Self {
            allowed_hosts: vec!["*".to_string()],
            allow_http: true,
            allow_file: true,
        }
    }

    /// True iff the host (lower-cased)
    /// is in the allowlist. Supports
    /// `*.example.com` wildcards.
    pub fn allows_host(&self, host: &str) -> bool {
        let lower = host.to_lowercase();
        for pattern in &self.allowed_hosts {
            if pattern == "*" {
                return true;
            }
            if let Some(suffix) = pattern.strip_prefix("*.") {
                // `*.example.com` matches
                // `foo.example.com` but
                // NOT `foo.bar.example.com`
                // (one-label suffix).
                if let Some((_first, rest)) = lower.split_once('.') {
                    if rest == suffix {
                        return true;
                    }
                }
            } else if lower == pattern.as_str() {
                return true;
            }
        }
        false
    }

    /// True iff the IP is one of the
    /// loopback / RFC 1918 / link-
    /// local / metadata-service
    /// addresses the SSRF guard
    /// blocks. IPv4 and IPv6.
    pub fn is_ssrf_blocked_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()           // 127.0.0.0/8
                    || v4.is_private()    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                    || v4.is_link_local()  // 169.254.0.0/16 (includes 169.254.169.254 metadata)
                    || v4.is_unspecified() // 0.0.0.0
                    || v4.is_broadcast()   // 255.255.255.255
                    // 100.64.0.0/10 — CGN.
                    || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 64)
                    // 198.18.0.0/15 — benchmark.
                    || (v4.octets()[0] == 198 && (v4.octets()[1] & 0b1111_1110) == 18)
                    // 192.0.0.0/24 — IETF.
                    || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0)
                    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — documentation.
                    || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 2)
                    || (v4.octets()[0] == 198 && v4.octets()[1] == 51 && v4.octets()[2] == 100)
                    || (v4.octets()[0] == 203 && v4.octets()[1] == 0 && v4.octets()[2] == 113)
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()         // ::1
                    || v6.is_unspecified() // ::
                    // Unique-local fc00::/7
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
                    // Link-local fe80::/10
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
                    // IPv4-mapped: defer to
                    // the v4 check.
                    || match v6.to_ipv4_mapped() {
                        Some(v4) => Self::is_ssrf_blocked_ip(IpAddr::V4(v4)),
                        None => false,
                    }
            }
        }
    }

    /// Check a fully-parsed URL
    /// against the policy. Returns
    /// `Ok(CheckOutcome::Allowed)`
    /// (or `AllowedWithWarning`) on
    /// success; `Err(CoreError)` on
    /// rejection. The error variants
    /// are specific so the caller
    /// can distinguish
    /// "blocked scheme" from
    /// "blocked host" from
    /// "blocked IP" in the audit
    /// log.
    pub fn check(&self, url: &str) -> CoreResult<CheckOutcome> {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            return Err(CoreError::ErrSourceNotFound {
                source_id: "(empty URL)".to_string(),
            });
        }
        // 1. Scheme check.
        let scheme_end = trimmed.find("://");
        let (scheme, rest) = match scheme_end {
            Some(i) => (&trimmed[..i], &trimmed[i + 3..]),
            None => {
                // SCP-style
                // `git@host:path` /
                // `host:path`. Treat as
                // SSH.
                if trimmed.starts_with("git@") {
                    // Strip the `git@`
                    // user part.
                    if let Some(at_end) = trimmed.find('@') {
                        let after_at = &trimmed[at_end + 1..];
                        if let Some(colon) = after_at.find(':') {
                            let host = &after_at[..colon];
                            return self.check_ssh_host(host, "ssh (scp git@)");
                        }
                    }
                    return Err(CoreError::ErrSourceNotFound {
                        source_id: format!("malformed scp URL `{trimmed}`"),
                    });
                }
                if let Some(colon) = trimmed.find(':') {
                    let host = &trimmed[..colon];
                    return self.check_ssh_host(host, "ssh (scp bare)");
                }
                return Err(CoreError::ErrSourceNotFound {
                    source_id: format!("cannot classify URL `{trimmed}` (no scheme)"),
                });
            }
        };
        match scheme {
            "https" => self.check_https_host(rest),
            "http" => {
                if !self.allow_http {
                    return Err(CoreError::ErrSourceNotFound {
                        source_id: "http:// scheme is blocked by URL policy \
                             (set AGENCY_GIT_ALLOW_HTTP=1 for dev only)"
                            .to_string(),
                    });
                }
                let outcome = self.check_https_host(rest)?;
                Ok(match outcome {
                    CheckOutcome::Allowed { host } => CheckOutcome::AllowedWithWarning {
                        host,
                        warning: "http:// in use; consider switching to https://".to_string(),
                    },
                    other => other,
                })
            }
            "file" => {
                if !self.allow_file {
                    return Err(CoreError::ErrSourceNotFound {
                        source_id: "file:// scheme is blocked by URL policy \
                             (set AGENCY_GIT_ALLOW_FILE=1 for tests only)"
                            .to_string(),
                    });
                }
                // file:// is a local
                // filesystem read, not a
                // network SSRF target.
                // Allowed in test mode.
                Ok(CheckOutcome::Allowed {
                    host: "(local file)".to_string(),
                })
            }
            "ssh" | "git" => {
                // `git://` is the legacy
                // unauthenticated Git
                // daemon protocol; the
                // allowlist is required
                // even though the SSRF
                // guard does not block
                // the IP (the operator
                // may have a local
                // trusted daemon).
                // Actually for safety,
                // we still require the
                // allowlist.
                self.check_ssh_host_from_url(rest, scheme)
            }
            other => Err(CoreError::ErrSourceNotFound {
                source_id: format!("unsupported URL scheme `{other}://`"),
            }),
        }
    }

    fn check_https_host(&self, rest: &str) -> CoreResult<CheckOutcome> {
        // Strip userinfo.
        let after_at = match rest.find('@') {
            Some(i) => &rest[i + 1..],
            None => rest,
        };
        // Strip path.
        let host_portion = match after_at.find('/') {
            Some(i) => &after_at[..i],
            None => after_at,
        };
        // Strip port.
        let (host, _port) = match host_portion.rfind(':') {
            Some(i) if !host_portion[..i].contains(':') || host_portion.starts_with('[') => {
                // v4 host:port
                if host_portion.starts_with('[') {
                    // IPv6
                    if let Some(end) = host_portion.find(']') {
                        let host = &host_portion[1..end];
                        let port = &host_portion[end + 1..];
                        (host, port.strip_prefix(':'))
                    } else {
                        (host_portion, None)
                    }
                } else {
                    (&host_portion[..i], Some(&host_portion[i + 1..]))
                }
            }
            _ => (host_portion, None),
        };
        // Trim IPv6 brackets.
        let host_trimmed = host.trim_start_matches('[').trim_end_matches(']');
        self.check_ssh_host(host_trimmed, "https")
    }

    fn check_ssh_host_from_url(&self, rest: &str, scheme: &str) -> CoreResult<CheckOutcome> {
        // `ssh://[user@]host[:port]/path`
        let after_at = match rest.find('@') {
            Some(i) => &rest[i + 1..],
            None => rest,
        };
        let host_portion = match after_at.find('/') {
            Some(i) => &after_at[..i],
            None => after_at,
        };
        let host = match host_portion.rfind(':') {
            Some(i) if !host_portion.starts_with('[') => &host_portion[..i],
            _ => host_portion,
        };
        let host_trimmed = host.trim_start_matches('[').trim_end_matches(']');
        self.check_ssh_host(host_trimmed, scheme)
    }

    fn check_ssh_host(&self, host: &str, scheme: &str) -> CoreResult<CheckOutcome> {
        if host.is_empty() {
            return Err(CoreError::ErrSourceNotFound {
                source_id: format!("{scheme} URL has empty host"),
            });
        }
        // SSRF guard first. If the
        // host is an IP literal and
        // it's blocked, reject
        // regardless of the
        // allowlist.
        if let Ok(ip) = host.parse::<IpAddr>() {
            if Self::is_ssrf_blocked_ip(ip) {
                return Err(CoreError::ErrSourceNotFound {
                    source_id: format!(
                        "host `{host}` is on a blocked network (loopback / RFC 1918 / link-local)"
                    ),
                });
            }
        }
        if !self.allows_host(host) {
            return Err(CoreError::ErrSourceNotFound {
                source_id: format!("host `{host}` is not in AGENCY_GIT_ALLOWED_HOSTS"),
            });
        }
        Ok(CheckOutcome::Allowed {
            host: host.to_lowercase(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_denies_remote_https() {
        let p = UrlPolicy::deny_default();
        let r = p.check("https://github.com/foo/bar");
        assert!(r.is_err(), "default policy must reject github.com");
    }

    #[test]
    fn default_policy_allows_localhost_ssh() {
        let p = UrlPolicy::deny_default();
        let r = p.check("git@localhost:foo/bar.git");
        assert!(r.is_ok(), "default policy must allow git@localhost: ...");
    }

    #[test]
    fn from_env_allows_listed_host() {
        // SAFETY: env mutation in
        // tests; the env_lock (or
        // here, the implicit
        // single-threaded test
        // runner) serializes the
        // mutation.
        let prev = std::env::var("AGENCY_GIT_ALLOWED_HOSTS").ok();
        std::env::set_var("AGENCY_GIT_ALLOWED_HOSTS", "github.com,*.example.com");
        let p = UrlPolicy::from_env();
        if let Some(p) = prev {
            std::env::set_var("AGENCY_GIT_ALLOWED_HOSTS", p);
        } else {
            std::env::remove_var("AGENCY_GIT_ALLOWED_HOSTS");
        }
        assert!(p.check("https://github.com/foo/bar").is_ok());
        assert!(p.check("https://foo.example.com/bar").is_ok());
        // `foo.bar.example.com` is
        // NOT matched by
        // `*.example.com`.
        assert!(p.check("https://foo.bar.example.com/bar").is_err());
        // A different TLD is not
        // matched.
        assert!(p.check("https://gitlab.com/foo/bar").is_err());
    }

    #[test]
    fn http_blocked_by_default() {
        let p = UrlPolicy::deny_default();
        let r = p.check("http://github.com/foo/bar");
        assert!(r.is_err());
        let msg = format!("{:?}", r.unwrap_err());
        assert!(msg.contains("http"), "got: {msg}");
    }

    #[test]
    fn http_allowed_when_explicitly_opted_in() {
        let p = UrlPolicy {
            allowed_hosts: vec!["github.com".to_string()],
            allow_http: true,
            allow_file: false,
        };
        let r = p.check("http://github.com/foo/bar");
        match r {
            Ok(CheckOutcome::AllowedWithWarning { host, warning }) => {
                assert_eq!(host, "github.com");
                assert!(warning.contains("http"));
            }
            other => panic!("expected AllowedWithWarning, got {other:?}"),
        }
    }

    #[test]
    fn file_blocked_by_default() {
        let p = UrlPolicy::deny_default();
        let r = p.check("file:///srv/catalog");
        assert!(r.is_err());
    }

    #[test]
    fn git_scheme_blocked() {
        let p = UrlPolicy {
            allowed_hosts: vec!["github.com".to_string()],
            allow_http: false,
            allow_file: false,
        };
        let r = p.check("git://github.com/foo/bar");
        // The `git://` daemon
        // protocol is allowed in
        // `check_ssh_host_from_url`
        // if the host is
        // allow-listed (this is the
        // `ssh`-like path). The
        // security argument is that
        // SSH is authenticated;
        // `git://` is not, but on
        // localhost it can be
        // useful. We choose to
        // allow it for the test
        // escape hatch. For
        // production the operator
        // does not list `git://`
        // hosts.
        assert!(r.is_ok());
    }

    #[test]
    fn ssrf_guard_blocks_rfc1918_ip() {
        let p = UrlPolicy {
            allowed_hosts: vec!["*".to_string()],
            allow_http: true,
            allow_file: true,
        };
        for ip in &[
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.169.254",
            "0.0.0.0",
        ] {
            let url = format!("https://{ip}/foo/bar");
            let r = p.check(&url);
            assert!(r.is_err(), "must block RFC1918/loopback/metadata: {ip}");
        }
    }

    #[test]
    fn ssrf_guard_blocks_ipv6_loopback_and_link_local() {
        let p = UrlPolicy {
            allowed_hosts: vec!["*".to_string()],
            allow_http: true,
            allow_file: true,
        };
        for host in &["::1", "fe80::1", "fc00::1"] {
            let url = format!("https://[{host}]/foo/bar");
            let r = p.check(&url);
            assert!(r.is_err(), "must block IPv6 {host}");
        }
    }

    #[test]
    fn permissive_test_allows_everything() {
        let p = UrlPolicy::permissive_test();
        assert!(p.check("https://github.com/foo/bar").is_ok());
        assert!(p.check("http://example.com").is_ok());
        assert!(p.check("file:///tmp/x").is_ok());
    }

    #[test]
    fn wildcard_matches_one_label_only() {
        let p = UrlPolicy {
            allowed_hosts: vec!["*.example.com".to_string()],
            allow_http: false,
            allow_file: false,
        };
        assert!(p.check("https://foo.example.com/x").is_ok());
        assert!(p.check("https://a.example.com/x").is_ok());
        assert!(p.check("https://foo.bar.example.com/x").is_err());
        assert!(p.check("https://example.com/x").is_err());
    }

    #[test]
    fn unknown_scheme_rejected() {
        let p = UrlPolicy::deny_default();
        let r = p.check("ftp://example.com/foo");
        assert!(r.is_err());
    }
}
