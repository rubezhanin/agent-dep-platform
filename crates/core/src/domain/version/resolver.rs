//! SemVer range resolution (TZ §8.3, ADR-0010, 1.2.0).
//!
//! Bridges the gap between `system.yaml` (which carries a
//! per-ref range, e.g. `^1.0.0`) and the catalog snapshot
//! (which carries one exact `Version` per agent). The
//! `VersionResolver` picks the highest `Version` from a
//! candidate list that satisfies a `VersionReq`.
//!
//! Resolution is **stable**: ties are broken by sorting
//! the candidates in descending order and returning the
//! first match. Empty candidate lists return `None`.
//!
//! Resolution is **side-effect-free**: no I/O, no
//! randomness, no global state. The same inputs always
//! produce the same output.

use semver::{Version, VersionReq};

/// Pick the highest `candidate` that satisfies `req`.
///
/// Examples (with the `semver` crate's `VersionReq` parser):
/// ```ignore
/// let req = VersionReq::parse("^1.0.0").unwrap();
/// let v = VersionResolver::resolve(&req, &[
///     Version::parse("1.0.0").unwrap(),
///     Version::parse("1.0.5").unwrap(),
///     Version::parse("1.2.0").unwrap(),
///     Version::parse("2.0.0").unwrap(),
/// ]);
/// assert_eq!(v.unwrap(), Version::parse("1.2.0").unwrap());
/// ```
pub struct VersionResolver;

impl VersionResolver {
    pub fn resolve(req: &VersionReq, candidates: &[Version]) -> Option<Version> {
        // Filter then take the max. Sorting is by
        // `semver::Version`'s `Ord` impl, which is the
        // canonical SemVer order: major, minor, patch
        // (and pre-release precedence inside the same
        // major.minor.patch).
        let mut matching: Vec<&Version> = candidates.iter().filter(|v| req.matches(v)).collect();
        matching.sort_by(|a, b| b.cmp(a)); // descending
        matching.into_iter().next().cloned()
    }

    /// Convenience wrapper: the caller passes the full
    /// list of `Version` values from the snapshot. The
    /// resolver returns the highest match.
    pub fn resolve_first(req: &VersionReq, candidates: &[Version]) -> Option<Version> {
        Self::resolve(req, candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use semver::Version;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    fn req(s: &str) -> VersionReq {
        VersionReq::parse(s).unwrap()
    }

    #[test]
    fn exact_version_is_a_single_match() {
        // In `semver` 1.x the bare triple `1.0.0` parses
        // as the range `^1.0.0`. To pin exactly one
        // version you have to prefix it with `=`.
        let r = req("=1.0.0");
        let chosen = VersionResolver::resolve(
            &r,
            &[v("0.9.0"), v("1.0.0"), v("1.0.1"), v("1.1.0"), v("2.0.0")],
        );
        assert_eq!(chosen, Some(v("1.0.0")));
    }

    #[test]
    fn bare_triple_is_caret_in_semver_1x() {
        // Document the gotcha: `VersionReq::parse("1.0.0")`
        // and `VersionReq::parse("^1.0.0")` are the same
        // range in `semver` 1.x. The CLI must store the
        // `=` prefix when it wants a true exact pin.
        let r = req("1.0.0");
        let chosen =
            VersionResolver::resolve(&r, &[v("0.9.0"), v("1.0.0"), v("1.5.0"), v("2.0.0")]);
        assert_eq!(chosen, Some(v("1.5.0")));
    }

    #[test]
    fn caret_picks_highest_minor_compatible() {
        let r = req("^1.0.0");
        let chosen = VersionResolver::resolve(
            &r,
            &[
                v("0.9.0"),
                v("1.0.0"),
                v("1.0.5"),
                v("1.2.0"),
                v("1.10.0"),
                v("2.0.0"),
            ],
        );
        assert_eq!(chosen, Some(v("1.10.0")));
    }

    #[test]
    fn tilde_picks_highest_patch_in_minor() {
        let r = req("~1.2.0");
        let chosen = VersionResolver::resolve(
            &r,
            &[v("1.2.0"), v("1.2.3"), v("1.2.9"), v("1.3.0"), v("2.0.0")],
        );
        assert_eq!(chosen, Some(v("1.2.9")));
    }

    #[test]
    fn range_with_two_bounds() {
        let r = req(">=1.0.0, <2.0.0");
        let chosen =
            VersionResolver::resolve(&r, &[v("0.9.0"), v("1.0.0"), v("1.5.0"), v("2.0.0")]);
        assert_eq!(chosen, Some(v("1.5.0")));
    }

    #[test]
    fn empty_candidate_list_returns_none() {
        let r = req("^1.0.0");
        let chosen = VersionResolver::resolve(&r, &[]);
        assert_eq!(chosen, None);
    }

    #[test]
    fn no_match_returns_none() {
        let r = req("^3.0.0");
        let chosen = VersionResolver::resolve(&r, &[v("1.0.0"), v("2.0.0")]);
        assert_eq!(chosen, None);
    }

    #[test]
    fn ties_break_by_descending_sort() {
        // `^1.0.0` matches every 1.x.y. With two candidates
        // we return the higher one. With three we return
        // the highest.
        let r = req("^1.0.0");
        assert_eq!(
            VersionResolver::resolve(&r, &[v("1.0.0"), v("1.2.0")]),
            Some(v("1.2.0"))
        );
        assert_eq!(
            VersionResolver::resolve(&r, &[v("1.0.0"), v("1.2.0"), v("1.2.0"), v("1.5.0")]),
            Some(v("1.5.0"))
        );
    }

    #[test]
    fn pre_releases_are_filtered_by_default() {
        // The `semver` crate's `VersionReq::matches` does
        // not include pre-releases unless explicitly
        // requested. We rely on that here.
        let r = req("^1.0.0");
        let chosen = VersionResolver::resolve(&r, &[v("1.0.0"), v("1.0.0-rc.1"), v("1.1.0")]);
        assert_eq!(chosen, Some(v("1.1.0")));
    }
}
