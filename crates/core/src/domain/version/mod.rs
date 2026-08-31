//! Semantic version (SemVer 2.0.0) for catalog entities.
//!
//! For MVP we use exact versions only (no ranges, no Solvers).
//! See ADR-0003.

use crate::error::CoreResult;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl Version {
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self { major, minor, patch }
    }

    pub fn parse(s: &str) -> CoreResult<Self> {
        let v = semver::Version::parse(s).map_err(|e| {
            crate::error::CoreError::ErrSchemaInvalid {
                path: format!("version:{s}"),
                reason: format!("semver parse: {e}"),
            }
        })?;
        Ok(Self { major: v.major, minor: v.minor, patch: v.patch })
    }

    pub fn as_string(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_string())
    }
}

/// Custom deserializer: accept a YAML/JSON string like "1.2.3" and parse
/// it via `semver`. This matches what humans write (YAML scalars) and
/// what `serde_yaml` produces for quoted strings.
impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(|e| D::Error::custom(format!("{e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_semver() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v, Version::new(1, 2, 3));
        assert_eq!(v.to_string(), "1.2.3");
    }

    #[test]
    fn reject_invalid_semver() {
        assert!(Version::parse("1.2").is_err());
        assert!(Version::parse("not-a-version").is_err());
        assert!(Version::parse("").is_err());
    }

    #[test]
    fn as_string_round_trip() {
        let original = "10.20.30";
        assert_eq!(Version::parse(original).unwrap().as_string(), original);
    }

    #[test]
    fn deserialize_from_string() {
        // Mirror what serde_yaml produces for `version: 1.0.0`.
        let json_v = serde_json::from_str::<Version>("\"1.2.3\"").unwrap();
        assert_eq!(json_v, Version::new(1, 2, 3));
    }
}
