//! Division: a group of related agents in a catalog.
//!
//! Mirrors the upstream `agency-agents/divisions.json` structure but
//! remains inside our domain so a future catalog format can differ.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Division {
    pub id: String,
    pub display_order: u32,
    pub label: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DivisionIndex {
    divisions: BTreeMap<String, Division>,
}

impl DivisionIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_upstream(root: &UpstreamDivisionsFile) -> Self {
        let mut idx = Self::new();
        for d in &root.divisions {
            idx.divisions.insert(
                d.id.clone(),
                Division {
                    id: d.id.clone(),
                    display_order: d.order,
                    label: d.label.clone(),
                    description: d.description.clone(),
                },
            );
        }
        idx
    }

    pub fn get(&self, id: &str) -> Option<&Division> {
        self.divisions.get(id)
    }

    /// Iterate over all divisions in their natural (BTreeMap) order.
    /// Each item is `(id, &Division)`.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Division)> {
        self.divisions.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.divisions.keys().map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.divisions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.divisions.is_empty()
    }
}

/// On-disk shape of `divisions.json`. Top-level `_note` is ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamDivisionsFile {
    #[serde(default, rename = "_note")]
    pub note: Option<String>,
    pub divisions: Vec<UpstreamDivision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamDivision {
    pub id: String,
    pub order: u32,
    pub label: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_divisions_file() {
        let json = r#"{
            "_note": "test",
            "divisions": [
                {"id": "engineering", "order": 1, "label": "Engineering", "description": "test"}
            ]
        }"#;
        let parsed: UpstreamDivisionsFile = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.divisions.len(), 1);
        assert_eq!(parsed.divisions[0].id, "engineering");
        assert_eq!(parsed.divisions[0].order, 1);

        let idx = DivisionIndex::from_upstream(&parsed);
        assert_eq!(idx.len(), 1);
        let eng = idx.get("engineering").unwrap();
        assert_eq!(eng.label, "Engineering");
    }

    #[test]
    fn missing_division_id_errors_via_serde() {
        let json = r#"{
            "divisions": [
                {"order": 1, "label": "NoId"}
            ]
        }"#;
        let parsed: Result<UpstreamDivisionsFile, _> = serde_json::from_str(json);
        assert!(parsed.is_err());
    }
}
