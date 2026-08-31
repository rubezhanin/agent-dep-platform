//! Infrastructure layer: external-world adapters (filesystem, sqlite, git, etc.).
//! Domain and application layers MUST NOT import from here directly except through
//! these modules' public APIs.

pub mod filesystem;
pub mod sqlite;
