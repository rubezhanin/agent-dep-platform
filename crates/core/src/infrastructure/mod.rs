//! Infrastructure layer: external-world adapters (filesystem, sqlite, git, etc.).
//! Domain and application layers MUST NOT import from here directly except through
//! these modules' public APIs.

pub mod content_store;
pub mod filesystem;
pub mod git_fetcher;
pub mod repository;
pub mod sqlite;
