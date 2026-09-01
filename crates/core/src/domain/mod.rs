//! Domain layer for the Agent Deployment Platform.
//!
//! The domain is the single source of truth for business concepts
//! (Source, Snapshot, Agent, ...). It depends on nothing platform-
//! specific (no Tauri, no Hermes types, no SQL). Infrastructure
//! adapters (SQLite, filesystem, content store, hermes-adapter) live
//! outside this crate's `domain/` subtree (see ADR-0007).
//!
//! MVP-3 only implements the slice needed for ingestion: Source,
//! Snapshot, Division, Agent, Version. Other domain entities
//! (System, DeploymentPlan, etc.) are added in MVP-3+ tasks.

pub mod agent;
pub mod division;
pub mod plan;
pub mod source;
pub mod system;
pub mod version;
