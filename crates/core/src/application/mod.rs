//! Application layer: use cases that orchestrate domain logic with
//! infrastructure adapters. No domain rules live here, but neither do
//! any I/O primitives — those are in `infrastructure::*`.
//!
//! MVP-3: only `ingest` is implemented. Other application services
//! (compose, plan, deploy, reconcile, rollback) land in later tasks.

pub mod compose;
pub mod deploy;
pub mod ingest;
pub mod ingest_v2;
pub mod journal;
pub mod plan;
pub mod policy;
pub mod reconcile;
pub mod scanner;
