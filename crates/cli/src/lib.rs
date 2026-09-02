//! Library surface for the `agency` CLI crate.
//!
//! 2.0.0: the `agent_dep_server` crate consumes the
//! `commands::rollback` module to serve
//! `POST /v1/rollback/:id`. Re-exporting the public
//! modules from here keeps the binary unchanged and
//! lets the server link against the same code path
//! the CLI uses (no duplicated rollback logic).

pub mod cli_def;
pub mod commands;
pub mod data_dir;
pub mod output;

#[cfg(test)]
mod cli_tests;
