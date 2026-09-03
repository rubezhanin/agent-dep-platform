//! Hermes runtime adapter.
#![doc = "Hermes runtime adapter implementing the `RuntimeAdapter` trait (TZ §12.3)."]

pub mod adapter;
pub mod detection;
pub mod hermes_adapter;
pub mod llm_probe;
pub mod mcp_server;
pub mod paths;
pub mod router_plugin;
pub mod types;

pub use adapter::RuntimeAdapter;
pub use hermes_adapter::HermesAdapter;
pub use types::RuntimeInfo;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }
}

#[cfg(test)]
#[path = "hermes_adapter_tests.rs"]
mod hermes_adapter_tests;
