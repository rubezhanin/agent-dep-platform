// MVP-0 stub. Real Tauri app lands in Task 8.
#![doc = "Tauri 2 host for the Agent Deployment Platform."]

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
