// MVP-0 stub. Real domain/application modules land in later tasks.
#![doc = "Core domain, application, and infrastructure for the Agent Deployment Platform."]

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
