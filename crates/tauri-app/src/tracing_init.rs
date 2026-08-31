//! Tracing initialization (TZ §34).
//!
//! Two layers: stderr for development, JSON daily-rolling file for diagnostics.
//! File lives at `{app_data_dir}/logs/app.json` (rotation via `Rotation::DAILY`).

use std::path::Path;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

/// Initialize tracing. Returns a guard that must be kept alive for the duration
/// of the program — dropping it flushes and stops the background writer.
pub fn init(app_data_dir: &Path) -> Result<TracingGuard, String> {
    let logs_dir = app_data_dir.join("logs");
    std::fs::create_dir_all(&logs_dir).map_err(|e| format!("create logs dir: {e}"))?;
    let file_appender = tracing_appender::rolling::daily(&logs_dir, "app.json");
    let (file_writer, file_guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tauri=info,agent_dep=debug"));

    let stderr_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_writer(std::io::stderr);

    let file_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .json()
        .with_current_span(true)
        .with_span_list(false)
        .with_writer(file_writer);

    Registry::default()
        .with(env_filter)
        .with(stderr_layer)
        .with(file_layer)
        .try_init()
        .map_err(|e| format!("tracing init: {e}"))?;

    Ok(TracingGuard { _file: file_guard })
}

pub struct TracingGuard {
    _file: WorkerGuard,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_creates_log_dir() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = init(dir.path()).expect("init");
        let log_path = dir.path().join("logs");
        assert!(log_path.is_dir(), "expected logs dir at {log_path:?}");
    }
}
