//! IPC error type. Wraps `CoreError` and serializes to a JSON-friendly shape.

use agent_dep_core::error::CoreError;
use serde::Serialize;

#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "kind", content = "message")]
pub enum IpcError {
    #[error("core: {0}")]
    Core(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl From<CoreError> for IpcError {
    fn from(e: CoreError) -> Self {
        IpcError::Core(e.to_string())
    }
}

pub type IpcResult<T> = Result<T, IpcError>;
