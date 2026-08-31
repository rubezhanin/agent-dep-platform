//! Tauri IPC commands (TZ §51).
//! Each command is a thin shim that calls into application/domain services.
//! MVP-0: all commands return safe stubs (empty vec or unimplemented).

pub mod backups;
pub mod catalog;
pub mod deployments;
pub mod hermes;
pub mod logs;
pub mod plans;
pub mod security;
pub mod sources;
pub mod systems;
