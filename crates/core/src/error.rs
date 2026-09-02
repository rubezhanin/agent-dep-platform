//! Core error taxonomy (TZ §35) plus an `Unimplemented` variant for stub features.

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("source not found: {source_id}")]
    ErrSourceNotFound { source_id: String },

    #[error("schema invalid at {path}: {reason}")]
    ErrSchemaInvalid { path: String, reason: String },

    #[error("untrusted source: {source_id} (reason: {reason})")]
    ErrUntrustedSource { source_id: String, reason: String },

    #[error("policy blocked (rule: {rule}) on {target}")]
    ErrPolicyBlocked { rule: String, target: String },

    #[error("dependency missing: {dependency} (required by {required_by})")]
    ErrDependencyMissing {
        dependency: String,
        required_by: String,
    },

    #[error("version conflict for {package}: {reason}")]
    ErrVersionConflict { package: String, reason: String },

    #[error("Hermes runtime not found in PATH or HERMES_HOME")]
    ErrHermesNotFound,

    #[error("Hermes runtime incompatible: required >= {required}, found {found}")]
    ErrHermesIncompatible { required: String, found: String },

    #[error("path outside root: {path} (root: {root})")]
    ErrPathOutsideRoot { path: String, root: String },

    #[error("symlink escape detected at {path}")]
    ErrSymlinkEscape { path: String },

    #[error("file modified externally at {path}")]
    ErrFileModified { path: String },

    #[error("transaction recovery required for operation {operation_id}")]
    ErrTransactionRecoveryRequired { operation_id: String },

    #[error("verification failed for {target}: {reason}")]
    ErrVerificationFailed { target: String, reason: String },

    #[error("I/O error: {0}")]
    ErrIo(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    ErrJson(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    ErrYaml(#[from] serde_yaml::Error),

    #[error("SQLx error: {0}")]
    ErrSqlx(#[from] sqlx::Error),

    #[error("not yet implemented: {feature}")]
    Unimplemented { feature: String },

    #[error("git clone of `{url}` failed: {reason}")]
    ErrGitClone { url: String, reason: String },

    #[error("git open of `{path}` failed: {reason}")]
    ErrGitOpen { path: String, reason: String },

    #[error("git fetch from `{url}` failed: {reason}")]
    ErrGitFetch { url: String, reason: String },

    #[error("git ref `{ref_name}` is invalid: {reason}")]
    ErrGitInvalidRef { ref_name: String, reason: String },

    #[error("git source kind mismatch: expected {expected}, got {got}")]
    ErrGitWrongKind { expected: String, got: String },

    #[error("git remote URL changed: was `{old}`, now `{new}`; remove the working copy at `{new}`'s source_id directory and retry")]
    ErrGitRemoteChanged { old: String, new: String },
}
