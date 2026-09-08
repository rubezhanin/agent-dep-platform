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

    /// 2.11.0 (P1-D-01b, TZ #1 §10 / D-01,
    /// CWE-494): a deploy was approved
    /// against one version of a
    /// `DeploymentIntent` field
    /// (currently only
    /// `target_config_version`)
    /// and the underlying value has
    /// since changed. Applying the
    /// deploy anyway would land a
    /// different artifact than the
    /// one the operator approved.
    /// The typed error carries the
    /// `deploy_id`, the
    /// `target_id`, the captured
    /// version, and the current
    /// version so the audit log can
    /// record the exact mismatch
    /// and the SPA can surface a
    /// "deploy stale" error.
    #[error("deploy {deploy_id} is stale: {kind} for target {target_id} was {captured_version} at approval, now {current_version}")]
    ErrStaleDeployment {
        deploy_id: i64,
        target_id: i64,
        /// 2.11.0 (P1-D-01b): the
        /// field that mismatched.
        /// Currently always
        /// `"target_config_version"`.
        kind: String,
        captured_version: i64,
        current_version: i64,
    },
}
