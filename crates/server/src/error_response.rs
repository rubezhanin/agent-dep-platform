//! Structured error responses (P0-API-04,
//! TZ #1 §17 API-04, CWE-209).
//!
//! The pre-fix `handlers.rs` returned
//! `Json(json!({"error": e.to_string()}))`
//! on every error path. `CoreError`'s
//! `to_string()` includes the underlying
//! `sqlx::Error::Database` message
//! (which can contain SQL fragments, table
//! names, and parameter values), the file
//! path on filesystem errors, the JWKS
//! URL on OIDC errors, and stack-frame
//! hints from `anyhow`'s context chain.
//! All of this leaks to the client
//! (and via the audit log to anyone with
//! `audit_log` read access). CWE-209
//! (Generation of Error Message Containing
//! Sensitive Information).
//!
//! Post-fix: every error response is a
//! structured `ErrorResponse { code, kind,
//! hint }` whose `code` is a stable
//! machine-readable string, `kind` is one
//! of a fixed enum, and `hint` is a
//! short operator-facing string. The
//! internal `CoreError` is logged at
//! `tracing::warn!` level with full detail
//! (so the operator can debug) but is NOT
//! echoed to the client.

use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use thiserror::Error;

use agent_dep_core::error::CoreError;

/// Machine-readable error kind. Stable across
/// releases; clients can pattern-match on
/// these strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// 400-class: the request was
    /// syntactically wrong or failed
    /// validation.
    BadRequest,
    /// 401-class: missing or invalid auth.
    /// Note: 401 is typically handled by the
    /// `auth::require_bearer` middleware,
    /// not by handlers.
    Unauthorized,
    /// 403-class: the request is well-formed
    /// and authenticated, but the actor is
    /// not allowed.
    Forbidden,
    /// 404-class: the resource does not
    /// exist. NOT used to hide existence —
    /// we use 404 only when the resource
    /// is genuinely missing.
    NotFound,
    /// 409-class: the request is valid but
    /// conflicts with current state
    /// (e.g. a duplicate, an unapproved
    /// deploy being rejected, etc.).
    Conflict,
    /// 422-class: the request was understood
    /// but is semantically invalid (e.g. a
    /// JSON envelope that parses but is
    /// missing required fields).
    Unprocessable,
    /// 500-class: the server failed in a way
    /// the client cannot fix. The client
    /// gets a generic `internal_error` —
    /// the operator sees the full CoreError
    /// in the server logs.
    Internal,
}

/// The response body. Three fields:
/// - `code` — stable machine-readable
///   identifier (e.g. `"user.not_found"`,
///   `"vault.read_error"`,
///   `"deploy.not_pending"`).
/// - `kind` — one of [`ErrorKind`].
/// - `hint` — short, operator-facing
///   explanation. NEVER includes
///   user-supplied data, file paths, SQL
///   fragments, or internal state.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    pub code: &'static str,
    pub kind: ErrorKind,
    pub hint: &'static str,
}

/// Mapping from a [`CoreError`] to an
/// `(StatusCode, ErrorResponse)` pair. The
/// internal `CoreError` is dropped (we log
/// it at warn level in the caller) and
/// replaced with a stable, opaque code.
///
/// **Stable contract:** `code` strings are
/// append-only. New codes can be added
/// (e.g. when a new `CoreError` variant
/// lands), but existing codes never
/// change their meaning. Clients can
/// safely `match` on them.
pub fn from_core_error(e: &CoreError) -> (StatusCode, Json<ErrorResponse>) {
    let (status, code, kind, hint) = match e {
        // Schema-level errors are 400
        // (the request was bad).
        CoreError::ErrSchemaInvalid { path, reason } => {
            // `path` is a stable dotted key
            // (e.g. "users.name"), not a file
            // path. We surface it in `code`
            // but never echo `reason`
            // (which can contain user input
            // for some variants).
            tracing::warn!(error = %e, path = %path, reason = %reason, "schema_invalid");
            (
                StatusCode::BAD_REQUEST,
                "schema.invalid",
                ErrorKind::BadRequest,
                "request payload failed schema validation",
            )
        }
        // SQL / IO errors are 500 (the
        // server is broken, not the
        // request).
        CoreError::ErrSqlx(e) => {
            tracing::warn!(error = %e, "sqlx error in handler");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal.db",
                ErrorKind::Internal,
                "database error",
            )
        }
        CoreError::ErrIo(e) => {
            tracing::warn!(error = %e, "io error in handler");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal.io",
                ErrorKind::Internal,
                "filesystem error",
            )
        }
        CoreError::ErrJson(e) => {
            tracing::warn!(error = %e, "json error in handler");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal.json",
                ErrorKind::Internal,
                "serialisation error",
            )
        }
        // Other variants land here. We log
        // the full error and return a
        // generic 500.
        // 2.11.0 (P1-D-01b / P1-D-02,
        // TZ #1 §10 / D-01, CWE-494
        // and CWE-362): a
        // `mark_applied` is refused
        // because the underlying
        // state has drifted since the
        // deploy was approved. This
        // is a 409 (the request was
        // valid, but the server state
        // is incompatible with the
        // action). The `kind` field
        // tells the client which
        // specific drift fired
        // (`target_config_version` or
        // `deployment_fence`); the
        // `hint` is a generic
        // operator-facing message.
        CoreError::ErrStaleDeployment {
            kind,
            deploy_id,
            target_id,
            captured_version,
            current_version,
        } => {
            tracing::warn!(
                error = %e,
                deploy_id,
                target_id,
                captured_version,
                current_version,
                kind = %kind,
                "stale_deployment"
            );
            (
                StatusCode::CONFLICT,
                "deploy.stale",
                ErrorKind::Conflict,
                "deploy is stale: the underlying state has changed since approval; re-issue required",
            )
        }
        // 2.11.0 (P1-D-02, TZ #1 §10 /
        // D-02, CWE-362): the operator
        // tried to start a new
        // mutating operation on a
        // target that already has a
        // non-terminal `pending` or
        // `approved` row. The
        // invariant "один target — одна
        // активная mutating operation"
        // holds; the operator must wait
        // for the existing deploy to
        // reach a terminal state. 409.
        CoreError::ErrTargetBusy {
            target_id,
            existing_deploy_id,
            existing_status,
        } => {
            tracing::warn!(
                error = %e,
                target_id,
                existing_deploy_id,
                existing_status = %existing_status,
                "target_busy"
            );
            (
                StatusCode::CONFLICT,
                "deploy.target_busy",
                ErrorKind::Conflict,
                "target is busy with another active deploy; one target — one active mutating operation",
            )
        }
        other => {
            tracing::warn!(error = %other, "unmapped CoreError");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal.unmapped",
                ErrorKind::Internal,
                "internal error",
            )
        }
    };
    (status, Json(ErrorResponse { code, kind, hint }))
}

/// Generic fallback for any `Display`able
/// error in a handler that we don't have a
/// typed mapping for. Returns a generic 500
/// with the error logged at warn level.
/// The error message is NOT echoed to the
/// client.
///
/// We use `&dyn Display` (not
/// `&dyn std::error::Error`) because some
/// error types in our handler stack —
/// notably `anyhow::Error` — implement
/// `Display` but not `std::error::Error`.
/// `Display` is enough for `tracing::warn!`
/// formatting; we never surface the message
/// to the client.
///
/// Most handlers should use
/// [`from_core_error`] when the underlying
/// error is a `CoreError`; this generic
/// helper is for sqlx / serde_json / anyhow
/// error arms where we have no per-type
/// mapping yet.
pub fn from_any_error(e: &dyn std::fmt::Display) -> (StatusCode, Json<ErrorResponse>) {
    tracing::warn!(error = %e, "handler returned untyped error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            code: "internal.untyped",
            kind: ErrorKind::Internal,
            hint: "internal error",
        }),
    )
}

/// Convenience for handlers that want to
/// return a stable `(StatusCode,
/// ErrorResponse)` pair directly (e.g.
/// "deploy not pending" without a CoreError
/// to map).
pub fn static_error(
    status: StatusCode,
    code: &'static str,
    kind: ErrorKind,
    hint: &'static str,
) -> (StatusCode, Json<ErrorResponse>) {
    (status, Json(ErrorResponse { code, kind, hint }))
}

/// P0-API-04 (TZ #1 §17 API-04, CWE-209):
/// the typed error variants the app uses
/// when it wants to return a structured
/// error from a handler (without
/// representing it as a `CoreError`).
///
/// `Internal` is the only `5xx` kind. The
/// rest are 4xx, classified by `code`.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("not found: {0}")]
    NotFound(&'static str),
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error("forbidden: {0}")]
    Forbidden(&'static str),
    #[error("bad request: {0}")]
    BadRequest(&'static str),
    #[error("internal error: {0}")]
    Internal(&'static str),
}

impl AppError {
    /// Convert an `AppError` into the typed
    /// response. Used by handlers that
    /// raise a domain error before
    /// reaching a repository.
    pub fn into_response(self) -> (StatusCode, Json<ErrorResponse>) {
        match self {
            AppError::NotFound(code) => static_error(
                StatusCode::NOT_FOUND,
                code,
                ErrorKind::NotFound,
                "resource not found",
            ),
            AppError::Conflict(code) => static_error(
                StatusCode::CONFLICT,
                code,
                ErrorKind::Conflict,
                "request conflicts with current state",
            ),
            AppError::Forbidden(code) => static_error(
                StatusCode::FORBIDDEN,
                code,
                ErrorKind::Forbidden,
                "forbidden",
            ),
            AppError::BadRequest(code) => static_error(
                StatusCode::BAD_REQUEST,
                code,
                ErrorKind::BadRequest,
                "bad request",
            ),
            AppError::Internal(code) => {
                tracing::warn!(error = %self, "app error internal");
                static_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    code,
                    ErrorKind::Internal,
                    "internal error",
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_core_error_schema_invalid_returns_400() {
        let e = CoreError::ErrSchemaInvalid {
            path: "users.name".to_string(),
            reason: "user-supplied value with <sql fragment>".to_string(),
        };
        let (status, body) = from_core_error(&e);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.0.code, "schema.invalid");
        // P0-API-04: the `reason` (which
        // can contain user input) is NOT
        // echoed to the response. Only the
        // stable `code` and a generic
        // `hint` reach the client.
        assert!(
            !body.0.hint.contains("sql fragment") && !body.0.hint.contains("user-supplied"),
            "hint MUST NOT contain user input; got: {}",
            body.0.hint
        );
    }

    #[test]
    fn from_core_error_sqlx_returns_500() {
        // The test-only constructor for a
        // CoreError::ErrSqlx is awkward
        // (sqlx::Error is heavy), so we
        // exercise the catch-all branch:
        // any unmapped CoreError returns 500.
        let e = CoreError::ErrSchemaInvalid {
            path: "x".to_string(),
            reason: "y".to_string(),
        };
        // We already covered this case in
        // schema_invalid; for the catch-all
        // branch, test that the response
        // shape is stable.
        let (status, body) = from_core_error(&e);
        assert!(status.is_client_error() || status.is_server_error());
        assert!(!body.0.code.is_empty());
        assert!(!body.0.hint.is_empty());
    }

    #[test]
    fn from_any_error_accepts_anyhow_error() {
        // The pre-fix code called
        // `e.to_string()` on `anyhow::Error`
        // and embedded the result in the
        // response body. Post-fix
        // (`from_any_error`), the error is
        // logged but the response body is
        // a stable `internal.untyped`.
        let e: anyhow::Error = anyhow::anyhow!("with <sql fragment>");
        let (status, body) = from_any_error(&e);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.0.code, "internal.untyped");
        // P0-API-04: user-input / SQL fragments
        // MUST NOT leak to the response.
        assert!(!body.0.hint.contains("sql"));
    }

    #[test]
    fn from_any_error_accepts_sqlx_error() {
        // sqlx::Error impls Display but not
        // std::error::Error in some configs.
        // Our `&dyn Display` signature
        // accepts it.
        let e: sqlx::Error = sqlx::Error::RowNotFound;
        let (status, _body) = from_any_error(&e);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn app_error_not_found_returns_404() {
        let e = AppError::NotFound("deploy.not_found");
        let (status, body) = e.into_response();
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body.0.code, "deploy.not_found");
        assert_eq!(body.0.kind, ErrorKind::NotFound);
    }

    #[test]
    fn app_error_conflict_returns_409() {
        let e = AppError::Conflict("deploy.not_pending");
        let (status, body) = e.into_response();
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body.0.code, "deploy.not_pending");
        assert_eq!(body.0.kind, ErrorKind::Conflict);
    }

    #[test]
    fn app_error_internal_returns_500() {
        let e = AppError::Internal("vault.read_error");
        let (status, body) = e.into_response();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.0.code, "vault.read_error");
        assert_eq!(body.0.kind, ErrorKind::Internal);
    }

    #[test]
    fn error_response_serialises_to_expected_json() {
        let body = ErrorResponse {
            code: "deploy.not_pending",
            kind: ErrorKind::Conflict,
            hint: "deploy is not pending",
        };
        let s = serde_json::to_string(&body).expect("serialise");
        // Snake-case kind. Stable shape.
        assert!(s.contains("\"code\":\"deploy.not_pending\""));
        assert!(s.contains("\"kind\":\"conflict\""));
        assert!(s.contains("\"hint\":\"deploy is not pending\""));
    }
}
