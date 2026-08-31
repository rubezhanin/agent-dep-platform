use crate::error::{CoreError, CoreResult};
use std::io;

#[test]
fn err_source_not_found_displays() {
    let e = CoreError::ErrSourceNotFound {
        source_id: "git@github.com:foo/bar".into(),
    };
    assert_eq!(e.to_string(), "source not found: git@github.com:foo/bar");
}

#[test]
fn err_untrusted_source_displays() {
    let e = CoreError::ErrUntrustedSource {
        source_id: "https://example.com/agents".into(),
        reason: "not in allowlist".into(),
    };
    let s = e.to_string();
    assert!(s.contains("untrusted source"));
    assert!(s.contains("https://example.com/agents"));
    assert!(s.contains("not in allowlist"));
}

#[test]
fn err_schema_invalid_displays() {
    let e = CoreError::ErrSchemaInvalid {
        path: "agents/foo/agent.yaml".into(),
        reason: "missing required field `metadata.id`".into(),
    };
    let s = e.to_string();
    assert!(s.contains("schema invalid"));
    assert!(s.contains("agents/foo/agent.yaml"));
    assert!(s.contains("metadata.id"));
}

#[test]
fn err_policy_blocked_displays() {
    let e = CoreError::ErrPolicyBlocked {
        rule: "plaintextSecrets".into(),
        target: "agents/foo/agent.yaml".into(),
    };
    assert!(e.to_string().contains("policy blocked"));
}

#[test]
fn err_hermes_not_found_displays() {
    let e = CoreError::ErrHermesNotFound;
    assert!(e.to_string().to_lowercase().contains("hermes"));
}

#[test]
fn err_path_outside_root_displays() {
    let e = CoreError::ErrPathOutsideRoot {
        path: "../../etc/passwd".into(),
        root: "/home/user/hermes".into(),
    };
    let s = e.to_string();
    assert!(s.contains("path outside root"));
    assert!(s.contains("../../etc/passwd"));
}

#[test]
fn err_symlink_escape_displays() {
    let e = CoreError::ErrSymlinkEscape {
        path: "/home/user/.hermes/plugins/foo".into(),
    };
    assert!(e.to_string().contains("symlink"));
}

#[test]
fn err_transaction_recovery_required_displays() {
    let e = CoreError::ErrTransactionRecoveryRequired {
        operation_id: "op-abc123".into(),
    };
    assert!(e.to_string().contains("recovery"));
    assert!(e.to_string().contains("op-abc123"));
}

#[test]
fn err_verification_failed_displays() {
    let e = CoreError::ErrVerificationFailed {
        target: "plugin.yaml".into(),
        reason: "hash mismatch".into(),
    };
    assert!(e.to_string().contains("verification failed"));
}

#[test]
fn err_unimplemented_displays() {
    let e = CoreError::Unimplemented {
        feature: "plans.compute".into(),
    };
    assert!(e.to_string().contains("not yet implemented"));
    assert!(e.to_string().contains("plans.compute"));
}

#[test]
fn from_io_error() {
    let io_err = io::Error::new(io::ErrorKind::NotFound, "no such file");
    let e: CoreError = io_err.into();
    match e {
        CoreError::ErrIo(_) => {}
        other => panic!("expected ErrIo, got {other:?}"),
    }
}

#[test]
fn core_result_alias_works() {
    fn returns_result() -> CoreResult<i32> {
        Ok(42)
    }
    let ok = returns_result();
    assert!(matches!(ok, Ok(42)));
    let err: CoreResult<i32> = Err(CoreError::Unimplemented {
        feature: "x".into(),
    });
    assert!(err.is_err());
}

#[test]
fn error_is_send_and_sync() {
    fn assert_send<T: Send + Sync>() {}
    assert_send::<CoreError>();
}

#[test]
fn error_implements_std_error() {
    fn check<E: std::error::Error>(_: E) {}
    check(CoreError::ErrHermesNotFound);
}
