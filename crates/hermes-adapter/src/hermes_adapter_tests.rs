use crate::detection::detect_hermes;

#[test]
fn detect_returns_not_found_when_home_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let result = detect_hermes(dir.path());
    assert!(matches!(
        result,
        Err(agent_dep_core::error::CoreError::ErrHermesNotFound)
    ));
}

#[test]
fn hermes_adapter_struct_can_be_constructed() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = crate::hermes_adapter::HermesAdapter::new(dir.path().to_path_buf());
    assert_eq!(adapter.hermes_home(), dir.path());
}
