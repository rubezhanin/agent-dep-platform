use crate::error::CoreError;
use crate::infrastructure::filesystem::safe_path::resolve_safe_path;
use proptest::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

fn temp_root() -> PathBuf {
    let dir = tempfile::tempdir().expect("tempdir");
    let raw = dir.keep();
    // Use dunce::canonicalize on Windows to avoid the `\\?\` verbatim prefix,
    // so the returned root is in the same form as the function's output.
    dunce::canonicalize(&raw).unwrap_or(raw)
}

#[test]
fn rejects_traversal_attempt() {
    let root = temp_root();
    let bad = Path::new("..").join("etc").join("passwd");
    let result = resolve_safe_path(&root, &bad);
    assert!(matches!(result, Err(CoreError::ErrPathOutsideRoot { .. })));
}

#[test]
fn rejects_absolute_path_outside_root() {
    let root = temp_root();
    let result = resolve_safe_path(&root, Path::new("C:\\Windows\\System32"));
    let is_blocked = matches!(
        result,
        Err(CoreError::ErrPathOutsideRoot { .. }) | Err(CoreError::ErrSymlinkEscape { .. })
    );
    assert!(is_blocked, "expected blocked, got: {result:?}");
}

/// Same as `rejects_absolute_path_outside_root` but with a forward-slash
/// drive-letter path (e.g. `D:/foo/bar`). The path shape is also
/// Windows-only and must be rejected on Linux/macOS where it would
/// otherwise be treated as a relative filename.
#[test]
fn rejects_windows_drive_letter_with_forward_slash() {
    let root = temp_root();
    let result = resolve_safe_path(&root, Path::new("D:/secrets/passwords"));
    let is_blocked = matches!(
        result,
        Err(CoreError::ErrPathOutsideRoot { .. }) | Err(CoreError::ErrSymlinkEscape { .. })
    );
    assert!(is_blocked, "expected blocked, got: {result:?}");
}

#[test]
fn accepts_relative_safe_path() {
    let root = temp_root();
    let sub = root.join("plugins").join("agency-agents");
    fs::create_dir_all(&sub).unwrap();
    let result = resolve_safe_path(&root, Path::new("plugins/agency-agents"));
    assert!(result.is_ok(), "got: {result:?}");
    let resolved = result.unwrap();
    assert!(resolved.starts_with(&root));
}

#[test]
fn accepts_safe_path_that_does_not_yet_exist() {
    let root = temp_root();
    let result = resolve_safe_path(&root, Path::new("plugins/not-yet-existing"));
    assert!(result.is_ok(), "got: {result:?}");
    let resolved = result.unwrap();
    assert!(resolved.starts_with(&root));
}

#[test]
fn rejects_nul_byte_in_path() {
    let root = temp_root();
    let bad = Path::new("foo\0bar");
    let result = resolve_safe_path(&root, bad);
    assert!(matches!(result, Err(CoreError::ErrPathOutsideRoot { .. })));
}

proptest! {
    /// Any relative path without `..` components, when joined with root,
    /// must canonicalize to a path inside root (or fail with ErrSymlinkEscape).
    #[test]
    fn safe_paths_remain_inside_root(
        segments in proptest::collection::vec("[a-z][a-z0-9_]{0,8}", 1..5)
    ) {
        let root = temp_root();
        let input: PathBuf = segments.iter().collect();
        let _ = fs::create_dir_all(root.join(&input));
        let result = resolve_safe_path(&root, &input);
        let is_ok_or_symlink_escape = matches!(
            &result,
            Ok(_) | Err(CoreError::ErrSymlinkEscape { .. })
        );
        if let Ok(p) = &result {
            prop_assert!(p.starts_with(&root));
        } else {
            prop_assert!(is_ok_or_symlink_escape, "unexpected error: {:?}", result);
        }
    }

    /// Any path with `..` components must be rejected.
    #[test]
    fn traversal_paths_are_rejected(
        prefix in proptest::collection::vec("[a-z]{1,5}", 1..3),
        suffix in proptest::collection::vec("[a-z]{1,5}", 1..3),
    ) {
        let root = temp_root();
        let mut input: PathBuf = prefix.iter().collect();
        input.push("..");
        input.push("..");
        for s in &suffix {
            input.push(s);
        }
        let result = resolve_safe_path(&root, &input);
        let blocked = matches!(
            &result,
            Err(CoreError::ErrPathOutsideRoot { .. }) | Err(CoreError::ErrSymlinkEscape { .. })
        );
        prop_assert!(blocked, "expected blocked, got: {:?}", result);
    }

    /// resolve_safe_path is idempotent.
    #[test]
    fn resolve_is_idempotent(
        segments in proptest::collection::vec("[a-z][a-z0-9_]{0,5}", 1..4)
    ) {
        let root = temp_root();
        let input: PathBuf = segments.iter().collect();
        let _ = fs::create_dir_all(root.join(&input));
        if let Ok(p1) = resolve_safe_path(&root, &input) {
            let p2 = resolve_safe_path(&root, &p1).expect("idempotent");
            prop_assert_eq!(p1, p2);
        }
    }
}
