//! Path safety: resolve user-supplied paths to canonical absolute paths inside a
//! trusted root, rejecting traversal, absolute escapes, and symlink-based escapes.

use crate::error::{CoreError, CoreResult};
use std::path::{Component, Path, PathBuf};

/// Resolve `input` relative to `root`, returning a canonical absolute path inside `root`.
///
/// # Errors
/// - `ErrPathOutsideRoot` if `input` (after normalization) escapes `root`
/// - `ErrSymlinkEscape` if a symlink/junction on the resolved path leads outside `root`
pub fn resolve_safe_path(root: &Path, input: &Path) -> CoreResult<PathBuf> {
    // 0. Normalize the root if it exists. This matters on Windows where
    //    the caller may pass an 8.3 short-name (DOS-compatible form) while
    //    `canonicalize` returns the long-name form. Without this, a byte-
    //    for-byte `starts_with` would fail even though the two paths
    //    point to the same directory. The fix: canonicalize the root once
    //    up front so the comparison is long-vs-long.
    let root = if root.exists() {
        strip_verbatim_prefix(&canonicalize_existing(root)?)
    } else {
        root.to_path_buf()
    };

    // 1. Reject explicit `..` components early (defense in depth).
    for comp in input.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(CoreError::ErrPathOutsideRoot {
                path: input.to_string_lossy().into_owned(),
                root: root.to_string_lossy().into_owned(),
            });
        }
    }

    // 2. Reject NUL bytes (Windows path injection).
    if let Some(s) = input.to_str() {
        if s.contains('\0') {
            return Err(CoreError::ErrPathOutsideRoot {
                path: input.to_string_lossy().into_owned(),
                root: root.to_string_lossy().into_owned(),
            });
        }
    }

    // 3. Join with root.
    let joined = if input.is_absolute() {
        input.to_path_buf()
    } else {
        root.join(input)
    };

    // 4. If joined already exists on disk, canonicalize and verify containment.
    if joined.exists() {
        let canon = strip_verbatim_prefix(&canonicalize_existing(&joined)?);
        if !canon.starts_with(&root) {
            return Err(CoreError::ErrPathOutsideRoot {
                path: input.to_string_lossy().into_owned(),
                root: root.to_string_lossy().into_owned(),
            });
        }
        // Walk every component for symlink/junction that escapes.
        let mut current = root.clone();
        let rel = canon.strip_prefix(&root).unwrap_or(&canon);
        for comp in rel.components() {
            current.push(comp);
            if let Ok(meta) = std::fs::symlink_metadata(&current) {
                if meta.file_type().is_symlink() {
                    let target = std::fs::read_link(&current)?;
                    let resolved_target = if target.is_absolute() {
                        target
                    } else {
                        current.parent().unwrap_or(&root).join(target)
                    };
                    let canon_target =
                        strip_verbatim_prefix(&canonicalize_existing(&resolved_target)?);
                    if !canon_target.starts_with(&root) {
                        return Err(CoreError::ErrSymlinkEscape {
                            path: current.to_string_lossy().into_owned(),
                        });
                    }
                }
            }
        }
        return Ok(canon);
    }

    // 5. Path does not exist yet — walk to the deepest existing ancestor, canonicalize, re-append tail.
    let mut existing = joined.clone();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    while !existing.exists() {
        let name = existing
            .file_name()
            .ok_or_else(|| CoreError::ErrPathOutsideRoot {
                path: joined.to_string_lossy().into_owned(),
                root: root.to_string_lossy().into_owned(),
            })?;
        tail.push(name.to_os_string());
        if !existing.pop() {
            return Err(CoreError::ErrPathOutsideRoot {
                path: joined.to_string_lossy().into_owned(),
                root: root.to_string_lossy().into_owned(),
            });
        }
    }
    let mut result = strip_verbatim_prefix(&canonicalize_existing(&existing)?);
    for c in tail.into_iter().rev() {
        result.push(c);
    }
    if !result.starts_with(strip_verbatim_prefix(
        &canonicalize_existing(&root).unwrap_or_else(|_| root.clone()),
    )) {
        return Err(CoreError::ErrPathOutsideRoot {
            path: joined.to_string_lossy().into_owned(),
            root: root.to_string_lossy().into_owned(),
        });
    }
    Ok(result)
}

fn canonicalize_existing(p: &Path) -> CoreResult<PathBuf> {
    std::fs::canonicalize(p).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => CoreError::ErrPathOutsideRoot {
            path: p.to_string_lossy().into_owned(),
            root: String::new(),
        },
        _ => CoreError::ErrIo(e),
    })
}

/// Strip the Windows verbatim `\\?\` prefix for diff-friendly paths.
fn strip_verbatim_prefix(p: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let s = p.to_string_lossy();
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            return PathBuf::from(rest);
        }
    }
    p.to_path_buf()
}

#[cfg(test)]
#[path = "safe_path_tests.rs"]
mod safe_path_tests;
