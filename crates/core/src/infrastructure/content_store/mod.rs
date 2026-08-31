//! Content-addressed store (CAS). Immutable content keyed by sha256.
//!
//! Layout: `{root}/sha256/ab/cd/abcdef...`
//! Per TZ §11.2: stores `instructions.md`, `SKILL.md`, generated artifacts,
//! deployment snapshots, backup content. SQLite holds only references to
//! content hashes (TZ §11.3).

use crate::error::{CoreError, CoreResult};
use crate::infrastructure::filesystem::safe_path::resolve_safe_path;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub struct ContentStore {
    root: PathBuf,
}

impl ContentStore {
    pub fn new(root: PathBuf) -> CoreResult<Self> {
        std::fs::create_dir_all(root.join("sha256"))?;
        Ok(Self { root })
    }

    /// Hash bytes with sha256 and store them. Returns lowercase hex hash.
    /// Uses atomic temp+rename inside the CAS root.
    pub fn put(&self, bytes: &[u8]) -> CoreResult<String> {
        let hash = Self::hash(bytes);
        let final_path = self.path(&hash)?;
        if final_path.exists() {
            return Ok(hash);
        }
        // Ensure parent exists.
        if let Some(parent) = final_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Atomic write via temp file in same dir.
        let temp = final_path.with_extension("tmp");
        std::fs::write(&temp, bytes)?;
        std::fs::rename(&temp, &final_path)?;
        Ok(hash)
    }

    pub fn get(&self, hash: &str) -> CoreResult<Option<Vec<u8>>> {
        let p = self.path(hash)?;
        match std::fs::read(&p) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn exists(&self, hash: &str) -> bool {
        self.path(hash).map(|p| p.exists()).unwrap_or(false)
    }

    /// Compute the canonical on-disk path for a given hash, validated through
    /// the safe path resolver (defense in depth: even if `hash` is malicious,
    /// it can only resolve to a path inside the CAS root).
    pub fn path(&self, hash: &str) -> CoreResult<PathBuf> {
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(CoreError::ErrPathOutsideRoot {
                path: hash.to_string(),
                root: self.root.to_string_lossy().into_owned(),
            });
        }
        let prefix = &hash[..2];
        let inner = &hash[2..4];
        let rel: PathBuf = ["sha256", prefix, inner, hash].iter().collect();
        resolve_safe_path(&self.root, &rel)
    }

    fn hash(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let result = hasher.finalize();
        hex::encode(result)
    }
}

#[cfg(test)]
#[path = "content_store_tests.rs"]
mod content_store_tests;
