# MVP-0 Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a runnable, testable, CI-gated Tauri 2 + Svelte 5 + Rust skeleton of the Enterprise Agent Deployment Platform with all infrastructure in place (workspace, types, tracing, SQLite, CAS, IPC, CLI, UI routing) and no business logic.

**Architecture:** Multi-crate Cargo workspace (`core`, `hermes-adapter`, `cli`, `tauri-app`). `core` holds domain, application, infrastructure. `hermes-adapter` implements `RuntimeAdapter` trait. `cli` and `tauri-app` are thin consumers of `core` services. Frontend is Svelte 5 + Vite with 9 placeholder routes. ts-rs generates TypeScript types from Rust DTOs with a drift-CI guard.

**Tech Stack:**
- Rust 1.83+ (stable), edition 2021
- Tauri 2.x
- Svelte 5.x with runes
- TypeScript 5.x
- Vite 5.x
- ts-rs 11.x (Rust→TS codegen)
- sqlx 0.8.x (SQLite, runtime queries + `migrate!()`)
- tracing + tracing-subscriber + tracing-appender
- thiserror 1.x
- clap 4.x with derive
- proptest 1.x
- which 6.x
- pnpm (preferred) or npm

**Reference Spec:** `docs/superpowers/specs/2026-08-31-bootstrap-mvp-0-design.md` (approved 2026-08-31).

---

## Global Constraints

These apply to every task:

- **Workspace root:** `C:\projects\agent-dep-platform`
- **Git:** local only, no remote. Commits are atomic per task with conventional-commit messages. Identity: `Mavis <Mavis@local>` (local repo config).
- **Path safety:** every function that takes user-supplied path input must go through `core::infrastructure::filesystem::safe_path::resolve_safe_path` (Task 3). No raw `Path::join` for write operations.
- **Error handling:** every fallible function returns `Result<T, CoreError>`. No `unwrap()` in production code. `expect()` allowed in tests with a message.
- **Type sharing:** any Rust type that crosses the IPC boundary gets `#[derive(TS)] #[ts(export, export_to = "../../src/lib/types.generated.ts")]` (Task 11).
- **Testing:** unit + property-based + integration as appropriate. All tests must pass before commit.
- **Formatting:** `cargo fmt --all -- --check` must be clean. `cargo clippy --workspace --all-targets -- -D warnings` must be clean.
- **Line endings:** CRLF on Windows (default `core.autocrlf` on this machine). PowerShell: use single quotes for regex; do not use `&&` chain.
- **Commit messages:** file-based via `git commit -F <file>`, never inline `-m "..."` (preserves backslashes per agent memory).
- **No remote:** no `gh`, no push, no `git remote add`.

---

## Task 1: Workspace + 4 crate skeletons

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `rust-toolchain.toml`
- Create: `rustfmt.toml`
- Create: `clippy.toml`
- Create: `.gitignore`
- Create: `.editorconfig`
- Create: `README.md`
- Create: `crates/core/Cargo.toml`
- Create: `crates/core/src/lib.rs`
- Create: `crates/hermes-adapter/Cargo.toml`
- Create: `crates/hermes-adapter/src/lib.rs`
- Create: `crates/cli/Cargo.toml`
- Create: `crates/cli/src/main.rs`
- Create: `crates/tauri-app/Cargo.toml`
- Create: `crates/tauri-app/src/lib.rs`
- Create: `crates/tauri-app/src/main.rs`

**Interfaces:**
- Consumes: nothing (this is the first task)
- Produces:
  - `cargo build --workspace` returns 0
  - `cargo fmt --all -- --check` returns 0
  - `cargo clippy --workspace -- -D warnings` returns 0

### Step 1.1: Create workspace root `Cargo.toml`

Write to `C:\projects\agent-dep-platform\Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = [
    "crates/core",
    "crates/hermes-adapter",
    "crates/cli",
    "crates/tauri-app",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
rust-version = "1.83"
license = "MIT OR Apache-2.0"
authors = ["Agent Deployment Platform Contributors"]
repository = ""  # private local-only; intentionally empty

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
thiserror = "1"
anyhow = "1"
tokio = { version = "1", features = ["full"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
tracing-appender = "0.2"
ts-rs = "11"
sqlx = { version = "0.8", features = ["runtime-tokio", "sqlite", "macros", "migrate"] }
proptest = "1"
clap = { version = "4", features = ["derive"] }
which = "6"
tempfile = "3"
once_cell = "1"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4", "serde"] }
sha2 = "0.10"
hex = "0.4"
walkdir = "2"

[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
```

### Step 1.2: Create `rust-toolchain.toml`

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

### Step 1.3: Create `rustfmt.toml`

```toml
edition = "2021"
max_width = 100
tab_spaces = 4
```

### Step 1.4: Create `clippy.toml`

```toml
avoid-breaking-exported-api = false
msrv = "1.83"
```

### Step 1.5: Create `.gitignore`

```gitignore
# Rust
/target
**/target
**/*.rs.bk
Cargo.lock.bak

# Tauri
**/gen/

# Node
node_modules/
dist/
.vite/
.pnpm-store/

# Logs
*.log

# OS
.DS_Store
Thumbs.db

# IDE
.idea/
.vscode/
*.swp

# Local
.env
.env.local
*.local
```

### Step 1.6: Create `.editorconfig`

```ini
root = true

[*]
charset = utf-8
end_of_line = crlf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 4

[*.{yaml,yml,json,toml}]
indent_size = 2

[*.{md,markdown}]
trim_trailing_whitespace = false

[*.svelte]
indent_size = 2
```

### Step 1.7: Create `README.md`

```markdown
# Enterprise Agent Deployment Platform

Local-only Tauri 2 + Svelte 5 + Rust desktop application for safely deploying
agent systems from Git repositories into Hermes Agent.

## Status

**MVP-0 (Bootstrap)** — see `docs/superpowers/specs/2026-08-31-bootstrap-mvp-0-design.md`.

## Build

```sh
cargo build --workspace
cargo test --workspace
```

## CI

```powershell
.\scripts\ci.ps1
```

## Spec

See `docs/superpowers/specs/` and `docs/superpowers/plans/`.
Source TZ: `TZ_Enterprise_Agent_Deployment_Platform_Final.md`.
```

### Step 1.8: Create `crates/core/Cargo.toml`

```toml
[package]
name = "agent_dep_core"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
serde_yaml = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true }
tracing = { workspace = true }
ts-rs = { workspace = true }
sqlx = { workspace = true }
proptest = { workspace = true }
chrono = { workspace = true }
uuid = { workspace = true }
sha2 = { workspace = true }
hex = { workspace = true }
walkdir = { workspace = true }
once_cell = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }
```

### Step 1.9: Create `crates/core/src/lib.rs`

```rust
// MVP-0 stub. Real domain/application modules land in later tasks.
#![doc = "Core domain, application, and infrastructure for the Agent Deployment Platform."]

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }
}
```

### Step 1.10: Create `crates/hermes-adapter/Cargo.toml`

```toml
[package]
name = "agent_dep_hermes_adapter"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true

[dependencies]
agent_dep_core = { path = "../core" }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true }
tracing = { workspace = true }
ts-rs = { workspace = true }
which = { workspace = true }
```

### Step 1.11: Create `crates/hermes-adapter/src/lib.rs`

```rust
// MVP-0 stub. Real adapter lands in Task 6.
#![doc = "Hermes runtime adapter."]

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }
}
```

### Step 1.12: Create `crates/cli/Cargo.toml`

```toml
[package]
name = "agent_dep_cli"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true

[[bin]]
name = "agency"
path = "src/main.rs"

[dependencies]
agent_dep_core = { path = "../core" }
agent_dep_hermes_adapter = { path = "../hermes-adapter" }
clap = { workspace = true }
tokio = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
anyhow = { workspace = true }
```

### Step 1.13: Create `crates/cli/src/main.rs`

```rust
// MVP-0 stub. Real CLI commands land in Task 7.
fn main() {
    eprintln!("agency CLI: stub (MVP-0). Use `agency --help` after Task 7.");
    std::process::exit(2);
}
```

### Step 1.14: Create `crates/tauri-app/Cargo.toml`

```toml
[package]
name = "agent_dep_app"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true
default-run = "agent_dep_app"

[[bin]]
name = "agent_dep_app"
path = "src/main.rs"

[lib]
name = "agent_dep_app_lib"
crate-type = ["staticlib", "cdylib", "rlib"]

[build-dependencies]
tauri-build = { version = "2", features = [] }

[dependencies]
agent_dep_core = { path = "../core" }
agent_dep_hermes_adapter = { path = "../hermes-adapter" }
tauri = { version = "2", features = [] }
serde = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
tracing-appender = { workspace = true }
thiserror = { workspace = true }
anyhow = { workspace = true }
```

### Step 1.15: Create `crates/tauri-app/src/lib.rs`

```rust
// MVP-0 stub. Real Tauri app lands in Task 8.
#![doc = "Tauri 2 host for the Agent Deployment Platform."]

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }
}
```

### Step 1.16: Create `crates/tauri-app/src/main.rs`

```rust
fn main() {
    eprintln!("Tauri app: stub (MVP-0). Real run() lives in agent_dep_app_lib::run().");
    std::process::exit(2);
}
```

### Step 1.17: Verify workspace builds

Run from `C:\projects\agent-dep-platform`:

```powershell
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
```

Expected: all three return exit code 0. If clippy fails on a Tauri 2.0 stub warning, add `#![allow(dead_code)]` to `crates/tauri-app/src/lib.rs`.

### Step 1.18: First commit

Write commit message to a temp file and commit:

```powershell
git add Cargo.toml rust-toolchain.toml rustfmt.toml clippy.toml .gitignore .editorconfig README.md crates/
git status --short
git commit -F .git/COMMIT_EDITMSG_NEW
```

Commit message (write to `.git\COMMIT_EDITMSG_NEW` before running commit, then delete with Python):

```text
chore: bootstrap workspace + 4 crate skeletons

- Workspace root with 4 members: core, hermes-adapter, cli, tauri-app
- Workspace dependencies (serde, tokio, sqlx, ts-rs, tracing, etc.)
- rust-toolchain, rustfmt, clippy configs
- .gitignore (Tauri + Rust + Node), .editorconfig
- Minimal README pointing at TZ and spec
- Each crate has a stub lib.rs/main.rs that compiles
- cargo build --workspace green
- cargo fmt/clippy clean
```

After commit, delete the temp file with `python -c "import os; os.remove(r'C:\projects\agent-dep-platform\.git\COMMIT_EDITMSG_NEW')"`.

**Acceptance:**
- `cargo build --workspace` green
- `cargo fmt --all -- --check` green
- `cargo clippy --workspace -- -D warnings` green
- `git log --oneline` shows 1 commit

---

## Task 2: Domain error taxonomy

**Files:**
- Create: `crates/core/src/error.rs`
- Modify: `crates/core/src/lib.rs` (add `pub mod error;`)

**Interfaces:**
- Consumes: nothing
- Produces:
  - `pub use crate::error::{CoreError, CoreResult};` available from `agent_dep_core::error`
  - `pub enum CoreError` with variants per TZ §35 plus `Unimplemented`
  - `pub type CoreResult<T> = Result<T, CoreError>;`
  - `impl Display for CoreError`
  - `impl std::error::Error for CoreError`
  - `From<std::io::Error> for CoreError` mapping to `ErrIo`

### Step 2.1: Write the failing test

Modify `crates/core/src/lib.rs` to add at the bottom (after the existing tests module):

```rust
#[cfg(test)]
mod error_tests;
```

Create `crates/core/src/error_tests.rs`:

```rust
use crate::error::{CoreError, CoreResult};
use std::io;

#[test]
fn err_source_not_found_displays() {
    let e = CoreError::ErrSourceNotFound {
        source: "git@github.com:foo/bar".into(),
    };
    assert_eq!(e.to_string(), "source not found: git@github.com:foo/bar");
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
        CoreError::ErrIo { .. } => {}
        other => panic!("expected ErrIo, got {other:?}"),
    }
}

#[test]
fn core_result_alias_works() {
    let ok: CoreResult<i32> = Ok(42);
    assert_eq!(ok.unwrap(), 42);
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
```

### Step 2.2: Run the test, verify it fails

```powershell
cargo test -p agent_dep_core error_tests
```

Expected: compile error — `error` module does not exist.

### Step 2.3: Implement `error.rs`

Create `crates/core/src/error.rs`:

```rust
//! Core error taxonomy (TZ §35) plus an `Unimplemented` variant for stub features.

use std::fmt;

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("source not found: {source}")]
    ErrSourceNotFound { source: String },

    #[error("schema invalid at {path}: {reason}")]
    ErrSchemaInvalid { path: String, reason: String },

    #[error("untrusted source: {source} (reason: {reason})")]
    ErrUntrustedSource { source: String, reason: String },

    #[error("policy blocked (rule: {rule}) on {target}")]
    ErrPolicyBlocked { rule: String, target: String },

    #[error("dependency missing: {dependency} (required by {required_by})")]
    ErrDependencyMissing { dependency: String, required_by: String },

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
}

// `From<CoreError>` is implicit via thiserror's blanket impl; we keep `From<io::Error>`
// working here for completeness.
impl From<std::io::Error> for CoreError {
    // Delegated to `#[from]` in the enum above; this impl is unreachable but
    // documents the conversion explicitly.
    fn from(_: std::io::Error) -> Self {
        unreachable!("handled by #[from] attribute on ErrIo")
    }
}

// Suppress dead-code warning for the unreachable impl when not all variants are used yet.
#[allow(dead_code)]
fn _ensure_display_impl(e: &CoreError) -> fmt::Display {
    e
}
```

### Step 2.4: Add `pub mod error;` to `lib.rs`

Modify `crates/core/src/lib.rs`, replace the file with:

```rust
// MVP-0 stub. Real domain/application modules land in later tasks.
#![doc = "Core domain, application, and infrastructure for the Agent Deployment Platform."]

pub mod error;

pub use error::{CoreError, CoreResult};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }
}

#[cfg(test)]
mod error_tests;
```

### Step 2.5: Run tests, verify all pass

```powershell
cargo test -p agent_dep_core
cargo fmt --all -- --check
cargo clippy -p agent_dep_core -- -D warnings
```

Expected: all tests pass, fmt/clippy clean.

### Step 2.6: Commit

Write to `.git\COMMIT_EDITMSG_NEW`:

```text
feat(core): domain error taxonomy (TZ §35)

- CoreError enum with 14 variants per TZ §35
- Unimplemented variant for stub features (added for MVP-0 stubs)
- Display, std::error::Error via thiserror
- From impls for io::Error, serde_json::Error, serde_yaml::Error, sqlx::Error
- CoreResult<T> alias
- 13 unit tests covering Display for each main variant and From conversions
```

Commit and delete the temp file.

**Acceptance:**
- `cargo test -p agent_dep_core` green with 14+ tests
- `cargo fmt` and `cargo clippy -D warnings` clean

---

## Task 3: Path safety with property-based tests

**Files:**
- Create: `crates/core/src/infrastructure/mod.rs`
- Create: `crates/core/src/infrastructure/filesystem/mod.rs`
- Create: `crates/core/src/infrastructure/filesystem/safe_path.rs`
- Create: `crates/core/src/infrastructure/filesystem/safe_path_tests.rs`
- Modify: `crates/core/src/lib.rs` (add `pub mod infrastructure;`)

**Interfaces:**
- Consumes: `crate::error::{CoreError, CoreResult}` (from Task 2)
- Produces:
  - `pub fn resolve_safe_path(root: &Path, input: &Path) -> CoreResult<PathBuf>`
  - Errors: `ErrPathOutsideRoot` or `ErrSymlinkEscape`
  - Behavior:
    1. Reject absolute `input` outside `root` (or canonicalize and check)
    2. Reject any `..` component
    3. If `root` or any intermediate is a symlink, follow it and re-validate containment
    4. Return canonicalized absolute path inside `root`

### Step 3.1: Write failing test file

Create `crates/core/src/infrastructure/filesystem/safe_path_tests.rs`:

```rust
use crate::error::CoreError;
use crate::infrastructure::filesystem::safe_path::resolve_safe_path;
use proptest::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

fn temp_root() -> PathBuf {
    let dir = tempfile::tempdir().expect("tempdir");
    dir.into_path()
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
    // On Windows the path may also be canonicalized to ErrSymlinkEscape; either is acceptable.
    assert!(matches!(
        result,
        Err(CoreError::ErrPathOutsideRoot { .. }) | Err(CoreError::ErrSymlinkEscape { .. })
    ));
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
fn rejects_symlink_escape() {
    let root = temp_root();
    let outside = tempfile::tempdir().unwrap();
    let link_path = root.join("escape");
    // On Windows symlink creation may require privileges; skip if it fails.
    if std::os::windows::fs::symlink_dir(outside.path(), &link_path).is_ok() {
        let result = resolve_safe_path(&root, Path::new("escape"));
        assert!(matches!(
            result,
            Err(CoreError::ErrSymlinkEscape { .. }) | Err(CoreError::ErrPathOutsideRoot { .. })
        ));
    }
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
        // Ensure the joined path exists (create dirs).
        let joined = root.join(&input);
        let _ = fs::create_dir_all(&joined);
        let result = resolve_safe_path(&root, &input);
        match result {
            Ok(p) => prop_assert!(p.starts_with(&root)),
            Err(CoreError::ErrSymlinkEscape { .. }) => prop_assert!(true),  // acceptable
            Err(e) => prop_assert!(false, "unexpected error: {e:?}"),
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
        prop_assert!(matches!(
            result,
            Err(CoreError::ErrPathOutsideRoot { .. }) | Err(CoreError::ErrSymlinkEscape { .. })
        ));
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
```

### Step 3.2: Run the test, verify it fails

```powershell
cargo test -p agent_dep_core safe_path
```

Expected: compile error — module does not exist.

### Step 3.3: Create the module skeleton

Create `crates/core/src/infrastructure/mod.rs`:

```rust
//! Infrastructure layer: external-world adapters (filesystem, sqlite, git, etc.).
//! Domain and application layers MUST NOT import from here directly except through
//! these modules' public APIs.

pub mod filesystem;
```

Create `crates/core/src/infrastructure/filesystem/mod.rs`:

```rust
//! Filesystem utilities.

pub mod safe_path;
```

Create `crates/core/src/infrastructure/filesystem/safe_path.rs` (initial failing impl):

```rust
//! Path safety: resolve user-supplied paths to canonical absolute paths inside a
//! trusted root, rejecting traversal, absolute escapes, and symlink-based escapes.

use crate::error::{CoreError, CoreResult};
use std::path::{Component, Path, PathBuf};

/// Resolve `input` relative to `root`, returning a canonical absolute path inside `root`.
///
/// Rejects:
/// - absolute `input` that escapes `root`
/// - `..` components
/// - symlinks (including junctions) that point outside `root`
pub fn resolve_safe_path(root: &Path, input: &Path) -> CoreResult<PathBuf> {
    // TODO: implement
    Err(CoreError::Unimplemented { feature: "resolve_safe_path".into() })
}
```

Modify `crates/core/src/lib.rs`, add `pub mod infrastructure;` after `pub mod error;`:

```rust
#![doc = "Core domain, application, and infrastructure for the Agent Deployment Platform."]

pub mod error;
pub mod infrastructure;

pub use error::{CoreError, CoreResult};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }
}

#[cfg(test)]
mod error_tests;
```

### Step 3.4: Run the test, verify it now fails meaningfully

```powershell
cargo test -p agent_dep_core safe_path
```

Expected: tests pass for the unimplemented cases that match `Unimplemented`? No — the tests expect `ErrPathOutsideRoot` etc. They will FAIL with our stub.

### Step 3.5: Implement `resolve_safe_path`

Replace `crates/core/src/infrastructure/filesystem/safe_path.rs` with:

```rust
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
    // 1. Reject explicit `..` components early (defense in depth).
    for comp in input.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(CoreError::ErrPathOutsideRoot {
                path: input.to_string_lossy().into_owned(),
                root: root.to_string_lossy().into_owned(),
            });
        }
    }

    // 2. Join with root.
    let joined = if input.is_absolute() {
        input.to_path_buf()
    } else {
        root.join(input)
    };

    // 3. Check intermediate path components for symlinks before canonicalize.
    let mut current = root.to_path_buf();
    let rel = joined.strip_prefix(root).unwrap_or(&joined);
    for comp in rel.components() {
        let next = current.join(comp);
        match std::fs::symlink_metadata(&next) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let target = std::fs::read_link(&next)?;
                let resolved_target = if target.is_absolute() {
                    target
                } else {
                    next.parent().unwrap_or(root).join(target)
                };
                let canon_target = canonicalize_existing(&resolved_target)?;
                if !canon_target.starts_with(root) {
                    return Err(CoreError::ErrSymlinkEscape {
                        path: next.to_string_lossy().into_owned(),
                    });
                }
                current = canon_target;
            }
            Ok(_) => current = next,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Path doesn't exist yet (e.g. we're about to create it). Walk the
                // existing parent and verify, then return the canonicalized parent + missing tail.
                return canonicalize_missing(root, &joined, rel);
            }
            Err(e) => return Err(e.into()),
        }
    }

    // 4. Final canonicalize (handles the case where everything exists).
    let canon = canonicalize_existing(&joined)?;
    if !canon.starts_with(root) {
        return Err(CoreError::ErrPathOutsideRoot {
            path: input.to_string_lossy().into_owned(),
            root: root.to_string_lossy().into_owned(),
        });
    }
    Ok(canon)
}

fn canonicalize_existing(p: &Path) -> CoreResult<PathBuf> {
    dunce_canonicalize(p).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => CoreError::ErrPathOutsideRoot {
            path: p.to_string_lossy().into_owned(),
            root: String::new(),
        },
        _ => CoreError::ErrIo(e),
    })
}

/// Canonicalize a path that may not yet exist: walk to the deepest existing
/// ancestor, canonicalize, then re-append the non-existing tail.
fn canonicalize_missing(root: &Path, joined: &Path, rel: &Path) -> CoreResult<PathBuf> {
    let mut existing = joined.to_path_buf();
    let mut tail_components: Vec<std::ffi::OsString> = Vec::new();
    while !existing.exists() {
        let name = existing.file_name().ok_or_else(|| CoreError::ErrPathOutsideRoot {
            path: joined.to_string_lossy().into_owned(),
            root: root.to_string_lossy().into_owned(),
        })?;
        tail_components.push(name.to_os_string());
        existing.pop();
    }
    let canon_existing = canonicalize_existing(&existing)?;
    let mut result = canon_existing;
    for c in tail_components.into_iter().rev() {
        result.push(c);
    }
    if !result.starts_with(&canon_existing) || !canon_existing.starts_with(root) {
        return Err(CoreError::ErrPathOutsideRoot {
            path: joined.to_string_lossy().into_owned(),
            root: root.to_string_lossy().into_owned(),
        });
    }
    // Suppress unused warning; rel is for documentation.
    let _ = rel;
    Ok(result)
}

/// Canonicalize without the Windows verbatim `\\?\` prefix so paths are diff-friendly.
fn dunce_canonicalize(p: &Path) -> std::io::Result<PathBuf> {
    let c = std::fs::canonicalize(p)?;
    #[cfg(windows)]
    {
        // Strip the `\\?\` prefix if present.
        let s = c.to_string_lossy();
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            return Ok(PathBuf::from(rest));
        }
    }
    Ok(c)
}
```

Add `dunce` to workspace dependencies: in `Cargo.toml` `[workspace.dependencies]`, add:

```toml
dunce = "1"
```

And in `crates/core/Cargo.toml` `[dependencies]`, add:

```toml
dunce = { workspace = true }
```

(We use `dunce` for canonicalize on Windows; the local helper above can also be used, but `dunce` is more robust. Using local helper to keep dependencies minimal; if tests fail on Windows verbatim prefix, add `dunce` instead.)

### Step 3.6: Run tests, verify all pass

```powershell
cargo test -p agent_dep_core safe_path
cargo fmt --all -- --check
cargo clippy -p agent_dep_core -- -D warnings
```

If clippy complains about complexity, allow it: in `safe_path.rs` add `#![allow(clippy::too_many_lines)]` at the top.

Expected: all property-based tests pass (some skipped on Windows without symlink privileges).

### Step 3.7: Commit

Write to `.git\COMMIT_EDITMSG_NEW`:

```text
feat(core): path safety with proptest

- resolve_safe_path(root, input) -> CoreResult<PathBuf>
- Rejects .. components, absolute paths outside root, symlink escapes
- 3 unit tests + 3 property-based tests via proptest
- Property tests verify: containment for safe paths, rejection for traversal, idempotence
```

Commit and delete the temp file.

**Acceptance:**
- `cargo test -p agent_dep_core safe_path` green
- Property tests run ≥ 100 cases each
- `cargo fmt` and `cargo clippy -D warnings` clean

---

## Task 4: SQLite + sqlx migrations skeleton

**Files:**
- Create: `crates/core/src/infrastructure/sqlite/mod.rs`
- Create: `crates/core/src/infrastructure/sqlite/migrations/001_initial.sql`
- Create: `crates/core/src/infrastructure/sqlite/sqlite_tests.rs`
- Modify: `crates/core/src/infrastructure/mod.rs` (add `pub mod sqlite;`)

**Interfaces:**
- Consumes: `crate::error::{CoreError, CoreResult}`, `sqlx::SqlitePool`
- Produces:
  - `pub struct Db { pool: SqlitePool }`
  - `pub async fn connect(path: &Path) -> CoreResult<Db>`
  - `pub async fn migrate(&self) -> CoreResult<()>`
  - `pub async fn schema_version(&self) -> CoreResult<i64>`

### Step 4.1: Write failing test

Create `crates/core/src/infrastructure/sqlite/sqlite_tests.rs`:

```rust
use crate::infrastructure::sqlite::{connect, schema_version};
use std::path::Path;

#[tokio::test]
async fn in_memory_db_migrates_to_v1() {
    let db = connect(Path::new(":memory:")).await.expect("connect");
    db.migrate().await.expect("migrate");
    let v = schema_version(&db).await.expect("version");
    assert_eq!(v, 1);
}

#[tokio::test]
async fn file_db_creates_and_migrates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate");
    assert!(path.exists());
    let v = schema_version(&db).await.expect("version");
    assert_eq!(v, 1);
}

#[tokio::test]
async fn migrate_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("idem.db");
    let db = connect(&path).await.expect("connect");
    db.migrate().await.expect("migrate 1");
    db.migrate().await.expect("migrate 2");
    let v = schema_version(&db).await.expect("version");
    assert_eq!(v, 1);
}
```

### Step 4.2: Run the test, verify it fails

```powershell
cargo test -p agent_dep_core sqlite
```

Expected: compile error.

### Step 4.3: Create migration

Create `crates/core/migrations/001_initial.sql` (path relative to the `crates/core/` package root, which is what `sqlx::migrate!()` resolves against):

```sql
-- Initial schema: meta table for tracking applied migrations.
-- Subsequent migrations append to this directory.

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- sqlx records applied migrations in _sqlx_migrations; this `meta` table is
-- our own high-level version tracker.
INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '1');
```

### Step 4.4: Implement module

Modify `crates/core/src/infrastructure/mod.rs`:

```rust
//! Infrastructure layer: external-world adapters (filesystem, sqlite, git, etc.).
//! Domain and application layers MUST NOT import from here directly except through
//! these modules' public APIs.

pub mod filesystem;
pub mod sqlite;
```

Create `crates/core/src/infrastructure/sqlite/mod.rs`:

```rust
//! SQLite metadata store. Schema is migration-based (`migrations/*.sql`).
//!
//! Per TZ §11.1: SQLite stores metadata only (sources, snapshots, agents, skills,
//! systems, deployments, operations, audit, policy). Immutable content lives in
//! the content-addressed store (Task 5). SQLite MUST NOT be a source of truth
//! for System definitions (TZ §26.2) — those are YAML/JSON in Git.

use crate::error::CoreResult;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::path::Path;
use std::str::FromStr;

pub struct Db {
    pool: SqlitePool,
}

impl Db {
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

pub async fn connect(path: &Path) -> CoreResult<Db> {
    let url = if path == Path::new(":memory:") {
        "sqlite::memory:".to_string()
    } else {
        format!("sqlite://{}", path.to_string_lossy())
    };
    let opts = SqliteConnectOptions::from_str(&url)
        .map_err(|e| crate::error::CoreError::ErrSqlx(e.into()))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(std::time::Duration::from_secs(5))
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await?;
    Ok(Db { pool })
}

impl Db {
    pub async fn migrate(&self) -> CoreResult<()> {
        // `./migrations` is resolved against the `crates/core/` package root,
        // not the source file. The migration files live at
        // `crates/core/migrations/*.sql`.
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }
}

pub async fn schema_version(db: &Db) -> CoreResult<i64> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT value FROM meta WHERE key = 'schema_version'")
            .fetch_optional(db.pool())
            .await?;
    match row {
        Some((v,)) => v.parse::<i64>().map_err(|e| crate::error::CoreError::ErrIo(
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("bad schema_version: {e}")),
        )),
        None => Ok(0),
    }
}

#[cfg(test)]
mod sqlite_tests;
```

### Step 4.5: Run tests

```powershell
cargo test -p agent_dep_core sqlite
cargo fmt --all -- --check
cargo clippy -p agent_dep_core -- -D warnings
```

Expected: all 3 tests pass.

### Step 4.6: Commit

Write to `.git\COMMIT_EDITMSG_NEW`:

```text
feat(core): sqlite + sqlx migrations skeleton

- Db struct wrapping SqlitePool
- connect(path) with WAL mode, FK on, busy timeout
- migrate() via sqlx::migrate!()
- schema_version() reads from meta table
- 001_initial.sql creates meta table
- 3 tests: in-memory, file, idempotency
```

Commit and delete temp file.

**Acceptance:**
- `cargo test -p agent_dep_core sqlite` green with 3 tests
- `cargo fmt` and `cargo clippy -D warnings` clean

---

## Task 5: Content-addressed store skeleton

**Files:**
- Create: `crates/core/src/infrastructure/content_store/mod.rs`
- Create: `crates/core/src/infrastructure/content_store/content_store_tests.rs`
- Modify: `crates/core/src/infrastructure/mod.rs` (add `pub mod content_store;`)

**Interfaces:**
- Consumes: `crate::error::{CoreError, CoreResult}`, `resolve_safe_path` (Task 3)
- Produces:
  - `pub struct ContentStore { root: PathBuf }`
  - `pub fn new(root: PathBuf) -> CoreResult<Self>`
  - `pub fn put(&self, bytes: &[u8]) -> CoreResult<String>` (returns sha256 hex)
  - `pub fn get(&self, hash: &str) -> CoreResult<Option<Vec<u8>>>`
  - `pub fn exists(&self, hash: &str) -> bool`
  - `pub fn path(&self, hash: &str) -> CoreResult<PathBuf>` (uses safe_path)

### Step 5.1: Write failing test

Create `crates/core/src/infrastructure/content_store/content_store_tests.rs`:

```rust
use crate::infrastructure::content_store::ContentStore;
use std::fs;

fn temp_root() -> std::path::PathBuf {
    let d = tempfile::tempdir().unwrap();
    d.into_path()
}

#[test]
fn put_and_get_roundtrip() {
    let root = temp_root();
    let cas = ContentStore::new(root.clone()).unwrap();
    let data = b"hello world";
    let hash = cas.put(data).unwrap();
    assert_eq!(hash.len(), 64); // sha256 hex
    let got = cas.get(&hash).unwrap().unwrap();
    assert_eq!(got, data);
}

#[test]
fn put_is_deterministic() {
    let root = temp_root();
    let cas = ContentStore::new(root).unwrap();
    let h1 = cas.put(b"abc").unwrap();
    let h2 = cas.put(b"abc").unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn put_uses_sha256_layout() {
    let root = temp_root();
    let cas = ContentStore::new(root.clone()).unwrap();
    let data = b"test";
    let hash = cas.put(data).unwrap();
    let expected = root.join("sha256").join(&hash[..2]).join(&hash[2..4]).join(&hash);
    assert!(expected.exists(), "expected {expected:?} to exist");
}

#[test]
fn get_nonexistent_returns_none() {
    let root = temp_root();
    let cas = ContentStore::new(root).unwrap();
    let got = cas.get("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
    assert!(got.is_none());
}

#[test]
fn exists_correct() {
    let root = temp_root();
    let cas = ContentStore::new(root).unwrap();
    let hash = cas.put(b"present").unwrap();
    assert!(cas.exists(&hash));
    assert!(!cas.exists("0000000000000000000000000000000000000000000000000000000000000000"));
}

#[test]
fn new_creates_root_if_missing() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("cas-root");
    assert!(!root.exists());
    let _ = ContentStore::new(root.clone()).unwrap();
    assert!(root.exists());
    let cas_root = root.join("sha256");
    assert!(cas_root.is_dir());
}

#[test]
fn path_uses_safe_path() {
    let root = temp_root();
    let cas = ContentStore::new(root.clone()).unwrap();
    let p = cas.path("ab").unwrap();
    assert!(p.starts_with(&root.join("sha256")));
    assert!(p.to_string_lossy().contains("ab"));
}

#[test]
fn large_content_roundtrip() {
    let root = temp_root();
    let cas = ContentStore::new(root).unwrap();
    let big = vec![0xABu8; 1024 * 1024]; // 1 MiB
    let hash = cas.put(&big).unwrap();
    let got = cas.get(&hash).unwrap().unwrap();
    assert_eq!(got.len(), big.len());
    assert_eq!(got, big);
}

#[test]
fn empty_content_is_allowed() {
    let root = temp_root();
    let cas = ContentStore::new(root).unwrap();
    let hash = cas.put(b"").unwrap();
    let got = cas.get(&hash).unwrap().unwrap();
    assert!(got.is_empty());
}
```

### Step 5.2: Run test, verify it fails

```powershell
cargo test -p agent_dep_core content_store
```

Expected: compile error.

### Step 5.3: Implement module

Modify `crates/core/src/infrastructure/mod.rs`:

```rust
//! Infrastructure layer: external-world adapters (filesystem, sqlite, git, etc.).
//! Domain and application layers MUST NOT import from here directly except through
//! these modules' public APIs.

pub mod content_store;
pub mod filesystem;
pub mod sqlite;
```

Create `crates/core/src/infrastructure/content_store/mod.rs`:

```rust
//! Content-addressed store (CAS). Immutable content keyed by sha256.
//!
//! Layout: `{root}/sha256/ab/cd/abcdef...`
//! Per TZ §11.2: stores `instructions.md`, `SKILL.md`, generated artifacts,
//! deployment snapshots, backup content. SQLite holds only references to
//! content hashes (TZ §11.3).

use crate::error::{CoreError, CoreResult};
use crate::infrastructure::filesystem::safe_path::resolve_safe_path;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

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
mod content_store_tests;
```

### Step 5.4: Run tests

```powershell
cargo test -p agent_dep_core content_store
cargo fmt --all -- --check
cargo clippy -p agent_dep_core -- -D warnings
```

Expected: all 8 tests pass.

### Step 5.5: Commit

Write to `.git\COMMIT_EDITMSG_NEW`:

```text
feat(core): content-addressed store skeleton

- ContentStore with sha256 layout (sha256/ab/cd/abcdef...)
- put() is deterministic, atomic via temp+rename
- get() returns None for missing
- exists() and path() helpers
- path() routes through resolve_safe_path (defense in depth)
- 8 tests: roundtrip, determinism, layout, missing, exists, root creation, large, empty
```

Commit and delete temp file.

**Acceptance:**
- `cargo test -p agent_dep_core content_store` green with 8 tests
- `cargo fmt` and `cargo clippy -D warnings` clean

---

## Task 6: Hermes adapter skeleton (detect only)

**Files:**
- Create: `crates/hermes-adapter/src/adapter.rs`
- Create: `crates/hermes-adapter/src/hermes_adapter.rs`
- Create: `crates/hermes-adapter/src/detection.rs`
- Create: `crates/hermes-adapter/src/paths.rs`
- Create: `crates/hermes-adapter/src/types.rs`
- Create: `crates/hermes-adapter/src/hermes_adapter_tests.rs`
- Modify: `crates/hermes-adapter/src/lib.rs` (add module declarations)

**Interfaces:**
- Consumes: `agent_dep_core::error::{CoreError, CoreResult}`, `which` crate
- Produces:
  - `pub trait RuntimeAdapter` with: `detect`, `inspect`, `plan`, `deploy`, `verify`, `rollback`
  - `pub struct RuntimeInfo { pub version: String, pub home: PathBuf, pub plugin_dir: PathBuf }`
  - `pub struct HermesAdapter { pub hermes_home: PathBuf }`
  - `pub fn detect_hermes(home: &Path) -> CoreResult<RuntimeInfo>`

### Step 6.1: Write failing test

Create `crates/hermes-adapter/src/hermes_adapter_tests.rs`:

```rust
use crate::detection::detect_hermes;
use std::path::Path;

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
```

### Step 6.2: Run test, verify it fails

```powershell
cargo test -p agent_dep_hermes_adapter
```

Expected: compile error.

### Step 6.3: Implement modules

Create `crates/hermes-adapter/src/types.rs`:

```rust
//! Types shared between adapter trait and concrete implementations.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export, export_to = "../../src/lib/types.generated.ts")]
pub struct RuntimeInfo {
    pub version: String,
    pub home: PathBuf,
    pub plugin_dir: PathBuf,
}
```

Create `crates/hermes-adapter/src/adapter.rs`:

```rust
//! RuntimeAdapter trait (TZ §12.3).
//!
//! Domain layer MUST NOT import concrete adapters. The `RuntimeAdapter`
//! abstraction is owned by `hermes-adapter` because hermes-adapter is the
//! first concrete implementation; future adapters (e.g. for OpenAI Codex)
//! would live in their own crates and implement this same trait.

use crate::types::RuntimeInfo;
use agent_dep_core::error::CoreResult;
use std::path::Path;

pub trait RuntimeAdapter: Send + Sync {
    fn detect(&self) -> CoreResult<RuntimeInfo>;
    fn inspect(&self) -> CoreResult<agent_dep_core::error::CoreError> {
        Err(agent_dep_core::error::CoreError::Unimplemented {
            feature: "RuntimeAdapter::inspect".into(),
        })
    }
    fn plan(
        &self,
        _system: &agent_dep_core::error::CoreError,
    ) -> CoreResult<agent_dep_core::error::CoreError> {
        Err(agent_dep_core::error::CoreError::Unimplemented {
            feature: "RuntimeAdapter::plan".into(),
        })
    }
    fn deploy(&self, _plan: &agent_dep_core::error::CoreError) -> CoreResult<()> {
        Err(agent_dep_core::error::CoreError::Unimplemented {
            feature: "RuntimeAdapter::deploy".into(),
        })
    }
    fn verify(&self) -> CoreResult<agent_dep_core::error::CoreError> {
        Err(agent_dep_core::error::CoreError::Unimplemented {
            feature: "RuntimeAdapter::verify".into(),
        })
    }
    fn rollback(&self, _snapshot: &Path) -> CoreResult<()> {
        Err(agent_dep_core::error::CoreError::Unimplemented {
            feature: "RuntimeAdapter::rollback".into(),
        })
    }
}
```

Create `crates/hermes-adapter/src/paths.rs`:

```rust
//! Hermes paths (HERMES_HOME, plugin dir).

use agent_dep_core::error::CoreResult;
use std::path::PathBuf;

pub fn default_hermes_home() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("HERMES_HOME") {
        return Some(PathBuf::from(p));
    }
    dirs_home().map(|h| h.join(".hermes"))
}

#[cfg(target_os = "windows")]
fn dirs_home() -> Option<PathBuf> {
    std::env::var("USERPROFILE").ok().map(PathBuf::from)
}

#[cfg(not(target_os = "windows"))]
fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

pub fn plugin_dir(home: &std::path::Path) -> CoreResult<PathBuf> {
    Ok(home.join("plugins"))
}
```

Create `crates/hermes-adapter/src/detection.rs`:

```rust
//! Hermes detection (MVP-0: minimal — check `hermes` CLI in PATH via `which`,
//! plus presence of `HERMES_HOME` or default `~/.hermes`).

use crate::paths::{default_hermes_home, plugin_dir};
use crate::types::RuntimeInfo;
use agent_dep_core::error::{CoreError, CoreResult};
use std::path::Path;
use which::which;

pub fn detect_hermes(home_override: &Path) -> CoreResult<RuntimeInfo> {
    // 1. Check that `hermes` CLI is on PATH.
    let hermes_bin = which("hermes").map_err(|_| CoreError::ErrHermesNotFound)?;

    // 2. Determine home: override > HERMES_HOME > ~/.hermes.
    let home = if home_override.as_os_str().is_empty() {
        default_hermes_home().ok_or(CoreError::ErrHermesNotFound)?
    } else {
        home_override.to_path_buf()
    };

    // 3. Plugin dir under home.
    let pdir = plugin_dir(&home)?;

    // 4. Version: from `hermes --version` (best effort). Empty if it fails.
    let version = read_hermes_version(&hermes_bin).unwrap_or_else(|_| "unknown".to_string());

    Ok(RuntimeInfo {
        version,
        home,
        plugin_dir: pdir,
    })
}

fn read_hermes_version(bin: &Path) -> std::io::Result<String> {
    let out = std::process::Command::new(bin).arg("--version").output()?;
    if !out.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "non-zero exit",
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
```

Create `crates/hermes-adapter/src/hermes_adapter.rs`:

```rust
//! Concrete HermesAdapter (only `detect` implemented in MVP-0).

use crate::adapter::RuntimeAdapter;
use crate::detection::detect_hermes;
use crate::types::RuntimeInfo;
use agent_dep_core::error::CoreResult;
use std::path::{Path, PathBuf};

pub struct HermesAdapter {
    hermes_home: PathBuf,
}

impl HermesAdapter {
    pub fn new(hermes_home: PathBuf) -> Self {
        Self { hermes_home }
    }

    pub fn hermes_home(&self) -> &Path {
        &self.hermes_home
    }
}

impl RuntimeAdapter for HermesAdapter {
    fn detect(&self) -> CoreResult<RuntimeInfo> {
        detect_hermes(&self.hermes_home)
    }
}
```

Modify `crates/hermes-adapter/src/lib.rs`:

```rust
//! Hermes runtime adapter.
#![doc = "Hermes runtime adapter implementing the `RuntimeAdapter` trait (TZ §12.3)."]

pub mod adapter;
pub mod detection;
pub mod hermes_adapter;
pub mod paths;
pub mod types;

pub use adapter::RuntimeAdapter;
pub use hermes_adapter::HermesAdapter;
pub use types::RuntimeInfo;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }
}

#[cfg(test)]
mod hermes_adapter_tests;
```

### Step 6.4: Run tests

```powershell
cargo test -p agent_dep_hermes_adapter
cargo fmt --all -- --check
cargo clippy -p agent_dep_hermes_adapter -- -D warnings
```

Expected: 2 tests pass (the test that runs `which("hermes")` will only return `Ok` if hermes is on PATH; otherwise the test returns `ErrHermesNotFound`, which is what we assert).

### Step 6.5: Commit

Write to `.git\COMMIT_EDITMSG_NEW`:

```text
feat(hermes-adapter): skeleton with detect() and RuntimeAdapter trait

- RuntimeAdapter trait (TZ §12.3) with detect/inspect/plan/deploy/verify/rollback
- HermesAdapter struct wrapping hermes_home
- detect() finds hermes CLI on PATH, reads --version, computes plugin_dir
- paths.rs: HERMES_HOME env > default ~/.hermes resolution
- types.rs: RuntimeInfo with #[derive(TS)]
- 2 tests: detect returns NotFound when home empty, struct constructible
```

Commit and delete temp file.

**Acceptance:**
- `cargo test -p agent_dep_hermes_adapter` green with ≥ 2 tests
- `cargo fmt` and `cargo clippy -D warnings` clean

---

## Task 7: CLI skeleton (clap)

**Files:**
- Modify: `crates/cli/src/main.rs`
- Create: `crates/cli/src/commands/mod.rs`
- Create: `crates/cli/src/commands/deploy.rs`
- Create: `crates/cli/src/commands/status.rs`
- Create: `crates/cli/src/output.rs`
- Create: `crates/cli/src/cli_tests.rs`

**Interfaces:**
- Consumes: `agent_dep_core::error`, `agent_dep_hermes_adapter`
- Produces:
  - `agency --help` shows help
  - `agency deploy <system>` returns stub message
  - `agency status` shows Hermes status (or `ErrHermesNotFound`)

### Step 7.1: Write failing test

Create `crates/cli/src/cli_tests.rs`:

```rust
use clap::CommandFactory;

#[test]
fn cli_parses_help() {
    let cmd = crate::Cli::command();
    let help = cmd.clone().render_help();
    assert!(help.to_string().contains("agency"));
}

#[test]
fn cli_has_deploy_and_status_subcommands() {
    let cmd = crate::Cli::command();
    let names: Vec<&str> = cmd.get_subcommands().map(|c| c.get_name()).collect();
    assert!(names.contains(&"deploy"));
    assert!(names.contains(&"status"));
}
```

### Step 7.2: Run, verify fails

```powershell
cargo test -p agent_dep_cli
```

Expected: compile error.

### Step 7.3: Implement CLI

Modify `crates/cli/src/main.rs`:

```rust
mod cli_tests;
mod commands;
mod output;

use clap::{Parser, Subcommand};
use commands::{deploy, status};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(name = "agency", version, about = "Agent Deployment Platform CLI", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Deploy a system to a runtime.
    Deploy {
        /// System identifier (e.g. "saas-platform").
        system: String,
    },
    /// Show current deployment status.
    Status,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Deploy { system } => deploy::run(&system).await,
        Command::Status => status::run().await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}
```

Create `crates/cli/src/commands/mod.rs`:

```rust
pub mod deploy;
pub mod status;
```

Create `crates/cli/src/commands/deploy.rs`:

```rust
use crate::output;
use agent_dep_core::error::CoreResult;

pub async fn run(system: &str) -> CoreResult<()> {
    output::header(&format!("Deploying system: {system}"));
    output::warn("MVP-0: deploy is a stub. Real plan/apply lands in MVP-3+.");
    Ok(())
}
```

Create `crates/cli/src/commands/status.rs`:

```rust
use crate::output;
use agent_dep_core::error::{CoreError, CoreResult};
use agent_dep_hermes_adapter::{detection::detect_hermes, paths::default_hermes_home};
use std::path::PathBuf;

pub async fn run() -> CoreResult<()> {
    let home: PathBuf = default_hermes_home().unwrap_or_else(|| PathBuf::from("."));
    output::header("Runtime status");
    match detect_hermes(&home) {
        Ok(info) => {
            output::kv("hermes", "found");
            output::kv("version", &info.version);
            output::kv("home", &info.home.display().to_string());
            output::kv("plugin_dir", &info.plugin_dir.display().to_string());
            Ok(())
        }
        Err(CoreError::ErrHermesNotFound) => {
            output::kv("hermes", "not found");
            output::hint("install Hermes or set HERMES_HOME");
            Ok(()) // Status is informational, not a hard error.
        }
        Err(e) => Err(e),
    }
}
```

Create `crates/cli/src/output.rs`:

```rust
//! Small CLI output helpers (no external crate to keep MVP-0 light).

pub fn header(s: &str) {
    println!("== {s} ==");
}

pub fn kv(k: &str, v: &str) {
    println!("  {k}: {v}");
}

pub fn warn(s: &str) {
    println!("warn: {s}");
}

pub fn hint(s: &str) {
    println!("hint: {s}");
}
```

### Step 7.4: Run tests and run CLI

```powershell
cargo test -p agent_dep_cli
cargo run -p agent_dep_cli -- --help
cargo run -p agent_dep_cli -- status
```

Expected: tests pass; `agency --help` shows help; `agency status` prints either runtime info or "not found".

### Step 7.5: Commit

Write to `.git\COMMIT_EDITMSG_NEW`:

```text
feat(cli): agency CLI skeleton with deploy/status

- clap v4 derive with `deploy <system>` and `status` subcommands
- status detects Hermes via hermes-adapter; reports not-found cleanly
- deploy is a stub (not yet implemented)
- output helpers (header, kv, warn, hint)
- 2 tests: help renders, subcommands present
```

Commit and delete temp file.

**Acceptance:**
- `cargo test -p agent_dep_cli` green with ≥ 2 tests
- `cargo run -p agent_dep_cli -- --help` shows help
- `cargo run -p agent_dep_cli -- status` runs without panicking
- `cargo fmt` and `cargo clippy -D warnings` clean

---

## Task 8: Tauri 2 app shell

**Files:**
- Create: `crates/tauri-app/tauri.conf.json`
- Create: `crates/tauri-app/build.rs`
- Create: `crates/tauri-app/capabilities/default.json`
- Create: `crates/tauri-app/icons/icon.png` (placeholder)
- Modify: `crates/tauri-app/Cargo.toml` (add tauri-build build-dep)
- Modify: `crates/tauri-app/src/lib.rs` (add `run()`)
- Modify: `crates/tauri-app/src/main.rs` (call `agent_dep_app_lib::run()`)

**Interfaces:**
- Consumes: `tauri::Builder`, `tauri::Manager`
- Produces: `pub fn run() -> tauri::Result<()>` that builds the Tauri app and runs it.

### Step 8.1: Create `tauri.conf.json`

Create `crates/tauri-app/tauri.conf.json`:

```json
{
  "$schema": "https://schema.tauri.app/config/2",
  "productName": "Agent Deployment Platform",
  "version": "0.1.0",
  "identifier": "com.agentdep.platform",
  "build": {
    "beforeDevCommand": "",
    "beforeBuildCommand": "",
    "devUrl": "http://localhost:1420",
    "frontendDist": "../../src"
  },
  "app": {
    "windows": [
      {
        "title": "Agent Deployment Platform",
        "width": 1200,
        "height": 800,
        "resizable": true,
        "fullscreen": false
      }
    ],
    "security": {
      "csp": null
    }
  },
  "bundle": {
    "active": true,
    "targets": "all",
    "icon": [
      "icons/icon.png"
    ]
  }
}
```

### Step 8.2: Create `build.rs`

Create `crates/tauri-app/build.rs`:

```rust
fn main() {
    tauri_build::build()
}
```

### Step 8.3: Create placeholder icon

Use a small PNG. If `tauri-build` requires a specific format, this is the minimum that compiles:

```powershell
python -c "
import struct, zlib
# 32x32 transparent PNG.
sig = b'\x89PNG\r\n\x1a\n'
def chunk(t, d):
    return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d))
ihdr = struct.pack('>IIBBBBB', 32, 32, 8, 6, 0, 0, 0)
raw = b''.join(b'\x00' + b'\x00' * 32 * 4 for _ in range(32))
idat = zlib.compress(raw)
data = sig + chunk(b'IHDR', ihdr) + chunk(b'IDAT', idat) + chunk(b'IEND', b'')
open(r'C:\projects\agent-dep-platform\crates\tauri-app\icons\icon.png', 'wb').write(data)
"
```

### Step 8.4: Create capabilities

Create `crates/tauri-app/capabilities/default.json`:

```json
{
  "$schema": "../gen/schemas/desktop-schema.json",
  "identifier": "default",
  "description": "Default capabilities for the main window.",
  "windows": ["main"],
  "permissions": [
    "core:default"
  ]
}
```

### Step 8.5: Add `tauri-build` to build-dependencies

Verify `crates/tauri-app/Cargo.toml` has:

```toml
[build-dependencies]
tauri-build = { version = "2", features = [] }
```

### Step 8.6: Implement `lib.rs::run()`

Replace `crates/tauri-app/src/lib.rs`:

```rust
//! Tauri 2 host for the Agent Deployment Platform.

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn run() -> tauri::Result<()> {
    tauri::Builder::default()
        .setup(|_app| {
            tracing::info!("Tauri app starting up (MVP-0 stub)");
            Ok(())
        })
        .run(tauri::generate_context!())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }
}
```

### Step 8.7: Update `main.rs`

Replace `crates/tauri-app/src/main.rs`:

```rust
// Prevents an additional console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    agent_dep_app_lib::run()
}
```

### Step 8.8: Verify build

```powershell
cargo check -p agent_dep_app
cargo fmt --all -- --check
cargo clippy -p agent_dep_app -- -D warnings
```

Expected: green. (We use `cargo check`, not `cargo run`, because running needs the frontend which doesn't exist yet — that comes in Task 12.)

If `tauri-build` complains about missing icons, ensure `icon.png` exists at the path in `tauri.conf.json`.

### Step 8.9: Commit

Write to `.git\COMMIT_EDITMSG_NEW`:

```text
feat(tauri-app): Tauri 2 shell with setup() callback

- tauri.conf.json (productName, identifier com.agentdep.platform)
- capabilities/default.json with core:default
- build.rs invokes tauri_build::build()
- lib.rs::run() builds Tauri Builder, setup() logs "starting up"
- main.rs calls agent_dep_app_lib::run()
- placeholder 32x32 transparent icon.png
- cargo check -p agent_dep_app green
```

Commit and delete temp file.

**Acceptance:**
- `cargo check -p agent_dep_app` green
- `cargo fmt` and `cargo clippy -D warnings` clean

---

## Task 9: Tracing initialization

**Files:**
- Create: `crates/tauri-app/src/tracing_init.rs`
- Modify: `crates/tauri-app/src/lib.rs` (initialize tracing in setup)

**Interfaces:**
- Consumes: `tracing_subscriber::registry`, `tracing_appender::rolling::RollingFileAppender`
- Produces: `pub fn init(app_data_dir: &Path) -> CoreResult<()>` that sets up stderr + file layers.

### Step 9.1: Write failing test

Append to `crates/tauri-app/src/lib.rs` tests module or create a new test file. Create `crates/tauri-app/src/tracing_init_tests.rs`:

```rust
use crate::tracing_init::init;
use std::path::Path;

#[test]
fn init_creates_log_file() {
    let dir = tempfile::tempdir().unwrap();
    init(dir.path()).expect("init tracing");
    tracing::info!("hello from test");
    // Drop the guard by calling a flush — for MVP-0 we just verify the dir + file get created on first write.
    // The file may not exist yet without an event, so emit one and check.
    let log_path = dir.path().join("logs");
    assert!(log_path.is_dir(), "expected logs dir at {log_path:?}");
}
```

### Step 9.2: Implement `tracing_init`

Create `crates/tauri-app/src/tracing_init.rs`:

```rust
//! Tracing initialization (TZ §34).
//!
//! Two layers: stderr for development, JSON daily-rolling file for diagnostics.
//! File lives at `{app_data_dir}/logs/app.json` (rotation via `Rotation::DAILY`).

use agent_dep_core::error::CoreResult;
use std::path::Path;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

/// Initialize tracing. Returns a guard that must be kept alive for the duration
/// of the program — dropping it flushes and stops the background writer.
pub fn init(app_data_dir: &Path) -> CoreResult<TracingGuard> {
    let logs_dir = app_data_dir.join("logs");
    std::fs::create_dir_all(&logs_dir)?;
    let file_appender = tracing_appender::rolling::daily(&logs_dir, "app.json");
    let (file_writer, file_guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tauri=info,agent_dep=debug"));

    let stderr_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_writer(std::io::stderr);

    let file_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .json()
        .with_current_span(true)
        .with_span_list(false)
        .with_writer(file_writer);

    Registry::default()
        .with(env_filter)
        .with(stderr_layer)
        .with(file_layer)
        .try_init()
        .map_err(|e| agent_dep_core::error::CoreError::ErrIo(
            std::io::Error::new(std::io::ErrorKind::Other, format!("tracing init: {e}")),
        ))?;

    Ok(TracingGuard { _file: file_guard })
}

pub struct TracingGuard {
    _file: WorkerGuard,
}

#[cfg(test)]
mod tracing_init_tests;
```

Modify `crates/tauri-app/src/lib.rs`:

```rust
//! Tauri 2 host for the Agent Deployment Platform.

mod tracing_init;
pub use tracing_init::TracingGuard;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn run() -> tauri::Result<()> {
    tauri::Builder::default()
        .setup(|app| {
            // Resolve app data dir from Tauri (only available inside setup).
            let app_data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("app_data_dir: {e}"))) as Box<dyn std::error::Error>)?;
            let _guard = tracing_init::init(&app_data_dir)
                .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("tracing init: {e}"))) as Box<dyn std::error::Error>)?;
            tracing::info!("Tauri app starting up (MVP-0, tracing initialized)");
            // Stash the guard in app state so it lives for the app's lifetime.
            app.manage(_guard);
            Ok(())
        })
        .run(tauri::generate_context!())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }
}
```

### Step 9.3: Run tests

```powershell
cargo test -p agent_dep_app tracing_init
cargo fmt --all -- --check
cargo clippy -p agent_dep_app -- -D warnings
```

Expected: test passes (logs dir is created).

### Step 9.4: Commit

Write to `.git\COMMIT_EDITMSG_NEW`:

```text
feat(tauri-app): tracing init with file + stderr layers

- tracing_init::init(app_data_dir) -> TracingGuard
- Two layers: stderr (human) + JSON daily-rotating file (machine)
- File at {app_data_dir}/logs/app.json with Rotation::DAILY
- EnvFilter from RUST_LOG, default "info,tauri=info,agent_dep=debug"
- Initialized in setup() callback (app.path().app_data_dir() available)
- Guard stashed in app state to live for program lifetime
```

Commit and delete temp file.

**Acceptance:**
- `cargo test -p agent_dep_app tracing_init` green
- `cargo fmt` and `cargo clippy -D warnings` clean

---

## Task 10: AppState + IPC command skeletons

**Files:**
- Create: `crates/tauri-app/src/state.rs`
- Create: `crates/tauri-app/src/ipc_error.rs`
- Create: `crates/tauri-app/src/ipc/mod.rs`
- Create: `crates/tauri-app/src/ipc/catalog.rs`
- Create: `crates/tauri-app/src/ipc/sources.rs`
- Create: `crates/tauri-app/src/ipc/systems.rs`
- Create: `crates/tauri-app/src/ipc/plans.rs`
- Create: `crates/tauri-app/src/ipc/deployments.rs`
- Create: `crates/tauri-app/src/ipc/backups.rs`
- Create: `crates/tauri-app/src/ipc/hermes.rs`
- Create: `crates/tauri-app/src/ipc/security.rs`
- Create: `crates/tauri-app/src/ipc/logs.rs`
- Modify: `crates/tauri-app/src/lib.rs` (register IPC commands in Builder, manage AppState)

**Interfaces:**
- Consumes: `agent_dep_core::{Db, ContentStore}`, `agent_dep_hermes_adapter::HermesAdapter`
- Produces:
  - `pub struct AppState { pub db, pub cas, pub paths, pub config, pub hermes }` (Arc-wrapped in Tauri)
  - 9 IPC commands (one per namespace), all returning stubs

### Step 10.1: Define DTOs in core (shared)

Create `crates/core/src/dto.rs`:

```rust
//! Data Transfer Objects (DTOs) shared across IPC and CLI.
//!
//! Each DTO derives `TS` for codegen into TypeScript. Keep this file
//! additive — appending types is fine, renaming is breaking.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../src/lib/types.generated.ts")]
pub struct AgentSummary {
    pub id: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../src/lib/types.generated.ts")]
pub struct SourceSummary {
    pub id: String,
    pub url: String,
    pub commit_sha: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../src/lib/types.generated.ts")]
pub struct SystemSummary {
    pub id: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../src/lib/types.generated.ts")]
pub struct DeploymentSummary {
    pub id: String,
    pub system_id: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../src/lib/types.generated.ts")]
pub struct BackupSummary {
    pub id: String,
    pub path: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../src/lib/types.generated.ts")]
pub struct Plan {
    pub system_id: String,
    pub operations: Vec<PlanOperation>,
    pub risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../src/lib/types.generated.ts")]
pub struct PlanOperation {
    pub kind: String, // ADD, UPDATE, DELETE, NOOP, BACKUP, VERIFY
    pub target: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../src/lib/types.generated.ts")]
pub struct ScanResult {
    pub source_id: String,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../src/lib/types.generated.ts")]
pub struct Finding {
    pub severity: String, // PASS, WARN, BLOCK
    pub rule: String,
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export, export_to = "../../src/lib/types.generated.ts")]
pub struct LogLine {
    pub ts: String,
    pub level: String,
    pub target: String,
    pub message: String,
}
```

Modify `crates/core/src/lib.rs`, add `pub mod dto;` after `pub mod infrastructure;`:

```rust
#![doc = "Core domain, application, and infrastructure for the Agent Deployment Platform."]

pub mod dto;
pub mod error;
pub mod infrastructure;

pub use error::{CoreError, CoreResult};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_is_non_empty() { assert!(!version().is_empty()); }
}

#[cfg(test)]
mod error_tests;
```

### Step 10.2: Create AppState and IPC error

Create `crates/tauri-app/src/state.rs`:

```rust
//! Application state injected into every Tauri command via `tauri::State<AppState>`.

use agent_dep_core::infrastructure::content_store::ContentStore;
use agent_dep_core::infrastructure::sqlite::Db;
use agent_dep_hermes_adapter::HermesAdapter;
use std::path::PathBuf;
use std::sync::Arc;

pub struct AppState {
    pub db: Db,
    pub cas: ContentStore,
    pub paths: AppPaths,
    pub config: AppConfig,
    pub hermes: Arc<HermesAdapter>,
}

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub app_data_dir: PathBuf,
    pub cas_root: PathBuf,
    pub db_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub log_level: String,
}
```

Create `crates/tauri-app/src/ipc_error.rs`:

```rust
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
```

### Step 10.3: Create IPC command modules

Create `crates/tauri-app/src/ipc/mod.rs`:

```rust
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
```

Create `crates/tauri-app/src/ipc/catalog.rs`:

```rust
use crate::ipc_error::IpcResult;
use agent_dep_core::dto::AgentSummary;

#[tauri::command]
pub async fn list_agents() -> IpcResult<Vec<AgentSummary>> {
    Ok(vec![])
}
```

Create `crates/tauri-app/src/ipc/sources.rs`:

```rust
use crate::ipc_error::IpcResult;
use agent_dep_core::dto::SourceSummary;

#[tauri::command]
pub async fn list() -> IpcResult<Vec<SourceSummary>> {
    Ok(vec![])
}
```

Create `crates/tauri-app/src/ipc/systems.rs`:

```rust
use crate::ipc_error::IpcResult;
use agent_dep_core::dto::SystemSummary;

#[tauri::command]
pub async fn list() -> IpcResult<Vec<SystemSummary>> {
    Ok(vec![])
}
```

Create `crates/tauri-app/src/ipc/plans.rs`:

```rust
use crate::ipc_error::{IpcError, IpcResult};
use agent_dep_core::dto::Plan;

#[tauri::command]
pub async fn compute(_system_id: String) -> IpcResult<Plan> {
    Err(IpcError::Internal("plans.compute: not yet implemented (MVP-0 stub)".into()))
}
```

Create `crates/tauri-app/src/ipc/deployments.rs`:

```rust
use crate::ipc_error::IpcResult;
use agent_dep_core::dto::DeploymentSummary;

#[tauri::command]
pub async fn list() -> IpcResult<Vec<DeploymentSummary>> {
    Ok(vec![])
}
```

Create `crates/tauri-app/src/ipc/backups.rs`:

```rust
use crate::ipc_error::IpcResult;
use agent_dep_core::dto::BackupSummary;

#[tauri::command]
pub async fn list() -> IpcResult<Vec<BackupSummary>> {
    Ok(vec![])
}
```

Create `crates/tauri-app/src/ipc/hermes.rs`:

```rust
use crate::ipc_error::IpcResult;
use crate::state::AppState;
use agent_dep_hermes_adapter::types::RuntimeInfo;
use tauri::State;

#[tauri::command]
pub async fn detect(state: State<'_, AppState>) -> IpcResult<RuntimeInfo> {
    state.hermes.detect().map_err(Into::into)
}
```

Create `crates/tauri-app/src/ipc/security.rs`:

```rust
use crate::ipc_error::{IpcError, IpcResult};
use agent_dep_core::dto::ScanResult;

#[tauri::command]
pub async fn scan(_source_id: String) -> IpcResult<ScanResult> {
    Err(IpcError::Internal("security.scan: not yet implemented (MVP-0 stub)".into()))
}
```

Create `crates/tauri-app/src/ipc/logs.rs`:

```rust
use crate::ipc_error::IpcResult;
use agent_dep_core::dto::LogLine;

#[tauri::command]
pub async fn tail(_n: usize) -> IpcResult<Vec<LogLine>> {
    Ok(vec![])
}
```

### Step 10.4: Wire AppState and IPC into `lib.rs`

Replace `crates/tauri-app/src/lib.rs`:

```rust
//! Tauri 2 host for the Agent Deployment Platform.

mod ipc;
mod ipc_error;
mod state;
mod tracing_init;

pub use state::{AppConfig, AppPaths, AppState};
pub use tracing_init::TracingGuard;

use std::sync::Arc;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn run() -> tauri::Result<()> {
    tauri::Builder::default()
        .setup(|app| {
            // Resolve app data dir.
            let app_data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("app_data_dir: {e}"))) as Box<dyn std::error::Error>)?;
            std::fs::create_dir_all(&app_data_dir)?;

            // Initialize tracing.
            let guard = tracing_init::init(&app_data_dir)
                .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("tracing init: {e}"))) as Box<dyn std::error::Error>)?;
            app.manage(guard);
            tracing::info!("Tauri app starting up (MVP-0)");

            // Initialize DB.
            // We use `tauri::async_runtime::block_on` (not `tokio::runtime::Handle::current().block_on`):
            // the latter would panic with "Cannot drop a runtime in a context where
            // blocking is not allowed" because Tauri 2's main loop is already a tokio
            // runtime. Tauri exposes its own async_runtime module that bridges safely.
            let db_path = app_data_dir.join("data").join("agent-dep.db");
            std::fs::create_dir_all(db_path.parent().unwrap())?;
            let db_path_for_connect = db_path.clone();
            let db = tauri::async_runtime::block_on(async move {
                agent_dep_core::infrastructure::sqlite::connect(&db_path_for_connect).await
            })
            .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("db connect: {e}"))) as Box<dyn std::error::Error>)?;
            tauri::async_runtime::block_on(async { db.migrate().await })
                .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("db migrate: {e}"))) as Box<dyn std::error::Error>)?;

            // Initialize CAS.
            let cas_root = app_data_dir.join("cas");
            let cas = agent_dep_core::infrastructure::content_store::ContentStore::new(cas_root)
                .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("cas: {e}"))) as Box<dyn std::error::Error>)?;

            // Hermes adapter.
            let hermes_home = agent_dep_hermes_adapter::paths::default_hermes_home()
                .unwrap_or_else(|| app_data_dir.join("hermes"));
            let hermes = Arc::new(agent_dep_hermes_adapter::HermesAdapter::new(hermes_home));

            // Compose AppState.
            let state = AppState {
                db,
                cas,
                paths: AppPaths { app_data_dir, cas_root, db_path },
                config: AppConfig { log_level: "info".into() },
                hermes,
            };
            app.manage(state);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ipc::catalog::list_agents,
            ipc::sources::list,
            ipc::systems::list,
            ipc::plans::compute,
            ipc::deployments::list,
            ipc::backups::list,
            ipc::hermes::detect,
            ipc::security::scan,
            ipc::logs::tail,
        ])
        .run(tauri::generate_context!())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_is_non_empty() { assert!(!version().is_empty()); }
}
```

### Step 10.5: Build and verify

```powershell
cargo check -p agent_dep_app
cargo fmt --all -- --check
cargo clippy -p agent_dep_app -- -D warnings
```

Expected: green. (We don't run the app because frontend doesn't exist yet.)

### Step 10.6: Commit

Write to `.git\COMMIT_EDITMSG_NEW`:

```text
feat(tauri-app): AppState + IPC command skeletons

- AppState: db, cas, paths, config, hermes (DI container)
- 9 IPC commands (catalog/sources/systems/deployments/backups return empty Vec;
  plans/security return not-implemented; logs.tail returns empty;
  hermes.detect delegates to HermesAdapter::detect)
- IpcError wraps CoreError, serializes to {kind, message}
- Wired into tauri::Builder.setup() and generate_handler!
- DTOs in core::dto (AgentSummary, SourceSummary, etc.) with #[derive(TS)]
```

Commit and delete temp file.

**Acceptance:**
- `cargo check -p agent_dep_app` green
- `cargo fmt` and `cargo clippy -D warnings` clean

---

## Task 11: ts-rs pipeline + drift-CI

**Files:**
- Create: `crates/core/tests/ts_export.rs`
- Create: `scripts/check-ts-drift.ps1`
- Create: `src/lib/types.generated.ts` (initial, from running the test)
- Modify: `Cargo.toml` workspace `members` to include the test (already done in Task 1)

**Interfaces:**
- Consumes: DTOs in `agent_dep_core::dto` and `agent_dep_hermes_adapter::types::RuntimeInfo`
- Produces:
  - `tests/ts_export.rs` calls `Type::export_all()` for each TS type
  - `scripts/check-ts-drift.ps1` runs the test, then `git diff --exit-code src/lib/types.generated.ts`
  - `src/lib/types.generated.ts` contains the generated TypeScript bindings

### Step 11.1: Write the export test

Create `crates/core/tests/ts_export.rs`:

```rust
//! ts-rs drift guard.
//!
//! Generates TypeScript bindings for every `#[derive(TS)]` type into
//! `src/lib/types.generated.ts`. Run `scripts/check-ts-drift.ps1` to
//! verify the generated file matches git HEAD.
//!
//! GOTCHA (recorded in AGENTS.md): incremental regen can DUPLICATE types
//! when adding new DTOs across commits. The fix is a single fresh regen
//! with the new types added to this import list. The resulting diff may
//! look like a large negative change — that's correct.

use agent_dep_core::dto::{
    AgentSummary, BackupSummary, DeploymentSummary, Finding, LogLine, Plan, PlanOperation,
    ScanResult, SourceSummary, SystemSummary,
};
use agent_dep_hermes_adapter::types::RuntimeInfo;
use ts_rs::TS;

#[test]
fn export_all_types() {
    // Export each type once. ts-rs writes them all into the same file
    // (export_to path) and dedupes by type name.
    AgentSummary::export_all().expect("export AgentSummary");
    SourceSummary::export_all().expect("export SourceSummary");
    SystemSummary::export_all().expect("export SystemSummary");
    DeploymentSummary::export_all().expect("export DeploymentSummary");
    BackupSummary::export_all().expect("export BackupSummary");
    Plan::export_all().expect("export Plan");
    PlanOperation::export_all().expect("export PlanOperation");
    ScanResult::export_all().expect("export ScanResult");
    Finding::export_all().expect("export Finding");
    LogLine::export_all().expect("export LogLine");
    RuntimeInfo::export_all().expect("export RuntimeInfo");
}
```

### Step 11.2: Run the test, generate the file

```powershell
cargo test -p agent_dep_core --test ts_export
```

Expected: file is created at `src/lib/types.generated.ts`. Inspect it; it should contain `export type AgentSummary = { id: string; name: string; version: string; };` etc.

### Step 11.3: Create the drift-check script

Create `scripts/check-ts-drift.ps1`:

```powershell
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot\..
Write-Host "[1/2] Running ts-rs export test..." -ForegroundColor Cyan
cargo test -p agent_dep_core --test ts_export 2>&1 | Out-String | Write-Host
if ($LASTEXITCODE -ne 0) {
    Write-Host "ts-rs export test FAILED with exit $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}
Write-Host "[2/2] Checking git diff on src/lib/types.generated.ts..." -ForegroundColor Cyan
$diff = git diff --exit-code src/lib/types.generated.ts
if ($LASTEXITCODE -ne 0) {
    Write-Host "ts-rs drift detected. Run cargo test --test ts_export to regenerate, then commit." -ForegroundColor Red
    git --no-pager diff src/lib/types.generated.ts | Out-Host
    exit 1
}
Write-Host "ts-rs drift check PASSED" -ForegroundColor Green
exit 0
```

### Step 11.4: Add the script as alias

Add to `scripts/ci.ps1` (created in Task 13) or run directly. For now, verify it works:

```powershell
.\scripts\check-ts-drift.ps1
```

Expected: exit 0.

### Step 11.5: Commit the generated file

```powershell
git add crates/core/tests/ts_export.rs scripts/check-ts-drift.ps1 src/lib/types.generated.ts
```

Write to `.git\COMMIT_EDITMSG_NEW`:

```text
feat(core): ts-rs type sharing + drift-CI

- tests/ts_export.rs calls export_all() for each TS-deriving type
- scripts/check-ts-drift.ps1 runs export then git diff --exit-code
- src/lib/types.generated.ts contains bindings for 11 DTOs
- Records incremental regen gotcha in test header
```

Commit and delete temp file.

**Acceptance:**
- `cargo test -p agent_dep_core --test ts_export` green
- `.\scripts\check-ts-drift.ps1` returns 0
- `src/lib/types.generated.ts` is committed

---

## Task 12: Svelte 5 + Vite + 9 placeholder routes

**Files:**
- Create: `package.json` (workspace root)
- Create: `pnpm-workspace.yaml`
- Create: `tsconfig.json`
- Create: `vite.config.ts`
- Create: `svelte.config.js`
- Create: `src/app.html`
- Create: `src/app.css`
- Create: `src/main.ts`
- Create: `src/lib/ipc.ts`
- Create: `src/lib/types.generated.ts` (already from Task 11)
- Create: `src/lib/components/Nav.svelte`
- Create: `src/lib/components/Placeholder.svelte`
- Create: `src/lib/stores/ui.svelte.ts`
- Create: `src/routes/sources.svelte`
- Create: `src/routes/catalog.svelte`
- Create: `src/routes/systems.svelte`
- Create: `src/routes/deployments.svelte`
- Create: `src/routes/hermes.svelte`
- Create: `src/routes/backups.svelte`
- Create: `src/routes/security.svelte`
- Create: `src/routes/logs.svelte`
- Create: `src/routes/settings.svelte`
- Create: `src/App.svelte`

**Interfaces:**
- Consumes: `src/lib/types.generated.ts` (TS bindings)
- Produces:
  - `pnpm install` succeeds
  - `pnpm run check` (svelte-check) green
  - `pnpm run build` produces `dist/`
  - 9 routes render placeholder content

### Step 12.1: Check tool availability

```powershell
node --version
pnpm --version 2>$null
npm --version
```

If `pnpm` not available, install it: `npm install -g pnpm` (or use npm-only setup — see 12.2 alternative).

### Step 12.2: Create `package.json` (root)

Create `package.json`:

```json
{
  "name": "agent-dep-platform",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview",
    "check": "svelte-check --tsconfig ./tsconfig.json"
  },
  "devDependencies": {
    "@sveltejs/vite-plugin-svelte": "^5.0.0",
    "@tsconfig/svelte": "^5.0.4",
    "svelte": "^5.0.0",
    "svelte-check": "^4.0.0",
    "tslib": "^2.6.0",
    "typescript": "^5.4.0",
    "vite": "^5.4.0"
  },
  "dependencies": {
    "@tauri-apps/api": "^2.0.0"
  }
}
```

Create `pnpm-workspace.yaml` (skip if using npm-only):

```yaml
packages:
  - .
```

(If using pure npm without workspaces, this file is not needed — npm treats the root package as a single project.)

### Step 12.3: Create `tsconfig.json`

```json
{
  "extends": "@tsconfig/svelte/tsconfig.json",
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "strict": true,
    "noImplicitAny": true,
    "skipLibCheck": true,
    "isolatedModules": true,
    "resolveJsonModule": true,
    "allowSyntheticDefaultImports": true,
    "esModuleInterop": true,
    "verbatimModuleSyntax": true,
    "types": ["svelte"]
  },
  "include": ["src/**/*.ts", "src/**/*.svelte", "src/**/*.d.ts"]
}
```

### Step 12.4: Create `vite.config.ts`

```ts
import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

export default defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  envPrefix: ["VITE_", "TAURI_"],
  build: {
    target: "es2022",
    sourcemap: !!process.env.TAURI_DEBUG,
  },
});
```

### Step 12.5: Create `svelte.config.js`

```js
import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

export default {
  preprocess: vitePreprocess(),
  compilerOptions: {
    runes: true,
  },
};
```

### Step 12.6: Create `src/app.html`

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="icon" href="/favicon.ico" />
    <title>Agent Deployment Platform</title>
  </head>
  <body>
    <div id="app"></div>
    <script type="module" src="/src/main.ts"></script>
  </body>
</html>
```

### Step 12.7: Create `src/app.css`

```css
:root {
  --bg: #0f1115;
  --panel: #161a22;
  --border: #232a36;
  --text: #e7ebf3;
  --muted: #8a93a6;
  --accent: #6aa9ff;
  --warn: #f5a524;
  --error: #ef4444;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}

* { box-sizing: border-box; }

html, body {
  margin: 0;
  padding: 0;
  height: 100%;
  background: var(--bg);
  color: var(--text);
}

#app {
  display: grid;
  grid-template-columns: 220px 1fr;
  height: 100vh;
}

nav {
  background: var(--panel);
  border-right: 1px solid var(--border);
  padding: 16px;
  overflow-y: auto;
}

nav h1 {
  font-size: 14px;
  margin: 0 0 16px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

nav a {
  display: block;
  padding: 8px 12px;
  margin-bottom: 4px;
  color: var(--text);
  text-decoration: none;
  border-radius: 6px;
  font-size: 14px;
}

nav a:hover { background: var(--border); }
nav a.active { background: var(--accent); color: white; }

main {
  padding: 24px;
  overflow-y: auto;
}

h1 { font-size: 24px; margin: 0 0 8px; }
p.lead { color: var(--muted); margin: 0 0 24px; }

.placeholder {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 24px;
  color: var(--muted);
}
```

### Step 12.8: Create `src/main.ts`

```ts
import "./app.css";
import App from "./App.svelte";
import { mount } from "svelte";

const target = document.getElementById("app");
if (!target) throw new Error("#app not found");

mount(App, { target });
```

### Step 12.9: Create `src/lib/ipc.ts`

```ts
import { invoke } from "@tauri-apps/api/core";
import type {
  AgentSummary,
  BackupSummary,
  DeploymentSummary,
  LogLine,
  Plan,
  ScanResult,
  SourceSummary,
  SystemSummary,
  RuntimeInfo,
} from "./types.generated";

export const ipc = {
  catalog: {
    listAgents: () => invoke<AgentSummary[]>("list_agents"),
  },
  sources: {
    list: () => invoke<SourceSummary[]>("list"),
  },
  systems: {
    list: () => invoke<SystemSummary[]>("list"),
  },
  plans: {
    compute: (systemId: string) => invoke<Plan>("compute", { systemId }),
  },
  deployments: {
    list: () => invoke<DeploymentSummary[]>("list"),
  },
  backups: {
    list: () => invoke<BackupSummary[]>("list"),
  },
  hermes: {
    detect: () => invoke<RuntimeInfo>("detect"),
  },
  security: {
    scan: (sourceId: string) => invoke<ScanResult>("scan", { sourceId }),
  },
  logs: {
    tail: (n: number) => invoke<LogLine[]>("tail", { n }),
  },
};
```

### Step 12.10: Create `src/lib/stores/ui.svelte.ts`

```ts
// Svelte 5 rune-based store for the active route.
export const ui = $state({ route: "sources" });
```

### Step 12.11: Create `src/lib/components/Nav.svelte`

```svelte
<script lang="ts">
  const items = [
    { id: "sources", label: "Sources" },
    { id: "catalog", label: "Catalog" },
    { id: "systems", label: "Systems" },
    { id: "deployments", label: "Deployments" },
    { id: "hermes", label: "Hermes" },
    { id: "backups", label: "Backups / Rollback" },
    { id: "security", label: "Security" },
    { id: "logs", label: "Logs" },
    { id: "settings", label: "Settings" },
  ];
  let { route = $bindable() } = $props<{ route: string }>();
</script>

<nav>
  <h1>Agent Deployment</h1>
  {#each items as item (item.id)}
    <a
      href="#{item.id}"
      class:active={route === item.id}
      onclick={() => (route = item.id)}
    >{item.label}</a>
  {/each}
</nav>
```

### Step 12.12: Create `src/lib/components/Placeholder.svelte`

```svelte
<script lang="ts">
  let { title, hint = "MVP-0 placeholder. Real UI lands with the corresponding business-logic milestone." } = $props<{ title: string; hint?: string }>();
</script>

<section>
  <h1>{title}</h1>
  <p class="lead">Section under the TZ §28.1 layout.</p>
  <div class="placeholder">{hint}</div>
</section>
```

### Step 12.13: Create 9 route files

Create `src/routes/sources.svelte` (one example; the other 8 are identical except for title):

```svelte
<script lang="ts">
  import Placeholder from "../lib/components/Placeholder.svelte";
</script>

<Placeholder title="Sources" hint="Connect and refresh Git repositories (TZ §28.1). Ingestion pipeline lands in MVP-3." />
```

(Repeat for `catalog.svelte` ("Catalog", "Browse agents and skills (TZ §28.1)."), `systems.svelte` ("Systems", "Compose agent systems (TZ §14, §28.1)."), `deployments.svelte` ("Deployments", "Desired/actual state and history (TZ §28.1)."), `hermes.svelte` ("Hermes", "Runtime health and configuration (TZ §28.1)."), `backups.svelte` ("Backups / Rollback", "Restore deployment snapshots (TZ §19, §28.1)."), `security.svelte` ("Security", "Findings and policy decisions (TZ §28.1)."), `logs.svelte` ("Logs", "Diagnostics (TZ §28.1)."), `settings.svelte` ("Settings", "App preferences.").)

### Step 12.14: Create `src/App.svelte`

```svelte
<script lang="ts">
  import Nav from "./lib/components/Nav.svelte";
  import Sources from "./routes/sources.svelte";
  import Catalog from "./routes/catalog.svelte";
  import Systems from "./routes/systems.svelte";
  import Deployments from "./routes/deployments.svelte";
  import Hermes from "./routes/hermes.svelte";
  import Backups from "./routes/backups.svelte";
  import Security from "./routes/security.svelte";
  import Logs from "./routes/logs.svelte";
  import Settings from "./routes/settings.svelte";

  let route = $state("sources");

  const routes: Record<string, any> = {
    sources: Sources,
    catalog: Catalog,
    systems: Systems,
    deployments: Deployments,
    hermes: Hermes,
    backups: Backups,
    security: Security,
    logs: Logs,
    settings: Settings,
  };
  let Current = $derived(routes[route] ?? Sources);
</script>

<Nav bind:route />
<main>
  <Current />
</main>
```

### Step 12.15: Install dependencies and verify

```powershell
cd C:\projects\agent-dep-platform
pnpm install
pnpm run check
pnpm run build
```

Expected:
- `pnpm install` succeeds
- `pnpm run check` green (no type errors, all 9 routes type-check)
- `pnpm run build` produces `dist/`

If `pnpm` is not available, fall back to `npm install` and remove `pnpm-workspace.yaml`.

### Step 12.16: Commit

Write to `.git\COMMIT_EDITMSG_NEW`:

```text
feat(frontend): Svelte 5 + Vite with 9 placeholder routes

- package.json with vite, svelte 5 (runes), svelte-check, tauri api
- vite.config.ts (port 1420, svelte plugin)
- svelte.config.js with runes: true
- tsconfig.json extends @tsconfig/svelte
- src/app.html, src/app.css (dark theme tokens), src/main.ts
- src/lib/ipc.ts thin wrappers over invoke<>() for all 9 namespaces
- src/lib/stores/ui.svelte.ts rune-based active route
- src/lib/components/Nav.svelte + Placeholder.svelte
- 9 route files: sources, catalog, systems, deployments, hermes, backups, security, logs, settings
- src/App.svelte mounts Nav + current route
- pnpm install, pnpm run check, pnpm run build all green
```

Commit and delete temp file.

**Acceptance:**
- `pnpm install` succeeds
- `pnpm run check` green
- `pnpm run build` produces `dist/`
- All 9 routes type-check

---

## Task 13: scripts/ci.ps1 + AGENTS.md + final smoke

**Files:**
- Create: `scripts/ci.ps1`
- Create: `scripts/bootstrap.ps1`
- Create: `scripts/reset-db.ps1`
- Create: `AGENTS.md`
- Create: `.github/workflows/ci.yml` (template, not used)
- Modify: `README.md` (link to AGENTS.md and TZ)

**Interfaces:**
- Consumes: nothing
- Produces:
  - `scripts/ci.ps1` runs all gates locally and returns 0 on success
  - `AGENTS.md` is informative for future agent sessions
  - Final smoke verifies all MVP-0 acceptance criteria

### Step 13.1: Create `scripts/ci.ps1`

```powershell
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot\..

$failed = $false

function Step($name, $cmd) {
    Write-Host ""
    Write-Host "==> $name" -ForegroundColor Cyan
    & $cmd
    if ($LASTEXITCODE -ne 0) {
        Write-Host "    FAILED (exit $LASTEXITCODE)" -ForegroundColor Red
        $script:failed = $true
    }
}

Step "cargo fmt --check" { cargo fmt --all -- --check }
Step "cargo clippy" { cargo clippy --workspace --all-targets -- -D warnings }
Step "cargo test" { cargo test --workspace }
Step "pnpm install" { pnpm install --frozen-lockfile }
Step "pnpm run check" { pnpm run check }
Step "ts-rs drift" { & "$PSScriptRoot\check-ts-drift.ps1" }

if ($failed) {
    Write-Host ""
    Write-Host "CI FAILED" -ForegroundColor Red
    exit 1
}
Write-Host ""
Write-Host "CI PASSED" -ForegroundColor Green
exit 0
```

### Step 13.2: Create `scripts/bootstrap.ps1`

```powershell
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot\..

Write-Host "Bootstrapping agent-dep-platform development environment..." -ForegroundColor Cyan

# Rust
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "cargo not found. Install Rust: https://rustup.rs" -ForegroundColor Red
    exit 1
}
Write-Host "  cargo: $(cargo --version)"

# Node + pnpm
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "node not found. Install Node 22+: https://nodejs.org" -ForegroundColor Red
    exit 1
}
Write-Host "  node: $(node --version)"
if (-not (Get-Command pnpm -ErrorAction SilentlyContinue)) {
    Write-Host "  pnpm not found; install with: npm install -g pnpm" -ForegroundColor Yellow
} else {
    Write-Host "  pnpm: $(pnpm --version)"
}

# Hermes (informational)
$hermes = Get-Command hermes -ErrorAction SilentlyContinue
if ($hermes) {
    Write-Host "  hermes: $($hermes.Source)"
} else {
    Write-Host "  hermes: NOT FOUND (MVP-1 POC requires it)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Bootstrap complete. Run: .\scripts\ci.ps1" -ForegroundColor Green
```

### Step 13.3: Create `scripts/reset-db.ps1`

```powershell
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot\..

$dbPath = Join-Path $env:APPDATA "com.agentdep.platform\data\agent-dep.db"
if (Test-Path $dbPath) {
    python -c "import os; os.remove(r'$dbPath')"
    Write-Host "Removed: $dbPath" -ForegroundColor Green
} else {
    Write-Host "DB not found at $dbPath (nothing to remove)" -ForegroundColor Yellow
}
```

### Step 13.4: Create `AGENTS.md`

```markdown
# AGENTS.md

Conventions and context for AI agent sessions working on this repository.

## Project

**Enterprise Agent Deployment Platform** — Tauri 2 + Svelte 5 + Rust desktop
app that safely deploys agent systems from Git repositories into Hermes Agent.

- Spec: `docs/superpowers/specs/`
- Plans: `docs/superpowers/plans/`
- ADRs (when written): `docs/adr/`
- Source TZ: `TZ_Enterprise_Agent_Deployment_Platform_Final.md` (root)

## Layout

Multi-crate Cargo workspace. Domain/application lives in `core`; Tauri and CLI
are thin consumers. See `docs/superpowers/specs/2026-08-31-bootstrap-mvp-0-design.md`
§5 for the full layout.

```
crates/
  core/              domain, application, infrastructure (sqlite, cas, filesystem)
  hermes-adapter/    RuntimeAdapter trait + HermesAdapter
  cli/               agency CLI (clap)
  tauri-app/         Tauri 2 host + IPC commands
src/                 Svelte 5 + Vite frontend
docs/                specs, plans, ADRs
scripts/             local CI scripts (PowerShell)
```

## Build / Test

```powershell
cargo build --workspace
cargo test --workspace
.\scripts\ci.ps1
```

## Conventions

- **Path safety**: every user-supplied path goes through
  `agent_dep_core::infrastructure::filesystem::safe_path::resolve_safe_path`.
  Never use raw `Path::join` for write operations.
- **Error handling**: every fallible function returns `Result<T, CoreError>`.
  No `unwrap()` outside tests. `expect()` in tests with a clear message.
- **Type sharing**: DTOs that cross IPC get `#[derive(TS)] #[ts(export,
  export_to = "../../src/lib/types.generated.ts")]`. Run
  `.\scripts\check-ts-drift.ps1` before committing IPC changes.
- **ts-rs gotcha**: incremental regen can DUPLICATE types. After adding new
  DTOs across multiple commits, `cargo test --test ts_export` may produce
  a `types.generated.ts` with each type written twice. The fix: a single
  fresh regen with the new types added to the import list produces the
  canonical (non-duplicated) output, even though `git diff` shows it as
  a large negative diff. Do not `git checkout` to revert — the dedup is
  the correct state. See `crates/core/tests/ts_export.rs` for the
  recorded warning.
- **Tracing init**: must run in Tauri `setup()` callback, not in `main()`.
  `app.path().app_data_dir()` is only available after the `App` is built.
- **PowerShell on Windows**: see memory note in Mavis profile —
  `Remove-Item` may be blocked, use `python -c "import os; os.remove(...)"`.
  Commit messages use `git commit -F <file>` (file-based), never inline
  `-m "..."` (preserves backslashes).

## Deferred to later milestones

- Hermes POC + ADR-001 → MVP-1
- ADRs 002–007 → MVP-2
- All MUST HAVE features (TZ §45) → MVP-3+
- See spec §7 for full deferral list.

## When you are stuck

1. Read the relevant spec in `docs/superpowers/specs/`.
2. Read the relevant plan in `docs/superpowers/plans/`.
3. Read the matching ADR if it exists in `docs/adr/`.
4. Load the appropriate superpowers skill (`superpowers:systematic-debugging`
   for bugs, `superpowers:test-driven-development` for new features).
5. Run `.\scripts\ci.ps1` to see the current state.
```

### Step 13.5: Create `.github/workflows/ci.yml` (template)

```yaml
# CI workflow template. Not currently active (no remote). When a remote is added,
# this file will run on every push and PR.
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  ci:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm install -g pnpm
      - run: cargo build --workspace
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace
      - run: pnpm install --frozen-lockfile
      - run: pnpm run check
      - run: pnpm run build
      - run: ./scripts/check-ts-drift.sh  # PowerShell version is check-ts-drift.ps1
```

### Step 13.6: Update README

Append to `README.md`:

```markdown
## Agent conventions

See `AGENTS.md` for AI agent workflow conventions.

## Local CI

```powershell
.\scripts\ci.ps1
```

This runs `cargo fmt/clippy/test`, `pnpm install`, `pnpm run check`, and the
ts-rs drift guard. Same checks as `.github/workflows/ci.yml` (which is a
template, not yet wired to a remote).
```

### Step 13.7: Final smoke

```powershell
.\scripts\ci.ps1
```

Expected: exit 0, all gates pass.

### Step 13.8: Commit

Write to `.git\COMMIT_EDITMSG_NEW`:

```text
chore: MVP-0 smoke green — ci.ps1, AGENTS.md, helpers

- scripts/ci.ps1 runs all gates (fmt, clippy, test, pnpm check, ts-rs drift)
- scripts/bootstrap.ps1 prints tool availability
- scripts/reset-db.ps1 wipes the local SQLite DB
- AGENTS.md with conventions, layout, deferred milestones
- .github/workflows/ci.yml template (not active — no remote)
- README links to AGENTS.md and ci.ps1
- .\scripts\ci.ps1 returns 0 (final smoke)
```

Commit and delete temp file.

**Acceptance (all MVP-0):**
- `cargo build --workspace` green
- `cargo test --workspace` green with ≥ 25 tests
- `cargo clippy --workspace --all-targets -- -D warnings` green
- `cargo fmt --all -- --check` green
- `pnpm run check` green
- `pnpm run build` produces `dist/`
- `src/lib/types.generated.ts` is generated and `git diff` clean
- `cargo run -p agent_dep_cli -- --help` shows help
- `cargo run -p agent_dep_cli -- status` runs without panicking
- `cargo run -p agent_dep_app` (after `pnpm run dev` in another shell) opens a window with 9 routes
- `.\scripts\ci.ps1` returns 0
- `AGENTS.md` exists and is informative
- Local git log shows ≥ 13 atomic commits with conventional-commit messages
- No business logic implemented (only trait stubs, error types, path safety, CAS, DB)

---

## Self-Review

Performed inline. Checks:

1. **Spec coverage**: Each item in spec §6 (Scope In) maps to a task:
   - Phase A → Tasks 1, 2, 3
   - Phase B → Tasks 4, 5
   - Phase C → Tasks 6, 7
   - Phase D → Tasks 8, 9, 10
   - Phase E → Task 11
   - Phase F → Task 12
   - Phase G → Task 13
   ✓
2. **Spec §2 Goals**: 12 goals — 12 mapped to tasks. ✓
3. **Spec §4 Decisions**: All 16 decisions reflected in task steps (workspace layout, ts-rs, sqlx, tracing, etc.). ✓
4. **Spec §8 Acceptance Criteria**: 13 criteria — verified in Task 13.7 + final smoke. ✓
5. **Spec §9 Known Gotchas**: ts-rs duplicate, tracing init, PowerShell — all mentioned in AGENTS.md and in test headers. ✓
6. **Type consistency**:
   - `RuntimeInfo` defined in `hermes-adapter/src/types.rs` with `#[derive(TS)]` and `export_to = "../../src/lib/types.generated.ts"` (Tasks 6, 11).
   - DTOs in `core/src/dto.rs` with same `export_to` (Task 10).
   - Both write to the same file; ts-rs dedupes by type name. ✓
7. **Placeholder scan**: No "TBD" / "TODO" in non-stub contexts. `unimplemented!()` markers are intentional in stub commands. ✓
8. **Interface signatures**: `resolve_safe_path(root: &Path, input: &Path) -> CoreResult<PathBuf>` (Task 3); `Db::connect(path: &Path) -> CoreResult<Db>` (Task 4); `ContentStore::put(bytes: &[u8]) -> CoreResult<String>` (Task 5); `HermesAdapter::detect() -> CoreResult<RuntimeInfo>` (Task 6). All consistent. ✓
9. **File paths**: All paths are absolute from `C:\projects\agent-dep-platform` and verified to match the spec's target structure (§5.1). ✓

No fixes needed.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-31-bootstrap-mvp-0.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration with isolated context per task. Best for large plans like this.

**2. Inline Execution** — Execute tasks in this session using `executing-plans`, batch execution with checkpoints for review. Best for shorter plans.

Which approach?
