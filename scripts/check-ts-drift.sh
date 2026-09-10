#!/usr/bin/env bash
# 3.0.0 (CI fix, post-0bfc58a): bash
# equivalent of
# `scripts/check-ts-drift.ps1`.
# The PowerShell version is
# used on the operator
# workstation and on
# `windows-latest` runners.
# The bash version is
# used on
# `ubuntu-latest` runners
# (the Linux `ci-linux`
# job does NOT call this
# script today, but the
# bash version is kept
# here so the script is
# portable across OSes
# for any future CI that
# wants to gate on ts-rs
# drift from a Linux
# host).
#
# The script:
# 1. runs
#    `cargo test -p agent_dep_core --test ts_export`
#    to (re)generate
#    `src/lib/types.generated.ts`,
# 2. asserts that
#    `git diff --exit-code src/lib/types.generated.ts`
#    is empty.
#
# Exit codes:
#   0 — no drift
#   1 — drift detected
#       (git diff found
#       changes), OR
#       cargo test
#       itself failed
#       (e.g. types
#       not exported)
set -euo pipefail

# Run from repo root
# regardless of where the
# script is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Make `cargo` discoverable
# when invoked from a
# stripped-down CI image
# (cargo is normally on
# PATH after
# `dtolnay/rust-toolchain@stable`,
# but defensive
# prepending is cheap).
for d in "$HOME/.cargo/bin" "/usr/local/cargo/bin"; do
    if [ -d "$d" ]; then
        export PATH="$d:$PATH"
        break
    fi
done

echo "[1/2] Running ts-rs export test..."
cargo test -p agent_dep_core --test ts_export

echo "[2/2] Checking git diff on src/lib/types.generated.ts..."
if ! git diff --exit-code src/lib/types.generated.ts >/dev/null; then
    echo "ts-rs drift detected. Run 'cargo test -p agent_dep_core --test ts_export' to regenerate, then commit." >&2
    git --no-pager diff src/lib/types.generated.ts >&2
    exit 1
fi
echo "ts-rs drift check PASSED"
exit 0
