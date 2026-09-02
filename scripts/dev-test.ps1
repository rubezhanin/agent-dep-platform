# Local development test wrapper.
#
# Mirrors the test gates from scripts/ci.ps1 but
# skips the slow / heavy steps that don't help
# during inner-loop development:
#   - cargo fmt --check     (run via "cargo fmt" manually)
#   - cargo clippy -D warnings (run separately)
#   - npm install           (run once after dependency changes)
#
# The key non-obvious step is the explicit
# `cargo test -p agent_dep_core --test ts_export`
# AFTER `cargo test --workspace`. The CI runs the
# same explicit step (ci.ps1 line 38) because
# `cargo test --workspace` runs test binaries
# in parallel: the hermes-adapter lib test's
# auto-export can clobber the DTO types that
# `ts_export.rs` writes, leaving the file with
# only the hermes-adapter types. The drift guard
# `git diff --exit-code src/lib/types.generated.ts`
# is byte-level and would PASS in that state,
# but svelte-check on the frontend would fail
# with "Module has no exported member X".
#
# This script is the local equivalent of the CI
# step order. Use it during development. The
# full `scripts/ci.ps1` is the source of truth
# before committing.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot\..

# Make `cargo` discoverable (same logic as
# ci.ps1, with explicit null guards because
# `$env:HOME` is null on a stock Windows box).
$candidateCargoDirs = @()
if ($env:USERPROFILE) {
    $candidateCargoDirs += (Join-Path $env:USERPROFILE '.cargo\bin')
}
if ($env:HOME) {
    $candidateCargoDirs += (Join-Path $env:HOME '.cargo/bin')
}
$candidateCargoDirs += '/usr/local/cargo/bin'
foreach ($d in $candidateCargoDirs) {
    if ($d -and (Test-Path -LiteralPath $d)) {
        $env:PATH = "$d;$env:PATH"
        break
    }
}

$failed = $false
function Step($name, [scriptblock]$cmd) {
    Write-Host ""
    Write-Host "==> $name" -ForegroundColor Cyan
    & $cmd
    if ($LASTEXITCODE -ne 0) {
        Write-Host "    FAILED (exit $LASTEXITCODE)" -ForegroundColor Red
        $script:failed = $true
    }
}

# 1. Run every test binary. This is parallel and
#    may produce a clobbered types.generated.ts;
#    step 2 fixes that.
Step "cargo test --workspace" { cargo test --workspace }

# 2. The dedicated regen test, run after
#    `cargo test --workspace` so it writes the
#    canonical file. See the comment at the top
#    of this file for the why.
Step "ts-rs regen (canonical)" {
    cargo test -p agent_dep_core --test ts_export
}

# 3. svelte-check verifies the frontend sees
#    all the types the regen just wrote.
Step "npm run check" { npm run check }

if ($failed) {
    Write-Host ""
    Write-Host "LOCAL TEST FAILED" -ForegroundColor Red
    exit 1
}
Write-Host ""
Write-Host "LOCAL TEST PASSED" -ForegroundColor Green
exit 0
