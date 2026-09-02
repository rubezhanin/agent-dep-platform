$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot\..

# Make `cargo` discoverable. On Windows cargo is installed under
# `%USERPROFILE%\.cargo\bin` (PowerShell session) or `~/.cargo/bin`
# (POSIX shells). We probe a few standard locations and prepend
# the first one that exists, falling back to the existing PATH.
# Guarded against null env vars — `$env:HOME` is null on a stock
# Windows box and `Join-Path null` would throw under
# `$ErrorActionPreference = 'Stop'`.
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

Step "cargo fmt --check" { cargo fmt --all -- --check }
Step "cargo clippy" { cargo clippy --workspace --all-targets -- -D warnings }
Step "cargo test" { cargo test --workspace }
# ts-rs auto-generates a test per `#[derive(TS)]` type that calls
# T::export_all() and overwrites the shared file. Run our dedicated
# ts_export test LAST so its output is the canonical state.
Step "ts-rs regen (canonical)" { cargo test -p agent_dep_core --test ts_export }
Step "npm install" { npm install }
Step "npm run check" { npm run check }
Step "ts-rs drift" { & "$PSScriptRoot\check-ts-drift.ps1" }

if ($failed) {
    Write-Host ""
    Write-Host "CI FAILED" -ForegroundColor Red
    exit 1
}
Write-Host ""
Write-Host "CI PASSED" -ForegroundColor Green
exit 0
