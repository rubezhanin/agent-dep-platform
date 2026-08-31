$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot\..

Write-Host "[1/2] Running ts-rs export test..." -ForegroundColor Cyan
$env:PATH = "C:\Users\Администратор\.cargo\bin;$env:PATH"
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
