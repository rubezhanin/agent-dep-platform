$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot\..

# Make `cargo` discoverable. See ci.ps1 for the same logic.
$candidateCargoDirs = @(
    (Join-Path $env:USERPROFILE '.cargo\bin')
    (Join-Path $env:HOME        '.cargo/bin')
    '/usr/local/cargo/bin'
)
foreach ($d in $candidateCargoDirs) {
    if ($d -and (Test-Path -LiteralPath $d)) {
        $env:PATH = "$d;$env:PATH"
        break
    }
}

Write-Host "[1/2] Running ts-rs export test..." -ForegroundColor Cyan
$out = [System.IO.Path]::GetTempFileName()
$err = [System.IO.Path]::GetTempFileName()
try {
    $p = Start-Process -FilePath "cargo.exe" -ArgumentList "test","-p","agent_dep_core","--test","ts_export" -Wait -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err
    Get-Content $out | Out-Host
    if ($p.ExitCode -ne 0) {
        Write-Host "ts-rs export test FAILED with exit $($p.ExitCode)" -ForegroundColor Red
        Get-Content $err | Out-Host
        exit $p.ExitCode
    }
} finally {
    Remove-Item $out, $err -ErrorAction SilentlyContinue
}

Write-Host "[2/2] Checking git diff on src/lib/types.generated.ts..." -ForegroundColor Cyan
$diffOutput = git diff --exit-code src/lib/types.generated.ts
if ($LASTEXITCODE -ne 0) {
    Write-Host "ts-rs drift detected. Run cargo test --test ts_export to regenerate, then commit." -ForegroundColor Red
    git --no-pager diff src/lib/types.generated.ts | Out-Host
    exit 1
}
Write-Host "ts-rs drift check PASSED" -ForegroundColor Green
exit 0
