$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot\..

$dbPath = Join-Path $env:APPDATA "com.agentdep.platform\data\agent-dep.db"
if (Test-Path $dbPath) {
    python -c "import os; os.remove(r'$dbPath')"
    Write-Host "Removed: $dbPath" -ForegroundColor Green
} else {
    Write-Host "DB not found at $dbPath (nothing to remove)" -ForegroundColor Yellow
}
