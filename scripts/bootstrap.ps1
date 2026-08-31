$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot\..

Write-Host "Bootstrapping agent-dep-platform development environment..." -ForegroundColor Cyan

# Rust
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "cargo not found. Install Rust: https://rustup.rs" -ForegroundColor Red
    exit 1
}
Write-Host "  cargo: $(cargo --version)"

# Node + npm
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "node not found. Install Node 22+: https://nodejs.org" -ForegroundColor Red
    exit 1
}
Write-Host "  node: $(node --version)"
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Host "  npm not found" -ForegroundColor Yellow
} else {
    Write-Host "  npm: $(npm --version)"
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
