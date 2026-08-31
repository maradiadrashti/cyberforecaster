$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot

if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw "Install Node.js 18 or newer first." }
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { throw "Install npm with Node.js first." }
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw "Install Python 3.10 or newer first." }

Push-Location $Root
try {
    foreach ($Directory in @("backend", "blockchain", "client")) {
        Write-Host "Installing Node dependencies in $Directory..."
        Push-Location (Join-Path $Root $Directory)
        npm ci
        Pop-Location
    }

    $Venv = Join-Path $Root ".venv"
    if (-not (Test-Path (Join-Path $Venv "Scripts\python.exe"))) { python -m venv $Venv }
    $Python = Join-Path $Venv "Scripts\python.exe"
    & $Python -m pip install --upgrade pip
    & $Python -m pip install -r (Join-Path $Root "ml-service\requirements.txt")
    & $Python -m pip install -r (Join-Path $Root "capture-service\requirements.txt")
    & $Python -m pip install -r (Join-Path $Root "simulator\requirements.txt")
} finally {
    Pop-Location
}

Write-Host "Setup complete. Install MongoDB Community Server and Npcap, then run .\start.ps1."