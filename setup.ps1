# =============================================================================
#  CyberForecaster - one-time setup (Windows PowerShell)
#
#  Run from INSIDE the project folder:
#      cd C:\path\to\cyberforecaster
#      Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#      .\setup.ps1
# =============================================================================
# Native tools (pip, npm) print warnings on stderr; rely on exit codes instead of stopping on them.
$ErrorActionPreference = "Continue"
$Root = $PSScriptRoot

function Fail([string]$Msg) {
    Write-Host ""
    Write-Host "[X] $Msg" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "CyberForecaster setup" -ForegroundColor Cyan
Write-Host "Project folder: $Root" -ForegroundColor DarkGray
Write-Host ""

# -- 1. Find a Python 3.10+ interpreter (py launcher first, then python) -----
$PyExe = $null
$PyArgs = @()
function Test-Python([string]$Exe, [string[]]$ExtraArgs) {
    if (-not (Get-Command $Exe -ErrorAction SilentlyContinue)) { return $false }
    try {
        & $Exe @ExtraArgs -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>$null | Out-Null
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}
if (Test-Python "py" @("-3")) { $PyExe = "py"; $PyArgs = @("-3") }
elseif (Test-Python "python" @()) { $PyExe = "python" }
if (-not $PyExe) {
    Fail "Python 3.10 or newer was not found. Install it from https://www.python.org/downloads/ (tick 'Add python.exe to PATH'), open a NEW PowerShell window and run .\setup.ps1 again."
}
$PyVersion = & $PyExe @PyArgs --version
Write-Host "[1/4] Found $PyVersion" -ForegroundColor Green

# -- 2. Check Node.js / npm ---------------------------------------------------
if (-not (Get-Command node -ErrorAction SilentlyContinue) -or -not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Fail "Node.js 18 or newer (with npm) was not found. Install the LTS version from https://nodejs.org/, open a NEW PowerShell window and run .\setup.ps1 again."
}
$NodeVersion = & node --version
Write-Host "[2/4] Found Node.js $NodeVersion" -ForegroundColor Green

# -- 3. Python virtual environment + packages ---------------------------------
$Venv = Join-Path $Root ".venv"
$VenvPython = Join-Path $Venv "Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "[3/4] Creating Python virtual environment in .venv ..." -ForegroundColor Yellow
    & $PyExe @PyArgs -m venv $Venv
    if ($LASTEXITCODE -ne 0) { Fail "Could not create the virtual environment." }
}
Write-Host "[3/4] Installing Python packages (first time can take several minutes; PyTorch is large) ..." -ForegroundColor Yellow
& $VenvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { Fail "pip upgrade failed. Check your internet connection and try again." }
& $VenvPython -m pip install -r (Join-Path $Root "requirements.txt")
if ($LASTEXITCODE -ne 0) { Fail "Installing Python packages failed (see the messages above)." }
Write-Host "[3/4] Python packages installed." -ForegroundColor Green

# -- 4. Dashboard (Node) packages ---------------------------------------------
Write-Host "[4/4] Installing dashboard packages (npm install) ..." -ForegroundColor Yellow
Push-Location (Join-Path $Root "client")
try {
    & npm install
    if ($LASTEXITCODE -ne 0) { Fail "npm install failed (see the messages above)." }
} finally {
    Pop-Location
}
Write-Host "[4/4] Dashboard packages installed." -ForegroundColor Green

Write-Host ""
Write-Host "Setup complete." -ForegroundColor Green
Write-Host "Next: (optional, for live capture) install Npcap from https://npcap.com with 'WinPcap API-compatible Mode' ticked," -ForegroundColor Cyan
Write-Host "      then start CyberForecaster from this same folder with:  .\start.ps1" -ForegroundColor Cyan
Write-Host ""
