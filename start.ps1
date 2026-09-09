# =============================================================================
#  CyberForecaster - Clean Service Manager & Launcher
#  Runs all background services silently, auto-elevates for Scapy/Npcap capture,
#  displays localhost links cleanly, and opens the Dashboard.
# =============================================================================
$ErrorActionPreference = "Stop"

# ── Auto-elevate to Administrator (required for Scapy/Npcap raw capture) ──────
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Elevating to Administrator for Scapy/Npcap capture support..." -ForegroundColor Cyan
    Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$Root = $PSScriptRoot

# ── Log directory ─────────────────────────────────────────────────────────────
$LogDir = Join-Path $Root "logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }

# ── Helper: write colored status line ────────────────────────────────────────
function Write-Status([string]$Step, [string]$Msg, [string]$Color = "Cyan") {
    Write-Host ("[{0}] {1}" -f $Step, $Msg) -ForegroundColor $Color
}

# ── Locate Python (prefer .venv) ──────────────────────────────────────────────
$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    $pyCmd = Get-Command python -ErrorAction SilentlyContinue
    $Python = if ($pyCmd) { $pyCmd.Source } else { "python" }
}

# ── Pre-flight checks ─────────────────────────────────────────────────────────
foreach ($cmd in @("node","npm")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "$cmd not found. Install Node.js 18+." }
}

# =============================================================================
#  DISPLAY HEADER
# =============================================================================
Clear-Host
Write-Host ""
Write-Host "  =================================================================" -ForegroundColor Magenta
Write-Host "   CyberForecaster  //  AI-Based Network Attack Forecasting System" -ForegroundColor Magenta
Write-Host "   Running as Administrator  -  Scapy/Npcap capture ENABLED" -ForegroundColor Green
Write-Host "  =================================================================" -ForegroundColor Magenta
Write-Host ""

# ── Clean up any lingering processes on project ports ────────────────────────
function Stop-PortProcess([int]$Port) {
    try {
        $conns = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
        if ($conns) {
            $pids = $conns | Select-Object -ExpandProperty OwningProcess -Unique
            foreach ($p in $pids) {
                if ($p -and $p -ne 0 -and $p -ne $PID) {
                    Write-Host "  [Cleanup] Terminating stale process on port $Port (PID $p)..." -ForegroundColor DarkGray
                    Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
                }
            }
        }
    } catch {}
}

Write-Status "0/4" "Cleaning up previous service ports..." "DarkGray"
foreach ($p in @(8080, 8000, 5173)) {
    Stop-PortProcess $p
}
Start-Sleep -Milliseconds 500

$procs = @{}   # track all child process objects for cleanup

function Wait-ServicePort([string]$ServiceName, [int]$Port, [int]$TimeoutSeconds = 30, [string]$ErrLog = "") {
    $waited = 0
    while ($waited -lt $TimeoutSeconds) {
        if ($procs.ContainsKey($ServiceName)) {
            $proc = $procs[$ServiceName]
            if ($proc -and $proc.HasExited) {
                $errMsg = "Service '$ServiceName' exited unexpectedly with code $($proc.ExitCode)."
                if ($ErrLog -and (Test-Path $ErrLog)) {
                    $logContent = Get-Content $ErrLog -Tail 15 -Raw
                    $errMsg += "`nError log ($ErrLog):`n$logContent"
                }
                throw $errMsg
            }
        }
        try {
            $t = New-Object Net.Sockets.TcpClient
            $t.Connect("127.0.0.1", $Port)
            $t.Close()
            return $true
        } catch {}
        Start-Sleep -Milliseconds 500
        $waited += 0.5
    }
    $errMsg = "Service '$ServiceName' did not start listening on port $Port within ${TimeoutSeconds}s."
    if ($ErrLog -and (Test-Path $ErrLog)) {
        $logContent = Get-Content $ErrLog -Tail 15 -Raw
        $errMsg += "`nError log ($ErrLog):`n$logContent"
    }
    throw $errMsg
}

# =============================================================================
#  STEP 1 - ML Service (FastAPI / PyTorch GRU)
# =============================================================================
Write-Status "1/4" "Starting FastAPI ML Service on 127.0.0.1:8000..." "Yellow"
$procs["ml-service"] = Start-Process -FilePath $Python `
    -ArgumentList "-m uvicorn main:app --host 127.0.0.1 --port 8000" `
    -WorkingDirectory (Join-Path $Root "ml-service") -NoNewWindow -PassThru `
    -RedirectStandardOutput (Join-Path $LogDir "ml-service.log") `
    -RedirectStandardError  (Join-Path $LogDir "ml-service.err")

Wait-ServicePort "ml-service" 8000 25 (Join-Path $LogDir "ml-service.err")
Write-Status "1/4" "FastAPI ML Service online (port 8000, PID $($procs['ml-service'].Id))" "Green"

# =============================================================================
#  STEP 2 - Capture Service (Scapy - needs Admin, already elevated)
# =============================================================================
Write-Status "2/4" "Starting Packet Capture Service on 0.0.0.0:8080 [Scapy ACTIVE]..." "Yellow"
$procs["capture"] = Start-Process -FilePath $Python `
    -ArgumentList "-m uvicorn capture_server:app --host 0.0.0.0 --port 8080" `
    -WorkingDirectory (Join-Path $Root "capture-service") -NoNewWindow -PassThru `
    -RedirectStandardOutput (Join-Path $LogDir "capture.log") `
    -RedirectStandardError  (Join-Path $LogDir "capture.err")

Wait-ServicePort "capture" 8080 25 (Join-Path $LogDir "capture.err")
Write-Status "2/4" "Packet Capture Service online (port 8080, PID $($procs['capture'].Id))" "Green"

# =============================================================================
#  STEP 3 - Vite React Client
# =============================================================================
Write-Status "3/4" "Starting Vite React Client on port 5173..." "Yellow"
$procs["client"] = Start-Process -FilePath "cmd.exe" `
    -ArgumentList "/c npm run dev -- --host 127.0.0.1" `
    -WorkingDirectory (Join-Path $Root "client") -NoNewWindow -PassThru `
    -RedirectStandardOutput (Join-Path $LogDir "client.log") `
    -RedirectStandardError  (Join-Path $LogDir "client.err")

Wait-ServicePort "client" 5173 30 (Join-Path $LogDir "client.err")
Write-Status "3/4" "Vite React Client online (port 5173, PID $($procs['client'].Id))" "Green"

# =============================================================================
#  STEP 4 - Attack Traffic Simulator
# =============================================================================
Write-Status "4/4" "Starting Attack Traffic Simulator..." "Yellow"
$procs["simulator"] = Start-Process -FilePath $Python `
    -ArgumentList "simulate.py" `
    -WorkingDirectory (Join-Path $Root "simulator") -NoNewWindow -PassThru `
    -RedirectStandardOutput (Join-Path $LogDir "simulator.log") `
    -RedirectStandardError  (Join-Path $LogDir "simulator.err")

Write-Status "4/4" "Attack Traffic Simulator started (PID $($procs['simulator'].Id))" "Green"

# Auto-open Dashboard in browser
Start-Sleep -Seconds 1
Start-Process "http://127.0.0.1:5173"

# =============================================================================
#  CLEAN STATUS DISPLAY & SERVICE CONTROL
# =============================================================================
Clear-Host
Write-Host ""
Write-Host "  =================================================================" -ForegroundColor Green
Write-Host "   CYBERFORECASTER  //  ALL SERVICES ONLINE" -ForegroundColor Green
Write-Host "  =================================================================" -ForegroundColor Green
Write-Host "   [+] Dashboard (SOC UI) : http://127.0.0.1:5173" -ForegroundColor Cyan
Write-Host "   [+] FastAPI ML Service : http://127.0.0.1:8000" -ForegroundColor White
Write-Host "   [+] Capture Service    : http://127.0.0.1:8080  [Scapy/Npcap ADMIN ACTIVE]" -ForegroundColor Green
Write-Host "  =================================================================" -ForegroundColor Green
Write-Host "   Logs saved to          : $LogDir\" -ForegroundColor DarkGray
Write-Host "  =================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "   Press [Enter] or Ctrl+C in this window to stop all services..." -ForegroundColor Yellow
Write-Host ""

try {
    # Keep script alive quietly without log spamming
    [void][System.Console]::ReadLine()
} finally {
    Write-Host ""
    Write-Host "Stopping all CyberForecaster services..." -ForegroundColor Red
    foreach ($name in $procs.Keys) {
        $p = $procs[$name]
        if ($p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host "All services stopped cleanly." -ForegroundColor Red
}
