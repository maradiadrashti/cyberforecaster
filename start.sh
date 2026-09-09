#!/usr/bin/env bash
# ============================================================
#  CyberForecaster – start all services
#  Run as:  sudo ./start.sh   (root required for Scapy capture)
# ============================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Privilege check ─────────────────────────────────────────
if [[ "$EUID" -ne 0 ]]; then
    echo "==========================================================="
    echo "  WARNING: Not running as root!"
    echo "  Real-time packet capture (Scapy/Npcap) requires root."
    echo "  Re-launch with:  sudo ./start.sh"
    echo "==========================================================="
fi

# ── Locate Python ────────────────────────────────────────────
PYTHON="$ROOT/.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then PYTHON="python3"; fi
command -v node    >/dev/null || { echo "Node.js 18+ is required."; exit 1; }
command -v npm     >/dev/null || { echo "npm is required.";         exit 1; }
command -v "$PYTHON" >/dev/null || { echo "Python 3.10+ is required."; exit 1; }

# ── Kill all children on Ctrl-C / exit ──────────────────────
trap 'echo ""; echo "[✖] Stopping all services..."; kill $(jobs -p) 2>/dev/null || true' EXIT

# ── 1. ML Service (FastAPI / PyTorch GRU) ───────────────────
echo "[▶] Starting ML Service on 127.0.0.1:8000..."
cd "$ROOT/ml-service"
"$PYTHON" -m uvicorn main:app --host 127.0.0.1 --port 8000 &

# ── 2. Capture Service (FastAPI / Scapy – needs root) ────────
echo "[▶] Starting Capture Service on 0.0.0.0:8080 (requires root for Scapy)..."
cd "$ROOT/capture-service"
"$PYTHON" -m uvicorn capture_server:app --host 0.0.0.0 --port 8080 &

# ── 3. React / Vite Frontend ─────────────────────────────────
echo "[▶] Starting Vite React Client on 5173..."
cd "$ROOT/client"
npm run dev -- --host 127.0.0.1 &

# ── 4. Attack Traffic Simulator ──────────────────────────────
echo "[▶] Starting Attack Traffic Simulator..."
cd "$ROOT/simulator"
"$PYTHON" simulate.py &

echo ""
echo "==========================================================="
echo "  CYBERFORECASTER is running!"
echo "  Frontend Dashboard : http://127.0.0.1:5173"
echo "  FastAPI ML Service : http://127.0.0.1:8000"
echo "  Capture Service    : http://127.0.0.1:8080"
echo "==========================================================="
echo "  Press Ctrl+C to stop all services."
echo "==========================================================="
wait
