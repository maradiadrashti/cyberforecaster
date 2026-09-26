#!/usr/bin/env bash
# =============================================================================
#  CyberForecaster - one-time setup (Linux / macOS)
#
#  Run from INSIDE the project folder:
#      cd /path/to/cyberforecaster
#      chmod +x setup.sh start.sh
#      ./setup.sh
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v python3 >/dev/null || { echo "[X] Python 3.10+ is required (python3 not found)."; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
    || { echo "[X] Python 3.10+ is required (found $(python3 --version))."; exit 1; }
command -v node >/dev/null || { echo "[X] Node.js 18+ is required."; exit 1; }
command -v npm  >/dev/null || { echo "[X] npm is required (it comes with Node.js)."; exit 1; }

echo "[1/3] Creating Python virtual environment in .venv ..."
[ -x "$ROOT/.venv/bin/python" ] || python3 -m venv "$ROOT/.venv"

echo "[2/3] Installing Python packages (first time can take several minutes) ..."
"$ROOT/.venv/bin/python" -m pip install --upgrade pip
"$ROOT/.venv/bin/python" -m pip install -r "$ROOT/requirements.txt"

echo "[3/3] Installing dashboard packages (npm install) ..."
(cd "$ROOT/client" && npm install)

echo ""
echo "Setup complete. Start CyberForecaster from this folder with:  sudo ./start.sh"
