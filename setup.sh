#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v node >/dev/null || { echo "Install Node.js 18+ first."; exit 1; }
command -v npm >/dev/null || { echo "Install npm first."; exit 1; }
command -v python3 >/dev/null || { echo "Install Python 3.10+ first."; exit 1; }

(cd "$ROOT/client" && npm ci)

python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install --upgrade pip
"$ROOT/.venv/bin/python" -m pip install -r "$ROOT/ml-service/requirements.txt"
"$ROOT/.venv/bin/python" -m pip install -r "$ROOT/capture-service/requirements.txt"
"$ROOT/.venv/bin/python" -m pip install -r "$ROOT/simulator/requirements.txt"

echo "Setup complete. Run ./start.sh."