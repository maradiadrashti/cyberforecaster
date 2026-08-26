#!/bin/bash

# SIH 2026 Proactive Attack Forecasting System - Startup Script

echo "=========================================================="
echo "Starting SIH 2026 Attack Forecasting System..."
echo "=========================================================="

# Clean up trap on exit to kill all background jobs
trap 'kill $(jobs -p)' EXIT

# 1. Start Hardhat Ethereum Node (if not already running on port 8545)
if lsof -Pi :8545 -sTCP:LISTEN -t >/dev/null ; then
    echo "[✔] Local Hardhat Node is already running."
else
    echo "[▶] Starting Hardhat Ethereum Node on localhost:8545..."
    cd blockchain && npx hardhat node &
    sleep 3
    # Deploy contract
    echo "[▶] Deploying ForecastRegistry Smart Contract..."
    npx hardhat run scripts/deploy.js --network localhost
    cd ..
fi

# 2. Start Python FastAPI ML Service
echo "[▶] Starting Python FastAPI ML Service on localhost:8000..."
cd ml_service
source venv/bin/activate
uvicorn main:app --host 127.0.0.1 --port 8000 &
cd ..
sleep 3

# 3. Start Node.js Express Orchestrator Backend
echo "[▶] Starting Express Backend Server on localhost:5000..."
cd backend
node server.js &
cd ..
sleep 2

# 4. Start React Frontend Client (Vite Dev Server)
echo "[▶] Starting React Client on localhost:5173..."
cd client
npm run dev -- --host 127.0.0.1 &
cd ..
sleep 2

# 5. Start Attack Traffic Simulator
echo "[▶] Starting Attack Traffic Simulator..."
cd ml_service
source venv/bin/activate
python3 ../simulator/simulate.py &
cd ..

echo "=========================================================="
echo "All services running successfully!"
echo "- Frontend Dashboard: http://127.0.0.1:5173"
echo "- Express Backend:    http://127.0.0.1:5050"
echo "- FastAPI ML Core:    http://127.0.0.1:8000"
echo "- Hardhat Localnet:   http://127.0.0.1:8545"
echo "=========================================================="
echo "Press Ctrl+C to terminate all services."
wait
