# CyberForecaster

CyberForecaster is a local cyber-attack forecasting demo with a React dashboard, Express orchestrator, PyTorch service, packet-capture API, MongoDB, and a local Hardhat ledger.

## Requirements

- Node.js 18 or newer
- Python 3.10 or newer
- MongoDB Community Server with `mongod` available on `PATH`
- Git and Git LFS if large model/binary assets are tracked with LFS
- Windows packet capture: install Npcap. The capture API may need an Administrator terminal.

## First run

Clone the repository and enter it:

```bash
git clone <repository-url>
cd cyberforecaster
```

Windows PowerShell:

```powershell
.\setup.ps1
.\start.ps1
```

Linux or macOS:

```bash
chmod +x setup.sh start.sh
./setup.sh
./start.sh
```

Open `http://127.0.0.1:5173`. The startup scripts launch MongoDB, Hardhat, deploy the local `ForecastRegistry`, start all APIs, the frontend, and the traffic simulator. The generated blockchain deployment file is intentionally ignored and recreated on every fresh checkout.

## MongoDB location

The scripts use `mongod` from `PATH`. Windows users can set a custom executable path before starting:

```powershell
$env:MONGOD_PATH = 'C:\Program Files\MongoDB\Server\8.0\bin\mongod.exe'
.\start.ps1
```

Linux users can use the same variable with an absolute executable path. MongoDB data is stored locally under `mongodb-server/data` and is ignored by Git.

## Service URLs

- Dashboard: `http://127.0.0.1:5173`
- Backend API: `http://127.0.0.1:5050`
- ML API: `http://127.0.0.1:8000`
- Capture API: `http://127.0.0.1:8080`
- Hardhat JSON-RPC: `http://127.0.0.1:8545`
- MongoDB: `mongodb://127.0.0.1:27017`

The backend accepts `BACKEND_PORT`, `ML_SERVICE_URL`, `MONGO_URI`, and `BLOCKCHAIN_RPC_URL` environment variables. Frontend capture host settings use `VITE_CAPTURE_HOST`.

## Troubleshooting

- If MongoDB cannot start, stop any existing `mongod` process or set `MONGOD_PATH`.
- If packet capture fails, install Npcap and run the capture service with Administrator privileges. The simulated dashboard traffic does not require packet capture.
- If a port is busy, stop the existing process before running the launcher.
- To reset the local ledger, stop services and delete `blockchain/deployments/localhost.json`; the next start deploys a fresh contract.