# CyberForecaster 🛡️⚡
### AI-Powered Real-Time Network Attack Forecasting & MITRE Kill Chain Prediction System

CyberForecaster is a real-time network defense and attack forecasting system. It combines microsecond packet capture (via Scapy/Npcap), flow-level machine learning classification (Random Forest), temporal multi-step stage forecasting (PyTorch GRU World Model), and an interactive SOC Dashboard (React + Vite).

---

## 🌟 Key Capabilities

1. **Live Network Traffic Capture & Inspection**:
   - Real-time packet capture on physical, virtual, Wi-Fi, and VPN network interfaces via Scapy and Npcap.
   - Microsecond bidirectional flow aggregation (forward/backward packet inter-arrival times, payload byte counts, TCP flag dynamics).
   - High-throughput WebSocket streaming with live packet & flow analytics.

2. **Multi-Stage Machine Learning Pipeline**:
   - **Flow Classification**: Instantaneous classification of network flows into granular attack classes (PortScan, DDoS, Brute Force, Web Attacks, Infiltration, Benign).
   - **Temporal Stage Forecaster (PyTorch GRU)**: Analyzes historical sequences of multi-dimensional traffic windows to forecast future attack progression along the **MITRE ATT&CK Kill Chain** (*Reconnaissance → Initial Access → Lateral Movement → Command & Control → Exfiltration*).
   - **Explainable Metrics**: Real-time confidence scores, Shannon port entropy, SYN/ACK ratios, and inter-arrival time variances.

3. **Attack Forecasting & Counterfactual Simulations**:
   - **Live Attack Forecast View**: Tracks active attacker-victim pairs, temporal progression windows, and early warning indicators.
   - **Counterfactual Rollout Engine**: Evaluates mitigation scenarios (*Do Nothing*, *Rate Limit*, *Block Ports*, *Isolate Host*) against projected threat trajectories.

---

## 🏗️ Architecture & Component Overview

```
[ Network Interface (Scapy / Npcap) ]
                 │
                 ▼
[ Capture Service (FastAPI / WebSockets - :8080) ] ───► [ ML Models (RF + GRU - :8000) ]
                 │                                                │
                 ▼                                                │
   [ Express Backend (:5050) ] ◄──────────────────────────────────┘
                 │
                 ▼
 [ SOC React Dashboard (Vite - :5173) ]
```

- **Frontend (`client/`)**: High-performance React 19 + Vite dashboard featuring Cyber-Tech UI styling, Recharts telemetry, and real-time WebSocket state management.
- **Capture Service (`capture-service/`)**: Fast packet sniffer and sliding-window feature extractor built on Scapy and FastAPI.
- **ML Service (`ml-service/` & `models/`)**: Pre-trained PyTorch GRU forecasting models and Scikit-Learn flow classifiers.
- **Backend Service (`backend/`)**: Node.js & Express API managing host states and socket telemetry broadcasts.
- **Simulator (`simulator/`)**: Synthetic attack vector replay engine for testing defense workflows in offline environments.

---

## 🚀 Quick Start

### Prerequisites

- **Node.js**: v18.0.0 or higher
- **Python**: v3.10 or higher
- **Npcap**: Installed on Windows (ensure "Install Npcap in WinPcap API-compatible Mode" is checked)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd cyberforecaster

# Install all backend, client, and python dependencies
.\setup.ps1      # (Windows PowerShell)
# or
./setup.sh       # (Linux / macOS)
```

### Launching All Services

```powershell
# Windows (PowerShell will auto-elevate to Administrator for Scapy capture)
.\start.ps1
```

```bash
# Linux / macOS
./start.sh
```

The startup script will automatically launch all microservices and open the dashboard in your browser:
- **SOC Dashboard**: `http://127.0.0.1:5173`
- **Capture Service API**: `http://127.0.0.1:8080`
- **FastAPI ML Service**: `http://127.0.0.1:8000`
- **Express Backend**: `http://127.0.0.1:5050`

---

## 📊 MITRE ATT&CK Stages Supported

| Kill Chain Stage | Description | Key Indicators |
| :--- | :--- | :--- |
| **Normal** | Clean background network traffic | Balanced SYN/ACK ratio, standard port distributions |
| **Reconnaissance** | Port scanning & network discovery | High port entropy, single-SYN bursts, RST floods |
| **Initial Access** | Exploitation & brute-forcing | Burst payloads, repeated failed handshakes |
| **Lateral Movement** | Internal pivot & credential transfer | SMB/RPC connection spikes, east-west anomalous flows |
| **Command & Control** | External beaconing | Periodic IAT intervals, encrypted egress tunnels |
| **Data Exfiltration** | Outbound data staging & theft | High outbound-to-inbound byte ratios |

---

## 🔒 License

MIT License. Designed for cybersecurity research, SOC training, and proactive network defense experimentation.