<div align="center">

# 🛡️ CyberForecaster

### AI-Based Network Attack Forecasting from Network Traffic Data

**Smart India Hackathon 2026 · Problem Statement SIH26153 · NTRO**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![PyTorch](https://img.shields.io/badge/PyTorch-LSTM%20World%20Model-EE4C2C?logo=pytorch&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-backend-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React%2019-Vite-61DAFB?logo=react&logoColor=black)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-C41E3A)

</div>

---

## 🏷️ Problem statement

| | |
| :--- | :--- |
| **Problem Statement ID** | SIH26153 |
| **Title** | AI-based Network Attack Forecasting from Network Traffic Data |
| **Organization** | National Technical Research Organisation (NTRO) |
| **Theme** | Blockchain & Cybersecurity |
| **Category** | Software |
| **Team** | Ninja · Team ID 143440 |

---

## 📌 What it does

You upload a traffic file (`.pcap`, `.pcapng` or flow `.csv`) or capture live traffic. For every source host,
CyberForecaster cuts the traffic into 10-second windows and gives the last 10 windows to an LSTM **world model**.
For each host and each window the model returns:

| Output | Meaning |
| :--- | :--- |
| **Attack probability, next 60 s** | Chance that this host is in an attack at any point in the next 10, 20 … 60 seconds |
| **Attack starts within 5 / 10 min** | For a host that is calm now: chance that an attack starts within 5 or 10 minutes |
| **Stage** | Which of 5 attack stages (reconnaissance, initial access, command & control, lateral movement, exfiltration) now and at +10 … +60 s, with the MITRE ATT&CK tactic and techniques |
| **Why** | Which traffic features moved the risk up or down (occlusion attribution) |
| **Next traffic** | The predicted features of the host's next window (this is what makes it a world model) |

The dashboard shows these per host, next to a logistic-regression baseline on the same inputs, and when the
uploaded file has labels it scores itself against them.

**What it is good at, and what it is not** (details and numbers below):

- ✅ Detects ongoing attacks and names their stage well on the networks it was trained on.
- ✅ Tells, a few minutes ahead, when an attack **comes back** on a host that was attacked before (tested on 12 hosts, works on 2 of 5 datasets).
- ❌ Does not warn before the **first** attack of a host in our test files.
- ❌ Not reliable on a network it has never seen: the alert threshold does not transfer.

---

## 📊 Results

All numbers are from the installed model (world model v4, 3 copies with different random seeds, averaged).
Test data: **hours held back from training** (traffic is split by 1-hour blocks: about 60% train, 20% validation,
20% test). The test hours come from the same six networks as the training hours.
Full detail: [`docs/RESULTS_world_model_v4.md`](docs/RESULTS_world_model_v4.md) · raw metrics:
[`training/world_model/results/results_v4.json`](training/world_model/results/results_v4.json).

### 1. Is the host under attack within the next 60 seconds? (299,632 test windows, 24,378 positive)

| Model (same 10 windows × 73 features) | F1 | False-alarm rate | AUROC |
| :--- | :---: | :---: | :---: |
| Logistic regression, last window only | 0.595 | 6.17% | 0.944 |
| Logistic regression, 10 windows | 0.814 | 2.48% | 0.984 |
| **World model (LSTM)** | **0.931** | **0.81%** | **0.9975** |
| XGBoost, 10 windows | 0.961 | 0.46% | 0.999 |

XGBoost is better than our model on this measure. It gives one number per window; it does not give stages,
the next-window forecast or the 5/10-minute output.

### 2. Which stage? (current window)

Macro-F1 over 6 classes: **0.822**.

| Stage | Recall |
| :--- | :---: |
| Normal | 99.0% |
| Command & control | 97.5% |
| Lateral movement | 97.2% |
| Exfiltration | 95.7% |
| Initial access | 78.9% |
| Reconnaissance | 76.2% |

### 3. Early warning: the last 10 windows are all normal, an attack starts within 60 s (47 attack starts)

| Model | AUROC | Attack starts warned | Precision of the warnings |
| :--- | :---: | :---: | :---: |
| Logistic regression, last window only | 0.619 | 0 of 47 | – |
| Logistic regression, 10 windows | 0.653 | 6 of 47 | 0.5% |
| **World model (LSTM)** | 0.931 | **8 of 47** | 13.8% |
| XGBoost, 10 windows | 0.963 | 20 of 47 | 2.2% |

The world model warns about few attack starts (8 of 47). This is the weakest part of the system.

### 4. Timing: does it know *when*, inside one host?

Rows: calm windows only (host normal now, no attack of that host in the previous 5 minutes).
"Inside-host AUROC" is computed within each host, so knowing *which* host is dangerous earns nothing
(0.5 = no timing ability, 1.0 = perfect).

| Output | Horizon | Inside-host AUROC | Precision | Recall |
| :--- | :---: | :---: | :---: | :---: |
| World model, 60-s risk | 60 s | 0.804 | 0.093 | 0.211 |
| **World model, start-soon output** | **5 min** | **0.892** | **0.958** | **0.340** |
| World model, start-soon output | 10 min | 0.890 | 0.486 | 0.279 |
| XGBoost, 10 windows | 5 min | 0.874 | 0.847 | 0.342 |
| XGBoost, 10 windows | 10 min | 0.849 | 0.615 | 0.636 |

Per dataset (5-minute output): Unraveled 0.95, CIC-IDS2017 0.97, CTU-13 0.50, DAPT2020 0.44, CSE-CIC-IDS2018 0.29.
So the timing ability comes from attacks that return on the same host; on three of five datasets it is at
chance level. The evidence rests on 12 hosts.

### 5. Four labelled files through the real upload ([`samples/test_files/`](samples/test_files/README.md))

| File | Attack windows alerted | False alarms on normal windows | Stage named correctly |
| :--- | :---: | :---: | :---: |
| A · CIC-IDS2017 DDoS (42,341 flows) | 100% (20 of 20) | 1.94% | no DDoS stage in the model |
| B · CSE-CIC-IDS2018 FTP brute force (76,922 flows) | 81% (55 of 68) | 0.19% | 94% |
| C · CTU-13 botnet (39,952 flows) | 39% (127 of 325) | 11.2% | 96% |
| D · Unraveled exfiltration (15,817 flows) | 91% (59 of 65) | 14.7% | 83% |

An upload of one of these files takes 8–26 seconds on a laptop.

Every value shown on the Attack Forecast page for these four files was compared with a separate recomputation
(page against backend: 106,105 values; backend rules: 30,764 checks; network outputs recomputed with separately
written code: about 22,000 values). No mismatch. Scripts: `training/world_model/checks/`.

### 6. A network never seen in training (previous model version, v3; not repeated for v4)

| Held-out network | Measure | World model v3 | XGBoost | Logistic regression |
| :--- | :--- | :---: | :---: | :---: |
| CIC-IDS2017 | early-warning AUROC | 0.55–0.60 | 0.52 | 0.46 |
| CIC-IDS2017 | attack starts warned (of 13) | 0–3 | 2 | 7 (at 37% false alarms) |
| UNSW-NB15 | AUROC, attack within 60 s | 0.33–0.73 (by seed) | 0.03 | 0.09 |

Early warning on an unseen network is not solved. See [`docs/RESULTS_world_model_v3.md`](docs/RESULTS_world_model_v3.md).

---

## ⚠️ Limitations

1. **No warning before a host's first attack** in our test files. The 5/10-minute output works for attacks that repeat on the same host.
2. **Unseen networks:** weak (table 6). All headline numbers are on held-back hours of networks the model was trained on.
3. **False alarms of 11–15% of normal windows on files C and D.**
4. **No DDoS stage.** DDoS is detected as an attack, but the stage shown for it is not meaningful.
5. **Reconnaissance and initial access** are the weakest stages (76% and 79% recall).
6. **The "what usually follows" tree is not a model output.** It is counted from the training data: 17 stage changes on 12 hosts.
7. **Live Traffic uses older models** (a 15-feature, 5-flow LSTM and an XGBoost per-flow classifier), not the world model. Their validation is in [`VALIDATION.md`](VALIDATION.md).
8. **Datasets:** 4 of the 7 datasets named in the problem statement are used (CTU-13, CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15), plus DAPT2020 and Unraveled. LANL, DARPA 1999 and CICIoT2023 are not used.
9. **A CSV must contain source IP, destination IP and a time per flow.** Files without them are refused with the reason.
10. The home page (3D robot and fonts) is bundled to work without internet; this has not been tested with networking switched off.

---

## 🚀 Setup & run

> Every command below must be run **from inside the project folder**.

### Prerequisites

| Requirement | Version | Download |
| :--- | :--- | :--- |
| **Python** | 3.10 or newer | [python.org/downloads](https://www.python.org/downloads/) — on Windows tick **"Add python.exe to PATH"** |
| **Node.js** (includes npm) | 18 or newer (LTS) | [nodejs.org](https://nodejs.org/) |
| **Git** *(optional)* | any | [git-scm.com](https://git-scm.com/downloads) — or use **Code → Download ZIP** on GitHub |
| **Npcap** *(Windows, live capture only)* | latest | [npcap.com](https://npcap.com/#download) — tick **"WinPcap API-compatible Mode"** |

Check them in a new terminal: `python --version` and `node --version`.
File upload works without Npcap; only live capture needs it.
Setup needs internet once (to download the Python and Node packages). No GPU is needed.

### 🪟 Windows

**Step 1 — Get the code**

```powershell
git clone https://github.com/maradiadrashti/cyberforecaster.git
```

*(or download the ZIP from GitHub and extract it)*

**Step 2 — Open PowerShell inside the project folder**

In File Explorer open the `cyberforecaster` folder, click the address bar, type `powershell`, press **Enter**.
Check: `dir` must list `setup.ps1`, `start.ps1` and `requirements.txt`.

**Step 3 — Allow the project scripts to run (this window only)**

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Answer **Y** if asked. This changes nothing permanently.

**Step 4 — Install (first time only, about 5–10 minutes)**

```powershell
.\setup.ps1
```

It creates a Python virtual environment in `.venv\`, installs the packages from `requirements.txt`
and installs the dashboard packages in `client\`.

**Step 5 — Start**

```powershell
.\start.ps1
```

Click **Yes** when Windows asks for Administrator permission (needed for live capture).
A new window starts the backend and the dashboard and opens **http://127.0.0.1:5173**.
Keep that window open. Press **Enter** in it to stop everything.

**Next time:** Steps 2, 3 and 5 only.

### 🐧 Linux / 🍎 macOS

```bash
git clone https://github.com/maradiadrashti/cyberforecaster.git
cd cyberforecaster
chmod +x setup.sh start.sh
./setup.sh                    # first time only
sudo ./start.sh               # sudo is needed for live packet capture
```

Open **http://127.0.0.1:5173**. Press **Ctrl + C** to stop.

### Manual start (any OS)

Two terminals, both inside the project folder, after the setup script has run once.

```bash
# Terminal 1 — backend
#   Windows:      .venv\Scripts\activate
#   Linux/macOS:  source .venv/bin/activate
cd capture-service
python -m uvicorn capture_server:app --host 127.0.0.1 --port 8080
```

```bash
# Terminal 2 — dashboard
cd client
npm run dev
```

| Service | URL |
| :--- | :--- |
| Dashboard | http://127.0.0.1:5173 |
| Backend API | http://127.0.0.1:8080 · interactive docs at http://127.0.0.1:8080/docs |

---

## ▶️ Try it

1. Open the dashboard and go to **File Upload**.
2. Upload **`samples/test_files/D_unraveled_exfiltration_forecast.csv`** (3 MB, takes under 30 seconds).
3. Go to **Attack Forecast**. Pick host **10.1.3.8** (command & control) or **10.1.3.17** (repeated exfiltration).
4. Click any point of the graph to see that window's stage, attribution and evidence.

To try a packet capture, upload `samples/darpa2000_lldos_inside_slice.pcap` (11 MB, unlabelled, from a network the model was not trained on, so read its result as a ranking only).

Other files and what to expect from each: [`samples/test_files/README.md`](samples/test_files/README.md).

Without the dashboard:

```bash
python capture-service/world_model.py samples/test_files/D_unraveled_exfiltration_forecast.csv
```

writes the full result as JSON into `forecast_out/`.

---

## 🖥️ Using the dashboard

| Page | What you get |
| :--- | :--- |
| **Live Telemetry** | Pick a network interface and start capture. Live traffic rate, topology, per-flow labels, and download of the captured traffic as PCAP or CSV. Uses the older live models (limitation 7). |
| **File Upload** | Upload `.pcap` / `.pcapng` / `.csv`. The world model scores every source host. |
| **Attack Forecast** | The result for the selected host (see below). |

**Attack Forecast page, top to bottom**

| Part | What it shows |
| :--- | :--- |
| **Threat level** | HIGH RISK when the 60-second risk is above the alert threshold (0.711, chosen on validation data); ELEVATED from 0.5; WATCH when only the 5-minute output is above its warning level |
| **Attack probability** | The 60-second risk, with the 5- and 10-minute values below it |
| **Model confidence** | The probability the model gives to the stage it names |
| **Risk forecast graph** | Risk of the host over the file, the range across the 3 model copies, the baseline, and the forecast for +10 … +60 s from the selected window |
| **Stage progression tree** | The model's stage, and what followed that stage in the training data (counts, not a model output) |
| **MITRE ATT&CK mapping** | Tactic and techniques for the named stage |
| **Feature attribution (occlusion)** | How much the risk changes when each feature is replaced by its training average |
| **Recommended actions / evidence** | Actions for the latest window, and the flows behind it |

---

## 🏗️ How it works

```text
PCAP / PCAPNG ──▶ flow extractor (dpkt) ─┐
flow CSV (CICFlowMeter or own schema) ───┼─▶ per source host: 10-second windows × 73 features
live capture (Scapy) ─▶ older live models │        (volume, timing, TCP flags, ports, packet details)
                                          ▼
                         last 10 windows ─▶ 2-layer LSTM (hidden 128) × 3 copies, averaged
                                          ▼
     next-window features · stage now … +60 s · attack within 10 … 60 s · attack starts within 5 / 10 min
                                          ▼
        FastAPI backend (capture-service/) ──▶ React dashboard (client/)
```

| Layer | Technology |
| :--- | :--- |
| Models | PyTorch (LSTM world model), scikit-learn (baseline), XGBoost (live per-flow classifier and comparison baseline) |
| Backend | Python, FastAPI, Uvicorn, WebSockets, Scapy, dpkt, pandas, NumPy |
| Frontend | React 19, Vite, Tailwind CSS, Recharts, lucide-react, Spline (home page) |

### Training data (not included in the repository)

2,233,318 host-windows, 73 features.

| Dataset | In problem statement | Host-windows | Hosts |
| :--- | :---: | ---: | ---: |
| CSE-CIC-IDS2018 | yes | 1,218,017 | 32,820 |
| Unraveled | no | 577,727 | 1,768 |
| CTU-13 | yes | 172,845 | 89,303 |
| CIC-IDS2017 | yes | 132,327 | 5,090 |
| UNSW-NB15 | yes | 117,963 | 43 |
| DAPT2020 | no | 14,439 | 129 |

How to rebuild and retrain: [`training/world_model/README.md`](training/world_model/README.md)
(the installed model trained in 1 hour 7 minutes on a laptop CPU).

---

## 📂 Repository layout

```text
cyberforecaster/
├── capture-service/         backend (FastAPI)
│   ├── capture_server.py    API, upload handling, live capture
│   ├── world_model.py       loads files, builds windows, runs the world model
│   └── extractor/           PCAP → flows
├── client/                  dashboard (React + Vite)
├── models/
│   ├── world_model/         the world model (weights, metadata, baseline, progression counts)
│   └── …                    older live models (stage LSTM, XGBoost flow classifier)
├── training/
│   ├── world_model/         data steps, training script, checks, logs and results of the real runs
│   └── *.py                 training of the live models
├── data_prep/               builds the flow corpus for the live models
├── evaluation/              evaluation of the live stage model
├── samples/                 files to upload (test_files/ has four labelled ones)
├── docs/                    result reports for world model v3 and v4
├── tests/                   tests of the live-capture path
├── legacy/                  earlier code and models, no longer used by the application
├── VALIDATION.md            validation of the live stage model
├── requirements.txt
├── setup.ps1 / setup.sh     one-time install
└── start.ps1 / start.sh     start backend + dashboard
```

---

## 🔌 Main API endpoints

| Method | Endpoint | Purpose |
| :--- | :--- | :--- |
| `POST` | `/api/upload` | Upload a PCAP/CSV, run the world model, return the hosts and conversations |
| `GET` | `/api/v2/forecast/latest` | Full world-model result of the last upload (graph, stages, attribution, self-check) |
| `GET` | `/api/forecast/latest` | Conversation list of the last upload |
| `POST` | `/api/forecast/reset` | Clear the last upload |
| `GET` | `/api/interfaces` | Network interfaces available for capture |
| `POST` | `/api/capture/start/{iface}` · `/api/capture/stop/{iface}` | Start / stop live capture |
| `GET` | `/api/capture/export-pcap` · `/api/capture/download` | Download captured traffic |
| `WS` | `/ws/live` | Live flow and forecast stream |

Full list: http://127.0.0.1:8080/docs while the backend is running.

---

## 🛠️ Troubleshooting

| Problem | Fix |
| :--- | :--- |
| `.\start.ps1 : The term ... is not recognized` | You are not inside the project folder. `dir` must show `start.ps1`. |
| *"running scripts is disabled on this system"* | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in the same window, then retry. |
| `setup.ps1` says Python / Node.js was not found | Install it, then open a **new** PowerShell window. |
| No interfaces / capture won't start (Windows) | Install **Npcap** with *WinPcap API-compatible Mode* and run `start.ps1` as Administrator. |
| Port 8080 or 5173 already in use | `start.ps1` frees them automatically; otherwise stop the other program. |
| Dashboard opens but uploads fail | The backend stopped. Close the start window and run `.\start.ps1` again. Errors are in `logs\capture.err`. |
| Upload is refused | The message says why (for a CSV: no source IP, destination IP or flow time). |
| Attack Forecast is empty | Upload a file on **File Upload** first. |

---

## 📚 References

1. I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, *"Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization"*, ICISSP 2018 (CIC-IDS2017 / CSE-CIC-IDS2018).
2. S. García, M. Grill, J. Stiborek, A. Zunino, *"An empirical comparison of botnet detection methods"*, Computers & Security 45, 2014 (CTU-13).
3. N. Moustafa, J. Slay, *"UNSW-NB15: a comprehensive data set for network intrusion detection systems"*, MilCIS 2015.
4. S. Myneni et al., *"DAPT 2020 — Constructing a Benchmark Dataset for Advanced Persistent Threats"*, Springer 2020.
5. S. Myneni et al., *"Unraveled — A semi-synthetic dataset for Advanced Persistent Threats"*, Computer Networks 227, 2023.
6. MITRE ATT&CK® — https://attack.mitre.org

---

<div align="center">

Built for **Smart India Hackathon 2026** · PS **SIH26153** (NTRO) · Team Ninja

</div>
