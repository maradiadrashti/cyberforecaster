# training/world_model/

Everything used to build, train and check the world model in `models/world_model/` (version 4).
Results: [`docs/RESULTS_world_model_v4.md`](../../docs/RESULTS_world_model_v4.md). Logs of the real runs: `results/`.

You do not need any of this to run the dashboard.

## What the model is

- One input row = one source host in one 10-second window, described by 73 numbers (`feature_groups.json`:
  volume, timing, TCP flags, ports, packet details).
- Input to the network: the last 10 windows of a host. Network: 2-layer LSTM, hidden size 128, dropout 0.3.
- Outputs: the next window's features, the stage now and at +10 … +60 s (6 classes), "attack within 10 … 60 s",
  and "an attack of this host starts within 5 / 10 minutes".
- Three copies with different random seeds are trained and averaged.

## Data

2,233,318 host-windows from six public datasets (not included in the repository):

| Dataset | Windows | Hosts |
|---|---|---|
| CSE-CIC-IDS2018 | 1,218,017 | 32,820 |
| Unraveled | 577,727 | 1,768 |
| CTU-13 | 172,845 | 89,303 |
| CIC-IDS2017 | 132,327 | 5,090 |
| UNSW-NB15 | 117,963 | 43 |
| DAPT2020 | 14,439 | 129 |

Split: by 1-hour blocks of time. Every hour goes whole into train (60%), validation (20%) or test (20%), so a
test window never shares its hour with a training window. The split is not by network: every dataset appears in
all three parts.

## Steps

The scripts expect to sit in `<data folder>/processed/` with the raw datasets one level up
(`<data folder>/merged_final_v5.csv`, `UNSW-NB15_1..4.csv`, `unraveled/`, `cic2017/`). Copy them there to re-run.

| Step | Script | Output |
|---|---|---|
| 1 | `data_prep/` in the repository root | `merged_final_v5.csv` (CSE-CIC-IDS2018, CTU-13, DAPT2020) |
| 2 | `step2_convert.py`, `step2b_cic2017.py` | UNSW-NB15, Unraveled, CIC-IDS2017 in the same columns |
| 3 | `step3_windows.py` | `windows.pkl`: 10-second windows per host, 73 features (`step3_report.txt` is the report of the real run) |
| 4 | `step4_train.py --epochs 15 --seeds 3 --v4 --unseen none` | `model_v4_unseen-none/`: `world_model.pt`, `world_model_meta.json`, `baseline_lr.json`, `results.json` |
| 5 | `build_progression.py` | `stage_progression.json` (counts for the "what usually follows" tree) |
| 6 | copy the four files into `models/world_model/` | |

The training run that produced the installed model took 1 hour 7 minutes on a laptop CPU (15 epochs, 3 seeds).
`step4_train.py --unseen <dataset>` holds one whole dataset out of training (used for the v3 unseen-network runs).

## Checks (`checks/`)

| Script | What it checks |
|---|---|
| `run_upload_all.py` | Starts the backend on a spare port, uploads test files A–D through the real upload endpoint, saves what the page receives (`checks/audit/`). |
| `audit_backend.py <result>` | Recomputes everything in a saved result that does not need PyTorch (thresholds, alerts, stage names, ranges, summary counts). |
| `audit_model.py` | Recomputes the network outputs and the attribution with separately written code and compares them with the backend. With `windows.pkl` present it also compares upload features with training features. |
| `audit_page.cjs` | Renders the Attack Forecast page with the saved result and compares every displayed number with the backend value. |
| `timing_check.py`, `find_warned_onsets.py` | Timing score inside each host; list of attack starts with a warning. Need `windows.pkl`. |
| `run_test_files.py`, `run_api_test.py`, `test_v2_api.py` | Run the model / the API on the test files. |

`runner.py` is a small job runner used to run long jobs unattended on the training PC (reads `jobs/*.job`).

## Results folder

- `results/results_v4.json`, `results/results_v3.json`: every metric of the two training runs (validation and test, each baseline, each seed).
- `results/logs_v4/`, `results/logs_v3/`: the console logs of training and of each check.
