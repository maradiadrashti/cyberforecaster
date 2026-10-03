# World model v3 — results and limits

Model: 2-layer LSTM world model over per-host network state. One row = one source host in one
10-second window, 73 features (volume 15, timing 11, flags 14, ports 20, packet 13). It reads the
last 10 windows of a host and outputs (a) the next window's features, (b) the stage now and at
each of the next 6 windows, (c) the probability that an attack starts within 10 … 60 s.
Three copies with different random seeds are averaged.

> v3 has been replaced by v4 (see `RESULTS_world_model_v4.md`). The v3 model files are in
> `legacy/models/world_model_v3/`; the training code (shared with v4) and the v3 logs are in
> `training/world_model/` and `training/world_model/results/logs_v3/`. Inference: `capture-service/world_model.py`.

Every number below comes from the logs in `training/world_model/results/logs_v3/`.

## Data

| Dataset | Windows | Attack windows | Notes |
|---|---|---|---|
| CSE-CIC-IDS2018 | 1,218,017 | 20,845 | from PCAP |
| Unraveled | 577,727 | 48,608 | multi-stage APT campaign, 6 attacker hosts |
| CTU-13 (one day, Neris) | 172,845 | 6,085 | from PCAP |
| CIC-IDS2017 | 132,327 | 1,965 | timestamps have minute resolution |
| UNSW-NB15 | 117,963 | 17,303 | no TCP flag counts |
| DAPT2020 | 14,429 | 540 | multi-stage, 11 attacker hosts |

Labels are per flow. A window counts as attack only if at least 20% of that host's flows in the
window are attack flows; windows with a few attack flows among many benign ones are excluded from
training and scoring. Real stage-to-stage transitions in the data: about 47 (DAPT 11, Unraveled 34,
CIC-IDS2017 2) — too few to claim that the model forecasts kill-chain progression.

## Test 1 — same networks, held-back hours (1-hour blocks: 60% train, 20% validation, 20% test)

"Early warning" = the host's last 10 windows are all normal and an attack starts within 60 s.

| Measure | World model v3 (3 seeds) | XGBoost (same inputs) | Logistic regression (same inputs) |
|---|---|---|---|
| Early-warning AUROC | 0.953 ± 0.005 | 0.963 | 0.653 |
| Attack onsets warned in time (of 47) | 11–13 | 20 | 6 |
| F1, attack within 60 s (all windows) | 0.910 ± 0.008 | 0.961 | 0.814 |

Stage named correctly (current window): command and control 94%, lateral movement 98%,
exfiltration 97%, reconnaissance 78%, initial access 67%. Per dataset: reconnaissance is 97–100%
everywhere except UNSW-NB15 (68%); initial access is 100% on CIC-IDS2017, 67% on UNSW-NB15,
44% on CSE-CIC-IDS2018 and 0% on DAPT2020 (12 windows). On UNSW-NB15 the two stages are confused
with each other because the same hosts run both at once. About 3% of normal windows are given an
attack stage, mostly on Unraveled (10% of its normal windows).

## Test 2 — a network never seen in training (whole dataset held out)

| Held-out network | Measure | World model v3 | XGBoost | Logistic regression |
|---|---|---|---|---|
| CIC-IDS2017 | early-warning AUROC | 0.55–0.60 | 0.52 | 0.46 |
| CIC-IDS2017 | onsets warned (of 13) | 0–3 | 2 | 7 (at 37% false alarms) |
| UNSW-NB15 | AUROC, attack within 60 s | 0.33–0.73 (by seed) | 0.03 | 0.09 |
| UNSW-NB15 | stage naming, macro-F1 | 0.04 | – | – |

**Early warning on an unseen network is not solved.** The model ranks attack-related hosts above
normal ones better than the baselines, but the alert threshold learned on the training networks
does not transfer.

Things tried for this, and what happened:

| Idea | Result |
|---|---|
| Train on short host histories (v3) | Fixes false alarms on short uploads; no gain on unseen networks |
| Alert threshold calibrated on the new network's own early traffic | Stops the false-alarm flood on UNSW (90% → 1%); no gain on CIC-IDS2017 |
| Standardise every network with its own statistics | CIC-IDS2017 AUROC 0.58 → 0.71, UNSW 0.33–0.73 → 0.09–0.13. Rejected. |

## Test 3 — real files through the loader

| File | Result |
|---|---|
| CIC-IDS2017 Friday PortScan CSV (in training data) | attack windows alerted 44%, false alarms 2.1%, stage named correctly 75%, window AUROC 0.94 (logistic regression 0.67) |
| DARPA 2000 LLDOS 1.0 PCAP (never seen, no labels) | 266 alert windows on 25 of 34,515 hosts; the attacker ranks 17th and is alerted once, at the DDoS launch; the four earlier phases score near zero |

## What the upload feature accepts

PCAP / PCAPNG, the project's flow CSV, CICFlowMeter CSV with IP addresses, UNSW-NB15 raw CSV,
NFStream CSV, CTU-13 binetflow (approximate), each also as .gz / .bz2 / .zip. Files without IP
addresses or without timestamps are refused with the reason. Features built from an uploaded
CIC-IDS2017 file were compared with the training features: identical.

## Limits, stated plainly

* On the training networks XGBoost on the same inputs is as good or better at detection; the
  world model's contribution is the per-host 60-second forecast and the per-step stage output.
* Early-warning precision is low (about 4%): most early alerts are false even at a 0.1% false-alarm rate, because real onsets are rare.
* Few attacker hosts (6–11 per multi-stage dataset); train and test share hosts, in different hours.
* Hosts with fewer than 10 windows of history are scored with padded history and marked.
* Of the seven datasets named in the problem statement, four are used (CTU-13 only one day);
  LANL, DARPA 1999 and CICIoT2023 are not.
