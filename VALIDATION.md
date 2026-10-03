# Validation of the Live Traffic stage model

> **Scope.** This document is about the earlier 15-feature LSTM (5 flows per conversation), which the dashboard
> now uses only on the **Live Traffic** page. It was written before the world model existed and has not been re-run.
> The stage-transition matrix described in section 3 is no longer used by the application (it is in `legacy/`).
> Uploaded files are scored by the world model; its results are in
> [`docs/RESULTS_world_model_v4.md`](docs/RESULTS_world_model_v4.md).


How CyberForecaster was evaluated, the exact numbers, and what they do and do not prove.
Every number here comes from the model files in `models/` and can be reproduced with the scripts in
`evaluation/`.

---

## 1. Setup

| | |
| :--- | :--- |
| **LSTM training data** | CSE-CIC-IDS-2018 + CTU-13 + DAPT-2020, mapped to one 15-feature flow schema |
| **Baseline training data** | an earlier snapshot of the same corpus, before DAPT-2020 was added (balanced 1:1 attack/normal subsample) |
| **Held-out evaluation data** | **CIC-IDS-2017, Thursday Web Attacks** (Brute Force, XSS, SQL Injection) — a different year and network, never used to train either model |
| **Input to both models** | the same 15 features per flow |
| **LSTM** | sliding window of the last 5 flows of each conversation (src → dst) |
| **Baseline** | logistic regression on the most recent flow only (no memory) |
| **Label of a window** | attack if its most recent flow is an attack |
| **Script** | `python evaluation/eval_cross_dataset.py <labeled_csv> --out evaluation/results/<name>.json` |
| **Saved run** | [`evaluation/results/cic2017_webattacks.json`](evaluation/results/cic2017_webattacks.json) |

**How the test set was built (important):**

- The public CIC-IDS-2017 flow CSV comes from CICFlowMeter. It has **no IP addresses, no timestamps
  and no TTL field**. Its columns were mapped to our 15 features; TTL was set to 64 (the Linux default,
  which the victim web server runs). Its TCP flag counts are defined by CICFlowMeter, not by our extractor.
- Conversations had to be reconstructed. The **2,180 attack flows** were assigned the attacker → victim
  pair documented by the dataset authors (`172.16.0.1 → 192.168.10.50`). The **168,186 benign flows** were
  spread across 48 invented internal sender addresses (all → `192.168.10.50`). **The benign
  conversations are therefore synthetic.**
- We checked that the training corpus contains no CIC-IDS-2017 hosts.

---

## 2. Cross-dataset benchmark — LSTM world model vs. logistic regression

**170,170 windows · 2,176 attack windows (1.3%) · 167,994 benign windows**

| Model | Accuracy | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **LSTM — risk head (p ≥ 0.5)** | **0.9922** | **0.6734** | 0.7629 | **0.7154** | **0.0048** | 1,660 | 805 | 516 | 167,189 |
| LSTM — stage head (stage ≠ normal) | 0.9834 | 0.4196 | 0.7822 | 0.5462 | 0.0140 | 1,702 | 2,354 | 474 | 165,640 |
| Logistic regression baseline | 0.0547 | 0.0133 | 1.0000 | 0.0263 | 0.9575 | 2,176 | 160,861 | 0 | 7,133 |

**MITRE stage accuracy:** the LSTM labels **1,702 / 2,176 (78.2%)** attack windows with the correct
stage, **Initial Access** (web attacks map to MITRE TA0001).

### How to read this

- **The LSTM generalizes to a new network.** It keeps false alarms at **0.48%** of benign windows
  while still detecting about three quarters of the attacks.
- **The per-flow baseline does not.** On its own training distribution it is good (next section),
  but on unseen traffic its decision boundary no longer fits: TCP flag-count features
  (`ack_count`, `fin_count`, `syn_count`) are distributed very differently in CICFlowMeter output,
  and a single linear rule on one flow cannot absorb that shift — it flags ~96% of benign traffic.
  The LSTM, which looks at how 5 consecutive flows behave together, is far more robust to it.
- **Class imbalance matters.** Attacks are only 1.3% of windows, so accuracy alone is flattering.
  Precision, recall, F1 and FPR are reported for that reason. The risk head is the better detector
  (it is what drives the dashboard's risk score); the stage head is used for *which* stage.

### Detection by attack type (risk head)

| Attack type | Attack windows | Detected | Rate |
| :--- | ---: | ---: | ---: |
| Brute Force | 1,503 | 1,104 | 73.5% |
| XSS | 652 | 556 | 85.3% |
| SQL Injection | 21 | 0 | 0% |

### Sensitivity to conversation grouping

The LSTM's result depends on flows being grouped into conversations. Feeding the same 170,366 flows in
raw file order with no grouping (attack flows interleaved with benign ones) gives LSTM recall of
**6.0% (risk head) / 7.9% (stage head)**. The baseline is unaffected because it scores one flow at a
time. The dashboard always groups traffic by sender → receiver, so the table above reflects how the
system is used — but on partly reconstructed conversations. A re-run on CIC-IDS-2017's labelled-flow
files that contain real IPs and timestamps would remove this caveat.

---

## 3. Baseline on its own training distribution

From `models/logreg_baseline_meta.json` (held-out 20% split of the training corpus):

| Accuracy | Precision | Recall | F1 | FPR |
| ---: | ---: | ---: | ---: | ---: |
| 0.9575 | 0.9349 | 0.9835 | 0.9586 | 0.0685 |

This is included so the comparison in §2 is fair: the baseline is a competent in-distribution
classifier; the difference is generalization.

The LSTM's own validation scores from its training run were printed to the console but not saved
with the model, so they are not quoted here. Re-running `training/train_lstm_world_model.py`
reprints them (`stage_val_accuracy`, `binary_val_accuracy`).

---

## 4. Multi-stage forecasting — kill-chain matrix (DAPT-2020 data + ATT&CK prior)

The *t+1 … t+5* forecast is a Markov roll-out over a **host-level kill-chain transition matrix**
(`models/stage_transition_matrix.json`), built by `data_prep/estimate_killchain_matrix.py` from the
order in which each DAPT-2020 attacker host moved through attack stages, combined with an explicit
MITRE ATT&CK ordering prior:

`row_i = normalize(counts_i + 2 × prior_i + 0.25)` for attack stages, where `prior_i` = stay 0.4 /
advance to the next ATT&CK stage 0.6. Normal and Exfiltration are absorbing.

| From | Most likely next stage | P(next \| current) | Observed transitions | Where it comes from |
| :--- | :--- | :---: | :---: | :--- |
| Reconnaissance | Initial Access | 0.73 | 4 | data (DAPT-2020) + prior |
| Initial Access | Lateral Movement | 0.78 | 6 | data (DAPT-2020) + prior |
| Lateral Movement | Command & Control | 0.32 (Exfiltration 0.28) | 1 (→ Exfiltration) | mostly prior |
| Command & Control | Exfiltration | 0.41 | 0 | **prior only** |

The prior exists because the data has **no transition out of Command & Control** (and only one out of
Lateral Movement): with data alone, a conversation classified as C&C — e.g. the botnet PCAP sample —
could not be forecast any further. The counts, the prior and its weight are all saved in
`models/stage_transition_matrix.json`.

Holding out one attacker host at a time, the matrix predicts the next stage correctly **10 / 11** times;
the single miss is the only Lateral Movement → Exfiltration transition (the prior prefers Command & Control).

**Caveat:** DAPT-2020 has thousands of attack flows but only **11 clean stage transitions across 7
attacker hosts** (Exfiltration has 15 flows in total). The matrix is directionally right — it
reproduces the textbook kill chain — but it is statistically under-powered, and "10/11" is not a
robust accuracy figure. In our labeled training data **no CSE-CIC-IDS-2018 attacker (27 hosts) or
CTU-13 attacker (2,377 hosts) moves through more than one stage**, and neither dataset has
Reconnaissance or Exfiltration flows — so all 11 transitions come from DAPT-2020. (CIC-IDS-2018's
infiltration scenario spans two machines — attacker, then infected victim — which a per-attacker-host
view does not count as a transition.)

---

## 5. Known boundaries

| Boundary | Effect | Status |
| :--- | :--- | :--- |
| **TTL missing in CSV** | with TTL = 0 the CIC-IDS-2017 stage-head accuracy drops to 34.8%; with TTL = 64 it is as in §2 | the CSV adapter imputes 64 and logs a warning; PCAP / live input carry real TTL |
| **Missed web attacks** | risk head misses 516 / 2,176 attack windows: 399 Brute Force (looks like normal HTTP at flow level), 96 XSS, all 21 SQL Injection | inherent to flow-level features |
| **Reconstructed conversations** | benign CIC-IDS-2017 conversations are synthetic (no IPs in the public CSV) | re-run on the labelled-flow files with real IPs |
| **Very old traffic** (e.g. DARPA 2000) | not reliably detected — far outside the 2017–2020 training distribution | documented, not claimed |
| **Sparse transitions** | forecast matrix built from 11 transitions | future work: more multi-stage APT data |

---

## 6. Summary

- **Shown with hard numbers, with a caveat:** on an unseen dataset the LSTM reaches **99.2% accuracy,
  0.48% false-positive rate, F1 0.72** where a per-flow logistic-regression baseline collapses — measured
  on partly reconstructed conversations (see §1).
- **Shown, but on little data:** multi-stage forecasting follows the real kill chain learned from
  DAPT-2020.
- **Not claimed:** robustness to TTL-less CSVs without imputation, or to decades-old traffic.
