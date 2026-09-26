# Validation

How CyberForecaster was evaluated, the exact numbers, and what they do and do not prove.
Every number here comes from the model files in `models/` and can be reproduced with the scripts in
`evaluation/`.

---

## 1. Setup

| | |
| :--- | :--- |
| **LSTM training data** | CSE-CIC-IDS-2018 + CTU-13 + DAPT-2020, mapped to one 15-feature flow schema |
| **Baseline training data** | the same merged corpus (balanced 1:1 attack/normal subsample) |
| **Held-out evaluation data** | **CIC-IDS-2017, Thursday Web Attacks** (Brute Force, XSS, SQL Injection) — a different year and network, never used to train either model |
| **Input to both models** | the same 15 features per flow |
| **LSTM** | sliding window of the last 5 flows of each conversation (src → dst) |
| **Baseline** | logistic regression on the most recent flow only (no memory) |
| **Label of a window** | attack if its most recent flow is an attack |
| **Script** | `python evaluation/eval_cross_dataset.py <labeled_csv> --out evaluation/results/<name>.json` |
| **Saved run** | [`evaluation/results/cic2017_webattacks.json`](evaluation/results/cic2017_webattacks.json) |

CIC-IDS-2017 CSVs come from CICFlowMeter and have **no TTL field**; TTL was set to 64, the real
default TTL of the dataset's Ubuntu hosts (see §4).

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

> An earlier run on a 34,053-window subset of the same file gave 98.4% accuracy (stage head), 98.7%
> of benign correctly normal and 77.5% correct stage — consistent with the full-file run above.

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

## 4. Multi-stage forecasting — DAPT-2020 kill-chain matrix

The *t+1 … t+5* forecast is a Markov roll-out over a **host-level kill-chain transition matrix**
(`models/stage_transition_matrix.json`), built by `data_prep/estimate_killchain_matrix.py` from the
order in which each DAPT-2020 attacker host moved through attack stages.

| From | → Next (most likely) | P | Observed transitions |
| :--- | :--- | :---: | :---: |
| Reconnaissance | Initial Access | 0.77 | 4 |
| Initial Access | Lateral Movement | 0.83 | 6 |
| Lateral Movement | Exfiltration | 0.50 | 1 |

Rows are smoothed, so unobserved transitions keep a small probability.

A 5-fold hold-out over attacker hosts predicted the next stage correctly **10 / 11** times.

**Caveat:** DAPT-2020 has thousands of attack flows but only **11 clean stage transitions across 7
attacker hosts** (Exfiltration has 15 flows in total). The matrix is directionally right — it
reproduces the textbook kill chain — but it is statistically under-powered, and "10/11" is not a
robust accuracy figure. CSE-CIC-IDS-2018 and CTU-13 contain attacks but **no multi-stage
transitions at all**, which is why DAPT-2020 is used for this part.

---

## 5. Known boundaries

| Boundary | Effect | Status |
| :--- | :--- | :--- |
| **TTL missing in CSV** | with TTL = 0 the CIC-IDS-2017 accuracy drops to ~35%; with the hosts' real TTL (64) it is as in §2 | the CSV adapter imputes 64 and logs a warning; PCAP / live input carry real TTL |
| **Web brute-force** | looks like normal HTTP at flow level → most of the ~22% missed attack windows | inherent to flow-level features |
| **Very old traffic** (e.g. DARPA 2000) | not reliably detected — far outside the 2017–2020 training distribution | documented, not claimed |
| **Sparse transitions** | forecast matrix built from 11 transitions | future work: more multi-stage APT data |

---

## 6. Summary

- **Shown with hard numbers:** detection generalizes to an unseen dataset — **99.2% accuracy,
  0.48% false-positive rate, F1 0.72** — where a per-flow logistic-regression baseline collapses.
- **Shown, but on little data:** multi-stage forecasting follows the real kill chain learned from
  DAPT-2020.
- **Not claimed:** robustness to TTL-less CSVs without imputation, or to decades-old traffic.
