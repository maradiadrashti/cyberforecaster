# World model v4: results (3 October 2026)

> v4 has been replaced by v5 (see `RESULTS_world_model_v5.md`). The v4 model files are in `legacy/models/world_model_v4/`.
> Test files B and C were rebuilt for v5, so the file table below refers to the earlier, thinned-out versions.

v4 = v3 plus two extra outputs: "an attack of this host starts within 5 minutes" and "within 10 minutes".
Same data, same 73 features, same hour-block split (60% train / 20% validation / 20% held back), 3 copies averaged.
Everything below is on the held-back hours unless it says otherwise. Scripts, logs and both result files are in
`training/world_model/` (logs: `results/logs_v4/`). The v3 model is kept in `legacy/models/world_model_v3/`.

## v3 against v4 (average of 3 copies)

| Measure | v3 | v4 |
|---|---|---|
| Attack within 60 s, all windows: F1 | 0.912 | 0.931 |
| Same: false-alarm rate | 1.03% | 0.81% |
| Same: AUROC | 0.9972 | 0.9975 |
| Stage now: macro-F1 | 0.737 | 0.822 |
| Stage recall: initial access | 0.667 | 0.789 |
| Stage recall: reconnaissance | 0.778 | 0.762 |
| Early warning (history all normal -> attack within 60 s): AUROC | 0.953 | 0.931 |
| Same: attack starts warned | 14 of 47 | 8 of 47 |
| Same: precision of those warnings | 4% | 14% |
| Alert threshold (risk within 60 s) | 0.815 | 0.711 |

v4 is better at detection and at naming the stage. It is worse on the 60-second early-warning count: it warns about
fewer attack starts, with fewer false warnings. XGBoost on the same 10 windows still warns about more starts (20 of 47).

## Timing: can the model tell WHEN, inside one host?

Rows: calm windows only (host normal now, no attack of that host in the previous 5 minutes).
"Inside-host" = AUROC computed within each host and averaged (weighted by the number of attack starts), so knowing
which host is dangerous earns nothing. 0.5 = no timing ability, 1.0 = perfect.

| Output | Horizon | AUROC | Inside-host | Precision | Recall | False alarms |
|---|---|---|---|---|---|---|
| v4 risk within 60 s | 60 s | 0.951 | 0.804 | 0.093 | 0.211 | 0.2% |
| v4 start-soon output | 5 min | 0.978 | 0.892 | 0.958 | 0.340 | 0.0% |
| v4 start-soon output | 10 min | 0.974 | 0.890 | 0.486 | 0.279 | 0.1% |
| XGBoost, 10 windows | 5 min | 0.972 | 0.874 | 0.847 | 0.342 | 0.0% |
| XGBoost, 10 windows | 10 min | 0.962 | 0.849 | 0.615 | 0.636 | 0.2% |

Inside-host score of the 5-minute output per dataset (attack starts, hosts):
Unraveled 0.95 (683, 3 hosts), CIC-IDS2017 0.97 (31, 2 hosts), CTU-13 0.50 (19, 3 hosts), DAPT2020 0.44 (68, 3 hosts),
CSE-CIC-IDS2018 0.29 (10, 1 host).

What this means: the timing ability comes from attacks that come back on the same host (Unraveled above all).
On three of the five datasets it is at chance level. The evidence rests on 12 hosts.

## The four labelled test files (`samples/test_files/`)

| File | Attack windows alerted (v3 -> v4) | False alarms on normal windows (v3 -> v4) | Stage correct on attack windows (v3 -> v4) |
|---|---|---|---|
| A, CIC-IDS2017 DDoS | 100% -> 100% | 1.15% -> 1.94% | no stage label (DDoS) |
| B, CSE-CIC-IDS2018 FTP brute force | 50% -> 81% | 0.00% -> 0.19% | 0% -> 93% |
| C, CTU-13 botnet | 38% -> 39% | 12.5% -> 11.2% | 32% -> 35% (averaged stage: 99.7% -> 96%) |
| D, Unraveled exfiltration | 89% -> 91% | 12.6% -> 14.7% | 80% -> 83% |

5-minute output on the test files: in file D, host 10.1.3.17 has five exfiltration bursts. The output was above its
warning level 30 seconds before the last one, not before the other four, and three times it went above the level with
no burst in the next 5 minutes. It was not above the level before any first attack (file B victim, file D 23:01).
At its tested threshold it is a high-precision, low-recall signal.

## What is not claimed

- No early warning before the first attack of a host.
- No tested result on a network the model was not trained on (the v3 hold-out runs still apply: weak).
- The "what usually follows" tree is counted from 17 stage changes on 12 hosts; it is not a model output.
