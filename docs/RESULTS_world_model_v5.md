# World model v5: results (3-4 October 2026)

v5 = v4 plus 15 "incoming traffic" features per host and window (what the host RECEIVED: flows, different
senders, different ports contacted, bare connection attempts, and the same added up over the last 60 s and 5 min),
and a larger share of attack starts in every training batch (22% instead of 15%). 88 features in total.
Same data, same hour-block split, 3 copies averaged. Training took 1 hour 6 minutes on a laptop CPU.

Raw metrics: `training/world_model/results/results_v5.json`. Logs: `training/world_model/results/logs_v5/`.
The v4 model is kept in `legacy/models/world_model_v4/`.

**Short version: v5 is a small step, not a breakthrough. It is better than v4 on detection, false alarms and the
number of attack starts warned on the held-back data, equal on validation data, and worse on test file B.**

## Held-back hours, v4 against v5 (average of 3 copies)

| Measure | v4 | v5 |
|---|---|---|
| Attack within 60 s, all windows: F1 | 0.931 | 0.945 |
| Same: false-alarm rate | 0.81% | 0.55% |
| Same: AUROC | 0.9975 | 0.9978 |
| Early warning (history all normal -> attack within 60 s): attack starts warned | 8 of 47 | 13 of 47 |
| Same: precision of those warnings | 13.8% | 9.2% |
| Same: AUROC | 0.931 | 0.923 |
| Same, per copy (3 random seeds): starts warned | 6, 13, 9 | 10, 12, 13 |
| Stage now, average of the copies: macro-F1 | 0.827 | 0.842 |
| Alert threshold (risk within 60 s) | 0.711 | 0.694 |

On the validation hours the two are level: F1 0.9726 / 0.9728, attack starts warned 8 / 9 of 26.
So part of the gain on the test hours is run-to-run noise.

Baselines on the same 88 features (test): logistic regression on 10 windows F1 0.833, 8 of 47 starts warned at
0.4% precision; XGBoost F1 0.969, 8 of 47 starts warned at 2.2% precision. XGBoost is still better at plain
detection. On attack starts warned the world model is now ahead (13 against 8).

## Stage, average of the copies (what the dashboard shows)

| Stage | v4 | v5 |
|---|---|---|
| Normal | 98.9% | 99.1% |
| Reconnaissance | 73.2% | 67.6% |
| Initial access | 83.6% | 88.7% |
| Command and control | 96.9% | 97.0% |
| Lateral movement | 96.1% | 96.5% |
| Exfiltration | 98.8% | 98.8% |

By dataset, the changes are not all in one direction:

| Stage, dataset (test windows) | v4 | v5 |
|---|---|---|
| Initial access, CSE-CIC-IDS2018 (78) | 93.6% | 46.2% |
| Initial access, UNSW-NB15 (2,489) | 83.3% | 90.2% |
| Reconnaissance, CIC-IDS2017 (36) | 36.1% | 77.8% |
| Reconnaissance, UNSW-NB15 (846) | 64.3% | 54.5% |
| Initial access, DAPT2020 (12) | 0% | 0% |

Note: the stage table in the v4 report (macro-F1 0.822) was measured on the single best copy, not on the average
of the three. The numbers above are on the average, for both versions.

## Timing inside one host (calm windows only; 0.5 = no timing ability)

| Output | Horizon | Inside-host AUROC | Precision | Recall |
|---|---|---|---|---|
| v5 risk within 60 s | 60 s | 0.822 | 0.152 | 0.178 |
| v5 start-soon output | 5 min | 0.891 | 0.918 | 0.343 |
| v5 start-soon output | 10 min | 0.887 | 0.653 | 0.269 |
| XGBoost, 10 windows | 5 min | 0.891 | 0.642 | 0.522 |
| XGBoost, 10 windows | 10 min | 0.859 | 0.710 | 0.563 |

5-minute output per dataset: Unraveled 0.95, CIC-IDS2017 0.97, DAPT2020 0.47, CTU-13 0.44, CSE-CIC-IDS2018 0.39.
Unchanged from v4 in substance: it works for attacks that return on the same host and is at chance level on three
of five datasets. The incoming-traffic features did not change this.

## The four labelled test files, both models on the same files

Files B and C were rebuilt as complete time slices (every host), because the incoming-traffic features need all
flows. B is 14:26-14:39 (273,229 flows, 7,053 hosts); C is 11:40-11:53 (130,384 flows, 23,631 hosts).
"Clean hosts" = hosts with no attack flow anywhere in the file.

| File | Measure | v4 | v5 |
|---|---|---|---|
| A, CIC-IDS2017 DDoS | attack windows alerted | 100% | 100% |
| | false alarms | 1.94% | 0.88% |
| B, CSE-CIC-IDS2018 FTP brute force | attack windows alerted | 81% | 50% |
| | false alarms | 0.15% | 0.78% |
| | stage correct on attack windows | 94% | 44% |
| | clean hosts flagged (of 7,051) | 27 | 138 |
| C, CTU-13 botnet | attack windows alerted | 39% | 37% |
| | false alarms on clean hosts | 10.2% | 8.2% |
| | stage correct on attack windows | 96% | 99.7% |
| | clean hosts flagged (of 23,425) | 1,114 | 986 |
| D, Unraveled exfiltration | attack windows alerted | 91% | 91% |
| | false alarms on clean hosts | 10.4% | 9.0% |
| | alerts in quiet windows of the two attacking hosts | 48% | 42% |
| | stage correct on attack windows | 83% | 85% |

File B is the regression: v5 still flags the attacker in every window but names its stage "command and control"
instead of "initial access", and it scores the victim's reply windows at about 0.5, just under the alert level
(v4: about 0.8). The window features of both hosts are identical to the training features, so this is the model,
not a loading error.

Early warning on these files, counting attack starts that follow 5 quiet minutes of the host (B 1, C 5, D 3):
the 60-second alert was already up in the minute before for 0 / 2 / 1 of them with v4 and 0 / 1 / 1 with v5.
The 5-minute output was above its warning level before none of them, with either model.
In files B and D no first attack of a host was warned; in file C two (v4) and one (v5) of five were.

## A packet capture from a network the model never saw (DARPA 2000 LLDOS 1.0, inside)

Scored against the phase lists shipped with the dataset (phases 1-4; phase 5 uses forged source addresses).
3,404 windows of 253 hosts before the DDoS.

| | v4 | v5 |
|---|---|---|
| Labelled attack windows alerted (IP sweep / probe / break-in / tool install) | 4 / 0 / 0 / 0 of 14 / 9 / 7 / 10 | 4 / 0 / 0 / 1 |
| False alarms on hosts outside the answer key | 6.5% | 4.2% |
| Those hosts with at least one alert (of 241) | 16 | 14 |
| Attacker 202.77.162.213: rank by peak risk | 11 | 19 |

Both versions are weak here. This confirms the earlier hold-out result: on an unseen network the model is not
reliable.

## v4 and v5 averaged together (tried, not used)

Averaging all six copies: test F1 0.940, false alarms 0.70%, 7 of 47 attack starts warned, initial access on
CSE-CIC-IDS2018 50%. It is between the two models on detection and worse than v5 on attack starts, so it is not
installed. Result file: `training/world_model/results/results_v4_v5_averaged.json`.

## What is not claimed

- No dependable early warning before the first attack of a host (0 of 2 in files B and D, 1 of 5 in file C).
- No reliable result on a network the model was not trained on.
- The 8 -> 13 gain in attack starts warned is within the spread between random seeds of v4.
- The "what usually follows" tree is counted from 17 stage changes on 12 hosts; it is not a model output.

## Going back to v4

Copy `world_model.pt`, `world_model_meta.json` and `baseline_lr.json` from `legacy/models/world_model_v4/` into
`models/world_model/` and restart the backend. No code change is needed: the backend reads the feature list from
the model's metadata.
