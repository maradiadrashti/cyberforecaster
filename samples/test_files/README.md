# Test files for the upload page

All four files are cut from hours that were held back from training (the test split). Labels are inside the files,
so the backend can score itself (`check_against_labels_in_file` in `logs/latest_forecast_v2.json`).
Every file is a complete time slice: all hosts, all flows. That matters because the model also uses what each
host receives.

| File | Source | What is in it | Host to open |
|---|---|---|---|
| `A_cic2017_friday_ddos_onset.csv` (18 MB) | CIC-IDS2017, Friday 7 July 2017, 15:40-16:00 (shown as 03:40-03:59, the file uses a 12-hour clock). Original CICFlowMeter format. | 18,476 normal flows, 23,865 DDoS flows, 511 hosts. Attack starts 03:56. | 172.16.0.1 (attacker) |
| `B_cic2018_ftp_bruteforce_onset.csv` (42 MB) | CSE-CIC-IDS2018, 14 Feb 2018, 14:26-14:39 UTC | 251,069 normal flows, 22,160 FTP brute-force flows, 7,053 hosts. Attack starts 14:33:26. | 18.221.219.4 (attacker), 172.31.69.25 (victim) |
| `C_ctu13_botnet_c2_forecast.csv` (19 MB) | CTU-13, 10 Aug 2011, 11:40-11:53 UTC | 129,413 normal flows, 971 command-and-control flows, 23,631 hosts | 147.32.84.165 (the infected machine) |
| `D_unraveled_exfiltration_forecast.csv` (3 MB) | Unraveled, 2 July 2021, 23:00-23:35 UTC | 15,817 flows, 62 hosts; command-and-control from 10.1.3.8, exfiltration bursts from 10.1.3.17 | 10.1.3.8 and 10.1.3.17 |

## What the model does on these files (world model v5, checked 4 Oct 2026)

"Clean hosts" have no attack flow anywhere in the file.

| File | Attack windows alerted | False alarms on clean hosts | Alerts in quiet windows of attacking hosts | Stage named correctly (averaged stage) | Hosts flagged |
|---|---|---|---|---|---|
| A | 100% (20 of 20) | 0.88% | - | no stage label for DDoS | 6 of 511 |
| B | 50% (34 of 68) | 0.78% | 0% (12 windows) | 44% | 139 of 7,053 |
| C | 37% (121 of 325) | 8.2% | 29% (121 windows) | 99.7% | 1,000 of 23,631 |
| D | 91% (59 of 65) | 9.0% | 42% (177 windows) | 85% | 25 of 62 |

- File A: the model has no DDoS stage, so the stage it shows for the attacker is not meaningful. The attacker has no traffic before the attack, so this file tests detection, not early warning.
- File B: the attacker is flagged in every window, but its stage is named "command and control" instead of "initial access". The victim's reply windows score about 0.5, just under the alert level, so they are missed. No warning before the attack. The previous model (v4) did better on this file: 81% alerted, 94% stage correct.
- File C: the infected machine is ranked second by peak risk; many clean hosts are flagged too.
- File D: all command-and-control windows of 10.1.3.8 are alerted; the exfiltration windows of 10.1.3.17 are not.

These numbers are written by the backend itself and were reproduced with separate code
(`training/world_model/checks/audit_model.py`). Both model versions on the same files:
[`docs/RESULTS_world_model_v5.md`](../../docs/RESULTS_world_model_v5.md).

Files B and C were rebuilt for v5 with `training/world_model/checks/make_test_files_v5.py` (earlier versions kept
only a quarter and a fifth of the normal hosts).
