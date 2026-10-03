# Test files for the upload page

All four files are cut from hours that were held back from training (the test split). Labels are inside the files,
so the backend can score itself (`check_against_labels_in_file` in `logs/latest_forecast_v2.json`).

| File | Source | What is in it | Attack starts |
|---|---|---|---|
| `A_cic2017_friday_ddos_onset.csv` | CIC-IDS2017, Friday 7 July 2017, 15:40-16:00 (shown as 03:40-03:59, the file uses a 12-hour clock) | 18,476 normal flows, 23,865 DDoS flows, 511 hosts | 03:56, from 172.16.0.1 to 192.168.10.50 |
| `B_cic2018_ftp_bruteforce_onset.csv` | CSE-CIC-IDS2018, 14 Feb 2018, 14:23-14:39 | 54,762 normal flows, 22,160 FTP brute-force flows, 1,968 hosts (attack hosts plus one quarter of the other hosts) | 14:33:20, 18.221.219.4 against 172.31.69.25 |

- File A is in the original CICFlowMeter format, so other tools that read CIC-IDS2017 can open it too.
- In file A the attacker has no traffic before the attack, so it tests detection, not early warning.
- In file B the victim 172.31.69.25 has 10 minutes of normal traffic before the attack: that host is the early-warning test.
- DDoS has no stage of its own in the model (it was trained as "attack", stage "other"), so file A has no stage score.

## Files C and D

| File | Source | What is in it | Host to open |
|---|---|---|---|
| `C_ctu13_botnet_c2_forecast.csv` | CTU-13, 10 Aug 2011, 11:40-11:53 (attack hosts plus one fifth of the other hosts) | 38,981 normal flows, 971 command-and-control flows, 4,806 hosts | 147.32.84.165 (the infected machine) |
| `D_unraveled_exfiltration_forecast.csv` | Unraveled, 2 July 2021, 23:00-23:35 | 15,817 flows, 62 hosts; command-and-control from 10.1.3.8, exfiltration bursts from 10.1.3.17 about every 10 minutes | 10.1.3.8 and 10.1.3.17 |

## What the model does on these files (world model v4, checked 3 Oct 2026)

| File | Attack windows alerted | False alarms on normal windows | Stage named correctly (averaged stage, attack windows) | Hosts flagged |
|---|---|---|---|---|
| A | 100% (20 of 20) | 1.94% | no stage label for DDoS | 7 of 511 |
| B | 81% (55 of 68) | 0.19% | 94% | 5 of 1,968 |
| C | 39% (127 of 325) | 11.2% | 96% | 236 of 4,806 |
| D | 91% (59 of 65) | 14.7% | 83% | 30 of 62 |

- File A: the model has no DDoS stage, so the stage it shows for the attacker is wrong.
- File B: the attacker is flagged from its first window. There is no warning before the attack.
- File C: the infected machine is ranked first, but many normal hosts are flagged too.
- File D, host 10.1.3.17 (five exfiltration bursts): the 5-minute "attack starts" output was above its warning level 30 seconds before the last burst. Before the other four it was not, and three times it went above the level with no burst in the next 5 minutes.

These numbers are written by the backend itself (`check_against_labels_in_file` in the result) and were reproduced
with separate code by `training/world_model/checks/audit_model.py`.
