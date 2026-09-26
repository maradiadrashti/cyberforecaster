#!/usr/bin/env python3
"""
label_attacks.py -- Correct labeling for the CIC-IDS-2018 part of your merged
flow CSV, using BOTH the official attack time windows AND the official
attacker / victim IP addresses published by the dataset authors (UNB CIC,
https://www.unb.ca/cic/datasets/ids-2018.html, Table 2).

WHY THIS REPLACES THE OLD VERSION:
    The old script (kept as label_attacks_OLD_time_only.py) labeled a flow as
    an attack purely because it happened DURING an attack time window. But
    the CIC-2018 network carries lots of ordinary traffic at the same time
    (Windows updates, CDN traffic like Cloudflare 104.20.x / Fastly 151.101.x,
    DNS to 172.31.0.2, ...). All of that got labeled "attack", so ~7.5 million
    benign flows were mislabeled. A model trained on those labels cannot
    separate attack from normal and learns to output ~0.55 for everything.

    Now a CIC-2018 flow is labeled an attack ONLY if it is between the
    documented attacker machine(s) and the documented victim machine(s) on
    that attack's day. Everything else from those days is labeled Benign.

RULES:
    * Attacker <-> victim pair on the attack day -> attack. The attacker IPs
      are dedicated attack machines, so all their traffic with the victim on
      that day is attack traffic (this also catches bot C&C beacons that
      continue slightly outside the published window).
    * Infiltration: the attacker (13.58.225.34) never appears in the flow
      data -- what IS visible is the infected victim scanning/connecting to
      other INTERNAL hosts (172.31.64.0/18) during the attack window. Those
      internal flows are labeled lateral_movement (strict time window only).
    * Rows that are NOT from CIC-2018 days (e.g. CTU-13 botnet rows, or your
      own live captures) keep whatever label/attack_stage they already had.
    * Corrupted rows (attack_stage not one of the 6 stages) are dropped.

MITRE stage mapping is the same one your project already used.

USAGE (PowerShell):
    python label_attacks.py merged_final_v3.csv merged_final_v4.csv
Then retrain on merged_final_v4.csv.
"""

import sys
import time
import numpy as np
import pandas as pd

CAPTURE_UTC_OFFSET_HOURS = -4          # CIC-2018 schedule is in local (Atlantic) time
VALID_STAGES = {"normal", "reconnaissance", "initial_access",
                "lateral_movement", "command_control", "exfiltration"}
CIC_FIRST_DAY = pd.Timestamp("2018-02-14")
CIC_LAST_DAY = pd.Timestamp("2018-03-02")

DDOS_ATTACKERS = ["18.218.115.60", "18.219.9.1", "18.219.32.43", "18.218.55.126",
                  "52.14.136.135", "18.219.5.43", "18.216.200.189", "18.218.229.235",
                  "18.218.11.51", "18.216.24.42"]
BOT_VICTIMS = ["172.31.69.23", "18.217.218.111", "172.31.69.17", "18.222.10.237",
               "172.31.69.14", "18.222.86.193", "172.31.69.12", "18.222.62.221",
               "172.31.69.10", "13.59.9.106", "172.31.69.8", "18.222.102.2",
               "172.31.69.6", "18.219.212.0", "172.31.69.26", "18.216.105.13",
               "172.31.69.29", "18.219.163.126", "172.31.69.30", "18.216.164.12"]

# (day, attackers, victims, label, stage) -- attacker<->victim on that day
PAIR_RULES = [
    ("2018-02-14", ["18.221.219.4", "172.31.70.4"], ["172.31.69.25", "18.217.21.148"],
     "FTP-BruteForce", "initial_access"),
    ("2018-02-14", ["13.58.98.64", "172.31.70.6"], ["172.31.69.25", "18.217.21.148"],
     "SSH-Bruteforce", "initial_access"),
    ("2018-02-20", DDOS_ATTACKERS, ["172.31.69.25", "18.217.21.148"],
     "DDoS-LOIC", "command_control"),
    ("2018-02-21", DDOS_ATTACKERS, ["172.31.69.28", "18.218.83.150"],
     "DDoS-LOIC-HOIC", "command_control"),
    ("2018-02-28", ["13.58.225.34"], ["172.31.69.24", "18.221.148.137"],
     "Infiltration", "lateral_movement"),
    ("2018-03-01", ["13.58.225.34"], ["172.31.69.13", "18.216.254.154"],
     "Infiltration", "lateral_movement"),
    ("2018-03-02", ["18.219.211.138"], BOT_VICTIMS,
     "Bot", "command_control"),
]

# Infiltration internal activity: victim <-> other internal host, strict window
INTERNAL_RULES = [
    ("2018-02-28", "172.31.69.24", [("10:50", "12:05"), ("13:42", "14:40")]),
    ("2018-03-01", "172.31.69.13", [("09:57", "10:55"), ("14:00", "15:37")]),
]
INTERNAL_EXCLUDE = {"172.31.0.2"}      # AWS VPC DNS resolver, not an attack target


def is_internal_victim_net(ip: pd.Series) -> pd.Series:
    """True for 172.31.64.0/18 (172.31.64.x - 172.31.127.x), the victim LAN."""
    parts = ip.str.split(".", expand=True)
    if parts.shape[1] < 4:
        return pd.Series(False, index=ip.index)
    third = pd.to_numeric(parts[2], errors="coerce")
    return (parts[0] == "172") & (parts[1] == "31") & third.between(64, 127)


def label_chunk(df: pd.DataFrame) -> pd.DataFrame:
    if "label" not in df.columns:
        df["label"] = "Benign"
    if "attack_stage" not in df.columns:
        df["attack_stage"] = "normal"

    src = df["src_ip"].astype(str).str.strip()
    dst = df["dst_ip"].astype(str).str.strip()
    ts = pd.to_numeric(df["flow_start"], errors="coerce")
    local = pd.to_datetime(ts, unit="s", errors="coerce") + pd.Timedelta(hours=CAPTURE_UTC_OFFSET_HOURS)
    day = local.dt.normalize()
    minute_of_day = local.dt.hour * 60 + local.dt.minute

    is_cic = day.between(CIC_FIRST_DAY, CIC_LAST_DAY)

    # Every CIC-2018 row starts as Benign; only proven attacker<->victim flows become attacks
    df.loc[is_cic, "label"] = "Benign"
    df.loc[is_cic, "attack_stage"] = "normal"

    for d, attackers, victims, label, stage in PAIR_RULES:
        on_day = is_cic & (day == pd.Timestamp(d))
        if not on_day.any():
            continue
        a, v = set(attackers), set(victims)
        pair = (src.isin(a) & dst.isin(v)) | (src.isin(v) & dst.isin(a))
        m = on_day & pair
        df.loc[m, "label"] = label
        df.loc[m, "attack_stage"] = stage

    for d, victim, windows in INTERNAL_RULES:
        on_day = is_cic & (day == pd.Timestamp(d))
        if not on_day.any():
            continue
        in_win = pd.Series(False, index=df.index)
        for start, end in windows:
            sh, sm = map(int, start.split(":"))
            eh, em = map(int, end.split(":"))
            in_win |= minute_of_day.between(sh * 60 + sm, eh * 60 + em)
        other_src_internal = is_internal_victim_net(src) & ~src.isin(INTERNAL_EXCLUDE)
        other_dst_internal = is_internal_victim_net(dst) & ~dst.isin(INTERNAL_EXCLUDE)
        m = on_day & in_win & (
            ((src == victim) & other_dst_internal & (dst != victim)) |
            ((dst == victim) & other_src_internal & (src != victim))
        )
        df.loc[m, "label"] = "Infiltration"
        df.loc[m, "attack_stage"] = "lateral_movement"

    return df


def main(input_csv, output_csv, chunksize=1_000_000):
    t0 = time.time()
    print(f"[*] Relabeling {input_csv} -> {output_csv} (chunks of {chunksize:,} rows)")
    stage_counts, label_counts = {}, {}
    n_in = n_out = n_dropped = 0
    first = True
    reader = pd.read_csv(input_csv, chunksize=chunksize, dtype={"src_ip": str, "dst_ip": str},
                         low_memory=False, on_bad_lines="skip")
    for i, chunk in enumerate(reader, start=1):
        n_in += len(chunk)
        chunk = label_chunk(chunk)
        valid = chunk["attack_stage"].isin(VALID_STAGES)
        n_dropped += int((~valid).sum())
        chunk = chunk[valid]
        n_out += len(chunk)
        for k, v in chunk["attack_stage"].value_counts().items():
            stage_counts[k] = stage_counts.get(k, 0) + int(v)
        for k, v in chunk["label"].value_counts().items():
            label_counts[k] = label_counts.get(k, 0) + int(v)
        chunk.to_csv(output_csv, mode="w" if first else "a", header=first, index=False)
        first = False
        print(f"    ...chunk {i}: {n_in:,} rows read, {sum(v for k, v in stage_counts.items() if k != 'normal'):,} attack rows so far "
              f"({time.time() - t0:.0f}s)", flush=True)

    n_attack = sum(v for k, v in stage_counts.items() if k != "normal")
    print(f"\n[+] Done in {time.time() - t0:.0f}s. Rows in: {n_in:,}  written: {n_out:,}  "
          f"dropped (corrupt stage value): {n_dropped:,}")
    print(f"[+] Attack rows: {n_attack:,} ({100 * n_attack / max(n_out, 1):.2f}%)")
    print("[+] By attack_stage:")
    for k, v in sorted(stage_counts.items(), key=lambda x: -x[1]):
        print(f"      {k:<18} {v:,}")
    print("[+] By label:")
    for k, v in sorted(label_counts.items(), key=lambda x: -x[1]):
        print(f"      {k:<18} {v:,}")
    missing = [s for s in VALID_STAGES if stage_counts.get(s, 0) == 0]
    if missing:
        print(f"[!] No rows at all for stages: {sorted(missing)} -- the model cannot learn these.")
    print(f"[+] Wrote {output_csv}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python label_attacks.py <input_csv> <output_labeled_csv>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
