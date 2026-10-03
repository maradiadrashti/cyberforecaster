r"""
STEP 2b - convert CIC-IDS2017 (GeneratedLabelledFlows) to the same common table as step 2.

Run from PowerShell:   python D:\ml-data\processed\step2b_cic2017.py
Quick test:            python D:\ml-data\processed\step2b_cic2017.py --test

Output (next to this script):
    cic2017_common.csv     same columns as unsw_common.csv / unraveled_common.csv
    step2b_report.txt      flows per file and stage (paste it back to me)

Things you should know (they are limits of the dataset, not of this script):
  * Timestamps have MINUTE resolution (only Monday has seconds) and a 12-hour clock without AM/PM.
    Hours 1-7 are taken as afternoon (+12). Flows inside one minute are spread evenly over
    that minute in FILE ORDER, so the order of events inside a minute is not real.
    Early-warning timing for this dataset is therefore blurred at the 60-second level.
  * Dates are day/month/year.  Blank rows (all commas) are dropped.
  * Flag counts from CICFlowMeter are per-flow (mostly 0/1), not packet counts like Unraveled.
  * Almost all attacks come from one attacker IP (172.16.0.1 after NAT), so this dataset has
    very few attacker hosts.  Treat results on it with that in mind.
Needs only pandas + numpy.
"""
import sys, re, glob
from pathlib import Path
import numpy as np
import pandas as pd

TEST = "--test" in sys.argv
DATA = Path(__file__).resolve().parent.parent
OUT = Path(__file__).resolve().parent
SRC = DATA / "cic2017"

BASE = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "flow_start", "flow_end",
        "duration", "packet_count", "byte_count", "syn_count", "ack_count", "fin_count",
        "rst_count", "ttl_mean", "ttl_var", "win_mean", "win_var", "frag_ratio",
        "payload_mean", "payload_std", "retransmit_count", "label", "attack_stage"]
EXTRA = ["iat_mean", "iat_std", "bwd_fwd_ratio", "psh_count"]
COLS = BASE + EXTRA + ["dataset"]

# ---------------- stage mapping (EDIT HERE).  Keys are lower-case label prefixes.
STAGE_RULES = [
    ("benign", "normal"),
    ("portscan", "reconnaissance"),
    ("ftp-patator", "initial_access"),        # brute force (ATT&CK: Credential Access, grouped here)
    ("ssh-patator", "initial_access"),
    ("web attack", "initial_access"),         # brute force / XSS / SQL injection
    ("heartbleed", "initial_access"),         # 11 flows only
    ("bot", "command_control"),
    ("infiltration", "lateral_movement"),     # 36 flows only
    ("dos", "other"),                         # Hulk, GoldenEye, slowloris, Slowhttptest
    ("ddos", "other"),
]


def stage_of(label):
    l = label.lower()
    for k, v in STAGE_RULES:
        if l.startswith(k):
            return v
    return None


NEED = ["Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp",
        "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "SYN Flag Count", "ACK Flag Count", "FIN Flag Count", "RST Flag Count", "PSH Flag Count",
        "Packet Length Mean", "Packet Length Std", "Flow IAT Mean", "Flow IAT Std",
        "Init_Win_bytes_forward", "Init_Win_bytes_backward", "Label"]
TS = re.compile(r"^\s*(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*$")


def num(s):
    return pd.to_numeric(s, errors="coerce")


def read_file(path):
    with open(path, encoding="latin-1") as fh:
        names = [c.strip() for c in fh.readline().rstrip("\r\n").split(",")]
    seen = {}
    uniq = []
    for c in names:                                   # 'Fwd Header Length' appears twice
        seen[c] = seen.get(c, 0) + 1
        uniq.append(c if seen[c] == 1 else f"{c}.{seen[c] - 1}")
    d = pd.read_csv(path, header=None, skiprows=1, names=uniq, usecols=NEED, dtype=str,
                    encoding="latin-1", nrows=40_000 if TEST else None, low_memory=False)
    return d


def convert(path):
    d = read_file(path)
    n0 = len(d)
    d = d[d["Source IP"].notna() & d["Label"].notna()].reset_index(drop=True)
    d["Label"] = d["Label"].str.strip().str.replace(r"[^\x20-\x7e]", " ", regex=True)
    d["attack_stage"] = d["Label"].map(stage_of)
    bad = d["attack_stage"].isna()
    if bad.any():
        print("  unknown labels dropped:", d.loc[bad, "Label"].value_counts().to_dict())
    d = d[~bad].reset_index(drop=True)
    m = d["Timestamp"].str.extract(TS)
    ok = m[0].notna()
    d, m = d[ok].reset_index(drop=True), m[ok].reset_index(drop=True)
    day, mon, yr = num(m[0]), num(m[1]), num(m[2])
    hr, mi, sec = num(m[3]), num(m[4]), num(m[5])
    hr = hr.where(hr >= 8, hr + 12)                    # 12-hour clock without AM/PM: 1..7 -> 13..19
    base = pd.to_datetime(pd.DataFrame({"year": yr, "month": mon, "day": day, "hour": hr, "minute": mi}))
    t = (base - pd.Timestamp("1970-01-01")).dt.total_seconds()
    has_sec = sec.notna()
    key = t.astype("int64")                            # the minute
    rank = d.groupby(key).cumcount()
    size = d.groupby(key)["Label"].transform("size")
    t = t + np.where(has_sec, sec.fillna(0), (rank + 0.5) / size * 60.0)
    dur = num(d["Flow Duration"]) / 1e6
    fp, bp = num(d["Total Fwd Packets"]), num(d["Total Backward Packets"])
    iw = pd.concat([num(d["Init_Win_bytes_forward"]), num(d["Init_Win_bytes_backward"])], axis=1)
    iw = iw.where(iw >= 0)
    proto = num(d["Protocol"])
    o = pd.DataFrame({
        "src_ip": d["Source IP"].str.strip(), "dst_ip": d["Destination IP"].str.strip(),
        "src_port": num(d["Source Port"]), "dst_port": num(d["Destination Port"]),
        "protocol": np.where(proto == 6, "TCP", np.where(proto == 17, "UDP", "OTHER")),
        "flow_start": t, "flow_end": t + dur.fillna(0), "duration": dur,
        "packet_count": fp + bp,
        "byte_count": num(d["Total Length of Fwd Packets"]) + num(d["Total Length of Bwd Packets"]),
        "syn_count": num(d["SYN Flag Count"]), "ack_count": num(d["ACK Flag Count"]),
        "fin_count": num(d["FIN Flag Count"]), "rst_count": num(d["RST Flag Count"]),
        "ttl_mean": np.nan, "ttl_var": np.nan,
        "win_mean": iw.mean(axis=1), "win_var": iw.var(axis=1, ddof=0),
        "frag_ratio": np.nan,
        "payload_mean": num(d["Packet Length Mean"]), "payload_std": num(d["Packet Length Std"]),
        "retransmit_count": np.nan,
        "label": d["Label"], "attack_stage": d["attack_stage"],
        "iat_mean": num(d["Flow IAT Mean"]) / 1000.0, "iat_std": num(d["Flow IAT Std"]) / 1000.0,
        "bwd_fwd_ratio": bp / fp.replace(0, np.nan),
        "psh_count": num(d["PSH Flag Count"]),
        "dataset": "cic2017",
    })
    o = o.replace([np.inf, -np.inf], np.nan).dropna(subset=["flow_start", "duration", "packet_count"])
    print(f"  rows read {n0:,}  kept {len(o):,}  (blank / unparsable rows dropped: {n0 - len(o):,})")
    return o[COLS]


if __name__ == "__main__":
    files = sorted(glob.glob(str(SRC / "**" / "*.csv"), recursive=True))
    if TEST:
        files = files[:2]
    if not files:
        sys.exit(f"no CSV files found under {SRC}")
    out_path = OUT / "cic2017_common.csv"
    if out_path.exists():
        out_path.unlink()
    stages = ["normal", "reconnaissance", "initial_access", "command_control",
              "lateral_movement", "exfiltration", "other"]
    rows, first = [], True
    for f in files:
        name = Path(f).name.replace(".pcap_ISCX.csv", "")
        print("reading", name, flush=True)
        o = convert(f)
        o.to_csv(out_path, mode="a", header=first, index=False)
        first = False
        c = o["attack_stage"].value_counts()
        rows.append(pd.Series({s: int(c.get(s, 0)) for s in stages}, name=name))
        lo, hi = pd.to_datetime(o["flow_start"].min(), unit="s"), pd.to_datetime(o["flow_start"].max(), unit="s")
        print(f"  time range {lo} -> {hi}", flush=True)
    tab = pd.DataFrame(rows)
    tab.loc["TOTAL"] = tab.sum()
    rep = "flows per file and stage" + (" (TEST RUN)" if TEST else "") + "\n" + tab.to_string()
    print("\n" + rep)
    (OUT / ("step2b_report_test.txt" if TEST else "step2b_report.txt")).write_text(rep)
    print("\nDONE. File:", out_path)
