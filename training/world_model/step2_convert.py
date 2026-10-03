"""
STEP 2 - convert UNSW-NB15 and Unraveled into the same table as merged_final_v5.csv.

Run from PowerShell:   python D:\ml-data\processed\step2_convert.py
Optional quick test:   python D:\ml-data\processed\step2_convert.py --test

Output (next to this script):
    unsw_common.csv        <- UNSW-NB15, same columns as merged_final_v5.csv (+ extras)
    unraveled_common.csv   <- Unraveled,  same columns as merged_final_v5.csv (+ extras)
    step2_report.txt       <- counts per stage (copy this back to me)

merged_final_v5.csv is NOT copied: it is already in the common format.
Needs only pandas + numpy.  Memory use stays under ~1.5 GB.
"""
import sys, glob, os
from pathlib import Path
import numpy as np
import pandas as pd

TEST = "--test" in sys.argv
DATA = Path(__file__).resolve().parent.parent          # D:\ml-data
OUT = Path(__file__).resolve().parent                  # D:\ml-data\processed

# ---------------------------------------------------------------- the common columns
BASE = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "flow_start", "flow_end",
        "duration", "packet_count", "byte_count", "syn_count", "ack_count", "fin_count",
        "rst_count", "ttl_mean", "ttl_var", "win_mean", "win_var", "frag_ratio",
        "payload_mean", "payload_std", "retransmit_count", "label", "attack_stage"]
EXTRA = ["iat_mean", "iat_std", "bwd_fwd_ratio", "psh_count"]       # new, may be empty
COLS = BASE + EXTRA + ["dataset"]

# ---------------------------------------------------------------- stage mappings (EDIT HERE)
UNSW_STAGE = {
    "Normal": "normal",
    "Reconnaissance": "reconnaissance",
    "Exploits": "initial_access",
    "Shellcode": "initial_access",
    "Generic": "initial_access",
    "Backdoor": "command_control",       # 'Backdoors' is renamed to 'Backdoor' first
    "Worms": "lateral_movement",
    "DoS": "other",
    "Fuzzers": "other",
    "Analysis": "other",
}
# Unraveled: first by 'Stage', then (only for Reconnaissance) by 'Activity'
UNRAVELED_STAGE = {
    "Benign": "normal",
    "Normal": "normal",
    "Reconnaissance": "reconnaissance",       # password guessing is split off below
    "Establish Foothold": "command_control",
    "Lateral Movement": "lateral_movement",
    "Data Exfiltration": "exfiltration",
    "Cover up": "other",
}


def proto_name(s):
    s = s.astype(str).str.strip().str.lower()
    return np.where(s.isin(["tcp", "6"]), "TCP", np.where(s.isin(["udp", "17"]), "UDP", "OTHER"))


def num(s):
    return pd.to_numeric(s, errors="coerce")


def to_port(s):
    """UNSW ports are sometimes hex ('0x000b') or '-'."""
    out = num(s)
    bad = out.isna() & s.notna()
    if bad.any():
        def f(x):
            try:
                return int(str(x).strip(), 0)
            except Exception:
                return -1
        out[bad] = s[bad].map(f)
    return out.fillna(-1).astype("int64")


# ================================================================= UNSW-NB15
def convert_unsw():
    print("\n=== UNSW-NB15 ===")
    names = pd.read_csv(DATA / "NUSW-NB15_features.csv", encoding="latin-1")["Name"]
    names = [n.strip() for n in names]                      # fixes 'ct_src_ ltm'
    out_path = OUT / "unsw_common.csv"
    if out_path.exists():
        out_path.unlink()
    counts = {}
    first = True
    for i in range(1, 5):
        f = DATA / f"UNSW-NB15_{i}.csv"
        print("reading", f.name, flush=True)
        for ch in pd.read_csv(f, header=None, names=names, encoding="latin-1", dtype=str,
                              chunksize=200_000, nrows=50_000 if TEST else None,
                              low_memory=False):
            ch.columns = [c.strip() for c in ch.columns]
            ch["attack_cat"] = (ch["attack_cat"].fillna("Normal").str.strip()
                                .replace({"": "Normal", "Backdoors": "Backdoor"}))
            ch = ch[ch["attack_cat"].isin(UNSW_STAGE)]       # drops anything unexpected
            n = lambda c: num(ch[c])
            spk, dpk = n("Spkts"), n("Dpkts")
            tot = (spk + dpk).replace(0, np.nan)
            ttl = pd.concat([n("sttl"), n("dttl")], axis=1)
            win = pd.concat([n("swin"), n("dwin")], axis=1)
            o = pd.DataFrame({
                "src_ip": ch["srcip"].str.strip(),
                "dst_ip": ch["dstip"].str.strip(),
                "src_port": to_port(ch["sport"]),
                "dst_port": to_port(ch["dsport"]),
                "protocol": proto_name(ch["proto"]),
                "flow_start": n("Stime"),
                "flow_end": n("Ltime"),
                "duration": n("dur"),
                "packet_count": spk + dpk,
                "byte_count": n("sbytes") + n("dbytes"),
                "syn_count": np.nan, "ack_count": np.nan, "fin_count": np.nan, "rst_count": np.nan,
                "ttl_mean": ttl.mean(axis=1),
                "ttl_var": ttl.var(axis=1, ddof=0),
                "win_mean": win.mean(axis=1),
                "win_var": win.var(axis=1, ddof=0),
                "frag_ratio": np.nan,
                "payload_mean": (n("smeansz") * spk + n("dmeansz") * dpk) / tot,
                "payload_std": np.nan,
                "retransmit_count": n("sloss") + n("dloss"),
                "label": ch["attack_cat"],
                "attack_stage": ch["attack_cat"].map(UNSW_STAGE),
                "iat_mean": pd.concat([n("Sintpkt"), n("Dintpkt")], axis=1).mean(axis=1),
                "iat_std": pd.concat([n("Sjit"), n("Djit")], axis=1).mean(axis=1),
                "bwd_fwd_ratio": dpk / spk.replace(0, np.nan),
                "psh_count": np.nan,
                "dataset": "unsw",
            })
            o = o.dropna(subset=["flow_start", "duration", "packet_count"])
            o[COLS].to_csv(out_path, mode="a", header=first, index=False)
            first = False
            for k, v in o["attack_stage"].value_counts().items():
                counts[k] = counts.get(k, 0) + int(v)
    print("UNSW rows per stage:", counts)
    return counts


# ================================================================= Unraveled
UNR_USE = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol",
           "bidirectional_first_seen_ms", "bidirectional_last_seen_ms", "bidirectional_duration_ms",
           "bidirectional_packets", "bidirectional_bytes", "src2dst_packets", "dst2src_packets",
           "bidirectional_mean_ps", "bidirectional_stddev_ps",
           "bidirectional_mean_piat_ms", "bidirectional_stddev_piat_ms",
           "bidirectional_syn_packets", "bidirectional_ack_packets", "bidirectional_fin_packets",
           "bidirectional_rst_packets", "bidirectional_psh_packets",
           "Activity", "Stage"]


def convert_unraveled():
    print("\n=== Unraveled ===")
    files = sorted(glob.glob(str(DATA / "unraveled" / "data" / "network-flows" / "*" / "*.csv")))
    if TEST:
        files = files[:3]
    print(len(files), "files")
    out_path = OUT / "unraveled_common.csv"
    if out_path.exists():
        out_path.unlink()
    counts, dropped, first = {}, 0, True
    for k, f in enumerate(files, 1):
        try:
            d = pd.read_csv(f, usecols=UNR_USE, dtype=str, on_bad_lines="skip", low_memory=False)
        except Exception as e:
            print("  skipped", os.path.basename(f), e)
            continue
        n0 = len(d)
        d["Stage"] = d["Stage"].astype(str).str.strip()
        d = d[d["Stage"].isin(UNRAVELED_STAGE)]              # drops the ~1.5k junk rows
        n = lambda c: num(d[c])
        d = d.assign(_s=n("bidirectional_first_seen_ms"))
        d = d[d["_s"].notna()]
        dropped += n0 - len(d)
        act = d["Activity"].astype(str)
        stage = d["Stage"].map(UNRAVELED_STAGE)
        stage = stage.mask((d["Stage"] == "Reconnaissance") & act.str.startswith("Bruteforce"),
                           "initial_access")
        o = pd.DataFrame({
            "src_ip": d["src_ip"], "dst_ip": d["dst_ip"],
            "src_port": n("src_port"), "dst_port": n("dst_port"),
            "protocol": proto_name(d["protocol"]),
            "flow_start": n("bidirectional_first_seen_ms") / 1000.0,
            "flow_end": n("bidirectional_last_seen_ms") / 1000.0,
            "duration": n("bidirectional_duration_ms") / 1000.0,
            "packet_count": n("bidirectional_packets"),
            "byte_count": n("bidirectional_bytes"),
            "syn_count": n("bidirectional_syn_packets"),
            "ack_count": n("bidirectional_ack_packets"),
            "fin_count": n("bidirectional_fin_packets"),
            "rst_count": n("bidirectional_rst_packets"),
            "ttl_mean": np.nan, "ttl_var": np.nan, "win_mean": np.nan, "win_var": np.nan,
            "frag_ratio": np.nan,
            "payload_mean": n("bidirectional_mean_ps"),
            "payload_std": n("bidirectional_stddev_ps"),
            "retransmit_count": np.nan,
            "label": act, "attack_stage": stage,
            "iat_mean": n("bidirectional_mean_piat_ms"),
            "iat_std": n("bidirectional_stddev_piat_ms"),
            "bwd_fwd_ratio": n("dst2src_packets") / n("src2dst_packets").replace(0, np.nan),
            "psh_count": n("bidirectional_psh_packets"),
            "dataset": "unraveled",
        })
        o.to_csv(out_path, mode="a", header=first, index=False, columns=COLS)
        first = False
        for s, v in o["attack_stage"].value_counts().items():
            counts[s] = counts.get(s, 0) + int(v)
        if k % 20 == 0 or k == len(files):
            print(f"  {k}/{len(files)} files done", flush=True)
    print("Unraveled rows per stage:", counts, "| junk rows dropped:", dropped)
    return counts


if __name__ == "__main__":
    u = convert_unsw()
    r = convert_unraveled()
    stages = ["normal", "reconnaissance", "initial_access", "command_control",
              "lateral_movement", "exfiltration", "other"]
    lines = ["rows per stage" + (" (TEST RUN)" if TEST else ""),
             f"{'stage':18s}{'unsw':>12s}{'unraveled':>12s}"]
    for s in stages:
        lines.append(f"{s:18s}{u.get(s, 0):>12,}{r.get(s, 0):>12,}")
    rep = "\n".join(lines)
    print("\n" + rep)
    (OUT / ("step2_report_test.txt" if TEST else "step2_report.txt")).write_text(rep)
    print("\nDONE. Files are in", OUT)
