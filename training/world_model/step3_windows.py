"""
STEP 3 - build the window table (73 features) from the 4 flow sources (merged, unraveled, unsw, cic2017).

Run from PowerShell:   python D:\ml-data\processed\step3_windows.py
Quick test:            python D:\ml-data\processed\step3_windows.py --test
Optional:              --merged PATH   (use another file instead of D:\ml-data\merged_final_v5.csv)

One output row = one source host (src_ip) in one 10-second window.
LABEL RULE (precise, per flow -> per window):
  * every flow keeps its OWN label; a flow is attack only if the dataset says so
  * a window is an attack window only if >= 1 attack flow AND >= 20% of the host's flows
    in that window are attack flows; its stage = the attack stage with the most flows
  * a window with a few attack flows among many benign ones is 'ambiguous' (stage_id = -1):
    it is NOT called normal and NOT called attack, and training ignores it.
Outputs (in D:\ml-data\processed):
    windows.pkl, feature_groups.json, mitre_map.json, step3_report.txt
"""
import sys, json
from pathlib import Path
import numpy as np
import pandas as pd

TEST = "--test" in sys.argv
DIR = Path(__file__).resolve().parent
DATA = DIR.parent
MERGED = DATA / "merged_final_v5.csv"
if "--merged" in sys.argv:
    MERGED = Path(sys.argv[sys.argv.index("--merged") + 1])
SOURCES = {"merged": MERGED,
           "unraveled": DIR / "unraveled_common.csv",
           "unsw": DIR / "unsw_common.csv",
           "cic2017": DIR / "cic2017_common.csv"}
# share of NORMAL-ONLY hosts kept (hosts that ever attack are always kept)
KEEP = {"merged": 0.15, "unraveled": 0.30, "unsw": 1.0, "cic2017": 0.30}
WIN = 10.0
ATTACK_MIN_FLOWS, ATTACK_MIN_SHARE = 1, 0.20
STAGES = ["normal", "reconnaissance", "initial_access", "command_control",
          "lateral_movement", "exfiltration", "other"]
CHUNK = 200_000 if TEST else 1_000_000
MAX_ROWS = 600_000 if TEST else None

GROUPS = {
    "volume": ["n_flows", "n_dst_ips", "n_dst_ports", "n_src_ports", "flows_per_dst_max",
               "top_dst_port_share", "dst_ip_entropy", "dst_port_entropy", "pkt_sum", "byte_sum",
               "pkt_mean", "pkt_std", "byte_mean", "byte_std", "bytes_per_pkt"],
    "timing": ["dur_mean", "dur_std", "dur_max", "dur_min", "short_flow_frac", "zero_dur_frac",
               "gap_mean", "gap_std", "iat_mean", "iat_std_mean", "flow_rate"],
    "flags": ["syn_sum", "ack_sum", "fin_sum", "rst_sum", "psh_sum", "syn_per_flow", "rst_per_flow",
              "fin_per_flow", "syn_only_frac", "half_open_frac", "syn_ack_ratio", "rst_frac",
              "fin_frac", "retrans_per_flow"],
    "ports": ["tcp_frac", "udp_frac", "other_proto_frac", "port_share_22", "port_share_21",
              "port_share_23", "port_share_53", "port_share_80", "port_share_443", "port_share_445",
              "port_share_3389", "port_share_db", "port_share_high", "port_share_wellknown",
              "ssh_flows", "ssh_syn_sum", "ssh_dst_ips", "port_diversity", "port_range",
              "dst_private_frac"],
    "packet": ["ttl_mean_mean", "ttl_mean_std", "ttl_var_mean", "win_mean_mean", "win_mean_std",
               "win_var_mean", "frag_mean", "payload_mean_mean", "payload_mean_std",
               "payload_std_mean", "bwd_fwd_mean", "bwd_fwd_std", "one_sided_frac"],
}
FEATS = [f for g in GROUPS.values() for f in g]

MITRE = {
    "reconnaissance": {"tactic_id": "TA0043", "tactic": "Reconnaissance",
        "techniques": [{"id": "T1595.001", "name": "Active Scanning: Scanning IP Blocks"},
                       {"id": "T1595.002", "name": "Active Scanning: Vulnerability Scanning"}]},
    "initial_access": {"tactic_id": "TA0001", "tactic": "Initial Access",
        "techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application"},
                       {"id": "T1110", "name": "Brute Force (ATT&CK files this under TA0006 Credential Access; our pipeline groups it with Initial Access)"}]},
    "command_control": {"tactic_id": "TA0011", "tactic": "Command and Control",
        "techniques": [{"id": "T1071", "name": "Application Layer Protocol"},
                       {"id": "T1573", "name": "Encrypted Channel"}]},
    "lateral_movement": {"tactic_id": "TA0008", "tactic": "Lateral Movement",
        "techniques": [{"id": "T1021", "name": "Remote Services"},
                       {"id": "T1570", "name": "Lateral Tool Transfer"}]},
    "exfiltration": {"tactic_id": "TA0010", "tactic": "Exfiltration",
        "techniques": [{"id": "T1041", "name": "Exfiltration Over C2 Channel"},
                       {"id": "T1030", "name": "Data Transfer Size Limits"}]},
}

PRIVATE = r"^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"


def sub_source(t0):
    """merged_final_v5 mixes 3 datasets; tell them apart by timestamp (see report to verify)."""
    t = np.asarray(t0, dtype="float64")
    return np.select([t < 1e8, t < 1.45e9, t < 1.55e9], ["rel", "ctu13", "cic2018"], "dapt2020")


def load_source(name, path):
    print(f"\n=== {name}: {path}", flush=True)
    hosts = None
    if KEEP[name] < 1.0:                                   # pass 1: which hosts ever attack
        hosts = set()
        for ch in pd.read_csv(path, usecols=["src_ip", "attack_stage"], chunksize=CHUNK, nrows=MAX_ROWS):
            hosts.update(ch.loc[ch["attack_stage"] != "normal", "src_ip"].unique())
        print(f"  attacker hosts found: {len(hosts):,}", flush=True)
    parts, seen = [], 0
    for ch in pd.read_csv(path, chunksize=CHUNK, nrows=MAX_ROWS, low_memory=False):
        seen += len(ch)
        ch["src_ip"] = ch["src_ip"].astype(str).str.replace("\u00ef\u00bb\u00bf", "", regex=False)
        if hosts is not None:
            h = pd.util.hash_pandas_object(ch["src_ip"], index=False).values % 1000
            ch = ch[ch["src_ip"].isin(hosts) | (h < KEEP[name] * 1000)]
        ch = ch[ch["attack_stage"].isin(STAGES)].dropna(subset=["flow_start"])
        for c in ["iat_mean", "iat_std", "bwd_fwd_ratio", "psh_count"]:
            if c not in ch.columns:
                ch[c] = np.nan
        parts.append(ch)
        print(f"  read {seen:,} rows", end="\r", flush=True)
    df = pd.concat(parts, ignore_index=True)
    print(f"\n  kept {len(df):,} flows")
    return df


def entropy_stats(df, key, col):
    c = df.groupby(key + [col], sort=False).size().rename("c").reset_index()
    c["clogc"] = c["c"] * np.log(c["c"])
    s = c.groupby(key, sort=False).agg(n=("c", "sum"), s=("clogc", "sum"), mx=("c", "max"))
    return np.log(s["n"]) - s["s"] / s["n"], s["mx"], s["n"]


def make_windows(df, name):
    key = ["host", "win"]
    f32 = "float32"
    df["host"], hostnames = pd.factorize(df["src_ip"])
    df["win"] = (df["flow_start"] // WIN).astype("int64")
    df = df.sort_values(key + ["flow_start"]).reset_index(drop=True)
    num = lambda c: pd.to_numeric(df[c], errors="coerce")
    syn, ack, fin, rst = num("syn_count"), num("ack_count"), num("fin_count"), num("rst_count")
    pk, by, dpt = num("packet_count"), num("byte_count"), num("dst_port")
    dur = num("duration").clip(lower=0)
    valid_f = syn.notna() & ack.notna()
    df["pk"], df["by"], df["dur"] = pk, by, dur
    df["syn"], df["ack"], df["fin"], df["rst"] = syn, ack, fin, rst
    df["psh"] = num("psh_count")
    df["retr"] = num("retransmit_count")
    df["ttlm"], df["ttlv"] = num("ttl_mean"), num("ttl_var")
    df["winm"], df["winv"] = num("win_mean"), num("win_var")
    df["frag"] = num("frag_ratio")
    df["plm"], df["pls"] = num("payload_mean"), num("payload_std")
    df["iat_m"], df["iat_s"] = num("iat_mean"), num("iat_std")
    df["bf"] = num("bwd_fwd_ratio")
    df["dip"], _ = pd.factorize(df["dst_ip"])
    df["dport"] = dpt.fillna(-1).astype("int32")
    df["sport"] = num("src_port").fillna(-1).astype("int32")
    df["gap"] = df.groupby(key, sort=False)["flow_start"].diff()
    df["short"] = (dur < 0.1).astype(f32)
    df["zero"] = (dur == 0).astype(f32)
    ind = lambda m, v=valid_f: m.astype(f32).where(v)
    df["syn_only"] = ind((syn > 0) & (ack == 0))
    df["half_open"] = ind((syn > 0) & (fin == 0) & (rst == 0) & (pk <= 3))
    df["rst_any"] = ind(rst > 0, rst.notna())
    df["fin_any"] = ind(fin > 0, fin.notna())
    df["one_sided"] = ind(df["bf"] == 0, df["bf"].notna())
    pr = df["protocol"].astype(str)
    df["tcp"], df["udp"] = (pr == "TCP").astype(f32), (pr == "UDP").astype(f32)
    df["oth"] = 1 - df["tcp"] - df["udp"]
    for p in [22, 21, 23, 53, 80, 443, 445, 3389]:
        df[f"p{p}"] = (dpt == p).astype(f32)
    df["pdb"] = dpt.isin([1433, 3306, 5432, 1521, 27017]).astype(f32)
    df["phigh"], df["pwk"] = (dpt >= 1024).astype(f32), (dpt.between(0, 1023)).astype(f32)
    df["ssh_syn"] = syn.where(dpt == 22, 0.0).where(valid_f)
    codes, uniq = pd.factorize(df["dst_ip"])
    df["dpriv"] = uniq.to_series().str.match(PRIVATE).astype(f32).values[codes]
    df["dpmin"] = df["dport"].where(df["dport"] >= 0)
    for s in STAGES:
        df["n_" + s] = (df["attack_stage"] == s).astype("int32")

    g = df.groupby(key, sort=False)
    A = g.agg(
        n_flows=("pk", "size"), n_dst_ips=("dip", "nunique"), n_dst_ports=("dport", "nunique"),
        n_src_ports=("sport", "nunique"),
        pkt_sum=("pk", "sum"), pkt_mean=("pk", "mean"), pkt_std=("pk", "std"),
        byte_sum=("by", "sum"), byte_mean=("by", "mean"), byte_std=("by", "std"),
        dur_mean=("dur", "mean"), dur_std=("dur", "std"), dur_max=("dur", "max"), dur_min=("dur", "min"),
        short_flow_frac=("short", "mean"), zero_dur_frac=("zero", "mean"),
        gap_mean=("gap", "mean"), gap_std=("gap", "std"),
        iat_mean=("iat_m", "mean"), iat_std_mean=("iat_s", "mean"),
        t_min=("flow_start", "min"), t_max=("flow_start", "max"),
        syn_sum=("syn", "sum"), ack_sum=("ack", "sum"), fin_sum=("fin", "sum"), rst_sum=("rst", "sum"),
        psh_sum=("psh", "sum"), psh_n=("psh", "count"), flag_n=("syn", "count"), retr_sum=("retr", "sum"),
        retr_n=("retr", "count"),
        syn_only_frac=("syn_only", "mean"), half_open_frac=("half_open", "mean"),
        rst_frac=("rst_any", "mean"), fin_frac=("fin_any", "mean"),
        tcp_frac=("tcp", "mean"), udp_frac=("udp", "mean"), other_proto_frac=("oth", "mean"),
        port_share_22=("p22", "mean"), port_share_21=("p21", "mean"), port_share_23=("p23", "mean"),
        port_share_53=("p53", "mean"), port_share_80=("p80", "mean"), port_share_443=("p443", "mean"),
        port_share_445=("p445", "mean"), port_share_3389=("p3389", "mean"), port_share_db=("pdb", "mean"),
        port_share_high=("phigh", "mean"), port_share_wellknown=("pwk", "mean"),
        ssh_flows=("p22", "sum"), ssh_syn_sum=("ssh_syn", "sum"),
        dp_min=("dpmin", "min"), dp_max=("dport", "max"), dst_private_frac=("dpriv", "mean"),
        ttl_mean_mean=("ttlm", "mean"), ttl_mean_std=("ttlm", "std"), ttl_var_mean=("ttlv", "mean"),
        win_mean_mean=("winm", "mean"), win_mean_std=("winm", "std"), win_var_mean=("winv", "mean"),
        frag_mean=("frag", "mean"), payload_mean_mean=("plm", "mean"), payload_mean_std=("plm", "std"),
        payload_std_mean=("pls", "mean"), bwd_fwd_mean=("bf", "mean"), bwd_fwd_std=("bf", "std"),
        one_sided_frac=("one_sided", "mean"),
        **{"n_" + s: ("n_" + s, "sum") for s in STAGES},
    )
    n = A["n_flows"]
    # flag-type sums are only meaningful where the source has flags (UNSW has none -> NaN)
    for c in ["syn_sum", "ack_sum", "fin_sum", "rst_sum", "ssh_syn_sum"]:
        A[c] = A[c].where(A["flag_n"] > 0)
    A["psh_sum"] = A["psh_sum"].where(A["psh_n"] > 0)
    A["retr_sum"] = A["retr_sum"].where(A["retr_n"] > 0)
    A["syn_per_flow"], A["rst_per_flow"] = A["syn_sum"] / n, A["rst_sum"] / n
    A["fin_per_flow"], A["retrans_per_flow"] = A["fin_sum"] / n, A["retr_sum"] / n
    A["syn_ack_ratio"] = A["syn_sum"] / (A["ack_sum"] + 1)
    A["bytes_per_pkt"] = A["byte_sum"] / A["pkt_sum"].replace(0, np.nan)
    A["flow_rate"] = n / (A["t_max"] - A["t_min"]).clip(lower=1.0)
    A["gap_mean"] = A["gap_mean"].fillna(WIN)                  # single-flow window
    A["port_diversity"] = A["n_dst_ports"] / n
    A["port_range"] = (A["dp_max"] - A["dp_min"]).clip(lower=0) / 65535.0
    for sd, mean in [("pkt_std", "pkt_mean"), ("byte_std", "byte_mean"), ("dur_std", "dur_mean"),
                     ("gap_std", "gap_mean"), ("ttl_mean_std", "ttl_mean_mean"),
                     ("win_mean_std", "win_mean_mean"), ("payload_mean_std", "payload_mean_mean"),
                     ("bwd_fwd_std", "bwd_fwd_mean")]:
        A[sd] = A[sd].where(~(A[sd].isna() & A[mean].notna()), 0.0)
    H, mx, _ = entropy_stats(df, key, "dip")
    A["dst_ip_entropy"], A["flows_per_dst_max"] = H, mx
    H, mx, nn = entropy_stats(df, key, "dport")
    A["dst_port_entropy"], A["top_dst_port_share"] = H, mx / nn
    ssh = df[df["dport"] == 22].groupby(key, sort=False)["dip"].nunique()
    A["ssh_dst_ips"] = ssh.reindex(A.index).fillna(0)

    # ---- labels
    cnt = A[["n_" + s for s in STAGES]]
    att_cols = ["n_" + s for s in STAGES[1:]]
    A["n_attack_flows"] = cnt[att_cols].sum(axis=1)
    A["attack_share"] = A["n_attack_flows"] / n
    best = cnt[att_cols].values.argmax(axis=1) + 1                 # index into STAGES
    is_att = (A["n_attack_flows"] >= ATTACK_MIN_FLOWS) & (A["attack_share"] >= ATTACK_MIN_SHARE)
    stage_id = np.where(is_att, best, np.where(A["n_attack_flows"] > 0, -1, 0))
    A["stage_id"] = stage_id.astype("int8")

    out = A[FEATS].replace([np.inf, -np.inf], np.nan).astype(f32)
    out.insert(0, "host_ip", np.asarray(hostnames)[A.index.get_level_values("host")])
    out.insert(1, "win", A.index.get_level_values("win").values)
    out.insert(2, "t0", out["win"].values * WIN)
    out["n_attack_flows"], out["attack_share"] = A["n_attack_flows"].values, A["attack_share"].values.astype(f32)
    out["stage_id"] = A["stage_id"].values
    out.insert(0, "source", name)
    out.insert(1, "sub", sub_source(out["t0"].values) if name == "merged" else name)
    return out.reset_index(drop=True)


def main():
    allw = []
    for name, path in SOURCES.items():
        if not path.exists():
            print(f"!! missing {path} - skipping {name}")
            continue
        w = make_windows(load_source(name, path), name)
        print(f"  windows: {len(w):,}")
        allw.append(w)
    W = pd.concat(allw, ignore_index=True)
    W.to_pickle(DIR / ("windows_test.pkl" if TEST else "windows.pkl"))
    (DIR / "feature_groups.json").write_text(json.dumps({"groups": GROUPS, "features": FEATS,
                                                          "stages": STAGES}, indent=1))
    (DIR / "mitre_map.json").write_text(json.dumps(MITRE, indent=1))
    names = {-1: "ambiguous", **{i: s for i, s in enumerate(STAGES)}}
    rep = [f"features: {len(FEATS)}  windows: {len(W):,}", "",
           "windows per sub-source and stage (ambiguous = few attack flows among many benign, ignored by training)"]
    tab = (W.assign(stage=W["stage_id"].map(names)).groupby(["sub", "stage"]).size().unstack(fill_value=0))
    rep.append(tab.to_string())
    rep += ["", "timestamp range per sub-source (check these look like the right years):"]
    for s, d in W.groupby("sub"):
        rep.append(f"  {s:10s} {pd.to_datetime(d['t0'].min(), unit='s', errors='coerce')} -> "
                   f"{pd.to_datetime(d['t0'].max(), unit='s', errors='coerce')}  hosts={d['host_ip'].nunique():,}")
    rep += ["", "share of attack windows where attack flows are < 100% of the host's flows (mixed windows):",
            f"  {((W.stage_id > 0) & (W.attack_share < 1)).sum():,} of {(W.stage_id > 0).sum():,}",
            "", "missing-value share per feature group, by source:"]
    for g, cols in GROUPS.items():
        rep.append(f"  {g:8s} " + "  ".join(f"{s}={W.loc[W.source == s, cols].isna().mean().mean():.0%}"
                                           for s in W.source.unique()))
    txt = "\n".join(rep)
    print("\n" + txt)
    (DIR / ("step3_report_test.txt" if TEST else "step3_report.txt")).write_text(txt)
    print("\nDONE")


if __name__ == "__main__":
    main()
