r"""
CyberForecaster world model - universal file loader + forecast (used by the dashboard for every upload).

    python world_model.py <file>            (a .pcap / .pcapng / .csv / .binetflow, also .gz / .bz2 / .zip)
    python world_model.py <file> --out DIR

What it does, in order:
  1. detects the file type from its CONTENT (not its name)
  2. turns it into the same flow table the model was trained on
  3. builds the same 73 features per source host per 10-second window (identical code to training)
  4. runs the trained world model (average of the trained copies) and writes the forecast:
        <name>_windows.csv   every host x window: risk in 10 / 30 / 60 s, alert, stage now, stage ahead
        <name>_hosts.csv     one row per host: peak risk, first alert, likely stage, MITRE tactic
        <name>_summary.json  everything above + notices (what was missing, what to trust less)

It never invents a result: if the file cannot be used it stops and says exactly why.
"""
import sys, os, io, re, json, gzip, bz2, zipfile, tempfile, argparse, shutil
from pathlib import Path
import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
MODEL_DIR = HERE.parent / "models" / "world_model"
WIN = 10.0
ATTACK_MIN_FLOWS, ATTACK_MIN_SHARE = 1, 0.20
MAXGAP = 12                       # a host timeline breaks after 12 empty windows (same as training)
STAGES = ["normal", "reconnaissance", "initial_access", "command_control",
          "lateral_movement", "exfiltration", "other"]
BASE = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "flow_start", "flow_end",
        "duration", "packet_count", "byte_count", "syn_count", "ack_count", "fin_count",
        "rst_count", "ttl_mean", "ttl_var", "win_mean", "win_var", "frag_ratio",
        "payload_mean", "payload_std", "retransmit_count", "label", "attack_stage"]
EXTRA = ["iat_mean", "iat_std", "bwd_fwd_ratio", "psh_count"]
COLS = BASE + EXTRA

# plain-language meaning of every model feature (all are per source host, per 10-second window)
FEATURE_DESC = {
    "n_flows": "Number of flows the host started", "n_dst_ips": "Number of different destination hosts contacted",
    "n_dst_ports": "Number of different destination ports contacted", "n_src_ports": "Number of different source ports used",
    "flows_per_dst_max": "Most flows sent to any single destination", "top_dst_port_share": "Share of flows going to the most-used destination port",
    "dst_ip_entropy": "How evenly flows are spread over destinations (high = many destinations)",
    "dst_port_entropy": "How evenly flows are spread over ports (high = many ports)",
    "pkt_sum": "Total packets", "byte_sum": "Total bytes", "pkt_mean": "Average packets per flow", "pkt_std": "Spread of packets per flow",
    "byte_mean": "Average bytes per flow", "byte_std": "Spread of bytes per flow", "bytes_per_pkt": "Average bytes per packet",
    "dur_mean": "Average flow duration (s)", "dur_std": "Spread of flow durations", "dur_max": "Longest flow duration (s)",
    "dur_min": "Shortest flow duration (s)", "short_flow_frac": "Share of flows shorter than 0.1 s", "zero_dur_frac": "Share of flows with zero duration",
    "gap_mean": "Average time between the host's flows (s)", "gap_std": "Spread of time between flows",
    "iat_mean": "Average time between packets inside a flow", "iat_std_mean": "Average variation of time between packets",
    "flow_rate": "Flows started per second",
    "syn_sum": "Total SYN flags", "ack_sum": "Total ACK flags", "fin_sum": "Total FIN flags", "rst_sum": "Total RST flags", "psh_sum": "Total PSH flags",
    "syn_per_flow": "SYN flags per flow", "rst_per_flow": "RST flags per flow", "fin_per_flow": "FIN flags per flow",
    "syn_only_frac": "Share of flows with SYN but no ACK (unanswered connection attempts)",
    "half_open_frac": "Share of half-open flows (SYN, no FIN / RST, at most 3 packets)",
    "syn_ack_ratio": "SYN flags relative to ACK flags", "rst_frac": "Share of flows with a reset", "fin_frac": "Share of flows closed with FIN",
    "retrans_per_flow": "Retransmissions per flow",
    "tcp_frac": "Share of TCP flows", "udp_frac": "Share of UDP flows", "other_proto_frac": "Share of flows that are neither TCP nor UDP",
    "port_share_22": "Share of flows to port 22 (SSH)", "port_share_21": "Share of flows to port 21 (FTP)",
    "port_share_23": "Share of flows to port 23 (Telnet)", "port_share_53": "Share of flows to port 53 (DNS)",
    "port_share_80": "Share of flows to port 80 (HTTP)", "port_share_443": "Share of flows to port 443 (HTTPS)",
    "port_share_445": "Share of flows to port 445 (SMB)", "port_share_3389": "Share of flows to port 3389 (RDP)",
    "port_share_db": "Share of flows to database ports", "port_share_high": "Share of flows to ports 1024 and above",
    "port_share_wellknown": "Share of flows to ports below 1024", "ssh_flows": "Number of SSH flows", "ssh_syn_sum": "SYN flags sent to SSH",
    "ssh_dst_ips": "Number of different hosts contacted on SSH", "port_diversity": "Different destination ports per flow",
    "port_range": "Width of the destination port range touched", "dst_private_frac": "Share of flows going to private (internal) addresses",
    "ttl_mean_mean": "Average packet TTL", "ttl_mean_std": "Spread of TTL between flows", "ttl_var_mean": "Average TTL variation inside flows",
    "win_mean_mean": "Average TCP window size", "win_mean_std": "Spread of TCP window size between flows",
    "win_var_mean": "Average TCP window variation inside flows", "frag_mean": "Share of fragmented packets",
    "payload_mean_mean": "Average payload size", "payload_mean_std": "Spread of payload size between flows",
    "payload_std_mean": "Average payload variation inside flows", "bwd_fwd_mean": "Reply packets per sent packet",
    "bwd_fwd_std": "Spread of the reply / sent ratio", "one_sided_frac": "Share of flows that got no reply",
}


class UnusableFile(Exception):
    """The file cannot be turned into per-host windows; the message says why."""


def sub_source(t0):                # only used by the training script for its merged file
    return "upload"


# ============================================================================================
# The block below is copied WITHOUT CHANGES from the training script (step3_windows.py), so an
# uploaded file gets exactly the features the model was trained on.
# ============================================================================================
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

PRIVATE = r"^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"


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


# ============================================================================================
# 1. file type detection
# ============================================================================================
PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}


def _unwrap(path, notices, tmpdir):
    """gunzip / bunzip / unzip to a temp file if needed; returns the path of the real content."""
    path = str(path)
    for _ in range(3):
        with open(path, "rb") as f:
            head = f.read(4)
        opener = gzip.open if head[:2] == b"\x1f\x8b" else bz2.open if head[:3] == b"BZh" else None
        if opener:
            out = os.path.join(tmpdir, "unwrapped_%d" % len(os.listdir(tmpdir)))
            with opener(path, "rb") as src, open(out, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            notices.append("compressed file was unpacked")
            path = out
            continue
        if head == b"PK\x03\x04":
            zf = zipfile.ZipFile(path)
            names = [n for n in zf.namelist() if not n.endswith("/") and zf.getinfo(n).file_size > 0]
            if not names:
                raise UnusableFile("the zip file is empty")
            big = max(names, key=lambda n: zf.getinfo(n).file_size)
            out = os.path.join(tmpdir, "unzipped_%d" % len(os.listdir(tmpdir)))
            with zf.open(big) as src, open(out, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            notices.append(f"zip file: used its largest member '{big}'" + (f" ({len(names) - 1} other file(s) ignored)" if len(names) > 1 else ""))
            path = out
            continue
        break
    return path


def detect(path):
    with open(path, "rb") as f:
        head = f.read(4)
        if head in PCAP_MAGIC:
            return "pcap", None
        f.seek(0)
        first = f.readline(200_000).decode("latin-1").replace("﻿", "").replace("ï»¿", "")
    cols = [c.strip().strip('"').lower() for c in first.rstrip("\r\n").split(",")]
    cs = set(cols)
    if {"src_ip", "dst_ip", "flow_start"} <= cs:
        return "common", cols
    if "bidirectional_first_seen_ms" in cs:
        return "nfstream", cols
    if {"starttime", "srcaddr", "dstaddr"} <= cs:
        return "binetflow", cols
    if "timestamp" in cs and ({"source ip", "destination ip"} <= cs or {"src ip", "dst ip"} <= cs):
        return "cicflowmeter", cols
    if "srcip" in cs and "dstip" in cs:
        return "unsw_header", cols
    if len(cols) == 49 and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", cols[0]):
        return "unsw", cols
    if "flow duration" in cs or "flow_duration" in cs or "tot fwd pkts" in cs:
        raise UnusableFile("this looks like a CICFlowMeter CSV WITHOUT IP addresses (no 'Source IP' / 'Src IP' column). "
                           "The model forecasts per host, so it needs source and destination IPs. "
                           "Use the version of the file that has the IP columns, or upload the PCAP.")
    raise UnusableFile("file type not recognised. Accepted: PCAP / PCAPNG, CyberForecaster flow CSV, CICFlowMeter CSV "
                       "(with IPs), UNSW-NB15 raw CSV, NFStream CSV, CTU-13 binetflow. "
                       f"First columns found: {cols[:12]}")


# ============================================================================================
# 2. converters -> the common flow table
# ============================================================================================
def num(s):
    return pd.to_numeric(s, errors="coerce")


def proto_name(s):
    s = s.astype(str).str.strip().str.lower()
    return np.where(s.isin(["tcp", "6", "6.0"]), "TCP", np.where(s.isin(["udp", "17", "17.0"]), "UDP", "OTHER"))


def _finish(o, notices):
    for c in COLS:
        if c not in o.columns:
            o[c] = np.nan
    o["flow_start"] = num(o["flow_start"])
    o["src_ip"] = o["src_ip"].astype(str).str.strip()
    o["dst_ip"] = o["dst_ip"].astype(str).str.strip()
    n0 = len(o)
    o = o[o["flow_start"].notna() & ~o["src_ip"].isin(["", "nan", "None"])].copy()
    if len(o) < n0:
        notices.append(f"{n0 - len(o):,} rows without a usable time or source IP were dropped")
    if len(o) == 0:
        raise UnusableFile("no usable flow rows: every row is missing its start time (or source IP). The model works on "
                           "the ORDER of events in time, so it needs a time for each flow.")
    return o.replace([np.inf, -np.inf], np.nan)[COLS].reset_index(drop=True)


def _labels(o, stage_fn, notices):
    """stage_fn: label text -> stage name or None.  Sets has-labels flag through the notices."""
    lab = o["label"].astype(str).str.strip()
    known = lab.notna() & ~lab.isin(["", "nan", "None"])
    if known.mean() < 0.5:
        o["attack_stage"] = np.nan
        return o
    st = lab.map(stage_fn)
    unknown = sorted(set(lab[st.isna() & known]))[:8]
    if unknown:
        notices.append(f"labels not in our stage map were counted as 'other': {unknown}")
    o["attack_stage"] = st.fillna("other").where(known)
    return o


CIC_RULES = [("benign", "normal"), ("normal", "normal"), ("portscan", "reconnaissance"), ("ftp-patator", "initial_access"),
             ("ssh-patator", "initial_access"), ("ftp-bruteforce", "initial_access"), ("ssh-bruteforce", "initial_access"),
             ("web attack", "initial_access"), ("brute force", "initial_access"), ("sql injection", "initial_access"),
             ("heartbleed", "initial_access"), ("bot", "command_control"), ("infilt", "lateral_movement"),
             ("ddos", "other"), ("dos", "other")]


def cic_stage(label):
    l = str(label).lower()
    for k, v in CIC_RULES:
        if l.startswith(k):
            return v
    return None


TS = re.compile(r"^\s*(\d{1,4})[/-](\d{1,2})[/-](\d{1,4})[ T]+(\d{1,2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?\s*([AaPp][Mm])?\s*$")


def parse_time(s, notices):
    """text timestamps -> epoch seconds. Handles d/m/Y and Y-m-d, 12-hour clocks, minute-only resolution."""
    s = s.astype(str)
    m = s.str.extract(TS)
    ok = m[0].notna()
    if ok.mean() < 0.9:
        t = pd.to_datetime(s, errors="coerce")
        return (t - pd.Timestamp("1970-01-01")).dt.total_seconds()
    a, b, c = num(m[0]), num(m[1]), num(m[2])
    hr, mi, sec = num(m[3]), num(m[4]), num(m[5])
    if a.max() > 31:                                  # Y-m-d
        yr, mon, day = a, b, c
    else:                                             # d/m/Y (CIC) unless the middle number cannot be a month
        day, mon, yr = (b, a, c) if b.max() > 12 else (a, b, c)
    ap = m[6].str.lower()
    if ap.notna().any():
        hr = hr.where(~((ap == "pm") & (hr < 12)), hr + 12).where(~((ap == "am") & (hr == 12)), 0)
    elif hr.max() <= 12 and hr.min() < 8 and (hr >= 8).any():
        hr = hr.where(hr >= 8, hr + 12)
        notices.append("timestamps use a 12-hour clock without AM/PM: hours 1-7 were taken as afternoon")
    t = pd.to_datetime(pd.DataFrame({"year": yr, "month": mon, "day": day, "hour": hr, "minute": mi}), errors="coerce")
    t = (t - pd.Timestamp("1970-01-01")).dt.total_seconds()
    if sec.notna().mean() < 0.5:
        key = t.fillna(-1).astype("int64")
        rank = s.groupby(key).cumcount()
        size = s.groupby(key).transform("size")
        t = t + (rank + 0.5) / size * 60.0
        notices.append("timestamps have MINUTE resolution: flows were spread evenly inside each minute, "
                       "so timing inside a minute is not real and early-warning timing is blurred to about 60 s")
    else:
        t = t + sec.fillna(0)
    return t


def from_common(path, cols, notices):
    d = pd.read_csv(path, low_memory=False, encoding="latin-1")
    d.columns = [c.strip().lower() for c in d.columns]
    d["protocol"] = proto_name(d["protocol"]) if "protocol" in d else "OTHER"
    if "attack_stage" in d and d["attack_stage"].notna().any() and d["attack_stage"].astype(str).str.strip().ne("").any():
        st = d["attack_stage"].astype(str).str.strip().str.lower()
        d["attack_stage"] = st.where(st.isin(STAGES))
    else:
        d["attack_stage"] = np.nan
    if "iat_mean" not in d:
        notices.append("no IAT / back-forward ratio / PSH columns in this file: those features are left empty "
                       "(the model was trained with them empty for this kind of data)")
    return _finish(d, notices)


CIC_ALIAS = {
    "src_ip": ["source ip", "src ip"], "dst_ip": ["destination ip", "dst ip"],
    "src_port": ["source port", "src port"], "dst_port": ["destination port", "dst port"],
    "protocol": ["protocol"], "ts": ["timestamp"], "dur": ["flow duration"],
    "fp": ["total fwd packets", "tot fwd pkts", "total fwd packet"],
    "bp": ["total backward packets", "tot bwd pkts", "total bwd packets"],
    "fb": ["total length of fwd packets", "totlen fwd pkts", "total length of fwd packet"],
    "bb": ["total length of bwd packets", "totlen bwd pkts", "total length of bwd packet"],
    "syn": ["syn flag count", "syn flag cnt"], "ack": ["ack flag count", "ack flag cnt"],
    "fin": ["fin flag count", "fin flag cnt"], "rst": ["rst flag count", "rst flag cnt"],
    "psh": ["psh flag count", "psh flag cnt"],
    "plm": ["packet length mean", "pkt len mean"], "pls": ["packet length std", "pkt len std"],
    "iatm": ["flow iat mean"], "iats": ["flow iat std"],
    "iwf": ["init_win_bytes_forward", "init fwd win byts", "fwd init win bytes"],
    "iwb": ["init_win_bytes_backward", "init bwd win byts", "bwd init win bytes"],
    "label": ["label"],
}


def from_cicflowmeter(path, cols, notices):
    seen, uniq = {}, []
    for c in cols:                                    # 'Fwd Header Length' appears twice in CIC-IDS2017
        seen[c] = seen.get(c, 0) + 1
        uniq.append(c if seen[c] == 1 else f"{c}.{seen[c] - 1}")
    pick = {k: next((a for a in al if a in seen), None) for k, al in CIC_ALIAS.items()}
    missing = [k for k in ["src_ip", "dst_ip", "ts", "dur", "fp"] if pick[k] is None]
    if missing:
        raise UnusableFile(f"CICFlowMeter CSV is missing required columns: {missing}")
    d = pd.read_csv(path, header=None, skiprows=1, names=uniq, usecols=[v for v in pick.values() if v],
                    dtype=str, encoding="latin-1", low_memory=False)
    g = lambda k: d[pick[k]] if pick[k] else pd.Series(np.nan, index=d.index)
    d = d[g("src_ip").notna()].reset_index(drop=True)
    g = lambda k: d[pick[k]] if pick[k] else pd.Series(np.nan, index=d.index)
    t = parse_time(g("ts"), notices)
    dur = num(g("dur")) / 1e6
    fp, bp = num(g("fp")), num(g("bp"))
    iw = pd.concat([num(g("iwf")), num(g("iwb"))], axis=1)
    iw = iw.where(iw >= 0)
    o = pd.DataFrame({
        "src_ip": g("src_ip"), "dst_ip": g("dst_ip"), "src_port": num(g("src_port")), "dst_port": num(g("dst_port")),
        "protocol": proto_name(g("protocol")), "flow_start": t, "flow_end": t + dur.fillna(0), "duration": dur,
        "packet_count": fp + bp.fillna(0), "byte_count": num(g("fb")) + num(g("bb")).fillna(0),
        "syn_count": num(g("syn")), "ack_count": num(g("ack")), "fin_count": num(g("fin")), "rst_count": num(g("rst")),
        "win_mean": iw.mean(axis=1), "win_var": iw.var(axis=1, ddof=0),
        "payload_mean": num(g("plm")), "payload_std": num(g("pls")),
        "iat_mean": num(g("iatm")) / 1000.0, "iat_std": num(g("iats")) / 1000.0,
        "bwd_fwd_ratio": bp / fp.replace(0, np.nan), "psh_count": num(g("psh")),
        "label": g("label").astype(str).str.replace(r"[^\x20-\x7e]", " ", regex=True),
    })
    o = _labels(o, cic_stage, notices) if pick["label"] else o
    notices.append("CICFlowMeter gives no TTL / fragment / retransmission values: those packet features are empty")
    return _finish(o, notices)


UNSW_NAMES = ['srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss',
              'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb', 'smeansz',
              'dmeansz', 'trans_depth', 'res_bdy_len', 'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 'tcprtt',
              'synack', 'ackdat', 'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd',
              'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm',
              'ct_dst_src_ltm', 'attack_cat', 'Label']
UNSW_STAGE = {"normal": "normal", "reconnaissance": "reconnaissance", "exploits": "initial_access",
              "shellcode": "initial_access", "generic": "initial_access", "backdoor": "command_control",
              "backdoors": "command_control", "worms": "lateral_movement", "dos": "other", "fuzzers": "other",
              "analysis": "other"}


def _port(s):
    out = num(s)
    bad = out.isna() & s.notna()
    if bad.any():
        def f(x):
            try:
                return int(str(x).strip(), 0)
            except Exception:
                return -1
        out[bad] = s[bad].map(f)
    return out.fillna(-1)


def from_unsw(path, cols, notices, header=False):
    if header:
        d = pd.read_csv(path, dtype=str, encoding="latin-1", low_memory=False)
        d.columns = [c.strip() for c in d.columns]
        low = {c.lower().replace(" ", ""): c for c in d.columns}
        d = d.rename(columns={low[n.lower()]: n for n in UNSW_NAMES if n.lower() in low})
    else:
        d = pd.read_csv(path, header=None, names=UNSW_NAMES, dtype=str, encoding="latin-1", low_memory=False)
    need = [c for c in ["srcip", "dstip", "Stime", "dur", "Spkts", "Dpkts"] if c not in d.columns]
    if need:
        raise UnusableFile(f"UNSW-NB15 file is missing columns {need}. The 'training-set' CSVs have no IPs / times; "
                           "use the raw UNSW-NB15_1..4.csv files.")
    n = lambda c: num(d[c]) if c in d.columns else pd.Series(np.nan, index=d.index)
    spk, dpk = n("Spkts"), n("Dpkts")
    tot = (spk + dpk).replace(0, np.nan)
    ttl = pd.concat([n("sttl"), n("dttl")], axis=1)
    win = pd.concat([n("swin"), n("dwin")], axis=1)
    cat = d["attack_cat"].fillna("Normal").str.strip().replace({"": "Normal"}) if "attack_cat" in d.columns else None
    o = pd.DataFrame({
        "src_ip": d["srcip"].str.replace("ï»¿", "", regex=False), "dst_ip": d["dstip"],
        "src_port": _port(d["sport"]), "dst_port": _port(d["dsport"]), "protocol": proto_name(d["proto"]),
        "flow_start": n("Stime"), "flow_end": n("Ltime"), "duration": n("dur"),
        "packet_count": spk + dpk, "byte_count": n("sbytes") + n("dbytes"),
        "ttl_mean": ttl.mean(axis=1), "ttl_var": ttl.var(axis=1, ddof=0),
        "win_mean": win.mean(axis=1), "win_var": win.var(axis=1, ddof=0),
        "payload_mean": (n("smeansz") * spk + n("dmeansz") * dpk) / tot,
        "retransmit_count": n("sloss") + n("dloss"),
        "iat_mean": pd.concat([n("Sintpkt"), n("Dintpkt")], axis=1).mean(axis=1),
        "iat_std": pd.concat([n("Sjit"), n("Djit")], axis=1).mean(axis=1),
        "bwd_fwd_ratio": dpk / spk.replace(0, np.nan),
        "label": cat if cat is not None else np.nan,
    })
    if cat is not None:
        o = _labels(o, lambda l: UNSW_STAGE.get(str(l).lower()), notices)
    notices.append("UNSW-NB15 records have no TCP flag counts: the 'flags' features are empty")
    return _finish(o, notices)


NFS_STAGE = {"benign": "normal", "normal": "normal", "reconnaissance": "reconnaissance",
             "establish foothold": "command_control", "lateral movement": "lateral_movement",
             "data exfiltration": "exfiltration", "cover up": "other"}


def from_nfstream(path, cols, notices):
    d = pd.read_csv(path, dtype=str, on_bad_lines="skip", low_memory=False, encoding="latin-1")
    d.columns = [c.strip() for c in d.columns]
    n = lambda c: num(d[c]) if c in d.columns else pd.Series(np.nan, index=d.index)
    o = pd.DataFrame({
        "src_ip": d["src_ip"], "dst_ip": d["dst_ip"], "src_port": n("src_port"), "dst_port": n("dst_port"),
        "protocol": proto_name(d["protocol"]),
        "flow_start": n("bidirectional_first_seen_ms") / 1000.0, "flow_end": n("bidirectional_last_seen_ms") / 1000.0,
        "duration": n("bidirectional_duration_ms") / 1000.0,
        "packet_count": n("bidirectional_packets"), "byte_count": n("bidirectional_bytes"),
        "syn_count": n("bidirectional_syn_packets"), "ack_count": n("bidirectional_ack_packets"),
        "fin_count": n("bidirectional_fin_packets"), "rst_count": n("bidirectional_rst_packets"),
        "payload_mean": n("bidirectional_mean_ps"), "payload_std": n("bidirectional_stddev_ps"),
        "iat_mean": n("bidirectional_mean_piat_ms"), "iat_std": n("bidirectional_stddev_piat_ms"),
        "bwd_fwd_ratio": n("dst2src_packets") / n("src2dst_packets").replace(0, np.nan),
        "psh_count": n("bidirectional_psh_packets"),
    })
    if "Stage" in d.columns:
        act = d["Activity"].astype(str) if "Activity" in d.columns else pd.Series("", index=d.index)
        o["label"] = d["Stage"].astype(str).str.strip()
        o = _labels(o, lambda l: NFS_STAGE.get(str(l).lower()), notices)
        brute = (o["label"] == "Reconnaissance") & act.str.startswith("Bruteforce")
        o["attack_stage"] = o["attack_stage"].mask(brute, "initial_access")
    notices.append("NFStream records have no TTL / TCP-window / fragment / retransmission values: those packet features are empty")
    return _finish(o, notices)


def binetflow_stage(label):
    l = str(label).lower()
    if "botnet" in l:
        return "command_control"
    if "normal" in l or "background" in l:
        return "normal"
    return None


def from_binetflow(path, cols, notices):
    d = pd.read_csv(path, dtype=str, low_memory=False, encoding="latin-1")
    d.columns = [c.strip().lower() for c in d.columns]
    n = lambda c: num(d[c]) if c in d.columns else pd.Series(np.nan, index=d.index)
    t = pd.to_datetime(d["starttime"], errors="coerce")
    t = (t - pd.Timestamp("1970-01-01")).dt.total_seconds()
    st = d["state"].astype(str) if "state" in d.columns else pd.Series("", index=d.index)
    tcp = d["proto"].astype(str).str.lower().eq("tcp")
    flag = lambda ch: st.str.contains(ch, regex=False).astype(float).where(tcp)
    src_b, tot_b = n("srcbytes"), n("totbytes")
    o = pd.DataFrame({
        "src_ip": d["srcaddr"], "dst_ip": d["dstaddr"], "src_port": _port(d["sport"]), "dst_port": _port(d["dport"]),
        "protocol": proto_name(d["proto"]), "flow_start": t, "flow_end": t + n("dur").fillna(0), "duration": n("dur"),
        "packet_count": n("totpkts"), "byte_count": tot_b,
        "syn_count": flag("S"), "ack_count": flag("A"), "fin_count": flag("F"), "rst_count": flag("R"),
        "psh_count": flag("P"),
        "bwd_fwd_ratio": (tot_b - src_b) / src_b.replace(0, np.nan),
        "label": d["label"] if "label" in d.columns else np.nan,
    })
    if "label" in d.columns:
        o = _labels(o, binetflow_stage, notices)
        notices.append("CTU-13 'Background' flows are unlabelled traffic and are treated as normal")
    notices.append("binetflow (Argus) support is APPROXIMATE: TCP flags come from the flow 'State' text (present / not "
                   "present, not packet counts), the back/forward ratio is in bytes, and there are no TTL / window / "
                   "payload / IAT values. The model was NOT trained on files in this format, so trust this result less.")
    return _finish(o, notices)


def from_pcap(path, notices, flows_csv=None):
    """`flows_csv`: flow table already produced from this capture by the same extractor (the upload endpoint
    extracts once and shares it), so the packets are not read a second time."""
    if flows_csv and os.path.exists(flows_csv) and os.path.getsize(flows_csv) > 0:
        d = pd.read_csv(flows_csv, low_memory=False)
    else:
        try:
            sys.path.insert(0, str(HERE))
            from extractor import extract_packet_features_v2 as ext
        except (SystemExit, ImportError) as e:
            raise UnusableFile(f"PCAP support needs the 'dpkt' package and the extractor folder (pip install dpkt). Detail: {e!r}")
        out = path + ".flows.csv"
        try:
            ext.extract(path, out)
            d = pd.read_csv(out, low_memory=False)
        finally:
            if os.path.exists(out):
                os.remove(out)
    if len(d) == 0:
        raise UnusableFile("no IP packets were found in the capture")
    # The model's PCAP-derived training data (CIC-IDS2018 / CTU-13 / DAPT2020 captures) was made by this same
    # extractor WITHOUT these three columns, so they are left empty here too - same input as in training.
    for c in ["iat_mean", "iat_std", "bwd_fwd_ratio"]:
        d[c] = np.nan
    d["psh_count"] = np.nan
    d["label"], d["attack_stage"] = np.nan, np.nan
    d["protocol"] = proto_name(d["protocol"])
    notices.append("PCAP: flows were rebuilt from packets with the same extractor used for the PCAP-based training data "
                   "(one record per direction of each connection)")
    return _finish(d, notices)


def load_flows(path, pcap_flows_csv=None):
    """any supported file -> (common flow table, format name, notices)"""
    notices = []
    tmpdir = tempfile.mkdtemp(prefix="cf_v2_")
    try:
        real = _unwrap(path, notices, tmpdir)
        kind, cols = detect(real)
        if kind == "pcap":
            flows = from_pcap(real, notices, pcap_flows_csv)
        elif kind == "common":
            flows = from_common(real, cols, notices)
        elif kind == "cicflowmeter":
            flows = from_cicflowmeter(real, cols, notices)
        elif kind == "nfstream":
            flows = from_nfstream(real, cols, notices)
        elif kind == "binetflow":
            flows = from_binetflow(real, cols, notices)
        else:
            flows = from_unsw(real, cols, notices, header=(kind == "unsw_header"))
        return flows, kind.replace("unsw_header", "unsw"), notices
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ============================================================================================
# 3. windows + model
# ============================================================================================
def build_windows(flows):
    f = flows.copy()
    has_labels = bool(f["attack_stage"].notna().mean() > 0.5)
    f["attack_stage"] = f["attack_stage"].where(f["attack_stage"].isin(STAGES), "normal") if has_labels else "normal"
    W = make_windows(f, "upload")
    return W.sort_values(["host_ip", "win"]).reset_index(drop=True), has_labels


_MODEL = None


def load_model():
    global _MODEL
    if _MODEL is not None:
        return _MODEL
    import torch, torch.nn as nn
    meta = json.loads((MODEL_DIR / "world_model_meta.json").read_text())
    ck = torch.load(MODEL_DIR / "world_model.pt", map_location="cpu")
    nf, K, C, H = len(meta["features"]), meta["K"], len(meta["classes"]), meta.get("hidden", 128)
    SOON = meta.get("soon_horizons") or []            # v4 models: "an attack starts within N seconds" outputs

    class WM(nn.Module):                               # must stay identical to the class in step4_train.py
        def __init__(s):
            super().__init__()
            s.lstm = nn.LSTM(nf, H, meta.get("layers", 2), batch_first=True, dropout=0.3)
            s.mu, s.ls = nn.Linear(H, nf), nn.Linear(H, nf)
            s.stage = nn.Linear(H, (K + 1) * C)
            s.within = nn.Linear(H, K)
            if SOON:
                s.soon = nn.Linear(H, len(SOON))

        def forward(s, x):
            h = s.lstm(x)[0][:, -1]
            out = (s.stage(h).view(-1, K + 1, C), s.within(h))
            return out + ((s.soon(h),) if SOON else ())

    models = []
    for st in ck["states"]:
        m = WM()
        m.load_state_dict(st)                          # strict: fails loudly if the file does not match
        m.eval()
        models.append(m)
    _MODEL = (meta, models)
    return _MODEL


_TREES = None


def _timing_trees(meta):
    """Optional gradient-boosted timing models saved next to the world model (timing_xgb_<seconds>.json).
    Used only when the model's meta file says so (soon_display == "tree"). Returns {seconds: model}."""
    global _TREES
    if _TREES is not None:
        return _TREES
    _TREES = {}
    if meta.get("soon_display") != "tree":
        return _TREES
    try:
        import xgboost as xgb
        for Hs in meta.get("soon_tree_horizons") or []:
            p = MODEL_DIR / f"timing_xgb_{Hs}.json"
            if p.exists():
                m = xgb.XGBClassifier()
                m.load_model(str(p))
                _TREES[int(Hs)] = m
    except Exception as e:                                   # never let the outlook break the forecast
        print(f"[world_model] timing tree models not loaded: {e!r}", flush=True)
        _TREES = {}
    return _TREES


def run_model(W):
    import torch
    meta, models = load_model()
    FE, L, K = meta["features"], meta["L"], meta["K"]
    X = W[FE].to_numpy(np.float32).copy()
    for j in meta["log_idx"]:
        X[:, j] = np.log1p(np.clip(X[:, j], 0, None))
    mean, std = np.asarray(meta["mean"], np.float32), np.asarray(meta["std"], np.float32)
    Xs = np.nan_to_num(np.clip((X - mean) / std, -6, 6), nan=0.0).astype(np.float32)
    host = pd.factorize(W["host_ip"])[0]
    win = W["win"].to_numpy(np.int64)
    n = len(W)
    row = np.arange(n)
    newseg = np.ones(n, bool)
    newseg[1:] = (host[1:] != host[:-1]) | ((win[1:] - win[:-1]) > MAXGAP)
    seg_start = np.maximum.accumulate(np.where(newseg, row, 0))
    hist_len = np.minimum(row - seg_start + 1, L)
    risk = np.zeros((n, K), np.float32)
    risk_lo, risk_hi = np.ones((n, K), np.float32), np.zeros((n, K), np.float32)   # range across the model copies
    stage = np.zeros((n, K + 1, len(meta["classes"])), np.float32)
    SOON = meta.get("soon_horizons") or []
    soon = np.zeros((n, len(SOON)), np.float32) if SOON else None
    trees = _timing_trees(meta)
    soon_tree = np.zeros((n, len(trees)), np.float32) if trees else None
    base, bl = None, None                               # logistic-regression baseline on the SAME inputs (if saved)
    bfile = MODEL_DIR / "baseline_lr.json"
    if bfile.exists():
        try:
            bl = json.loads(bfile.read_text())
            if bl["L"] != L or bl["n_features"] != Xs.shape[1] or len(bl["coef"]) != L * Xs.shape[1]:
                bl = None
            else:
                base, bcoef = np.zeros(n, np.float32), np.asarray(bl["coef"], np.float32)
        except Exception:
            bl = None
    with torch.no_grad():
        for i in range(0, n, 2048):
            r = row[i:i + 2048]
            idx = np.maximum(r[:, None] + np.arange(-L + 1, 1), seg_start[r][:, None])   # short history: repeat first window
            if bl is not None:
                z = Xs[idx].reshape(len(r), -1) @ bcoef + bl["intercept"]
                base[i:i + 2048] = 1.0 / (1.0 + np.exp(-np.clip(z, -30, 30)))
            if trees:
                flat = Xs[idx].reshape(len(r), -1)                   # same input as in training: 10 windows, flattened
                for jt, tm in enumerate(trees.values()):
                    soon_tree[i:i + 2048, jt] = tm.predict_proba(flat)[:, 1]
            x = torch.from_numpy(Xs[idx])
            for m in models:
                o = m(x)
                sl, wl = o[0], o[1]
                if SOON:
                    soon[i:i + 2048] += torch.sigmoid(o[2]).numpy() / len(models)
                pm = torch.sigmoid(wl).numpy()
                risk[i:i + 2048] += pm / len(models)
                risk_lo[i:i + 2048] = np.minimum(risk_lo[i:i + 2048], pm)      # lowest / highest copy at every step
                risk_hi[i:i + 2048] = np.maximum(risk_hi[i:i + 2048], pm)
                stage[i:i + 2048] += torch.softmax(sl, -1).numpy() / len(models)
    risk = np.maximum.accumulate(risk, axis=1)          # risk can only grow with the horizon (same as training eval)
    # The range is made non-decreasing the same way, AFTER taking min / max over the copies, so the main line
    # (average of the copies) always lies inside it.
    risk_lo, risk_hi = np.maximum.accumulate(risk_lo, axis=1), np.maximum.accumulate(risk_hi, axis=1)
    extra = {"Xs": Xs, "seg_start": seg_start, "risk_lo": risk_lo, "risk_hi": risk_hi, "soon": soon,
             "soon_tree": soon_tree, "soon_tree_horizons": list(trees.keys())}
    return meta, risk, stage, hist_len, base, extra


def occlusion_attribution(meta, models, Xs, seg_start, i, raw_row=None, top=10):
    """Which features drive the 60-second risk of window i: every feature is replaced, over the whole history,
    by its training-set average, and the drop in risk is that feature's contribution (positive = raises risk).
    This is an occlusion attribution, not SHAP: contributions do not have to add up to the risk."""
    import torch
    FE, L = meta["features"], meta["L"]
    idx = np.maximum(i + np.arange(-L + 1, 1), seg_start[i])
    x = Xs[idx]                                           # (L, F)
    F = x.shape[1]
    batch = np.repeat(x[None], F + 1, axis=0).copy()
    for j in range(F):
        batch[j + 1, :, j] = 0.0                           # 0 = training mean after standardising
    p = np.zeros((F + 1, meta["K"]), np.float32)
    with torch.no_grad():
        xb = torch.from_numpy(batch)
        for m in models:
            p += torch.sigmoid(m(xb)[1]).numpy() / len(models)
    r = np.maximum.accumulate(p, axis=1)[:, -1]
    delta = r[0] - r[1:]
    grp = {f: g for g, cols in meta["groups"].items() for f in cols}
    order = np.argsort(-np.abs(delta))[:top]
    tot = float(np.abs(delta).sum()) or 1.0
    return {"risk_60s": float(r[0]), "method": "occlusion (feature replaced by its training average)",
            "features": [{"feature": FE[j], "description": FEATURE_DESC.get(FE[j], FE[j].replace("_", " ")), "group": grp.get(FE[j], ""), "contribution": round(float(delta[j]), 4),
                          "share": round(float(abs(delta[j]) / tot), 4),
                          "value": (None if raw_row is None or not np.isfinite(raw_row[j]) else round(float(raw_row[j]), 4)),
                          "standardised": round(float(x[-1, j]), 3)} for j in order],
            "by_group": {g: round(float(sum(delta[FE.index(f)] for f in cols)), 4) for g, cols in meta["groups"].items()}}


def _threshold(meta, subset):
    th = meta.get("thresholds", {})
    K = meta["K"]
    for prefix in ["WORLD MODEL (ensemble", "WORLD MODEL (head)"]:
        for k, v in th.items():
            if k.startswith(prefix) and k.endswith(f"|{K}|{subset}"):
                return float(v)
    return 0.5


def _clean(o):
    """make a result JSON-safe (NaN / numpy types -> plain values)"""
    if isinstance(o, dict):
        return {str(k): _clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_clean(v) for v in o]
    if isinstance(o, np.ndarray):
        return _clean(o.tolist())
    if isinstance(o, (np.bool_,)):
        return bool(o)
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (float, np.floating)):
        return None if not np.isfinite(o) else float(o)
    return o


_PROG = None


def _load_progression():
    global _PROG
    if _PROG is None:
        f = MODEL_DIR / "stage_progression.json"
        _PROG = json.loads(f.read_text()) if f.exists() else {}
    return _PROG


def progression_outlook(dist, classes, depth=3, max_children=3):
    """Multi-stage outlook for one host.
    Start = the stages the MODEL currently sees for this host (its own probabilities).
    Each further level = which NEW stage attacker hosts in the training data reached next from that stage,
    with how often it was observed and how long it took. Nothing is assumed: a stage with no observed
    continuation is a leaf. `dist` is the model's stage distribution [step][class] for the latest window."""
    P = _load_progression()
    if not P or dist is None:
        return {"available": False, "reason": "Stage-progression statistics are not installed."}
    dist = np.asarray(dist, dtype=float)
    row, when = dist[0], "now"
    if row[1:].sum() < 0.5:                                  # no attack stage now: use the model's 60-second view
        row, when = dist[-1], "within 60 s"
    mass = float(row[1:].sum())
    if mass < 0.5:
        return {"available": False, "attack_stage_probability": round(mass, 3),
                "reason": "The model sees no attack stage for this host, so there is no progression to show."}
    S = P["stages"]
    nodes, levels = [], []
    # Starting stage = the model's stage forecast averaged over all its steps (now .. +60 s). This is the same
    # quantity as `likely_attack_stage` in the tables, so the tiles, the tree and the MITRE cards agree.
    avg = dist[:, 1:].mean(0)
    start = sorted(((classes[j + 1], float(avg[j])) for j in range(len(avg))), key=lambda x: -x[1])
    start = [(st, pr) for st, pr in start if pr / max(float(avg.sum()), 1e-9) >= 0.10][:2]
    lvl = []
    for st, pr in start:
        n = {"id": len(nodes), "parent": None, "level": 0, "stage": st, "prob": round(pr, 3),
             "path_prob": round(pr / max(float(avg.sum()), 1e-9), 4), "basis": "model", "path": [st]}
        nodes.append(n); lvl.append(n)
    levels.append(lvl)
    for d in range(1, depth + 1):
        nxt = []
        for par in levels[-1]:
            info = S.get(par["stage"], {})
            cand = {b: v for b, v in info.get("next", {}).items() if b not in par["path"]}
            tot = sum(v["count"] for v in cand.values())
            par["hosts_reached"], par["hosts_moved_on"] = info.get("hosts_reached", 0), info.get("hosts_moved_on", 0)
            if tot == 0:
                par["leaf"] = True
                par["leaf_reason"] = (f"none of the {par['hosts_reached']} hosts seen in this stage went on to a new stage"
                                      if not info.get("next") else "no further new stage was observed after this path")
                continue
            for b, v in sorted(cand.items(), key=lambda x: -x[1]["count"])[:max_children]:
                pr = v["count"] / tot
                n = {"id": len(nodes), "parent": par["id"], "level": d, "stage": b, "prob": round(pr, 3),
                     "path_prob": round(par["path_prob"] * pr, 4), "basis": "training data",
                     "observed": v["count"], "observed_total": tot, "median_delay_min": v["median_delay_min"],
                     "datasets": v.get("datasets", {}), "path": par["path"] + [b]}
                nodes.append(n); nxt.append(n)
        if not nxt:
            break
        levels.append(nxt)
    for n in nodes:                                           # last level: mark stages without a known continuation
        if "hosts_reached" not in n:
            info = S.get(n["stage"], {})
            n["hosts_reached"], n["hosts_moved_on"] = info.get("hosts_reached", 0), info.get("hosts_moved_on", 0)
    path, cur = [], levels[0][0] if levels and levels[0] else None
    while cur is not None:
        path.append(cur["id"])
        kids = [n for n in nodes if n["parent"] == cur["id"]]
        cur = max(kids, key=lambda n: n["prob"]) if kids else None
    labels = ["NOW" if when == "now" else "WITHIN 60 S", "NEXT", "THEN", "AFTER THAT"]
    steps = []
    for k, i in enumerate(path):
        n = nodes[i]
        dly = n.get("median_delay_min")
        steps.append({"label": labels[min(k, 3)], "stage": n["stage"], "prob": n["prob"], "basis": n["basis"],
                      "observed": n.get("observed"), "observed_total": n.get("observed_total"),
                      "typical_delay": (None if dly is None else (f"about {dly:.0f} min" if dly < 90 else
                                                                 (f"about {dly / 60:.0f} h" if dly < 2880 else f"about {dly / 1440:.0f} days")))})
    for n in nodes:
        n.pop("path", None)
    return {"available": True, "start_from": when, "nodes": nodes, "levels": [[n["id"] for n in l] for l in levels],
            "most_likely_path": path, "steps": steps,
            "evidence": {"progressions_observed": P.get("total_progressions"), "hosts_with_a_progression": P.get("hosts_with_a_progression"),
                         "attacker_hosts": P.get("attacker_hosts"), "datasets": P.get("datasets")},
            "note": (f"The first column is this host's stage according to the model (its stage forecast averaged over "
                     f"now to +60 s). Every later column shows which new stage "
                     f"attacker hosts in the training data reached next, counted from {P.get('total_progressions')} observed stage "
                     f"changes on {P.get('hosts_with_a_progression')} hosts. It is a record of what happened in that data, "
                     "not a forecast with measured accuracy.")}


def _attr(meta, extra, W, i):
    if meta is None or extra is None:
        return None
    try:
        raw = W[meta["features"]].iloc[int(i)].to_numpy(np.float64)
        return occlusion_attribution(meta, load_model()[1], extra["Xs"], extra["seg_start"], int(i), raw)
    except Exception as e:                                   # never let the explanation break the forecast
        return {"error": repr(e)}


def chart_data(out, W, risk, thr, has_labels, stage=None, classes=None, mitre=None, extra=None, meta=None, top=25):
    """Chart-ready series for the dashboard: one risk timeline per host (top hosts by peak risk) and one for
    the whole network. Every point also carries the forecast made AT that window (risk within 10..60 s)."""
    K = risk.shape[1]
    t = W["t0"].to_numpy()
    hip = out["host_ip"].to_numpy()
    peak = out.groupby("host_ip", sort=False)["risk_60s"].max().sort_values(ascending=False)
    order = list(peak.index[:top])
    hosts = {}
    for h in order:
        idx = np.where(hip == h)[0]
        d = out.iloc[idx]
        hosts[h] = {
            "t": t[idx], "time": d["window_start"].tolist(), "flows": d["flows"].tolist(),
            "risk_60s": d["risk_60s"].tolist(), "risk_10s": d["risk_10s"].tolist(),
            "alert": d["alert"].tolist(), "stage_now": d["stage_now"].tolist(),
            "likely_attack_stage": d["likely_attack_stage"].tolist(),
            "likely_attack_stage_prob": d["likely_attack_stage_prob"].tolist(),
            # v4 only: {"300": [...], "600": [...]} = chance an attack starts within that many seconds, per window
            "start_soon": ({c[len("start_within_"):-1]: d[c].tolist() for c in d.columns
                            if c.startswith("start_within_") and c.endswith("s")} or None),
            "short_history": d["short_history"].tolist(),
            "forecast_curve": np.round(risk[idx], 4),          # [window][k]  k = 10, 20, ... s ahead
            # lowest / highest value among the trained model copies (a spread, not a confidence interval)
            "forecast_curve_min": np.round(extra["risk_lo"][idx], 4) if extra is not None else None,
            "forecast_curve_max": np.round(extra["risk_hi"][idx], 4) if extra is not None else None,
            # stage the model expects at each step: [window][step], step 0 = now, 1 = +10 s, ... K = +60 s
            "stage_forecast": [[classes[j] for j in row] for row in stage[idx].argmax(-1)] if stage is not None else None,
            "stage_forecast_prob": np.round(stage[idx].max(-1), 3) if stage is not None else None,
            # the model's SECOND choice at each step (same shape), for the 60-second forecast strip
            "stage_forecast_second": [[classes[j] for j in row] for row in np.argsort(stage[idx], axis=-1)[..., -2]]
                                     if stage is not None else None,
            "stage_forecast_second_prob": np.round(np.sort(stage[idx], axis=-1)[..., -2], 3) if stage is not None else None,
            # full stage distribution [step][class] (classes in chart.classes) for two windows of this host
            "stage_dist_last": np.round(stage[idx[-1]], 3) if stage is not None else None,
            "stage_dist_peak": np.round(stage[idx[int(np.argmax(risk[idx, -1]))]], 3) if stage is not None else None,
            "peak_window_index": int(np.argmax(risk[idx, -1])),
            "progression": progression_outlook(stage[idx[-1]], classes) if stage is not None else None,
            "attribution_last": _attr(meta, extra, W, idx[-1]),
            "attribution_peak": _attr(meta, extra, W, idx[int(np.argmax(risk[idx, -1]))]),
            "true_stage": d["true_stage"].tolist() if has_labels else None,
            "baseline_risk_60s": d["baseline_risk_60s"].tolist() if "baseline_risk_60s" in d else None,
        }
    has_base = "baseline_risk_60s" in out
    g = pd.DataFrame({"t": t, "r": out["risk_60s"].to_numpy(), "a": out["alert"].to_numpy(),
                      "b": out["baseline_risk_60s"].to_numpy() if has_base else 0.0})
    if has_labels:
        g["true"] = ~out["true_stage"].isin(["normal", "ambiguous"]).to_numpy()
    n = g.groupby("t", sort=True).agg(max_risk=("r", "max"), base_max=("b", "max"), hosts_active=("r", "size"), hosts_alerting=("a", "sum"),
                                       **({"hosts_truly_attacking": ("true", "sum")} if has_labels else {}))
    net = {"t": n.index.to_numpy(), "time": pd.to_datetime(n.index, unit="s").strftime("%Y-%m-%d %H:%M:%S").tolist(),
           "max_risk_60s": n["max_risk"].round(4).to_numpy(), "hosts_active": n["hosts_active"].to_numpy(),
           "hosts_alerting": n["hosts_alerting"].to_numpy(),
           "hosts_truly_attacking": n["hosts_truly_attacking"].to_numpy() if has_labels else None,
           "baseline_max_risk_60s": n["base_max"].round(4).to_numpy() if has_base else None}
    return {"threshold": thr, "window_seconds": WIN, "horizon_seconds": [int((k + 1) * WIN) for k in range(K)],
            "stage_steps": ["now"] + [f"+{int((k + 1) * WIN)} s" for k in range(K)], "mitre": mitre or {}, "classes": list(classes) if classes is not None else None,
            "host_order": order, "hosts": hosts, "network": net, "baseline_available": bool(has_base), "model_copies": len(load_model()[1]),
            "start_outlook": out.attrs.get("soon_info"),
            "has_labels": has_labels}


def analyze(path, out_dir=None, pcap_flows_csv=None):
    """Full pipeline. Returns a dict (also written as JSON). Raises UnusableFile with a clear reason."""
    path = str(path)
    flows, kind, notices = load_flows(path, pcap_flows_csv)
    W, has_labels = build_windows(flows)
    meta, risk, stage, hist_len, base, extra = run_model(W)
    L, K, CL = meta["L"], meta["K"], meta["classes"]
    G = meta["groups"]
    thr = _threshold(meta, "all")
    r60 = risk[:, K - 1]
    now = stage[:, 0].argmax(1)
    ahead = stage[:, K].argmax(1)
    att = stage[:, :, 1:].mean(1)                       # mean probability of each attack stage over t .. t+K
    likely = att.argmax(1) + 1
    alert = r60 >= thr
    t0 = pd.to_datetime(W["t0"], unit="s", errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S")
    out = pd.DataFrame({
        "host_ip": W["host_ip"], "window_start": t0, "flows": W["n_flows"].astype(int),
        "risk_10s": risk[:, 0].round(4), "risk_30s": risk[:, min(2, K - 1)].round(4), "risk_60s": r60.round(4),
        "alert": alert, "stage_now": [CL[i] for i in now], "stage_now_prob": stage[:, 0].max(1).round(3),
        f"stage_in_{int(K * WIN)}s": [CL[i] for i in ahead],
        "likely_attack_stage": [CL[i] for i in likely], "likely_attack_stage_prob": att.max(1).round(3),
        "history_windows": hist_len, "short_history": hist_len < L,
    })
    if base is not None:
        out["baseline_risk_60s"] = base.round(4)
    soon_info = None
    use_tree = extra.get("soon_tree") is not None
    if use_tree or extra.get("soon") is not None:         # chance that an attack STARTS within 5 / 10 minutes
        hz = extra["soon_tree_horizons"] if use_tree else (meta.get("soon_horizons") or [])
        vals = extra["soon_tree"] if use_tree else extra["soon"]
        for j, Hs in enumerate(hz):
            out[f"start_within_{Hs}s"] = vals[:, j].round(4)
        soon_info = {"horizons_seconds": hz, "tested": (meta.get("soon_tree") if use_tree else meta.get("soon")) or {},
                     "model": ("gradient-boosted trees on the same 10 windows of 73 features" if use_tree
                               else "world model (LSTM), start-soon output"),
                     "what": "chance that an attack of this host STARTS within the horizon. Trained and tested on calm "
                             "hosts (normal now, no attack in the last 5 minutes); for a host already under attack it "
                             "says little.",
                     "how_tested": "held-back hours; 'test_within_host' is the AUROC inside each host (0.5 = no timing "
                                   "ability, 1.0 = perfect), so knowing which host is dangerous earns no credit",
                     "limits": meta.get("soon_note")}
    out.attrs["soon_info"] = soon_info
    mitre = meta.get("mitre", {})
    out["mitre_tactic"] = [mitre.get(s, {}).get("tactic_id", "") if a else "" for s, a in zip(out["likely_attack_stage"], alert)]
    if has_labels:
        names = {-1: "ambiguous", **{i: s for i, s in enumerate(STAGES)}}
        out["true_stage"] = W["stage_id"].map(names).values

    # ---- per host (vectorised: a capture can hold tens of thousands of hosts)
    g = out.groupby("host_ip", sort=False)
    top = out.loc[g["risk_60s"].idxmax()].set_index("host_ip")
    al = out[out["alert"]]
    ga = al.groupby("host_ip", sort=False)
    mode = (al.groupby(["host_ip", "likely_attack_stage"], sort=True).size().rename("n").reset_index()
            .sort_values(["host_ip", "n", "likely_attack_stage"], ascending=[True, False, True], kind="stable")
            .drop_duplicates("host_ip").set_index("host_ip")["likely_attack_stage"])
    hosts = pd.DataFrame({"windows": g.size().astype(int), "flows": g["flows"].sum().astype(int)})
    hosts["peak_risk_60s"] = top["risk_60s"].astype(float)
    hosts["peak_time"] = top["window_start"]
    hosts["alert_windows"] = ga.size().reindex(hosts.index).fillna(0).astype(int)
    hosts["first_alert"] = ga["window_start"].first().reindex(hosts.index).fillna("")
    hosts["likely_stage"] = mode.reindex(hosts.index).fillna("")
    hosts["mitre_tactic"] = [mitre.get(s, {}).get("tactic_id", "") for s in hosts["likely_stage"]]
    hosts["mitre_tactic_name"] = [mitre.get(s, {}).get("tactic", "") for s in hosts["likely_stage"]]
    hosts["short_history_only"] = g["short_history"].all().astype(bool)
    hosts = hosts.rename_axis("host_ip").reset_index()
    hosts = hosts.sort_values("peak_risk_60s", ascending=False).reset_index(drop=True)

    # ---- notices about what the model could not see
    miss = {g: float(W[cols].isna().mean().mean()) for g, cols in G.items()}
    for g, v in miss.items():
        if v > 0.5:
            notices.append(f"feature group '{g}' is {v:.0%} empty in this file: the model saw this situation in training "
                           "for some datasets, but forecasts are less reliable without it")
    sh = float(out["short_history"].mean())
    if sh > 0:
        notices.append(f"{sh:.0%} of windows have fewer than {L} windows of history for their host (the model was trained "
                       f"with {L}); they are scored by repeating the earliest window and are marked short_history")
    span = float(W["t0"].max() - W["t0"].min()) + WIN
    if span < L * WIN:
        notices.append(f"the capture covers only {span:.0f} s; the model looks at {int(L * WIN)} s of history, so treat "
                       "every score here as low confidence")
    notices.append("alert threshold comes from the training networks. On a network the model has never seen, early "
                   "warning is NOT proven (see results), so read risk as a ranking of hosts, not a calibrated probability")

    summary = {
        "file": os.path.basename(path), "format_detected": kind, "flows": int(len(flows)),
        "windows": int(len(W)), "hosts": int(W["host_ip"].nunique()),
        "time_span_seconds": round(span, 1), "first_window": str(t0.iloc[W["t0"].values.argmin()]),
        "model": {"features": len(meta["features"]), "copies_averaged": len(load_model()[1]), "history_windows": L,
                  "horizon_seconds": int(K * WIN), "alert_threshold_risk_60s": round(thr, 4), "start_outlook": soon_info},
        "network": {"hosts_flagged": int((hosts["alert_windows"] > 0).sum()), "alert_windows": int(alert.sum()),
                    "peak_risk_60s": float(r60.max()), "share_of_windows_alerted": round(float(alert.mean()), 4)},
        "empty_share_per_feature_group": {g: round(v, 3) for g, v in miss.items()},
        "has_labels": has_labels, "notices": notices,
        "top_hosts": hosts.head(20).to_dict("records"),
    }
    if has_labels:
        truth = W["stage_id"].to_numpy()
        ta, tn = truth >= 1, truth == 0
        chk = {"windows_truly_attack": int(ta.sum()), "windows_truly_normal": int(tn.sum()),
               "attack_windows_alerted": round(float(alert[ta].mean()), 4) if ta.any() else None,
               "normal_windows_alerted_false_alarms": round(float(alert[tn].mean()), 4) if tn.any() else None}
        st_ok = (truth >= 1) & (truth <= 5)
        if st_ok.any():
            chk["stage_named_correctly_on_attack_windows"] = round(float((now[st_ok] == truth[st_ok]).mean()), 4)
            # the stage shown on the page for alerting hosts: average of the stage forecast over now .. +60 s
            chk["averaged_stage_named_correctly_on_attack_windows"] = round(float((likely[st_ok] == truth[st_ok]).mean()), 4)
            if (st_ok & alert).any():
                chk["averaged_stage_named_correctly_on_alerted_attack_windows"] = [
                    round(float((likely[st_ok & alert] == truth[st_ok & alert]).mean()), 4), int((st_ok & alert).sum())]
            chk["stage_recall_by_true_stage"] = {STAGES[c]: [round(float((now[truth == c] == c).mean()), 3), int((truth == c).sum())]
                                                 for c in range(1, 6) if (truth == c).any()}
        summary["check_against_labels_in_file"] = chk
    summary["chart"] = chart_data(out, W, risk, thr, has_labels, stage, CL, mitre, extra, meta)
    summary = _clean(summary)
    if out_dir is not None:
        od = Path(out_dir)
        od.mkdir(parents=True, exist_ok=True)
        stem = Path(path).name.split(".")[0]
        out.to_csv(od / f"{stem}_windows.csv", index=False)
        hosts.to_csv(od / f"{stem}_hosts.csv", index=False)
        (od / f"{stem}_summary.json").write_text(json.dumps({k: v for k, v in summary.items() if k != "chart"}, indent=1))
        (od / f"{stem}_chart.json").write_text(json.dumps(summary["chart"]))
        summary["output_files"] = [str(od / f"{stem}_{x}") for x in ["windows.csv", "hosts.csv", "summary.json"]]
    return summary


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--out", default=str(HERE.parent / "forecast_out"))
    ap.add_argument("--flows-only", action="store_true", help="stop after loading (no model): shows what was read")
    ap.add_argument("--model", default=None, help="folder with world_model.pt + world_model_meta.json (default: models/world_model)")
    A = ap.parse_args()
    if A.model:
        MODEL_DIR = Path(A.model)
    try:
        if A.flows_only:
            fl, kind, notes = load_flows(A.file)
            W, hl = build_windows(fl)
            print(f"format: {kind}   flows: {len(fl):,}   windows: {len(W):,}   hosts: {W['host_ip'].nunique():,}   labels: {hl}")
            for x in notes:
                print(" -", x)
            sys.exit(0)
        s = analyze(A.file, A.out)
    except UnusableFile as e:
        print("\nCANNOT USE THIS FILE:", e)
        sys.exit(2)
    print(f"\nfile: {s['file']}   format detected: {s['format_detected']}")
    print(f"flows: {s['flows']:,}   windows: {s['windows']:,}   hosts: {s['hosts']:,}   time span: {s['time_span_seconds']:.0f} s")
    n = s["network"]
    print(f"NETWORK: {n['hosts_flagged']} host(s) flagged   alert windows: {n['alert_windows']:,} "
          f"({n['share_of_windows_alerted']:.1%})   peak risk: {n['peak_risk_60s']:.3f}   "
          f"(alert when risk_60s >= {s['model']['alert_threshold_risk_60s']})")
    print("\ntop hosts by peak risk:")
    print(f"{'host':18s}{'peak':>7s}{'alerts':>8s}  {'first alert':20s}{'likely stage':20s}{'MITRE':8s}")
    for h in s["top_hosts"][:10]:
        print(f"{h['host_ip']:18s}{h['peak_risk_60s']:>7.3f}{h['alert_windows']:>8d}  {h['first_alert'] or '-':20s}"
              f"{h['likely_stage'] or '-':20s}{h['mitre_tactic'] or '-':8s}")
    if "check_against_labels_in_file" in s:
        print("\ncheck against the labels in this file:", json.dumps(s["check_against_labels_in_file"], indent=1))
    print("\nnotices:")
    for x in s["notices"]:
        print(" -", x)
    print("\nsaved:", *s.get("output_files", []), sep="\n  ")
