r"""Scores a world model on the DARPA 2000 LLDOS 1.0 'inside' packet capture (a network the model never saw).
Answer key: the official phase lists shipped with the dataset (phase-1..4.list; phase 5 is the DDoS with forged
source addresses, so it has no real source host to score).
Usage: python darpa_eval.py <model folder> <tag>"""
import sys, gzip, shutil, os, json, datetime
from pathlib import Path
import pandas as pd, numpy as np
HERE = Path(__file__).resolve().parent
REPO = Path(r"C:\Users\htc\OneDrive\Desktop\cyberforecaster")
MODEL, TAG = Path(sys.argv[1]), sys.argv[2]
PCAP = HERE / "darpa_full_inside.pcap"
if not PCAP.exists():
    with gzip.open(HERE.parent / "LLS_DDOS_1.0-inside.dump.gz", "rb") as a, open(PCAP, "wb") as b:
        shutil.copyfileobj(a, b, 1 << 20)
sys.path.insert(0, str(REPO / "capture-service"))
import world_model as wm
wm.MODEL_DIR = MODEL
OUT = HERE / f"darpa_out_{TAG}"
r = wm.analyze(str(PCAP), out_dir=str(OUT))
W = pd.read_csv(next(OUT.glob("*_windows.csv")))
W["t"] = pd.to_datetime(W["window_start"]).astype("int64") // 10**9
ip = lambda s: ".".join(str(int(p)) for p in s.split("."))
PH = {1: "IP sweep (reconnaissance)", 2: "sadmind probe (reconnaissance)", 3: "break-in (initial access)", 4: "install DDoS tool"}
key, start = {}, {}
for p in PH:
    for ln in open(HERE / f"phase-{p}.list"):
        f = ln.split()
        if len(f) < 9: continue
        d = datetime.datetime.strptime(f[1] + " " + f[2], "%m/%d/%Y %H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp() + 5 * 3600   # EST -> UTC
        key.setdefault((ip(f[7]), int(d // 10) * 10), p); start[p] = min(start.get(p, d), d)
ddos = datetime.datetime(2000, 3, 7, 16, 27, 50, tzinfo=datetime.timezone.utc).timestamp()      # start of the 10-second window that holds the first forged DDoS packet (11:27:51 EST in phase-5.list)
W["phase"] = [key.get((h, t), 0) for h, t in zip(W["host_ip"], W["t"])]
inv = {h for h, _ in key}
res = {"model": str(MODEL), "flows": r["flows"], "hosts": r["hosts"], "windows": int(len(W)), "threshold": r["chart"]["threshold"],
       "hosts_flagged": r["network"]["hosts_flagged"], "phases": {}}
for p, name in PH.items():
    x = W[W.phase == p]
    res["phases"][name] = {"labelled host-windows found": int(len(x)), "alerted": int(x.alert.sum()), "mean risk": round(float(x.risk_60s.mean()), 3) if len(x) else None,
                           "stage named": x.likely_attack_stage.value_counts().to_dict()}
pre = W[W.t < ddos]
oth = pre[(pre.phase == 0) & (~pre.host_ip.isin(inv))]
res["before the DDoS: windows of hosts not in the answer key"] = {"windows": int(len(oth)), "alerted (false alarms)": int(oth.alert.sum()), "rate": round(float(oth.alert.mean()), 4), "hosts": int(oth.host_ip.nunique()), "hosts with an alert": int(oth[oth.alert].host_ip.nunique())}
att = pre[pre.phase > 0]
rank = pre.groupby("host_ip").risk_60s.max().sort_values(ascending=False)
res["rank of hosts in the answer key by peak risk (before the DDoS)"] = {h: int(list(rank.index).index(h)) + 1 for h in inv if h in rank.index}
res["first alert of each answer-key host"] = {}
for h in sorted(inv):
    a = pre[(pre.host_ip == h) & pre.alert]
    res["first alert of each answer-key host"][h] = (f"{(ddos - a.t.min()) / 60:.1f} min before the DDoS" if len(a) else "no alert before the DDoS")
res["phase starts (minutes before the DDoS)"] = {PH[p]: round((ddos - s) / 60, 1) for p, s in start.items()}
print(json.dumps(res, indent=1)); (HERE / f"darpa_eval_{TAG}.json").write_text(json.dumps(res, indent=1))
