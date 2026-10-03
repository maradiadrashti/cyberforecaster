r"""Run the four labelled test files through a model folder and print how the output compares with the labels.
    python run_test_files.py <model folder> <output folder>"""
import os as _os
from pathlib import Path as _P
REPO = _P(_os.environ.get("CYBERFORECASTER_REPO") or _P(__file__).resolve().parents[3])   # repository root
import sys, json, time
from pathlib import Path
import numpy as np, pandas as pd
sys.path.insert(0, str(REPO / "capture-service"))
import world_model as f
f.MODEL_DIR = Path(sys.argv[1])
OUT = Path(sys.argv[2]); OUT.mkdir(parents=True, exist_ok=True)
T = Path(str(REPO / "samples" / "test_files"))
FILES = {"A_cic2017_friday_ddos_onset.csv": ["172.16.0.1"], "B_cic2018_ftp_bruteforce_onset.csv": ["18.221.219.4", "172.31.69.25"],
         "C_ctu13_botnet_c2_forecast.csv": ["147.32.84.165", "195.113.232.88"], "D_unraveled_exfiltration_forecast.csv": ["10.1.3.17", "10.1.3.8"]}
for name, hosts in FILES.items():
    t = time.time()
    r = f.analyze(str(T / name))
    (OUT / (name.split(".")[0] + ".json")).write_text(json.dumps(r))
    c = r["chart"]
    print(f"\n===== {name}   {time.time() - t:.1f} s   windows {r['windows']}  hosts {r['hosts']}  threshold {c['threshold']:.4f}")
    print("check:", json.dumps(r.get("check_against_labels_in_file")))
    print("network:", json.dumps(r["network"]))
    print("top hosts:", [(h["host_ip"], round(h["peak_risk_60s"], 3), h["alert_windows"], h["windows"], h["likely_stage"]) for h in r["top_hosts"][:6]])
    so = c.get("start_outlook") or {}
    thr5 = ((so.get("tested") or {}).get("300") or {}).get("threshold")
    print("start outlook:", so.get("model"), so.get("horizons_seconds"), "threshold 300 s:", thr5)
    tot = dict(pre=0, pre_w=0, far=0, far_w=0)
    for ip, H in c["hosts"].items():
        ss = (H.get("start_soon") or {}).get("300")
        ts = pd.Series(H["true_stage"]) if H.get("true_stage") else None
        if ss is None or ts is None or thr5 is None:
            continue
        tm = pd.to_datetime(pd.Series(H["time"])); att = tm[~ts.isin(["normal", "ambiguous"])].tolist()
        last = pd.Series([max([(ti - x).total_seconds() for x in att if x <= ti] or [-1]) for ti in tm])   # s since last attack
        nxt = pd.Series([min([(x - ti).total_seconds() for x in att if x > ti] or [1e9]) for ti in tm])
        quiet = (ts == "normal") & ((last < 0) | (last > 300))
        w = pd.Series(ss) >= thr5
        y = nxt <= 300
        tot["pre"] += int((quiet & y).sum()); tot["pre_w"] += int((quiet & y & w).sum())
        tot["far"] += int((quiet & ~y).sum()); tot["far_w"] += int((quiet & ~y & w).sum())
        if ip in hosts:
            print(f"  host {ip}: rank {c['host_order'].index(ip)}  windows {len(tm)}  alerts {int(sum(H['alert']))}  "
                  f"stage shown at last alert: {next((s for s, a in zip(H['likely_attack_stage'][::-1], H['alert'][::-1]) if a), None)}  "
                  f"| calm windows with a start within 5 min: {int((quiet & y).sum())}, warned {int((quiet & y & w).sum())}"
                  f"  | calm windows with no start: {int((quiet & ~y).sum())}, warned {int((quiet & ~y & w).sum())}")
            if ip in ("10.1.3.17", "172.31.69.25", "195.113.232.88"):
                print("   time      risk60  start5m  true")
                for a, b, cc, d in zip(H["time"], H["risk_60s"], ss, H["true_stage"]):
                    print(f"   {a[11:]}  {b:.3f}   {cc:.3f}   {d}")
    for ip in hosts:
        if ip not in c["hosts"]:
            print(f"  host {ip}: not among the {len(c['hosts'])} charted hosts")
    print("  5-minute outlook on calm windows of charted hosts:", tot)
print("\nALL FILES DONE")
