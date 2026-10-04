r"""Runs the installed world model on the complete DAPT2020 flow table and shows, for the hosts that go through
several attack stages, which stage the model names in each labelled phase and whether the window was held back."""
import sys, json
from pathlib import Path
import numpy as np, pandas as pd
REPO = Path(r"C:\Users\htc\OneDrive\Desktop\cyberforecaster"); sys.path.insert(0, str(REPO / "capture-service"))
import world_model as wm
flows, kind, notes = wm.load_flows(r"D:\ml-data\dapt_mapped_v1.csv"); W, has = wm.build_windows(flows)
print("format", kind, "flows", len(flows), "windows", len(W), "hosts", W.host_ip.nunique(), "labels", has)
meta, risk, stage, hl, base, extra = wm.run_model(W); K, CL = meta["K"], meta["classes"]; thr = wm._threshold(meta, "all")
likely = stage[:, :, 1:].mean(1).argmax(1) + 1; al = risk[:, K - 1] >= thr; sid = W.stage_id.to_numpy()
fold = ((W.t0.to_numpy() // 3600).astype(np.int64) * 2654435761 % 2**32) % 10
split = np.where(fold < 6, "train", np.where(fold < 8, "val", "test"))
for ip in ["206.207.50.50", "184.98.36.245", "192.168.3.29", "209.147.138.38", "209.147.138.211"]:
    m = (W.host_ip == ip).to_numpy(); print("\n", ip, "windows", int(m.sum()))
    for s in range(1, 6):
        for sp in ["train", "val", "test"]:
            k = m & (sid == s) & (split == sp)
            if k.any():
                named = pd.Series([CL[i] for i in likely[k]]).value_counts().to_dict()
                print(f"   true {wm.STAGES[s]:17s} {sp:5s} windows {int(k.sum()):4d}  alerted {int(al[k].sum()):4d}  stage named: {named}")
ok = (sid >= 1) & (sid <= 5)
for sp in ["train", "val", "test"]:
    k = ok & (split == sp)
    print(sp, "attack windows", int(k.sum()), "alerted", round(float(al[k].mean()), 3), "stage correct", round(float((likely[k] == sid[k]).mean()), 3), "| false alarms on normal", round(float(al[(sid == 0) & (split == sp)].mean()), 4))
