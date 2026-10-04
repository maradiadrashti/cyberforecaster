r"""Builds a demo file from complete 1-hour slices of the Unraveled network and scores the installed model on it."""
import sys, os, json, datetime
from pathlib import Path
import numpy as np, pandas as pd
HERE = Path(__file__).resolve().parent; REPO = Path(r"C:\Users\htc\OneDrive\Desktop\cyberforecaster")
sys.path.insert(0, str(REPO / "capture-service")); import world_model as wm
U = lambda *a: datetime.datetime(*a, tzinfo=datetime.timezone.utc).timestamp()
SETS = {"demo_heldback": [U(2021, 6, 22, 1), U(2021, 6, 25, 21), U(2021, 6, 30, 19), U(2021, 7, 2, 6)],
        "demo_plus_initial_access": [U(2021, 6, 22, 1), U(2021, 6, 25, 21), U(2021, 6, 29, 6), U(2021, 6, 30, 19), U(2021, 7, 2, 6)]}
OUT = HERE / "demo"; OUT.mkdir(exist_ok=True)
allh = sorted({h for v in SETS.values() for h in v}); parts = {h: [] for h in allh}
for ch in pd.read_csv(HERE / "unraveled_common.csv", chunksize=1_000_000, low_memory=False):
    t = pd.to_numeric(ch["flow_start"], errors="coerce")
    for h in allh:
        x = ch[(t >= h) & (t < h + 3600)]
        if len(x): parts[h].append(x)
for name, hours in SETS.items():
    d = pd.concat([p for h in hours for p in parts[h]], ignore_index=True).sort_values("flow_start")
    f = OUT / f"{name}.csv"; d.to_csv(f, index=False)
    print(f"\n===== {name}: {len(d):,} flows, {os.path.getsize(f) / 1e6:.1f} MB, hosts {d.src_ip.nunique()}, labels {d.attack_stage.value_counts().to_dict()}")
    flows, kind, notes = wm.load_flows(str(f)); W, has = wm.build_windows(flows)
    meta, risk, stage, hl, base, extra = wm.run_model(W); K, CL = meta["K"], meta["classes"]; thr = wm._threshold(meta, "all")
    likely = stage[:, :, 1:].mean(1).argmax(1) + 1; conf = stage[:, :, 1:].mean(1).max(1); al = risk[:, K - 1] >= thr; sid = W.stage_id.to_numpy(); host = W.host_ip.to_numpy()
    blk = (W.t0.to_numpy() // 3600).astype(np.int64)
    fold = (blk * 2654435761 % 2**32) % 10; split = np.where(fold < 6, "train", np.where(fold < 8, "val", "test"))
    dirty = np.isin(host, np.unique(host[sid != 0])); ok = (sid >= 1) & (sid <= 5)
    print(f"windows {len(W)}, attack windows {int(ok.sum())}, alerted {al[ok].mean():.3f}, stage correct {(likely[ok] == sid[ok]).mean():.3f}, stage correct on alerted {(likely[ok & al] == sid[ok & al]).mean():.3f}")
    print(f"clean hosts {len(set(host[~dirty]))}, flagged {len(set(host[al & ~dirty]))}, false alarms on clean-host windows {al[(sid == 0) & ~dirty].mean():.4f}; alerts in quiet windows of attacking hosts {al[(sid == 0) & dirty].mean():.3f}")
    for h in sorted(set(host[ok])):
        for b in sorted(set(blk[(host == h)])):
            m = (host == h) & (blk == b)
            for s in sorted(set(sid[m & ok])):
                k = m & (sid == s)
                print(f"   {h:15s} {pd.to_datetime(b * 3600, unit='s')} {split[k][0]:5s} true {wm.STAGES[s]:17s} windows {int(k.sum()):4d} alerted {int(al[k].sum()):4d} named {pd.Series([CL[i] for i in likely[k]]).value_counts().to_dict()} mean stage confidence {conf[k].mean():.2f}")
    rank = pd.Series(risk[:, K - 1]).groupby(host).max().sort_values(ascending=False)
    print("   top hosts by peak risk:", [(h, round(float(v), 3), "ATTACKER" if h in set(host[ok]) else "clean") for h, v in rank.head(8).items()])
