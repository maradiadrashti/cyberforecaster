r"""Which attack starts in the HELD-BACK hours did the world model warn about before they began?

For every host in the test split: a "start" is the first attack window after at least 3 normal windows in a row.
The model's risk is read on the normal windows of the 60 s before the start. "Warned" = risk_60s was at or above
the alert threshold on at least one of them. Nothing is trained here; it only runs the saved model.

    python find_warned_onsets.py            -> logs/warned_onsets.json + a table
"""
import os as _os
from pathlib import Path as _P
REPO = _P(_os.environ.get("CYBERFORECASTER_REPO") or _P(__file__).resolve().parents[3])   # repository root
import sys, json
from pathlib import Path
import numpy as np, pandas as pd

sys.path.insert(0, str(REPO / "capture-service"))
import world_model as f

DIR = Path(__file__).resolve().parent
NAMES = ["normal", "reconnaissance", "initial_access", "command_control", "lateral_movement", "exfiltration", "other"]
W = pd.read_pickle(DIR / "windows.pkl")
W = W[W["t0"] < 1.7e9]
blk = (W["t0"].values // 3600).astype(np.int64)
fold = ((blk * 2654435761) % (2 ** 32)) % 10
W = W[fold >= 8]                                            # the 20% of hours never used for training or tuning
meta = f.load_model()[0]
K, thr = meta["K"], f._threshold(meta, "all")
print(f"held-back windows: {len(W):,}   alert threshold: {thr:.4f}", flush=True)
out = []
for (src, sub), G in W.groupby(["source", "sub"], sort=True):
    G = G.sort_values(["host_ip", "win"]).reset_index(drop=True)
    _, risk, stage, hist, base, extra = f.run_model(G)
    r60 = risk[:, K - 1]
    st, host, win, t0 = G["stage_id"].values, G["host_ip"].values, G["win"].values, G["t0"].values
    seg = extra["seg_start"]
    n = len(G)
    for i in range(1, n):
        if st[i] < 1 or host[i - 1] != host[i] or seg[i] != seg[i - 1]:
            continue
        lo = max(seg[i], i - 10)
        if i - lo < 3 or not (st[lo:i] == 0).all():
            continue                                        # needs >= 3 normal windows straight before the start
        pre = [j for j in range(lo, i) if win[i] - win[j] <= K]      # normal windows within 60 s before the start
        if not pre:
            continue
        hit = [j for j in pre if r60[j] >= thr]
        j2 = i
        while j2 + 1 < n and seg[j2 + 1] == seg[i] and win[j2 + 1] - win[i] <= 30:
            j2 += 1
        out.append({"sub": sub, "source": src, "host": host[i], "start_epoch": float(t0[i]),
                    "start": str(pd.to_datetime(t0[i], unit="s")), "stage": NAMES[int(st[i])],
                    "normal_windows_before": int(i - lo), "risk_before_max": round(float(r60[pre].max()), 4),
                    "warned": bool(hit), "lead_seconds": int((win[i] - win[hit[0]]) * 10) if hit else 0,
                    "baseline_before_max": None if base is None else round(float(base[pre].max()), 4),
                    "attack_windows_next_5min": int((st[i:j2 + 1] >= 1).sum()),
                    "stage_forecast_before": [meta["classes"][c] for c in stage[pre[-1]].argmax(-1)]})
    print(f"{sub}: windows {n:,}  starts found so far {len(out)}", flush=True)
(DIR / "logs").mkdir(exist_ok=True)
(DIR / "logs" / "warned_onsets.json").write_text(json.dumps(out, indent=1))
d = pd.DataFrame(out)
if len(d):
    print("\nstarts and warnings per dataset and stage:")
    print(d.groupby(["sub", "stage"])["warned"].agg(["size", "sum"]).rename(columns={"size": "starts", "sum": "warned"}).to_string())
    print(f"\nTOTAL starts {len(d)}   warned {int(d['warned'].sum())}")
    print("\nwarned starts (best first):")
    print(d[d["warned"]].sort_values(["attack_windows_next_5min", "lead_seconds"], ascending=False)
          .drop(columns=["source", "start_epoch", "stage_forecast_before"]).head(40).to_string(index=False))
else:
    print("no attack starts found in the held-back hours")
