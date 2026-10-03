r"""Is there a TIMING signal in the data?  (quick check, no LSTM training)

Question: for a host that is normal right now, can anything in its traffic tell that an attack will start
within the next H seconds - better than just knowing WHICH host it is?

 * rows   = windows where the host is normal now and had no attack in the previous 5 minutes,
            for hosts that have both normal and attack windows
 * target = an attack window of the same host starts within H seconds (H = 60, 300, 600)
 * model  = gradient-boosted trees on the 73 window features + how they changed over the last 1 and 3 windows
 * split  = same hour blocks as the main model (train hours / held-back test hours)
 * metric = AUROC over all rows ("pooled") and AUROC INSIDE each host ("within host").
            Within-host removes host identity: 0.5 = no timing signal, 1.0 = perfect timing.
Also scores the saved world model (risk_60s) on the same rows for H = 60.
"""
import os as _os
from pathlib import Path as _P
REPO = _P(_os.environ.get("CYBERFORECASTER_REPO") or _P(__file__).resolve().parents[3])   # repository root
import sys, json, os, time
from pathlib import Path
import numpy as np, pandas as pd

DIR = Path(__file__).resolve().parent
DRY = os.environ.get("DRY") == "1"
T0 = time.time()
def log(*a): print(f"[{time.time() - T0:6.0f}s]", *a, flush=True)

def auroc(y, s):
    y = np.asarray(y, bool); s = np.asarray(s, float)
    n1, n0 = int(y.sum()), int((~y).sum())
    if n1 == 0 or n0 == 0:
        return None
    r = pd.Series(s).rank(method="average").to_numpy()
    return float((r[y].sum() - n1 * (n1 + 1) / 2) / (n1 * n0))

def within_host(df, col):
    """AUROC inside each host that has both outcomes; returns (hosts, median, mean weighted by positives)."""
    vals, wts = [], []
    for _, g in df.groupby("hk", sort=False):
        a = auroc(g["y"].values, g[col].values)
        if a is not None:
            vals.append(a); wts.append(int(g["y"].sum()))
    if not vals:
        return 0, None, None
    return len(vals), float(np.median(vals)), float(np.average(vals, weights=wts))

W = pd.read_pickle(DIR / "windows.pkl")
FE = json.loads((DIR / "feature_groups.json").read_text())["features"]
W = W[W["t0"] < 1.7e9]
W["hk"] = W["source"].astype(str) + "|" + W["host_ip"].astype(str)
sg = W.groupby("hk")["stage_id"]
mixed = (sg.max() >= 1) & (W["stage_id"].eq(0).groupby(W["hk"]).any())
W = W[W["hk"].isin(mixed.index[mixed.values])].sort_values(["hk", "win"]).reset_index(drop=True)
log(f"hosts with both normal and attack windows: {W['hk'].nunique():,}   their windows: {len(W):,}")

t0 = W["t0"].to_numpy(float)
att_t = np.where(W["stage_id"].to_numpy() >= 1, t0, np.inf)
nxt = pd.Series(att_t[::-1]).groupby(W["hk"].to_numpy()[::-1], sort=False).cummin().to_numpy()[::-1]   # next attack time
gap = nxt - t0
prev_t = np.where(W["stage_id"].to_numpy() >= 1, t0, -np.inf)
prv = pd.Series(prev_t).groupby(W["hk"].to_numpy(), sort=False).cummax().to_numpy()                     # last attack time
quiet = (t0 - prv) > 300          # no attack of this host in the previous 5 minutes: a new start, not a continuation
blk = (t0 // 3600).astype(np.int64)
fold = ((blk * 2654435761) % (2 ** 32)) % 10
X = W[FE].to_numpy(np.float32)
g = W.groupby("hk", sort=False)[FE]
d1 = X - g.shift(1).to_numpy(np.float32)
d3 = X - g.shift(3).to_numpy(np.float32)
XX = np.hstack([X, d1, d3])
normal_now = (W["stage_id"].to_numpy() == 0) & quiet
tr, te = normal_now & (fold < 6), normal_now & (fold >= 8)
log(f"quiet normal rows: train {int(tr.sum()):,}   held-back test {int(te.sum()):,}")

wm = None
if not DRY:
    try:                                                    # saved world model on the same test rows
        sys.path.insert(0, str(REPO / "capture-service"))
        import world_model as f
        K = f.load_model()[0]["K"]
        Wt = W[fold >= 8].copy()
        Wt["host_ip"] = Wt["hk"]                            # keep hosts of different datasets apart
        r = f.run_model(Wt.reset_index(drop=True))[1][:, K - 1]
        wm = np.full(len(W), np.nan); wm[np.where(fold >= 8)[0]] = r
        log("world model scored")
    except Exception as e:
        log("world model not scored:", repr(e))

res = {}
for H in (60, 300, 600):
    y = (gap > 0) & (gap <= H)
    ytr, yte = y[tr], y[te]
    log(f"\n=== attack starts within {H} s ===   train positives {int(ytr.sum()):,} of {len(ytr):,}   test positives {int(yte.sum()):,} of {len(yte):,}")
    if DRY or ytr.sum() < 20 or yte.sum() < 10:
        continue
    try:
        import xgboost as xgb
        m = xgb.XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.08, subsample=0.8, colsample_bytree=0.6,
                              tree_method="hist", n_jobs=4, scale_pos_weight=float((~ytr).sum() / max(ytr.sum(), 1)),
                              eval_metric="logloss")
        m.fit(XX[tr], ytr); p = m.predict_proba(XX[te])[:, 1]; name = "xgboost"
    except ImportError:
        from sklearn.ensemble import HistGradientBoostingClassifier
        m = HistGradientBoostingClassifier(max_iter=300, max_depth=6, learning_rate=0.08, class_weight="balanced")
        m.fit(XX[tr], ytr); p = m.predict_proba(XX[te])[:, 1]; name = "hist-gbm"
    D = pd.DataFrame({"hk": W["hk"].to_numpy()[te], "sub": W["sub"].to_numpy()[te], "y": yte, "new": p})
    out = {"model": name, "test_rows": int(len(D)), "test_positives": int(yte.sum()), "pooled_auroc_new": auroc(D["y"], D["new"])}
    out["within_host_new"] = dict(zip(["hosts", "median", "weighted_mean"], within_host(D, "new")))
    if wm is not None and H == 60:
        D["wm"] = wm[te]
        out["pooled_auroc_world_model"] = auroc(D["y"], D["wm"])
        out["within_host_world_model"] = dict(zip(["hosts", "median", "weighted_mean"], within_host(D, "wm")))
    out["by_dataset"] = {s: {"rows": int(len(G)), "positives": int(G["y"].sum()), "pooled_new": auroc(G["y"], G["new"]),
                             "within_host_new": within_host(G, "new")} for s, G in D.groupby("sub")}
    res[H] = out
    log(json.dumps(out, indent=1))
(DIR / "logs").mkdir(exist_ok=True)
(DIR / "logs" / "timing_check.json").write_text(json.dumps(res, indent=1))
log("done")
