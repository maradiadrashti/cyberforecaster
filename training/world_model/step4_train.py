r"""
STEP 4 - train the world model v2 + baselines and evaluate honestly.

Run from PowerShell:
    python D:\ml-data\processed\step4_train.py --smoke      (3-5 min check that everything runs)
    python D:\ml-data\processed\step4_train.py              (real training)
Options:  --seeds 3   --epochs 30   --ablate   --windows PATH   --no-torch (only data + baselines)

What it does
  1. loads windows.pkl (73 features per host per 10 s), cleans and standardises them
  2. builds sequences: 10 windows of history -> forecasts for the next 6 windows
  3. splits by 1-hour TIME BLOCKS (60% train / 20% val / 20% test); a sequence never crosses a block.
     UNSW-NB15 is never trained on: it is the unseen network.
  4. trains baselines (persistence, logistic regression, XGBoost if installed)
  5. trains the LSTM world model with 3 heads:
        next-window features (Gaussian), stage of windows t..t+6, 'attack within k windows' (k=1..6)
  6. evaluates everything, incl. 'onset' sequences (history is all-normal: a TRUE early warning)
  7. saves model + metrics in D:\ml-data\processed\model_v2\
"""
import sys, json, time, argparse
from pathlib import Path
import numpy as np
import pandas as pd

ap = argparse.ArgumentParser()
ap.add_argument("--smoke", action="store_true")
ap.add_argument("--no-torch", action="store_true")
ap.add_argument("--ablate", action="store_true")
ap.add_argument("--groups", default="all", help="feature groups to use, e.g. volume,timing  (the CORE model for data without flags/packet info)")
ap.add_argument("--rollout", action="store_true", help="also run the (slow) sampled-futures rollout evaluation")
ap.add_argument("--unseen", default="unsw", help="dataset held out as the unseen network: unsw | cic2017 | cic2018 | ctu13 | dapt2020 | unraveled | none")
ap.add_argument("--train-unsw", action="store_true", help="same as --unseen none")
ap.add_argument("--seeds", type=int, default=1)
ap.add_argument("--baseline-only", action="store_true", help="only train + save the logistic-regression baseline (a few minutes), then stop; nothing else in the model folder is touched")
ap.add_argument("--v3", action="store_true", help="train also on hosts with a SHORT history (fewer than L windows) and give every attack stage a fairer share of the samples")
ap.add_argument("--v4", action="store_true", help="v3 + two extra outputs: 'an attack STARTS within 5 / 10 minutes', trained on quiet hosts (normal now, no attack in the last 5 minutes) and judged INSIDE each host (timing, not host identity)")
ap.add_argument("--netnorm", action="store_true", help="EXPERIMENT: standardise every network with its OWN statistics (unseen network: its earliest 30%% of traffic, no labels)")
ap.add_argument("--epochs", type=int, default=30)
ap.add_argument("--windows", default=None)
ap.add_argument("--L", type=int, default=10)
ap.add_argument("--K", type=int, default=6)
A = ap.parse_args()
if A.v4:
    A.v3 = True

DIR = Path(__file__).resolve().parent
UN = "none" if A.train_unsw else A.unseen
GTAG = "" if A.groups == "all" else "_groups-" + A.groups.replace(",", "-")
OUT = DIR / (("model_v4" if A.v4 else "model_v3" if A.v3 else "model_v2") + GTAG + ("_netnorm" if A.netnorm else "") + ("_smoke" if A.smoke else "") + f"_unseen-{UN}")
OUT.mkdir(exist_ok=True)
L, K, MAXGAP = A.L, A.K, 12            # MAXGAP: a host timeline breaks after 12 empty windows (120 s)
C = 6                                   # classes: normal, recon, initial_access, c2, lateral, exfil
KS = sorted({1, 3, K})
STAGES = ["normal", "reconnaissance", "initial_access", "command_control", "lateral_movement",
          "exfiltration", "other"]
CLASS_NAMES = STAGES[:6]


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# =========================================================== 1. load + clean
W = pd.read_pickle(A.windows or DIR / "windows.pkl")
G = json.loads((DIR / "feature_groups.json").read_text())
FEATS, GROUPS = G["features"], G["groups"]
W = W[W["t0"] < 1.7e9]                      # drops 10 junk windows dated 2026 (bad timestamps in DAPT)
if A.smoke:                                                    # keep 25% of hosts
    hk = W["source"] + "|" + W["host_ip"]
    hh = pd.util.hash_pandas_object(hk, index=False).values % 100
    W = W[(hh < 25) | hk.isin(set(hk[W["stage_id"] > 0]))]
W = W.sort_values(["source", "host_ip", "win"]).reset_index(drop=True)
N, F = len(W), len(FEATS)
log(f"windows: {N:,}   features: {F}   unseen dataset: {UN}")

blk = (W["t0"].values // 3600).astype(np.int64)
fold = ((blk * 2654435761) % (2 ** 32)) % 10
is_unsw = (W["sub"] == UN).values                       # the held-out ("unseen") dataset
split_w = np.where(is_unsw, "unseen", np.where(fold < 6, "train", np.where(fold < 8, "val", "test")))

# standardise using TRAIN windows only
X = W[FEATS].to_numpy(np.float32).copy()
tr = split_w == "train"
dtr = pd.DataFrame(X[tr])
log_idx = [j for j in range(F) if dtr[j].min() >= 0 and dtr[j].quantile(0.99) > 50]
for j in log_idx:
    X[:, j] = np.log1p(np.clip(X[:, j], 0, None))
with np.errstate(all="ignore"):
    mean, std = np.nanmean(X[tr], 0), np.nanstd(X[tr], 0)
mean, std = np.nan_to_num(mean).astype(np.float32), np.nan_to_num(std).astype(np.float32)
std[std < 1e-6] = 1.0
# a missing value (e.g. UNSW has no TCP flags) becomes 0 = the training mean, exactly what group dropout uses
Xs = np.nan_to_num(np.clip((X - mean) / std, -6, 6), nan=0.0).astype(np.float32)
if A.netnorm:
    # every network is measured against its OWN usual traffic, so "unusual for this network" means the same thing
    # everywhere. Reference rows: training networks -> their train windows; unseen network -> its earliest 30%
    # of windows by time (labels are NOT used). Features a network lacks fall back to the global statistics.
    _sub, _t0 = W["sub"].to_numpy(), W["t0"].to_numpy()
    for _s in pd.unique(_sub):
        _m = _sub == _s
        _ref = _m & ((_t0 <= np.quantile(_t0[_m], 0.30)) if _s == UN else tr)
        if _ref.sum() < 200:
            log(f"netnorm: {_s} has too few reference windows -> global statistics kept")
            continue
        with np.errstate(all="ignore"):
            _mu, _sd = np.nanmean(X[_ref], 0), np.nanstd(X[_ref], 0)
        _bad = (np.sum(~np.isnan(X[_ref]), 0) < 200) | ~np.isfinite(_mu) | ~np.isfinite(_sd) | (_sd < 1e-6)
        _mu, _sd = np.where(_bad, mean, _mu).astype(np.float32), np.where(_bad, std, _sd).astype(np.float32)
        Xs[_m] = np.nan_to_num(np.clip((X[_m] - _mu) / _sd, -6, 6), nan=0.0).astype(np.float32)
        log(f"netnorm: {_s:10s} reference windows {int(_ref.sum()):,}  features on own statistics {int((~_bad).sum())}/{F}")
med = np.zeros(F, np.float32)
del X
if A.groups != "all":                       # CORE model: keep only the chosen feature groups
    _g = [g.strip() for g in A.groups.split(",")]
    _idx = [FEATS.index(c) for g in _g for c in GROUPS[g]]
    Xs, mean, std = Xs[:, _idx], mean[_idx], std[_idx]
    log_idx = [_idx.index(j) for j in log_idx if j in _idx]
    FEATS, GROUPS = [FEATS[i] for i in _idx], {g: GROUPS[g] for g in _g}
    F = len(FEATS)
    log(f"CORE model: groups {_g} -> {F} features")

stage = W["stage_id"].to_numpy(np.int16)
atk = stage >= 1                       # attack window (incl. 'other')
cls_map = np.array([-100, 0, 1, 2, 3, 4, 5, -100], dtype=np.int64)     # index = stage_id+1
host_code = pd.factorize(W["source"] + "|" + W["host_ip"])[0]
win = W["win"].to_numpy(np.int64)
newseg = np.ones(N, bool)
newseg[1:] = (host_code[1:] != host_code[:-1]) | ((win[1:] - win[:-1]) > MAXGAP) | (blk[1:] != blk[:-1])
row = np.arange(N)
seg_start = np.maximum.accumulate(np.where(newseg, row, 0))
is_end = np.ones(N, bool)
is_end[:-1] = newseg[1:]
seg_end = np.minimum.accumulate(np.where(is_end, row, N)[::-1])[::-1]
valid_end = (row - seg_start >= L - 1) & (seg_end - row >= 1)
cs0 = np.concatenate([[0], np.cumsum(stage != 0)])
hist_normal = (cs0[row + 1] - cs0[np.maximum(row - L + 1, seg_start)]) == 0      # last L windows (of this host) all normal
rows_by = {s: np.where(valid_end & (split_w == s))[0] for s in ["train", "val", "test", "unseen"]}
if A.v3:      # TRAINING also uses windows whose host has fewer than L windows of history (as in short uploads).
    rows_by["train"] = np.where((seg_end - row >= 1) & (split_w == "train"))[0]      # val / test / unseen rows are unchanged
log("sequences:", {k: f"{len(v):,}" for k, v in rows_by.items()})


# ---- "an attack STARTS soon" targets (v4). Everything is kept inside the row's own 1-hour block, so a training
# row never reads a label from a validation / test hour.
SOON = [300, 600]                                    # seconds: outputs of the new head
T0S = W["t0"].to_numpy(np.float64)
BLK_START, BLK_END = blk * 3600.0, (blk + 1) * 3600.0
_blkkey = host_code.astype(np.int64) * 10_000_000 + (blk - blk.min())          # one key per host and hour block
NXT_ATT = pd.Series(np.where(atk, T0S, np.inf)[::-1]).groupby(_blkkey[::-1], sort=False).cummin().to_numpy()[::-1]
PRV_ATT = pd.Series(np.where(atk, T0S, -np.inf)).groupby(_blkkey, sort=False).cummax().to_numpy()
# quiet = normal now, no attack of this host in the previous 5 minutes, and those 5 minutes lie inside this block
QUIET = (stage == 0) & ((T0S - PRV_ATT) > 300) & ((T0S - BLK_START) >= 300)


def soon_targets(r, horizons=SOON):
    """y[:, j] = an attack of this host starts within horizons[j] seconds;  m = row may be used for that horizon
    (quiet row, and either the attack is seen or the whole horizon lies inside the hour block)."""
    gap = NXT_ATT[r] - T0S[r]
    y = np.stack([(gap > 0) & (gap <= H) for H in horizons], 1)
    known = np.stack([(T0S[r] + H) <= BLK_END[r] for H in horizons], 1)
    return y.astype(np.float32), QUIET[r][:, None] & (y | known)


def targets(r):
    """r: end-row indices -> dict of numpy targets"""
    fut = r[:, None] + np.arange(0, K + 1)
    valid = fut <= seg_end[r][:, None]
    futc = np.minimum(fut, N - 1)
    s = stage[futc]
    stage_t = np.where(valid, cls_map[s + 1], -100)
    a = (s >= 1) & valid
    u = (s == -1) | (~valid)
    anyA = np.maximum.accumulate(a[:, 1:], axis=1)
    anyU = np.maximum.accumulate(u[:, 1:], axis=1)
    first = r + np.argmax(a[:, 1:], axis=1) + 1                 # row of the first attack window ahead
    sy, sm = soon_targets(r)
    return dict(stage=stage_t, y=anyA.astype(np.float32), m=(anyA | ~anyU), fa=first,
                cur=atk[r], onset=hist_normal[r] & (stage[r] == 0), soon_y=sy, soon_m=sm)


def hist(r, fidx=None):
    h = np.maximum(r[:, None] + np.arange(-L + 1, 1), seg_start[r][:, None])   # short history: repeat the earliest window (same rule as world_model.py)
    x = Xs[h]
    return x if fidx is None else x[:, :, fidx]


# print split coverage so you can see if any attack stage is missing from a split
cov = pd.DataFrame({s: pd.Series(cls_map[stage[rows_by[s]] + 1]).map(
    lambda c: CLASS_NAMES[c] if c >= 0 else "other/ambiguous").value_counts() for s in rows_by}).fillna(0).astype(int)
log("current-stage windows at sequence ends, per split:\n" + cov.to_string())

# =========================================================== metrics helpers
from sklearn.metrics import average_precision_score, precision_recall_curve, f1_score, roc_auc_score


def best_thr(y, p):
    if y.sum() == 0 or np.ptp(p) == 0:        # no positives, or a constant score (e.g. persistence)
        return 0.5
    pr, rc, th = precision_recall_curve(y, p)
    f = 2 * pr * rc / np.maximum(pr + rc, 1e-9)
    return float(th[max(0, min(np.argmax(f[:-1]), len(th) - 1))])


def met(y, p, thr):
    pred = p >= thr
    tp, fp = int((pred & (y == 1)).sum()), int((pred & (y == 0)).sum())
    fn, tn = int((~pred & (y == 1)).sum()), int((~pred & (y == 0)).sum())
    pre, rec = tp / max(tp + fp, 1), tp / max(tp + fn, 1)
    return dict(n=int(len(y)), pos=int(y.sum()), precision=round(pre, 4), recall=round(rec, 4),
                f1=round(2 * pre * rec / max(pre + rec, 1e-9), 4), fpr=round(fp / max(fp + tn, 1), 4),
                ap=round(float(average_precision_score(y, p)), 4) if y.sum() > 0 else None,
                auroc=round(float(roc_auc_score(y, p)), 4) if 0 < y.sum() < len(y) and np.ptp(p) > 0 else None)


RESULTS, THR = {}, {}
TIME = W["t0"].to_numpy()          # window start time of every row (used for per-network calibration)


def _calibrated(name, P, T, rows, tag, q=0.99):
    """Per-network calibration on the UNSEEN network: the alert threshold is set from that network's OWN
    earliest 30% of traffic (its normal sequences only, 1% false-alarm budget); scores are then judged on the
    remaining 70%. No training-network threshold is used. The calibration part is excluded from the numbers."""
    tt = TIME[rows]
    cal = tt <= np.quantile(tt, 0.30)
    for k in KS:
        y, m, p = T["y"][:, k - 1], T["m"][:, k - 1], P[:, k - 1]
        negcal = cal & m & (y == 0)
        if negcal.sum() < 50:
            continue
        thr = float(np.quantile(p[negcal], q))
        for subset, sm in [("all", m), ("onset", m & T["onset"])]:
            base = sm & ~cal
            if base.sum() == 0:
                continue
            res = met(y[base], p[base], thr)
            if subset == "onset":
                pos = base & (y == 1)
                res["events"] = int(len(np.unique(T["fa"][pos])))
                res["warned_events"] = int(len(np.unique(T["fa"][pos & (p >= thr)])))
            RESULTS.setdefault("unseen_calibrated" + tag, {}).setdefault(name, {})[f"k{k}_{subset}"] = res


def evaluate(split, rows, scorers, tag=""):
    T = targets(rows)
    for name, fn in scorers.items():
        P = np.maximum.accumulate(fn(rows), axis=1)                 # risk can only grow with k
        for k in KS:
            y, m, p = T["y"][:, k - 1], T["m"][:, k - 1], P[:, k - 1]
            for subset, sm in [("all", m), ("onset", m & T["onset"])]:
                if sm.sum() == 0:
                    continue
                key = (name, k, subset)
                if split == "val":
                    THR[key] = best_thr(y[sm], p[sm])
                thr = THR.get(key, 0.5)
                res = met(y[sm], p[sm], thr)
                if subset == "onset":            # count distinct attack onsets that were warned about in time
                    pos = sm & (y == 1)
                    res["events"] = int(len(np.unique(T["fa"][pos])))
                    res["warned_events"] = int(len(np.unique(T["fa"][pos & (p >= thr)])))
                RESULTS.setdefault(split + tag, {}).setdefault(name, {})[f"k{k}_{subset}"] = res
        if split == "unseen":
            _calibrated(name, P, T, rows, tag)


def show(split, k=K, subset="onset"):
    print(f"\n--- {split}  |  attack within next {k} windows  |  {subset} sequences "
          f"({'history all normal = true early warning' if subset == 'onset' else 'all'})")
    print(f"{'model':22s}{'prec':>8s}{'recall':>8s}{'F1':>8s}{'FPR':>8s}{'AP':>8s}{'AUROC':>8s}{'#pos':>8s}{'onsets warned':>16s}")
    for name, d in RESULTS.get(split, {}).items():
        r = d.get(f"k{k}_{subset}")
        if r:
            print(f"{name:22s}{r['precision']:>8.3f}{r['recall']:>8.3f}{r['f1']:>8.3f}{r['fpr']:>8.3f}"
                  f"{(r['ap'] if r['ap'] is not None else float('nan')):>8.3f}"
                  f"{(r['auroc'] if r.get('auroc') is not None else float('nan')):>8.3f}{r['pos']:>8d}"
                  f"{(str(r['warned_events']) + '/' + str(r['events'])) if 'events' in r else '-':>16s}")


# =========================================================== 2. baselines
rng = np.random.default_rng(0)
trr = rows_by["train"]
Tt = targets(trr)
pos_mask = (Tt["y"][:, K - 1] == 1) & Tt["m"][:, K - 1]
neg_mask = (Tt["y"][:, K - 1] == 0) & Tt["m"][:, K - 1]
pos_idx = np.where(pos_mask)[0]
neg_idx = np.where(neg_mask)[0]
log(f"train sequences: positives {len(pos_idx):,}  negatives {len(neg_idx):,}")
pos_on = np.where(pos_mask & Tt["onset"])[0]
pos_oth = np.where(pos_mask & ~Tt["onset"])[0]
log(f"train onset events (history normal -> attack within {K}): {len(pos_on):,}")
sel = np.concatenate([pos_on, rng.choice(pos_oth, min(len(pos_oth), 60_000), replace=False),
                      rng.choice(neg_idx, min(len(neg_idx), 250_000), replace=False)])
btr_rows, btr_y = trr[sel], Tt["y"][sel, K - 1]


def chunked(fn, rows, bs=50_000):
    return np.concatenate([fn(rows[i:i + bs]) for i in range(0, len(rows), bs)])


def sk_scorer(model, flat):
    def f(rows):
        def one(r):
            x = hist(r)
            x = x.reshape(len(r), -1) if flat else x[:, -1]
            p = model.predict_proba(x)[:, 1]
            return np.tile(p[:, None], (1, K))        # trained on k=K; same score for every k
        return chunked(one, rows)
    return f


scorers = {"persistence(oracle)": lambda r: np.tile(atk[r][:, None].astype(float), (1, K))}
if len(pos_idx) >= 10:
    from sklearn.linear_model import LogisticRegression
    for nm, flat in [("LogReg last window", False), ("LogReg 10 windows", True)]:
        log("training", nm)
        xb = hist(btr_rows)
        xb = xb.reshape(len(btr_rows), -1) if flat else xb[:, -1]
        m = LogisticRegression(max_iter=150, class_weight="balanced", C=0.5).fit(xb, btr_y)
        scorers[nm] = sk_scorer(m, flat)
        if flat:      # save the baseline so the dashboard can draw it next to the world model (same inputs)
            try:
                (OUT / "baseline_lr.json").write_text(json.dumps({
                    "name": nm, "target": f"attack within {K} windows", "L": L, "n_features": int(Xs.shape[1]),
                    "features": FEATS, "input": "last L standardised windows, flattened oldest->newest",
                    "coef": [round(float(v), 6) for v in m.coef_[0]], "intercept": float(m.intercept_[0])}))
                log("saved", OUT / "baseline_lr.json")
            except Exception as e:
                log("!! could not save the baseline:", repr(e))
    if A.baseline_only:
        log("--baseline-only: done")
        sys.exit(0)
    try:
        import xgboost as xgb
        log("training XGBoost 10 windows")
        xb = hist(btr_rows).reshape(len(btr_rows), -1)
        m = xgb.XGBClassifier(n_estimators=200 if not A.smoke else 30, max_depth=6, learning_rate=0.1,
                              subsample=0.8, colsample_bytree=0.5, tree_method="hist",
                              scale_pos_weight=max(1.0, (btr_y == 0).sum() / max(btr_y.sum(), 1)) ** 0.5)
        m.fit(xb, btr_y)
        scorers["XGBoost 10 windows"] = sk_scorer(m, True)
    except ImportError:
        log("xgboost not installed -> skipped (pip install xgboost to include it)")
else:
    log("!! fewer than 10 positive training sequences - baselines skipped")


def run_eval(scorers, tag=""):
    for s in ["val", "test", "unseen"]:
        if len(rows_by[s]):
            evaluate(s, rows_by[s], scorers, tag)


# =========================================================== 3. world model
def train_world_model(fidx, seed, epochs, steps, tag):
    import torch, torch.nn as nn, torch.nn.functional as Fn
    torch.manual_seed(seed)
    np.random.seed(seed)
    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    nf = len(fidx)
    inv = {j: i for i, j in enumerate(fidx)}
    gmat = np.zeros((len(GROUPS), nf), np.float32)
    for gi, (g, cols) in enumerate(GROUPS.items()):
        for c in cols:
            if FEATS.index(c) in inv:
                gmat[gi, inv[FEATS.index(c)]] = 1
    gmat_t = torch.tensor(gmat, device=dev)
    DROP = {"volume": 0.05, "timing": 0.20, "flags": 0.40, "ports": 0.15, "packet": 0.40}
    pdrop = torch.tensor([DROP.get(g, 0.2) for g in GROUPS], device=dev)

    class WM(nn.Module):
        def __init__(s, H=128):
            super().__init__()
            s.lstm = nn.LSTM(nf, H, 2, batch_first=True, dropout=0.3)
            s.mu, s.ls = nn.Linear(H, nf), nn.Linear(H, nf)
            s.stage = nn.Linear(H, (K + 1) * C)
            s.within = nn.Linear(H, K)
            if A.v4:
                s.soon = nn.Linear(H, len(SOON))

        def forward(s, x):
            h = s.lstm(x)[0][:, -1]
            out = (x[:, -1] + s.mu(h), s.ls(h).clamp(-5, 2),
                   s.stage(h).view(-1, K + 1, C), s.within(h))
            return out + ((s.soon(h),) if A.v4 else ())

    model = WM().to(dev)
    opt = torch.optim.AdamW(model.parameters(), 1e-3, weight_decay=1e-4)
    # sampler weights: enrich attack-related sequences to ~30%
    T = targets(trr)
    yk = (T["y"][:, K - 1] == 1) & T["m"][:, K - 1]
    g_on = T["onset"] & yk                                   # true onsets: normal history -> attack
    g_att = (~g_on) & (yk | T["cur"])                        # attack already running / continuing
    g_rest = ~(g_on | g_att)
    groups_ = [(g_on, 0.15), (g_att, 0.25), (g_rest, 0.60)]
    if A.v4:      # v4: quiet rows shortly BEFORE an attack start, and quiet rows of the same hosts at other times
        _has_att = np.bincount(host_code[atk & (split_w == "train")], minlength=host_code.max() + 1) > 0
        g_soon = (T["soon_y"][:, -1] == 1) & T["soon_m"][:, -1] & g_rest
        g_hard = (T["soon_y"][:, -1] == 0) & T["soon_m"][:, -1] & _has_att[host_code[trr]] & g_rest
        g_rest = g_rest & ~(g_soon | g_hard)
        groups_ = [(g_on, 0.15), (g_att, 0.25), (g_soon, 0.08), (g_hard, 0.12), (g_rest, 0.40)]
        log(f"v4 sampler groups: attack starts within {SOON[-1]} s {g_soon.sum():,}  same hosts, no start {g_hard.sum():,}")
    wgt = np.zeros(len(trr))
    for g, share in groups_:
        if g.sum() > 0 and A.v3 and g is g_att:      # rarer attack stages get a fairer share (weight ~ 1/sqrt(count))
            _st0, _w = T["stage"][:, 0], np.zeros(len(trr))
            for _c in np.unique(_st0[g]):
                _mc = g & (_st0 == _c)
                _w[_mc] = 1.0 / np.sqrt(_mc.sum())
            wgt[g] = share * _w[g] / _w[g].sum()
        elif g.sum() > 0:
            wgt[g] = share / g.sum()
    wgt /= wgt.sum()
    log(f"sampler groups: onset {g_on.sum():,}  attack-ongoing {g_att.sum():,}  normal {g_rest.sum():,}")
    cnt = np.bincount(T["stage"][:, 0][T["stage"][:, 0] >= 0], minlength=C).astype(float) + 1
    cw = torch.tensor((cnt.sum() / (C * cnt)) ** 0.5, dtype=torch.float32, device=dev)
    cw = cw / cw.mean()

    def batch(r, train):
        x = torch.tensor(hist(r, fidx), device=dev)
        t = targets(r)
        nxt = torch.tensor(Xs[r + 1][:, fidx], device=dev)
        if train:
            keep = (torch.rand(len(r), len(GROUPS), device=dev) > pdrop).float()      # group dropout
            x = x * (keep @ gmat_t).unsqueeze(1).clamp(0, 1)
        return x, nxt, torch.tensor(t["stage"], device=dev), torch.tensor(t["y"], device=dev), \
            torch.tensor(t["m"], device=dev).float(), torch.tensor(t["soon_y"], device=dev), \
            torch.tensor(t["soon_m"], device=dev).float()

    def loss_fn(out, nxt, st, y, m, sy, sm):
        mu, ls, sl, wl = out[:4]
        l_next = (0.5 * (2 * ls + (nxt - mu) ** 2 * torch.exp(-2 * ls))).mean()
        l_stage = Fn.cross_entropy(sl.reshape(-1, C), st.reshape(-1), weight=cw, ignore_index=-100)
        l_in = (Fn.binary_cross_entropy_with_logits(wl, y, reduction="none") * m).sum() / m.sum().clamp(min=1)
        l_soon = wl.sum() * 0.0
        if A.v4:
            l_soon = (Fn.binary_cross_entropy_with_logits(out[4], sy, reduction="none") * sm).sum() / sm.sum().clamp(min=1)
        return l_stage + l_in + 0.2 * l_next + l_soon, (l_stage.item(), l_in.item(), l_next.item(), float(l_soon.item()))

    @torch.no_grad()
    def predict(rows, bs=4096):
        model.eval()
        outs = []
        for i in range(0, len(rows), bs):
            x = torch.tensor(hist(rows[i:i + bs], fidx), device=dev)
            outs.append(torch.sigmoid(model(x)[3]).cpu().numpy())
        return np.concatenate(outs)

    @torch.no_grad()
    def predict_soon(rows, bs=4096):
        model.eval()
        outs = []
        for i in range(0, len(rows), bs):
            x = torch.tensor(hist(rows[i:i + bs], fidx), device=dev)
            outs.append(torch.sigmoid(model(x)[4]).cpu().numpy())
        return np.concatenate(outs)

    vrows = rows_by["val"]
    if len(vrows) > 120_000:
        vrows = np.sort(np.random.default_rng(1).choice(vrows, 120_000, replace=False))
    Tv = targets(vrows)

    def val_score():
        P = np.maximum.accumulate(predict(vrows), axis=1)
        sc = []
        for sm in [Tv["m"][:, K - 1], Tv["m"][:, K - 1] & Tv["onset"]]:
            y = Tv["y"][sm, K - 1]
            if y.sum() > 0:
                sc.append(average_precision_score(y, P[sm, K - 1]))
        if A.v4:                                   # the new head counts too when choosing the best epoch
            ms = Tv["soon_m"][:, 0]
            if Tv["soon_y"][ms, 0].sum() > 0:
                sc.append(average_precision_score(Tv["soon_y"][ms, 0], predict_soon(vrows)[ms, 0]))
        return float(np.mean(sc)) if sc else None

    best, best_state, bad = -1, None, 0
    for ep in range(1, epochs + 1):
        model.train()
        tl = []
        draw = np.random.choice(len(trr), steps * 512, p=wgt)
        for st_i in range(steps):
            r = trr[draw[st_i * 512:(st_i + 1) * 512]]
            x, nxt, st, y, m, sy, sm = batch(r, True)
            loss, parts = loss_fn(model(x), nxt, st, y, m, sy, sm)
            opt.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            tl.append(parts)
        vs = val_score()
        if vs is None:                     # no attack in validation set: fall back to training loss
            vs = -float(np.mean([p_[0] + p_[1] for p_ in tl]))
        log(f"[{tag} seed{seed}] epoch {ep:02d}  stage {np.mean([p_[0] for p_ in tl]):.3f}  "
            f"within {np.mean([p_[1] for p_ in tl]):.3f}  next {np.mean([p_[2] for p_ in tl]):.3f}  "
            f"soon {np.mean([p_[3] for p_ in tl]):.3f}  val-AP {vs:.4f}")
        if vs > best:
            best, bad = vs, 0
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= 6:
                log("early stop")
                break
    model.load_state_dict(best_state)
    model.eval()

    # ---------- rollout: sample 32 futures, risk = share of futures that reach an attack stage
    @torch.no_grad()
    def rollout(rows, S=32, bs=256):
        res = []
        for i in range(0, len(rows), bs):
            r = rows[i:i + bs]
            B = len(r)
            x = torch.tensor(hist(r, fidx), device=dev).repeat_interleave(S, 0)
            hit = torch.zeros(B * S, dtype=torch.bool, device=dev)
            risk = []
            out = model(x)
            for _ in range(K):
                mu, ls = out[0], out[1]
                new = mu + torch.exp(ls) * torch.randn_like(mu)
                x = torch.cat([x[:, 1:], new.unsqueeze(1)], 1)
                out = model(x)
                s = torch.distributions.Categorical(logits=out[2][:, 0]).sample()
                hit |= s != 0
                risk.append(hit.float().view(B, S).mean(1))
            res.append(torch.stack(risk, 1).cpu().numpy())
        return np.concatenate(res)

    return model, predict, rollout, best, {k: v for k, v in best_state.items()}, dev, predict_soon


if not A.no_torch:
    epochs, steps = (2, 40) if A.smoke else (A.epochs, 300)
    all_idx = list(range(F))
    runs = []
    for seed in range(A.seeds):
        runs.append(train_world_model(all_idx, seed, epochs, steps, "WM73"))   # (model, predict, rollout, vscore, state, dev)
    bi = int(np.argmax([r[3] for r in runs]))
    model, predict, rollout, vscore, state, dev = runs[bi][:6]
    log("val score per seed:", [round(r[3], 4) for r in runs], "-> best seed", bi)
    scorers_wm = dict(scorers)
    scorers_wm["WORLD MODEL (head)"] = predict
    for i, r in enumerate(runs):                      # every seed is evaluated on its own (to show the run-to-run spread)
        scorers_wm[f"WM seed{i}"] = r[1]
    if len(runs) > 1:
        scorers_wm[f"WORLD MODEL (ensemble of {len(runs)})"] = lambda rows: np.mean([r[1](rows) for r in runs], axis=0)
    log("evaluating")
    run_eval(scorers_wm)
    if A.rollout:
        sub = {s: np.sort(np.random.default_rng(2).choice(rows_by[s], min(len(rows_by[s]), 3000 if A.smoke else 12000),
                                                            replace=False)) for s in ['val', 'test', 'unseen'] if len(rows_by[s])}
        for s, rr in sub.items():
            evaluate(s, rr, {"WORLD MODEL (rollout)": rollout, "WORLD MODEL (head, same rows)": predict}, tag="_rollout_subset")
    # stage accuracy of the stage head
    import torch
    @torch.no_grad()
    def stage_pred(rows, k):
        out = []
        for i in range(0, len(rows), 4096):
            x = torch.tensor(hist(rows[i:i + 4096]), device=next(model.parameters()).device)
            out.append(model(x)[2][:, k].argmax(-1).cpu().numpy())
        return np.concatenate(out)
    for s in ["test", "unseen"]:
        if len(rows_by[s]) == 0:
            continue
        T = targets(rows_by[s])
        for k in [0, 1]:
            ok = T["stage"][:, k] >= 0
            if ok.sum() == 0:
                continue
            p = stage_pred(rows_by[s], k)
            labs = sorted(set(T["stage"][ok, k]))
            RESULTS.setdefault(s, {}).setdefault("stage_head", {})[f"macroF1_t+{k}"] = round(
                float(f1_score(T["stage"][ok, k], p[ok], labels=labs, average="macro")), 4)
            RESULTS[s]["stage_head"][f"per_class_recall_t+{k}"] = {
                CLASS_NAMES[c]: round(float((p[ok][T["stage"][ok, k] == c] == c).mean()), 3) for c in labs}
            if k == 0:                         # diagnostic: which dataset / which wrong class each stage's misses come from
                try:
                    _sub = W["sub"].to_numpy()[rows_by[s]][ok]
                    _y, _p = T["stage"][ok, k], p[ok]
                    RESULTS[s]["stage_head"]["recall_by_dataset_t+0"] = {
                        CLASS_NAMES[c]: {str(d): [round(float((_p[(_y == c) & (_sub == d)] == c).mean()), 3),
                                                  int(((_y == c) & (_sub == d)).sum())]
                                         for d in pd.unique(_sub[_y == c])} for c in labs}
                    RESULTS[s]["stage_head"]["predicted_as_t+0"] = {
                        CLASS_NAMES[c]: {CLASS_NAMES[int(q)]: int(n) for q, n in
                                         zip(*np.unique(_p[_y == c], return_counts=True))} for c in labs}
                except Exception as e:
                    log("stage diagnostic skipped:", repr(e))
    # ---------- TIMING: can the model tell WHEN an attack starts, inside one host? (quiet rows only)
    SOON_META = {}
    try:
        def _within_host(hk, y, p):
            keep = np.isin(hk, np.unique(hk[y == 1]))            # only hosts that have at least one start
            vals, wts = [], []
            for _, g_ in pd.DataFrame({"h": hk[keep], "y": y[keep], "p": p[keep]}).groupby("h", sort=False):
                yy, pp = g_["y"].to_numpy(), g_["p"].to_numpy()
                if 0 < yy.sum() < len(yy) and np.ptp(pp) > 0:
                    vals.append(roc_auc_score(yy, pp)); wts.append(int(yy.sum()))
            if not vals:
                return {"hosts": 0, "median": None, "weighted_mean": None}
            return {"hosts": len(vals), "median": round(float(np.median(vals)), 4),
                    "weighted_mean": round(float(np.average(vals, weights=wts)), 4)}

        HZ = [60] + SOON
        # name -> (function giving scores for rows, {horizon: column of that output or None})
        sc_models = {"WORLD MODEL 60 s risk": (
            lambda rows: np.maximum.accumulate(np.mean([r[1](rows) for r in runs], axis=0), axis=1)[:, K - 1],
            {H: None for H in HZ})}
        if A.v4:
            sc_models["WORLD MODEL start-soon head"] = (lambda rows: np.mean([r[6](rows) for r in runs], axis=0),
                                                        {H: j for j, H in enumerate(SOON)})
        try:                                               # tree baseline on the same rows (also saved to disk)
            import xgboost as xgb
            _y, _m = soon_targets(trr)
            for _j, _H in enumerate(SOON):
                _pos, _neg = np.where(_m[:, _j] & (_y[:, _j] == 1))[0], np.where(_m[:, _j] & (_y[:, _j] == 0))[0]
                if len(_pos) < 20:
                    continue
                _sel = np.concatenate([_pos, rng.choice(_neg, min(len(_neg), 250_000), replace=False)])
                _xm = xgb.XGBClassifier(n_estimators=200 if not A.smoke else 30, max_depth=6, learning_rate=0.1, subsample=0.8,
                                        colsample_bytree=0.5, tree_method="hist",
                                        scale_pos_weight=max(1.0, len(_sel) / max(len(_pos), 1)) ** 0.5)
                _xm.fit(hist(trr[_sel]).reshape(len(_sel), -1), _y[_sel, _j])
                try:
                    _xm.save_model(str(OUT / f"timing_xgb_{_H}.json"))
                except Exception as e:
                    log("could not save the tree timing model:", repr(e))
                sc_models[f"XGBoost 10 windows (start within {_H} s)"] = (
                    lambda rows, _xm=_xm: chunked(lambda r: _xm.predict_proba(hist(r).reshape(len(r), -1))[:, 1], rows), {_H: None})
                log(f"tree timing model for {_H} s trained on {len(_sel):,} rows ({len(_pos):,} positives)")
        except ImportError:
            pass
        TIMING, _thr = {}, {}
        for s in ["val", "test"]:
            rows = rows_by[s]
            if len(rows) == 0:
                continue
            Y, M = soon_targets(rows, HZ)
            hk, sub_ = host_code[rows], W["sub"].to_numpy()[rows]
            for name, (fn, cols) in sc_models.items():
                P_ = fn(rows)
                for H, col in cols.items():
                    j = HZ.index(H)
                    ok = M[:, j]
                    y = Y[ok, j]
                    if y.sum() == 0 or y.sum() == len(y):
                        continue
                    p = (P_ if col is None else P_[:, col])[ok]
                    if s == "val":
                        _thr[(name, H)] = best_thr(y, p)
                    res = met(y, p, _thr.get((name, H), 0.5))
                    res["threshold"] = round(float(_thr.get((name, H), 0.5)), 4)
                    res["within_host"] = _within_host(hk[ok], y, p)
                    res["by_dataset"] = {str(d): {"rows": int((sub_[ok] == d).sum()), "positives": int(y[sub_[ok] == d].sum()),
                                                  "within_host": _within_host(hk[ok][sub_[ok] == d], y[sub_[ok] == d], p[sub_[ok] == d])}
                                         for d in pd.unique(sub_[ok])}
                    TIMING.setdefault(s, {}).setdefault(name, {})[f"start_within_{H}s"] = res
            log(f"timing evaluated on {s}")
        RESULTS["timing"] = TIMING
        if A.v4 and "test" in TIMING and "WORLD MODEL start-soon head" in TIMING["test"]:
            for H in SOON:
                r_ = TIMING["test"]["WORLD MODEL start-soon head"].get(f"start_within_{H}s")
                if r_:
                    SOON_META[str(H)] = {"threshold": r_["threshold"], "test_precision": r_["precision"], "test_recall": r_["recall"],
                                         "test_fpr": r_["fpr"], "test_auroc": r_["auroc"], "test_positives": r_["pos"],
                                         "test_within_host": r_["within_host"]}
    except Exception as e:
        import traceback
        log("timing evaluation failed:", repr(e))
        traceback.print_exc()
    if A.ablate:
        for nm, groups in [("volume+timing", ["volume", "timing"]),
                           ("+flags+ports", ["volume", "timing", "flags", "ports"])]:
            fi = [FEATS.index(c) for g in groups for c in GROUPS[g]]
            log(f"ablation: {nm} ({len(fi)} features)")
            m2, p2 = train_world_model(fi, 0, epochs, steps, nm)[:2]
            for s in ["val", "test", "unseen"]:
                if len(rows_by[s]):
                    evaluate(s, rows_by[s], {f"WM {nm} ({len(fi)})": p2}, "_ablation")
    import torch
    torch.save({"states": [r[4] for r in runs], "best": bi}, OUT / "world_model.pt")
    meta = dict(features=FEATS, groups=GROUPS, log_idx=log_idx, nan_fill="zero_after_standardise", v3=bool(A.v3), netnorm=bool(A.netnorm),
                v4=bool(A.v4), soon_horizons=(SOON if A.v4 else []), soon=SOON_META, mean=mean.tolist(),
                std=std.tolist(), L=L, K=K, classes=CLASS_NAMES, hidden=128, layers=2,
                thresholds={f"{a}|{b}|{c}": v for (a, b, c), v in THR.items() if a.startswith("WORLD MODEL")},
                mitre=json.loads((DIR / "mitre_map.json").read_text()))
    (OUT / "world_model_meta.json").write_text(json.dumps(meta))
else:
    log("--no-torch: evaluating baselines only")
    run_eval(scorers)

(OUT / "results.json").write_text(json.dumps(RESULTS, indent=1))
for s in ["val", "test", "unseen"]:
    for sub_ in ["onset", "all"]:
        show(s, K, sub_)
if "unseen_calibrated" in RESULTS:
    print("\n##### UNSEEN NETWORK, THRESHOLD CALIBRATED ON ITS OWN EARLIEST 30% (normal traffic, 1% false-alarm budget);"
          " numbers below are on the remaining 70% #####")
    show("unseen_calibrated", K, "onset")
    show("unseen_calibrated", K, "all")
for tag in ["_rollout_subset", "_ablation"]:
    for s in ["test", "unseen"]:
        if s + tag in RESULTS:
            show(s + tag, K, "onset")
            show(s + tag, K, "all")
if "timing" in RESULTS and "test" in RESULTS["timing"]:
    print("\n##### TIMING on quiet hosts (normal now, no attack in the last 5 min), held-back hours."
          " 'within-host' = AUROC inside each host: 0.5 = no timing, 1.0 = perfect #####")
    print(f"{'model':42s}{'horizon':>9s}{'rows':>9s}{'#pos':>7s}{'AUROC':>8s}{'in-host':>9s}{'hosts':>7s}{'prec':>7s}{'recall':>8s}{'FPR':>7s}")
    for name, d in RESULTS["timing"]["test"].items():
        for hk_, r in d.items():
            wh = r["within_host"]
            print(f"{name:42s}{hk_.replace('start_within_', ''):>9s}{r['n']:>9d}{r['pos']:>7d}"
                  f"{(r['auroc'] if r['auroc'] is not None else float('nan')):>8.3f}"
                  f"{(wh['weighted_mean'] if wh['weighted_mean'] is not None else float('nan')):>9.3f}{wh['hosts']:>7d}"
                  f"{r['precision']:>7.3f}{r['recall']:>8.3f}{r['fpr']:>7.3f}")
if "test" in RESULTS and "stage_head" in RESULTS["test"]:
    print("\nstage head (test):", json.dumps(RESULTS["test"]["stage_head"], indent=1))
    if "unseen" in RESULTS:
        print(f"stage head (unseen {UN}):", json.dumps(RESULTS["unseen"].get("stage_head", {}), indent=1))
names = [n for n in RESULTS.get("test", {}) if n.startswith("WM seed")]
if len(names) >= 2:
    print(f"\n=== run-to-run spread over {len(names)} seeds (same data, same settings, different random start) ===")
    for label, split, key, field in [("test onset AUROC", "test", f"k{K}_onset", "auroc"),
                                     ("test onsets warned", "test", f"k{K}_onset", "warned_events"),
                                     ("test all-seq F1", "test", f"k{K}_all", "f1"),
                                     ("unseen-net AUROC", "unseen", f"k{K}_all", "auroc"),
                                     ("unseen-net F1", "unseen", f"k{K}_all", "f1")]:
        v = [RESULTS[split][n][key][field] for n in names
             if split in RESULTS and key in RESULTS[split].get(n, {}) and RESULTS[split][n][key].get(field) is not None]
        if v:
            print(f"{label:22s} mean {np.mean(v):.3f}  std {np.std(v):.3f}  min {min(v):.3f}  max {max(v):.3f}  (n={len(v)})")
log("DONE - everything is in", OUT)
