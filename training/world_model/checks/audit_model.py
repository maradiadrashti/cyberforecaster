r"""Model-level audit: recompute the model's outputs for test files A-D with SEPARATE code (own preprocessing, own
network definition, own occlusion loop) and compare them with what the dashboard backend (world_model.analyze) returns.
Also compares the window features of an upload with the features the model was trained on (windows.pkl)."""
import os as _os
from pathlib import Path as _P
REPO = _P(_os.environ.get("CYBERFORECASTER_REPO") or _P(__file__).resolve().parents[3])   # repository root
import sys, json, math
from pathlib import Path
import numpy as np, pandas as pd, torch, torch.nn as nn
sys.path.insert(0, str(REPO / "capture-service"))
import world_model as f
MD = Path(str(REPO / "models" / "world_model"))
T = Path(str(REPO / "samples" / "test_files"))
HERE = Path(__file__).resolve().parent
meta = json.loads((MD / "world_model_meta.json").read_text()); ck = torch.load(MD / "world_model.pt", map_location="cpu")
FE, L, K, CL = meta["features"], meta["L"], meta["K"], meta["classes"]; nf, C = len(FE), len(CL); SOON = meta.get("soon_horizons") or []
thr = [v for k, v in meta["thresholds"].items() if k.startswith("WORLD MODEL (ensemble") and k.endswith(f"|{K}|all")][0]

class Net(nn.Module):                      # written separately from world_model.py; the saved weights must fit it exactly
    def __init__(s):
        super().__init__()
        s.lstm = nn.LSTM(input_size=nf, hidden_size=128, num_layers=2, batch_first=True, dropout=0.3)
        s.mu = nn.Linear(128, nf); s.ls = nn.Linear(128, nf)
        s.stage = nn.Linear(128, (K + 1) * C); s.within = nn.Linear(128, K)
        if SOON: s.soon = nn.Linear(128, len(SOON))
nets = []
for st in ck["states"]:
    n_ = Net(); n_.load_state_dict(st, strict=True); n_.eval(); nets.append(n_)

@torch.no_grad()
def forward(xb):                           # xb: (B, L, F) numpy -> per-copy outputs
    x = torch.tensor(xb, dtype=torch.float32); outs = []
    for n_ in nets:
        h = n_.lstm(x)[0][:, -1, :]
        outs.append((torch.sigmoid(n_.within(h)).numpy(), torch.softmax(n_.stage(h).reshape(-1, K + 1, C), -1).numpy(),
                     torch.sigmoid(n_.soon(h)).numpy() if SOON else None))
    return outs

stat, fails = {}, []
def chk(k, ok, d=""):
    s = stat.setdefault(k, [0, 0]); s[0] += 1
    if not ok:
        s[1] += 1
        if len([x for x in fails if x[0] == k]) < 4: fails.append((k, d))
def close(a, b, t=3e-4): return abs(float(a) - float(b)) <= t

WP = None
FILES = {"A_cic2017_friday_ddos_onset.csv": None, "B_cic2018_ftp_bruteforce_onset.csv": ("merged", ["18.221.219.4", "172.31.69.25"]),
         "C_ctu13_botnet_c2_forecast.csv": ("merged", ["147.32.84.165"]), "D_unraveled_exfiltration_forecast.csv": ("unraveled", ["10.1.3.17", "10.1.3.8"])}
for name, train_ref in FILES.items():
    R = f.analyze(str(T / name)); Ch = R["chart"]
    (HERE / "audit").mkdir(exist_ok=True); (HERE / "audit" / (name[0] + "_cli_v2.json")).write_text(json.dumps(R))
    chk("alert threshold", close(Ch["threshold"], thr, 1e-9))
    fl, kind, notes = f.load_flows(str(T / name)); W, has_labels = f.build_windows(fl)
    X = W[FE].to_numpy(np.float64).copy()
    for j in meta["log_idx"]: X[:, j] = np.log1p(np.clip(X[:, j], 0, None))
    Xs = np.clip((X - np.array(meta["mean"])) / np.array(meta["std"]), -6, 6); Xs[np.isnan(Xs)] = 0.0
    hosts, win = W["host_ip"].to_numpy(), W["win"].to_numpy(); seg = np.zeros(len(W), int)
    for i in range(1, len(W)): seg[i] = seg[i - 1] if (hosts[i] == hosts[i - 1] and win[i] - win[i - 1] <= 12) else i
    hist = lambda i: [max(i - L + 1 + k, seg[i]) for k in range(L)]
    for ip, H in Ch["hosts"].items():
        idx = np.where(hosts == ip)[0]
        outs = forward(np.stack([Xs[hist(i)] for i in idx]))
        pm = np.stack([o[0] for o in outs]); risk = np.maximum.accumulate(pm.mean(0), axis=1)
        lo, hi = np.maximum.accumulate(pm.min(0), axis=1), np.maximum.accumulate(pm.max(0), axis=1)
        stg = np.stack([o[1] for o in outs]).mean(0)
        for a in range(len(idx)):
            chk("risk within 60 s", close(H["risk_60s"][a], risk[a, K - 1]), f"{name[0]} {ip} w{a}: {H['risk_60s'][a]} vs {risk[a, K-1]:.4f}")
            chk("forecast curve (10..60 s)", all(close(H["forecast_curve"][a][k], risk[a, k]) for k in range(K)), f"{name[0]} {ip} w{a}")
            chk("range across copies: lower / upper", all(close(H["forecast_curve_min"][a][k], lo[a, k]) and close(H["forecast_curve_max"][a][k], hi[a, k]) for k in range(K)), f"{name[0]} {ip} w{a}")
            chk("line inside its range", all(lo[a, k] - 1e-6 <= risk[a, k] <= hi[a, k] + 1e-6 for k in range(K)), f"{name[0]} {ip} w{a}")
            if abs(risk[a, K - 1] - thr) > 5e-4: chk("alert flag", H["alert"][a] == bool(risk[a, K - 1] >= thr), f"{name[0]} {ip} w{a}")
            top = np.sort(stg[a], 1)
            amb = (top[:, -1] - top[:, -2]) < 1e-3
            chk("stage per step", all(amb[k] or CL[int(stg[a, k].argmax())] == H["stage_forecast"][a][k] for k in range(K + 1)), f"{name[0]} {ip} w{a}")
            chk("stage probability per step (model confidence when not alerting)", all(close(H["stage_forecast_prob"][a][k], stg[a, k].max(), 1.1e-3) for k in range(K + 1)), f"{name[0]} {ip} w{a}")
            av = stg[a][:, 1:].mean(0); o_ = np.argsort(-av)
            if av[o_[0]] - av[o_[1]] > 1e-3: chk("averaged stage (shown when alerting)", CL[o_[0] + 1] == H["likely_attack_stage"][a], f"{name[0]} {ip} w{a}")
            chk("averaged stage probability (model confidence when alerting)", close(H["likely_attack_stage_prob"][a], av.max(), 1.1e-3), f"{name[0]} {ip} w{a}: {H['likely_attack_stage_prob'][a]} vs {av.max():.4f}")
            if SOON:
                so = np.stack([o[2] for o in outs]).mean(0)
                chk("5 / 10 minute start values", all(close(H["start_soon"][str(Hs)][a], so[a, j]) for j, Hs in enumerate(SOON)), f"{name[0]} {ip} w{a}")
        # ---- occlusion attribution of the latest window, with a plain loop
        A = H["attribution_last"]; i = idx[-1]; base_x = Xs[hist(i)]
        batch = np.repeat(base_x[None], nf + 1, 0).copy()
        for j in range(nf): batch[j + 1, :, j] = 0.0
        r = np.maximum.accumulate(np.stack([o[0] for o in forward(batch)]).mean(0), axis=1)[:, K - 1]
        delta = r[0] - r[1:]; order = np.argsort(-np.abs(delta)); tot = float(np.abs(delta).sum()) or 1.0
        chk("attribution: risk of the window", close(A["risk_60s"], r[0]), f"{name[0]} {ip}")
        for rank_, x in enumerate(A["features"]):
            j = FE.index(x["feature"])
            chk("attribution: contribution of each listed feature", close(x["contribution"], delta[j], 2e-4), f"{name[0]} {ip} {x['feature']}: {x['contribution']} vs {delta[j]:.4f}")
            chk("attribution: share of each listed feature", close(x["share"], abs(delta[j]) / tot, 2e-4), f"{name[0]} {ip} {x['feature']}")
        mine = [FE[j] for j in order[:len(A["features"])]]; theirs = [x["feature"] for x in A["features"]]
        tie = any(abs(abs(delta[FE.index(a_)]) - abs(delta[FE.index(b_)])) < 1e-6 for a_, b_ in zip(mine, theirs) if a_ != b_)
        chk("attribution: same top features in the same order", mine == theirs or tie, f"{name[0]} {ip}: {mine[:4]} vs {theirs[:4]}")
        for g, cols in meta["groups"].items():
            chk("attribution: per-group totals", close(A["by_group"][g], sum(delta[FE.index(c_)] for c_ in cols), 3e-4), f"{name[0]} {ip} {g}")
    # ---- features of the upload against the features used in training (same host, same 10-second window)
    if train_ref:
        if WP is None:
            WP = pd.read_pickle(HERE / "windows.pkl")
        src, hs = train_ref
        for ip in hs:
            a = W[W["host_ip"] == ip].set_index("t0"); b = WP[(WP["source"] == src) & (WP["host_ip"] == ip)].set_index("t0")
            common = a.index.intersection(b.index)
            common = common[(common > a.index.min()) & (common < a.index.max())]      # first / last window of a cut file are partial
            xa, xb = a.loc[common, FE].to_numpy(float), b.loc[common, FE].to_numpy(float)
            same = np.isclose(xa, xb, rtol=1e-5, atol=1e-6, equal_nan=True)
            chk("upload features = training features (same host and window)", len(common) > 0 and bool(same.all()),
                f"{name[0]} {ip}: {len(common)} windows, mismatching cells {int((~same).sum())}; e.g. {[FE[j] for j in np.where(~same.all(0))[0][:6]]}")
            print(f"   features vs training: {name[0]} {ip}: {len(common)} common windows, {int((~same).sum())} differing cells of {same.size}", flush=True)
    print(f"{name}: done ({len(Ch['hosts'])} hosts)", flush=True)
print("\n=== MODEL AUDIT (independent recomputation)")
for k, (n_, bad) in stat.items(): print(f"  {'OK  ' if bad == 0 else 'FAIL'} {k}: {n_ - bad}/{n_}")
for k, d in fails: print("   !!", k, "|", d)
