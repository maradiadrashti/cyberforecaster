#!/usr/bin/env python3
"""
eval_cross_dataset.py -- Compare the LSTM world model against the logistic-regression
baseline on a labeled flow CSV that NEITHER model was trained on.

Both models get exactly the same input: the 15-feature flow schema used by the app.

  * LSTM world model  -- sees a sliding window of the last 5 flows of a conversation
                         (src_ip -> dst_ip), exactly like the dashboard.
  * Logistic baseline -- sees only the most recent flow of that same window
                         (a traditional per-flow classifier, no memory).

A window is labeled "attack" when its most recent flow's attack_stage is not "normal".

USAGE
    python evaluation/eval_cross_dataset.py path/to/labeled_flows.csv
    python evaluation/eval_cross_dataset.py path/to/labeled_flows.csv --out evaluation/results/my_run.json

The CSV must use the app's schema (see samples/real_sample_v4.csv): src_ip, dst_ip,
the 15 feature columns, and attack_stage. Raw CICFlowMeter exports can be converted by
uploading them in the dashboard (the backend adapter) or with your own mapping.
"""
import argparse
import json
import os
import sys
import warnings

import numpy as np
import pandas as pd

warnings.simplefilter("ignore")

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODELS_DIR = os.path.join(REPO_ROOT, "models")
SEQ_LEN = 5


def load_meta():
    with open(os.path.join(MODELS_DIR, "stage_forecaster_lstm_v1_meta.json")) as f:
        return json.load(f)


def build_lstm_predictor(meta, npz_path=None):
    """Returns f(X[N,5,15] normalized) -> (stage_idx[N], risk[N])."""
    if npz_path is None:
        import torch
        sys.path.insert(0, REPO_ROOT)
        from models.stage_forecaster_lstm_infer import StageForecasterLSTM

        cfg = meta["model_config"]
        model = StageForecasterLSTM(
            input_size=cfg["input_size"], hidden_size=cfg["hidden_size"],
            num_layers=cfg["num_layers"], num_classes=cfg["num_stages"],
            dropout=cfg["dropout"],
        )
        ckpt = torch.load(os.path.join(MODELS_DIR, "stage_forecaster_lstm_v1.pth"),
                          map_location="cpu", weights_only=True)
        model.load_state_dict(ckpt["model_state_dict"])
        model.eval()

        def predict(X):
            with torch.no_grad():
                logits, risk = model(torch.tensor(X, dtype=torch.float32))
            return logits.argmax(1).numpy(), risk[:, 0].numpy()
        return predict

    # Torch-free path: identical LSTM maths in NumPy, from weights exported to .npz
    W = np.load(npz_path)
    H = meta["model_config"]["hidden_size"]
    sig = lambda x: 1.0 / (1.0 + np.exp(-x))

    def layer(X, l):
        Wi, Wh = W[f"lstm.weight_ih_l{l}"], W[f"lstm.weight_hh_l{l}"]
        b = W[f"lstm.bias_ih_l{l}"] + W[f"lstm.bias_hh_l{l}"]
        h = np.zeros((X.shape[0], H)); c = np.zeros((X.shape[0], H)); out = []
        for t in range(X.shape[1]):
            g = X[:, t] @ Wi.T + h @ Wh.T + b
            i, f, gg, o = sig(g[:, :H]), sig(g[:, H:2*H]), np.tanh(g[:, 2*H:3*H]), sig(g[:, 3*H:])
            c = f * c + i * gg; h = o * np.tanh(c); out.append(h)
        return np.stack(out, 1)

    def predict(X):
        h = layer(layer(X, 0), 1)[:, -1]
        s = np.maximum(h @ W["stage_head.0.weight"].T + W["stage_head.0.bias"], 0)
        s = s @ W["stage_head.3.weight"].T + W["stage_head.3.bias"]
        r = np.maximum(h @ W["risk_head.0.weight"].T + W["risk_head.0.bias"], 0)
        r = sig(r @ W["risk_head.2.weight"].T + W["risk_head.2.bias"])[:, 0]
        return s.argmax(1), r
    return predict


def metrics(y, p):
    tp = int(((y == 1) & (p == 1)).sum()); tn = int(((y == 0) & (p == 0)).sum())
    fp = int(((y == 0) & (p == 1)).sum()); fn = int(((y == 1) & (p == 0)).sum())
    return {
        "accuracy": round((tp + tn) / len(y), 4),
        "precision": round(tp / max(tp + fp, 1), 4),
        "recall": round(tp / max(tp + fn, 1), 4),
        "f1": round(2 * tp / max(2 * tp + fp + fn, 1), 4),
        "false_positive_rate": round(fp / max(fp + tn, 1), 4),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv")
    ap.add_argument("--out", default=None, help="write results JSON here")
    ap.add_argument("--npz", default=None, help="(optional) torch-free LSTM weights .npz")
    args = ap.parse_args()

    import joblib
    meta = load_meta()
    feat = meta["feature_columns"]; logc = set(meta["log_transform_columns"])
    fmin = np.array(meta["normalizer"]["feature_min"], dtype=np.float32)
    fmax = np.array(meta["normalizer"]["feature_max"], dtype=np.float32)

    df = pd.read_csv(args.csv)
    df["attack_stage"] = df["attack_stage"].fillna("normal").astype(str)
    df[feat] = df[feat].replace([np.inf, -np.inf], 0).fillna(0)
    if "flow_start" in df.columns and df["flow_start"].notna().all():
        df = df.sort_values(["src_ip", "dst_ip", "flow_start"])
    df = df.reset_index(drop=True)

    raw = df[feat].values.astype(np.float32)
    for i, c in enumerate(feat):
        if c in logc:
            raw[:, i] = np.log1p(np.clip(raw[:, i], 0, None))
    norm = np.clip((raw - fmin) / (fmax - fmin + 1e-8), 0, 1)

    y_flow = (df["attack_stage"] != "normal").values.astype(int)
    stages = meta["stages"]

    # sliding windows of 5 consecutive flows per conversation
    win = []
    for _, g in df.groupby(["src_ip", "dst_ip"], sort=False):
        ix = g.index.values
        for s in range(0, len(ix) - SEQ_LEN + 1):
            win.append(ix[s:s + SEQ_LEN])
    if not win:
        sys.exit("No conversation has >= 5 flows; nothing to evaluate.")
    win = np.array(win)
    last = win[:, -1]
    y = y_flow[last]

    predict = build_lstm_predictor(meta, args.npz)
    ps, pr = [], []
    for b in range(0, len(win), 4096):
        a, r = predict(norm[win[b:b + 4096]])
        ps.append(a); pr.append(r)
    ps = np.concatenate(ps); pr = np.concatenate(pr)

    clf = joblib.load(os.path.join(MODELS_DIR, "logreg_baseline_v1.joblib"))
    sc = joblib.load(os.path.join(MODELS_DIR, "logreg_baseline_scaler_v1.joblib"))
    lr = clf.predict(sc.transform(raw[last]))

    true_stage = df["attack_stage"].values[last]
    stage_ok = sum(1 for p, t in zip(ps, true_stage) if t != "normal" and stages[p] == t)

    res = {
        "dataset": os.path.basename(args.csv),
        "windows": int(len(y)), "attack_windows": int(y.sum()),
        "lstm_risk_head_threshold_0.5": metrics(y, (pr >= 0.5).astype(int)),
        "lstm_stage_head_not_normal": metrics(y, (ps != 0).astype(int)),
        "logistic_regression_baseline": metrics(y, lr.astype(int)),
        "lstm_exact_stage_on_attack_windows": f"{stage_ok}/{int(y.sum())}",
    }

    print(f"\nDataset: {res['dataset']}   windows: {res['windows']:,}   attack windows: {res['attack_windows']:,}\n")
    cols = ["accuracy", "precision", "recall", "f1", "false_positive_rate"]
    print(f"{'Model':<34}" + "".join(f"{c[:9]:>11}" for c in cols))
    for name, key in [("LSTM world model (risk head)", "lstm_risk_head_threshold_0.5"),
                      ("LSTM world model (stage head)", "lstm_stage_head_not_normal"),
                      ("Logistic regression (baseline)", "logistic_regression_baseline")]:
        print(f"{name:<34}" + "".join(f"{res[key][c]:>11.4f}" for c in cols))
    print(f"\nLSTM exact MITRE stage on attack windows: {res['lstm_exact_stage_on_attack_windows']}")

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w") as f:
            json.dump(res, f, indent=2)
        print(f"[+] wrote {args.out}")


if __name__ == "__main__":
    main()
