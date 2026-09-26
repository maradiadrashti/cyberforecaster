#!/usr/bin/env python3
"""
evaluate_predictions.py -- Answers the question "how much of the forecasting
is actually right or wrong?" with real numbers, not a guess.

WHAT THIS DOES:
    Takes a LABELED csv (one that already has attack_stage filled in --
    could be a slice of your own merged_final_v3.csv, or any labeled file).
    It builds the exact same forecasting sequences your training script
    builds (last 5 flows -> predict the stage 3 flows into the future),
    runs each one through your trained model, and compares the model's
    prediction against the REAL label that was already sitting in the file.

    It then prints:
      - Binary accuracy (attack vs normal) + precision/recall/F1
      - Stage accuracy (which of the 6 MITRE stages) + per-class
        precision/recall/F1 -- exactly the benchmark metrics the problem
        statement asks you to report.
      - A confusion matrix (which stages get mixed up with which).

    IMPORTANT: for this to mean anything, run it on a slice of data the
    model did NOT train on (a genuine holdout), not the exact same file
    used for training -- otherwise the numbers are inflated and meaningless.

USAGE:
    python evaluate_predictions.py "some_labeled_flows.csv"
    python evaluate_predictions.py "some_labeled_flows.csv" --model-dir .
"""

import sys
import os
import json
import argparse
from collections import defaultdict

import numpy as np
import pandas as pd
import torch
import torch.nn as nn


class StageForecasterLSTM(nn.Module):
    def __init__(self, input_size, hidden_size=64, num_layers=2, num_classes=6, dropout=0.2):
        super().__init__()
        self.lstm = nn.LSTM(input_size=input_size, hidden_size=hidden_size,
                             num_layers=num_layers, batch_first=True,
                             dropout=dropout if num_layers > 1 else 0)
        self.dropout = nn.Dropout(dropout)
        self.stage_head = nn.Sequential(
            nn.Linear(hidden_size, 32), nn.ReLU(),
            nn.Dropout(dropout), nn.Linear(32, num_classes),
        )
        self.risk_head = nn.Sequential(
            nn.Linear(hidden_size, 16), nn.ReLU(),
            nn.Linear(16, 1), nn.Sigmoid(),
        )

    def forward(self, x):
        out, _ = self.lstm(x)
        last = self.dropout(out[:, -1, :])
        return self.stage_head(last), self.risk_head(last)


def load_model(model_dir):
    meta_path = os.path.join(model_dir, "stage_forecaster_lstm_v1_meta.json")
    weights_path = os.path.join(model_dir, "stage_forecaster_lstm_v1.pth")
    if not os.path.exists(meta_path) or not os.path.exists(weights_path):
        print(f"[!] Could not find model files in {model_dir}")
        sys.exit(1)
    with open(meta_path) as f:
        meta = json.load(f)
    cfg = meta["model_config"]
    model = StageForecasterLSTM(
        input_size=cfg["input_size"], hidden_size=cfg["hidden_size"],
        num_layers=cfg["num_layers"], num_classes=cfg["num_stages"],
        dropout=cfg["dropout"],
    )
    state = torch.load(weights_path, map_location="cpu")
    model.load_state_dict(state["model_state_dict"])
    model.eval()
    return model, meta


def prf1(tp, fp, fn):
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return precision, recall, f1


def main(input_csv, model_dir):
    model, meta = load_model(model_dir)
    feature_cols = meta["feature_columns"]
    log_cols = meta.get("log_transform_columns", [])
    stages = meta["stages"]
    seq_len = meta["sequence_length"]
    horizon = meta.get("forecast_horizon", 0)
    feat_min = np.array(meta["normalizer"]["feature_min"], dtype=np.float32)
    feat_max = np.array(meta["normalizer"]["feature_max"], dtype=np.float32)
    stage_to_idx = {s: i for i, s in enumerate(stages)}

    print(f"[*] Loading {input_csv} ...")
    needed = ["src_ip", "dst_ip", "flow_start", "attack_stage"] + feature_cols
    df = pd.read_csv(input_csv, usecols=lambda c: c in needed)
    if "attack_stage" not in df.columns:
        print("[!] This CSV has no 'attack_stage' column -- I need real labels to "
              "check right vs wrong. Use a labeled file, not a raw prediction target.")
        sys.exit(1)

    df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], 0).fillna(0)
    for col in log_cols:
        if col in df.columns:
            df[col] = np.log1p(df[col].clip(lower=0))

    df = df.sort_values(["src_ip", "dst_ip", "flow_start"]).reset_index(drop=True)

    y_true_binary, y_pred_binary = [], []
    y_true_stage, y_pred_stage = [], []
    n_windows = 0
    n_skipped_mixed = 0
    n_skipped_short = 0

    with torch.no_grad():
        for (src_ip, dst_ip), group in df.groupby(["src_ip", "dst_ip"]):
            group = group.reset_index(drop=True)
            n = len(group)
            if n < seq_len + horizon:
                n_skipped_short += 1
                continue
            for start in range(0, n - seq_len - horizon + 1):
                input_stages = group["attack_stage"].iloc[start:start + seq_len].unique()
                if len(input_stages) > 1:
                    n_skipped_mixed += 1
                    continue
                target_idx = start + seq_len - 1 + horizon
                true_stage = group["attack_stage"].iloc[target_idx]
                if true_stage not in stage_to_idx:
                    continue

                window = group[feature_cols].iloc[start:start + seq_len].values
                window_norm = (window - feat_min) / (feat_max - feat_min + 1e-8)
                window_norm = np.clip(window_norm, 0.0, 1.0)
                x = torch.tensor(window_norm, dtype=torch.float32).unsqueeze(0)

                stage_logits, risk_pred = model(x)
                probs = torch.softmax(stage_logits, dim=1).squeeze(0).numpy()
                pred_stage_idx = int(probs.argmax())
                pred_binary = 1 if float(risk_pred.item()) > 0.5 else 0
                true_binary = 0 if true_stage == "normal" else 1

                y_true_stage.append(stage_to_idx[true_stage])
                y_pred_stage.append(pred_stage_idx)
                y_true_binary.append(true_binary)
                y_pred_binary.append(pred_binary)
                n_windows += 1

    if n_windows == 0:
        print("[!] No valid forecasting windows could be built from this file. "
              "Need conversations with enough consecutive same-label flows "
              f"(at least {seq_len + horizon} flows per src/dst pair).")
        sys.exit(0)

    y_true_binary = np.array(y_true_binary)
    y_pred_binary = np.array(y_pred_binary)
    y_true_stage = np.array(y_true_stage)
    y_pred_stage = np.array(y_pred_stage)

    print(f"\n[+] Evaluated {n_windows:,} forecasting windows "
          f"(skipped {n_skipped_mixed:,} mixed-label windows, "
          f"{n_skipped_short:,} conversations too short).\n")

    # ---- Binary metrics ----
    tp = int(((y_pred_binary == 1) & (y_true_binary == 1)).sum())
    fp = int(((y_pred_binary == 1) & (y_true_binary == 0)).sum())
    fn = int(((y_pred_binary == 0) & (y_true_binary == 1)).sum())
    tn = int(((y_pred_binary == 0) & (y_true_binary == 0)).sum())
    acc_binary = (tp + tn) / n_windows
    precision, recall, f1 = prf1(tp, fp, fn)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print("=== BINARY (attack vs normal) ===")
    print(f"  Accuracy:  {acc_binary:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1 score:  {f1:.4f}")
    print(f"  False Positive Rate: {fpr:.4f}")
    print(f"  (TP={tp}, FP={fp}, FN={fn}, TN={tn})\n")

    # ---- Stage metrics ----
    acc_stage = float((y_pred_stage == y_true_stage).mean())
    print("=== STAGE (MITRE forecast, {} flows ahead) ===".format(horizon))
    print(f"  Overall stage accuracy: {acc_stage:.4f}\n")

    print("  Per-class breakdown:")
    for idx, stage_name in enumerate(stages):
        support = int((y_true_stage == idx).sum())
        if support == 0:
            print(f"    {stage_name:<18} -- no examples in this file, skipped")
            continue
        s_tp = int(((y_pred_stage == idx) & (y_true_stage == idx)).sum())
        s_fp = int(((y_pred_stage == idx) & (y_true_stage != idx)).sum())
        s_fn = int(((y_pred_stage != idx) & (y_true_stage == idx)).sum())
        p, r, f = prf1(s_tp, s_fp, s_fn)
        print(f"    {stage_name:<18} precision={p:.3f}  recall={r:.3f}  f1={f:.3f}  (support={support})")

    print("\n  Confusion matrix (rows=true, cols=predicted):")
    header = "                    " + "".join(f"{s[:10]:>12}" for s in stages)
    print(header)
    for i, s_true in enumerate(stages):
        row_counts = [int(((y_true_stage == i) & (y_pred_stage == j)).sum()) for j in range(len(stages))]
        print(f"    {s_true[:16]:<16}" + "".join(f"{c:>12}" for c in row_counts))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_csv", help="A LABELED flow-features csv (must have attack_stage column)")
    parser.add_argument("--model-dir", default=".", help="Folder with the trained model files")
    args = parser.parse_args()
    main(args.input_csv, args.model_dir)
