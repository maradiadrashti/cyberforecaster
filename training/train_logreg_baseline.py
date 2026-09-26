#!/usr/bin/env python3
"""
train_logreg_baseline.py -- The required benchmark comparison model.

WHAT THIS DOES:
    Trains a plain logistic regression classifier on the SAME flow features
    as your LSTM, but treating each flow independently (no sequences, no
    temporal memory -- exactly the "traditional ML classifier" the problem
    statement describes as the outdated approach world models are supposed
    to beat).

    It predicts attack vs normal (binary) for a single flow at a time using
    only that flow's own features -- it cannot see history or forecast the
    future the way your LSTM does.

    At the end, it prints Accuracy, Precision, Recall, F1, and False
    Positive Rate -- the exact benchmark metrics the problem statement asks
    you to report side-by-side with your LSTM's numbers, to prove your
    world model's temporal dynamics learning provides measurable
    improvement over a non-temporal baseline.

USAGE:
    python train_logreg_baseline.py merged_final_v3.csv
"""

import sys
import json
import argparse

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
import joblib


FEATURE_COLS = [
    "duration", "packet_count", "byte_count",
    "syn_count", "ack_count", "fin_count", "rst_count",
    "ttl_mean", "ttl_var", "win_mean", "win_var", "frag_ratio",
    "payload_mean", "payload_std", "retransmit_count",
]

LOG_TRANSFORM_COLS = [
    "duration", "packet_count", "byte_count", "syn_count", "ack_count",
    "fin_count", "rst_count", "ttl_var", "win_var", "payload_mean",
    "payload_std", "retransmit_count",
]


def main(input_csv, model_dir, max_rows):
    print(f"[*] Loading {input_csv} ...")
    usecols = FEATURE_COLS + ["attack_stage"]
    df = pd.read_csv(input_csv, usecols=lambda c: c in usecols)
    print(f"[+] Loaded {len(df):,} rows.")

    if max_rows and len(df) > max_rows:
        print(f"[*] Subsampling to {max_rows:,} rows for faster training "
              f"(logistic regression doesn't need millions of rows the way "
              f"a deep model does -- this keeps a fair, genuine 1:1 balance).")
        attack_df = df[df["attack_stage"] != "normal"]
        normal_df = df[df["attack_stage"] == "normal"]
        n_each = min(max_rows // 2, len(attack_df), len(normal_df))
        df = pd.concat([
            attack_df.sample(n=n_each, random_state=42),
            normal_df.sample(n=n_each, random_state=42),
        ], ignore_index=True)
        print(f"[+] Subsampled to {len(df):,} rows ({n_each:,} attack, {n_each:,} normal).")

    df[FEATURE_COLS] = df[FEATURE_COLS].replace([np.inf, -np.inf], 0).fillna(0)
    for col in LOG_TRANSFORM_COLS:
        df[col] = np.log1p(df[col].clip(lower=0))

    X = df[FEATURE_COLS].values
    y = (df["attack_stage"] != "normal").astype(int).values

    print(f"[*] Class balance: {y.sum():,} attack / {(y == 0).sum():,} normal "
          f"({100 * y.mean():.1f}% attack)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("[*] Training logistic regression baseline...")
    clf = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)
    clf.fit(X_train_scaled, y_train)

    y_pred = clf.predict(X_test_scaled)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print("\n=== LOGISTIC REGRESSION BASELINE (non-temporal, single-flow) ===")
    print(f"  Accuracy:  {acc:.4f}")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall:    {rec:.4f}")
    print(f"  F1 score:  {f1:.4f}")
    print(f"  False Positive Rate: {fpr:.4f}")
    print(f"  (TP={tp}, FP={fp}, FN={fn}, TN={tn})")

    print("\n  Per-feature coefficients (higher |value| = more influence on the "
          "attack/normal decision):")
    coefs = sorted(zip(FEATURE_COLS, clf.coef_[0]), key=lambda x: -abs(x[1]))
    for name, coef in coefs:
        direction = "attack" if coef > 0 else "normal"
        print(f"      {name:<18} coef={coef:+.4f}  (pushes toward {direction})")

    joblib.dump(clf, "logreg_baseline_v1.joblib")
    joblib.dump(scaler, "logreg_baseline_scaler_v1.joblib")
    with open("logreg_baseline_meta.json", "w") as f:
        json.dump({
            "feature_columns": FEATURE_COLS,
            "log_transform_columns": LOG_TRANSFORM_COLS,
            "test_metrics": {
                "accuracy": acc, "precision": prec, "recall": rec,
                "f1": f1, "false_positive_rate": fpr,
            },
        }, f, indent=2)

    print("\n[+] Saved logreg_baseline_v1.joblib, logreg_baseline_scaler_v1.joblib, "
          "logreg_baseline_meta.json")
    print("\n[+] COPY THIS TABLE INTO YOUR SLIDES/REPORT:")
    print(f"      {'Metric':<12}{'Logistic Regression':<22}{'LSTM World Model'}")
    print(f"      {'Accuracy':<12}{acc:<22.4f}{'(binary_val_accuracy from training log)'}")
    print(f"      {'Precision':<12}{prec:<22.4f}{'(from evaluate_predictions.py)'}")
    print(f"      {'Recall':<12}{rec:<22.4f}{'(from evaluate_predictions.py)'}")
    print(f"      {'F1':<12}{f1:<22.4f}{'(from evaluate_predictions.py)'}")
    print(f"      {'FPR':<12}{fpr:<22.4f}{'(from evaluate_predictions.py)'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_csv")
    parser.add_argument("--max-rows", type=int, default=2_000_000,
                         help="Cap total rows used (logistic regression trains fine on far fewer rows than the LSTM needed)")
    args = parser.parse_args()
    main(args.input_csv, ".", args.max_rows)
