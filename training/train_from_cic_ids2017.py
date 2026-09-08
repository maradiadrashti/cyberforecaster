#!/usr/bin/env python3
"""
train_from_cic_ids2017.py — Train the flow classifier on the FULL CIC-IDS2017 dataset.

Reads the raw CIC-IDS2017 CSVs from the download directory, extracts the 14 features
compatible with the live capture pipeline, and trains XGBoost with proper class balancing.

This produces a classifier that can be used in the live pipeline because the feature
schema matches exactly what capture_server.py provides at inference time.
"""

import os
import sys
import csv
import json
import warnings
from datetime import datetime
from collections import defaultdict

import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_recall_fscore_support, accuracy_score
)
from imblearn.over_sampling import SMOTE
import xgboost as xgb
import joblib

warnings.filterwarnings('ignore')

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# The 14 features used in the live pipeline (capture_server.py → flow_classifier_infer.py)
LIVE_FEATURES = [
    'duration', 'packet_count', 'byte_count',
    'src_port', 'dst_port',
    'packets_per_second', 'bytes_per_packet',
    'syn_flag', 'ack_flag', 'rst_flag', 'fin_flag',
    'protocol_tcp', 'protocol_udp', 'protocol_other',
]

ATTACK_LABELS = ['benign', 'port_scan', 'brute_force', 'dos_ddos', 'exfiltration']

XGB_PARAMS = {
    'objective': 'multi:softprob',
    'num_class': len(ATTACK_LABELS),
    'max_depth': 8,
    'learning_rate': 0.05,
    'n_estimators': 500,
    'min_child_weight': 5,
    'subsample': 0.8,
    'colsample_bytree': 0.8,
    'reg_alpha': 0.5,
    'reg_lambda': 2.0,
    'gamma': 0.2,
    'random_state': 42,
    'eval_metric': 'mlogloss',
    'use_label_encoder': False,
    'n_jobs': -1,
}

# ---------------------------------------------------------------------------
# Label mapping
# ---------------------------------------------------------------------------

def map_label(raw: str) -> str:
    """Map CIC-IDS2017 label to CyberForecaster taxonomy."""
    try:
        from models.taxonomy import normalize_label
        return normalize_label(raw)
    except Exception:
        s = raw.strip().lower()
        if s == 'benign': return 'benign'
        if 'portscan' in s: return 'port_scan'
        if 'ddos' in s or 'dos' in s or 'heartbleed' in s or 'bot' in s: return 'dos_ddos'
        if 'patator' in s or 'brute force' in s: return 'brute_force'
        if 'infiltration' in s: return 'exfiltration'
        return 'unknown'


# ---------------------------------------------------------------------------
# Import CIC-IDS2017 and extract 14 live-compatible features
# ---------------------------------------------------------------------------

def import_cic_ids2017(base_dir: str) -> pd.DataFrame:
    """Import all CIC-IDS2017 CSVs, extract 14 live-pipeline features."""
    print(f"[*] Importing from: {base_dir}")

    rows = []
    skipped = 0

    for fname in sorted(os.listdir(base_dir)):
        if not fname.endswith('.csv'):
            continue
        fpath = os.path.join(base_dir, fname)
        print(f"    Processing: {fname}...", end=" ", flush=True)

        file_rows = 0
        with open(fpath, 'r', errors='replace') as fh:
            reader = csv.DictReader(fh)
            # Strip whitespace from header
            reader.fieldnames = [k.strip() for k in reader.fieldnames]

            for row in reader:
                row = {k.strip(): v for k, v in row.items()}
                try:
                    raw_label = row.get('Label', '').strip()
                    if not raw_label:
                        skipped += 1
                        continue

                    label = map_label(raw_label)
                    if label is None:
                        skipped += 1
                        continue

                    # Safe float parser
                    def sf(v, default=0.0):
                        if v is None or v.strip() == '':
                            return default
                        try:
                            fv = float(v)
                            if fv != fv or abs(fv) == float('inf'):
                                return default
                            return fv
                        except:
                            return default

                    # Extract the 14 features that match the live pipeline
                    dst_port = sf(row.get('Destination Port', 0))
                    duration = sf(row.get('Flow Duration', 0))
                    if duration > 1_000_000:
                        duration /= 1_000_000  # Convert microseconds to seconds

                    fwd_pkts = sf(row.get('Total Fwd Packets', 0))
                    bwd_pkts = sf(row.get('Total Backward Packets', 0))
                    packet_count = max(fwd_pkts + bwd_pkts, 1)

                    fwd_bytes = sf(row.get('Total Length of Fwd Packets', 0))
                    bwd_bytes = sf(row.get('Total Length of Bwd Packets', 0))
                    byte_count = max(fwd_bytes + bwd_bytes, 1)

                    syn_flag = 1 if sf(row.get('SYN Flag Count', 0)) > 0 else 0
                    ack_flag = 1 if sf(row.get('ACK Flag Count', 0)) > 0 else 0
                    rst_flag = 1 if sf(row.get('RST Flag Count', 0)) > 0 else 0
                    fin_flag = 1 if sf(row.get('FIN Flag Count', 0)) > 0 else 0

                    duration_safe = max(duration, 0.001)
                    packets_per_second = packet_count / duration_safe
                    bytes_per_packet = byte_count / max(packet_count, 1)

                    rows.append({
                        'duration': duration,
                        'packet_count': packet_count,
                        'byte_count': byte_count,
                        'src_port': 0,  # CIC-IDS2017 doesn't have src_port
                        'dst_port': dst_port,
                        'packets_per_second': packets_per_second,
                        'bytes_per_packet': bytes_per_packet,
                        'syn_flag': syn_flag,
                        'ack_flag': ack_flag,
                        'rst_flag': rst_flag,
                        'fin_flag': fin_flag,
                        'protocol_tcp': 1,  # CIC-IDS2017 is almost entirely TCP
                        'protocol_udp': 0,
                        'protocol_other': 0,
                        'label': label,
                    })
                    file_rows += 1
                except Exception:
                    skipped += 1

        print(f"{file_rows:,} rows")

    df = pd.DataFrame(rows)
    print(f"\n[+] Total: {len(df):,} flows imported ({skipped:,} skipped)")
    print(f"    Label distribution:")
    for lbl, cnt in df['label'].value_counts().items():
        print(f"      {lbl}: {cnt:,} ({cnt/len(df)*100:.1f}%)")

    return df


# ---------------------------------------------------------------------------
# Training pipeline
# ---------------------------------------------------------------------------

def train(df: pd.DataFrame, output_dir: str = "models"):
    """Train XGBoost on the 14-feature schema from full CIC-IDS2017 data."""
    print("\n" + "=" * 60)
    print("  FLOW CLASSIFIER TRAINING (Full CIC-IDS2017, 14 Features)")
    print("=" * 60)

    # Features and labels
    X = df[LIVE_FEATURES].values.astype(np.float32)
    y_raw = df['label'].values

    # Encode labels
    le = LabelEncoder()
    le.fit(y_raw)
    y = le.transform(y_raw)

    print(f"\n    Features: {len(LIVE_FEATURES)}")
    print(f"    Classes: {list(le.classes_)}")
    print(f"    Total samples: {len(X):,}")

    # Split 80/10/10 stratified
    X_trainval, X_test, y_trainval, y_test = train_test_split(
        X, y, test_size=0.10, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_trainval, y_trainval, test_size=0.111,  # ~10% of total
        random_state=42, stratify=y_trainval
    )

    print(f"    Train: {len(X_train):,} | Val: {len(X_val):,} | Test: {len(X_test):,}")

    # SMOTE on training set
    print("\n    Applying SMOTE...")
    train_counts = defaultdict(int)
    for y in y_train:
        train_counts[y] += 1
    min_class = min(train_counts.values())
    k = max(2, min(min_class - 1, 5))
    smote = SMOTE(random_state=42, k_neighbors=k)
    X_train_res, y_train_res = smote.fit_resample(X_train, y_train)
    print(f"    Before SMOTE: {len(X_train):,} | After: {len(X_train_res):,}")

    # Train XGBoost
    print(f"\n    Training XGBoost (max_depth=8, lr=0.05, n_est=500)...")
    model = xgb.XGBClassifier(**XGB_PARAMS)
    model.fit(
        X_train_res, y_train_res,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )
    print("    Training complete.")

    # Evaluate
    for split_name, Xs, ys in [
        ("TRAIN", X_train, y_train),
        ("VALIDATION", X_val, y_val),
        ("TEST", X_test, y_test),
    ]:
        y_pred = model.predict(Xs)
        acc = accuracy_score(ys, y_pred)
        present = sorted(set(ys) | set(y_pred))
        p, r, f1, s = precision_recall_fscore_support(ys, y_pred, average=None, labels=present)
        names = [le.inverse_transform([i])[0] for i in present]

        print(f"\n    --- {split_name} ---")
        print(f"    Accuracy: {acc:.4f}")
        print(f"    {'Label':<18} {'Prec':>8} {'Rec':>8} {'F1':>8} {'N':>8}")
        for i, idx in enumerate(present):
            name = names[i]
            print(f"    {name:<18} {p[i]:>8.4f} {r[i]:>8.4f} {f1[i]:>8.4f} {int(s[i]) if i < len(s) else 0:>8}")

        # FPR on benign
        if 'benign' in names:
            benign_idx = names.index('benign')
            cm = confusion_matrix(ys, y_pred, labels=present)
            bn_pos = list(present).index(le.transform(['benign'])[0])
            fp = cm[:, bn_pos].sum() - cm[bn_pos, bn_pos]
            tn = cm.sum() - cm[bn_pos, :].sum() - cm[:, bn_pos].sum() + cm[bn_pos, bn_pos]
            fpr = fp / (fp + tn + 1e-8)
            print(f"    ** Benign FPR: {fpr:.4f} ({fpr*100:.2f}%) **")

    # Confusion matrix
    print(f"\n    --- CONFUSION MATRIX (Test) ---")
    y_pred_test = model.predict(X_test)
    present = sorted(set(y_test) | set(y_pred_test))
    cm = confusion_matrix(y_test, y_pred_test, labels=present)
    names = [le.inverse_transform([i])[0][:8] for i in present]
    print(f"    {'':>14}", end='')
    for n in names:
        print(f" {n:>8}", end='')
    print()
    for i, name in enumerate(names):
        print(f"    {name:>14}", end='')
        for j in range(len(names)):
            val = cm[i][j] if i < cm.shape[0] and j < cm.shape[1] else 0
            print(f" {val:>8}", end='')
        print()

    # Save
    print(f"\n    Saving model...")
    os.makedirs(output_dir, exist_ok=True)

    model_path = os.path.join(output_dir, "flow_classifier_v1.joblib")
    enc_path = os.path.join(output_dir, "flow_label_encoder_v1.joblib")
    meta_path = os.path.join(output_dir, "flow_classifier_meta.json")

    joblib.dump(model, model_path)
    joblib.dump(le, enc_path)

    meta = {
        'version': 'v1',
        'created': datetime.now().isoformat(),
        'features': LIVE_FEATURES,
        'num_classes': len(ATTACK_LABELS),
        'classes': ATTACK_LABELS,
        'model_type': 'XGBClassifier',
        'xgb_params': {k: v for k, v in XGB_PARAMS.items() if k != 'use_label_encoder'},
        'training_samples': len(X_train_res),
        'test_accuracy': float(accuracy_score(y_test, y_pred_test)),
        'dataset_source': 'CIC-IDS2017_full_2.8M',
    }
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)

    # Also save the inference wrapper (same as flow_classifier_infer.py)
    infer_path = os.path.join(output_dir, "flow_classifier_infer.py")
    print(f"    Model: {model_path}")
    print(f"    Encoder: {enc_path}")
    print(f"    Meta: {meta_path}")

    print(f"\n    Test Accuracy: {meta['test_accuracy']:.4f}")
    print("=" * 60)

    return model, le, meta


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("data_dir", help="Path to CIC-IDS2017 CSV directory")
    parser.add_argument("--output-dir", default="../models")
    args = parser.parse_args()

    df = import_cic_ids2017(args.data_dir)
    train(df, args.output_dir)
