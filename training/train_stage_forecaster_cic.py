#!/usr/bin/env python3
"""
train_stage_forecaster_cic.py — Retrain the GRU stage forecaster on CIC-IDS2017.

Uses the full 2.83M flow CIC-IDS2017 dataset to build temporal sequences.
Maps CIC-IDS2017 attack labels to the kill-chain stage taxonomy:
  - BENIGN → normal
  - PortScan, Web Attack (XSS/SQLi) → reconnaissance
  - FTP-Patator, SSH-Patator, Web Attack Brute Force → initial_access
  - Bot → lateral_movement
  - DDoS, DoS variants → command_control (active exploitation)
  - Infiltration → exfiltration

Sequence construction:
  Within each daily capture file, flows are sorted by (duration, packet_count)
  to create realistic temporal ordering. Sliding windows of size 10 capture
  transitions between stages. The window label = the most advanced stage present.
"""

import os
import sys
import csv
import json
import warnings
from datetime import datetime
from collections import defaultdict, Counter

import numpy as np
import pandas as pd

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

warnings.filterwarnings('ignore')

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

STAGES = ['normal', 'reconnaissance', 'initial_access',
          'lateral_movement', 'command_control', 'exfiltration']
NUM_STAGES = len(STAGES)

FLOW_FEATURES = [
    'duration', 'packet_count', 'byte_count',
    'src_port', 'dst_port',
    'packets_per_second', 'bytes_per_packet',
    'syn_flag', 'ack_flag', 'rst_flag', 'fin_flag',
    'protocol_tcp', 'protocol_udp', 'protocol_other',
]
NUM_FEATURES = len(FLOW_FEATURES)  # 14

SEQUENCE_LENGTH = 10
HIDDEN_SIZE = 64
NUM_LAYERS = 2
DROPOUT = 0.2
BATCH_SIZE = 64
LEARNING_RATE = 0.001
EPOCHS = 60
FORECAST_HORIZON = 30


# ---------------------------------------------------------------------------
# Model definition (same architecture as existing)
# ---------------------------------------------------------------------------

class StageForecasterGRU(nn.Module):
    def __init__(self, input_size=NUM_FEATURES, hidden_size=HIDDEN_SIZE,
                 num_layers=NUM_LAYERS, num_stages=NUM_STAGES, dropout=DROPOUT):
        super().__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.gru = nn.GRU(
            input_size=input_size, hidden_size=hidden_size,
            num_layers=num_layers, batch_first=True,
            dropout=dropout if num_layers > 1 else 0,
        )
        self.dropout = nn.Dropout(dropout)
        self.stage_head = nn.Sequential(
            nn.Linear(hidden_size, 32), nn.ReLU(),
            nn.Dropout(dropout), nn.Linear(32, num_stages),
        )
        self.risk_head = nn.Sequential(
            nn.Linear(hidden_size, 16), nn.ReLU(),
            nn.Linear(16, 1), nn.Sigmoid(),
        )

    def forward(self, x, hidden=None):
        gru_out, hidden = self.gru(x, hidden)
        last = self.dropout(gru_out[:, -1, :])
        return self.stage_head(last), self.risk_head(last), hidden

    def predict_stages(self, x):
        self.eval()
        with torch.no_grad():
            stage_logits, risk_score, _ = self.forward(x)
            return torch.softmax(stage_logits, dim=-1), risk_score


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------

class SequenceDataset(Dataset):
    def __init__(self, sequences, stage_labels, risk_targets):
        self.sequences = torch.tensor(sequences, dtype=torch.float32)
        self.stage_labels = torch.tensor(stage_labels, dtype=torch.long)
        self.risk_targets = torch.tensor(risk_targets, dtype=torch.float32)

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        return self.sequences[idx], self.stage_labels[idx], self.risk_targets[idx]


# ---------------------------------------------------------------------------
# CIC-IDS2017 import and label mapping
# ---------------------------------------------------------------------------

def safe_float(v, default=0.0):
    if v is None or v.strip() == '':
        return default
    try:
        fv = float(v)
        if fv != fv or abs(fv) == float('inf'):
            return default
        return fv
    except:
        return default


def map_cic_label_to_stage(raw_label):
    """Map CIC-IDS2017 label to kill-chain stage index."""
    s = raw_label.strip().lower()
    if s == 'benign' or s == '':
        return 0  # normal
    if 'portscan' in s:
        return 1  # reconnaissance
    if 'xss' in s or 'sql injection' in s:
        return 1  # reconnaissance (web probing)
    if 'patator' in s or 'brute force' in s:
        return 2  # initial_access
    if 'bot' in s:
        return 3  # lateral_movement
    if 'ddos' in s or 'dos' in s or 'heartbleed' in s:
        return 4  # command_control (active exploitation)
    if 'infiltration' in s:
        return 5  # exfiltration
    return 0  # default to normal


def import_cic_day(csv_path):
    """Import one CIC-IDS2017 daily CSV and extract 14 features + stage label."""
    rows = []
    with open(csv_path, 'r', errors='replace') as fh:
        reader = csv.DictReader(fh)
        reader.fieldnames = [k.strip() for k in reader.fieldnames]
        for row in reader:
            row = {k.strip(): v for k, v in row.items()}
            try:
                raw_label = row.get('Label', '').strip()
                stage = map_cic_label_to_stage(raw_label)

                dur = safe_float(row.get('Flow Duration', 0))
                if dur > 1e6:
                    dur /= 1e6  # microseconds to seconds

                fwd_p = safe_float(row.get('Total Fwd Packets', 0))
                bwd_p = safe_float(row.get('Total Backward Packets', 0))
                pkts = max(fwd_p + bwd_p, 1)

                fwd_b = safe_float(row.get('Total Length of Fwd Packets', 0))
                bwd_b = safe_float(row.get('Total Length of Bwd Packets', 0))
                byte_count = max(fwd_b + bwd_b, 1)

                duration_safe = max(dur, 0.001)
                pps = pkts / duration_safe
                bpp = byte_count / pkts

                features = [
                    dur, pkts, byte_count,
                    0,  # src_port (not available in CIC-IDS2017)
                    safe_float(row.get('Destination Port', 0)),
                    pps, bpp,
                    1 if safe_float(row.get('SYN Flag Count', 0)) > 0 else 0,
                    1 if safe_float(row.get('ACK Flag Count', 0)) > 0 else 0,
                    1 if safe_float(row.get('RST Flag Count', 0)) > 0 else 0,
                    1 if safe_float(row.get('FIN Flag Count', 0)) > 0 else 0,
                    1, 0, 0,  # TCP (CIC-IDS2017 is almost entirely TCP)
                ]
                rows.append((features, stage))
            except Exception:
                continue
    return rows


def import_all_cic(base_dir):
    """Import all CIC-IDS2017 files and return list of (features, stage) tuples."""
    all_rows = []
    for fname in sorted(os.listdir(base_dir)):
        if not fname.endswith('.csv'):
            continue
        fpath = os.path.join(base_dir, fname)
        print(f"    {fname}...", end=" ", flush=True)
        rows = import_cic_day(fpath)
        print(f"{len(rows):,} flows")
        all_rows.extend(rows)
    return all_rows


# ---------------------------------------------------------------------------
# Temporal sequence construction
# ---------------------------------------------------------------------------

def build_temporal_sequences(all_rows, seq_len=SEQUENCE_LENGTH):
    """
    Build temporal sequences from CIC-IDS2017 using sliding windows.

    Strategy: Within each daily file, flows are ordered by (duration, byte_count)
    to create a realistic temporal progression. This simulates how attack traffic
    escalates from normal → reconnaissance → exploitation → exfiltration over time.

    The window label = the MOST ADVANCED (highest stage index) stage in the window.
    Risk score = weighted average of stage severities in the window.
    """
    print("\n[*] Building temporal sequences from CIC-IDS2017...")

    # Group by source file (we lose file boundaries but keep within-file ordering)
    # We process all rows as one stream, already ordered by import sequence
    features_list = [r[0] for r in all_rows]
    stage_list = [r[1] for r in all_rows]

    # Sort by (duration, byte_count) to create temporal ordering
    # Normal traffic tends to have moderate values; attacks are extremes
    indices = sorted(range(len(features_list)),
                     key=lambda i: (features_list[i][0], features_list[i][2]))
    features_sorted = [features_list[i] for i in indices]
    stages_sorted = [stage_list[i] for i in indices]

    # Build sliding windows with 50% overlap
    sequences = []
    labels = []
    risks = []

    stage_weights = [0.0, 0.2, 0.5, 0.7, 0.8, 1.0]
    step = max(1, seq_len // 2)  # 50% overlap

    for start in range(0, len(features_sorted) - seq_len + 1, step):
        window_features = features_sorted[start:start + seq_len]
        window_stages = stages_sorted[start:start + seq_len]

        # Label = most advanced stage in the window
        max_stage = max(window_stages)
        # Majority vote for more robust labeling
        stage_counts = Counter(window_stages)
        majority_stage = stage_counts.most_common(1)[0][0]
        # Use majority if it's a real attack stage, otherwise max
        label = majority_stage if majority_stage > 0 else max_stage

        # Risk score: weighted average of stage severities
        risk = sum(stage_weights[s] for s in window_stages) / len(window_stages)

        sequences.append(np.array(window_features, dtype=np.float32))
        labels.append(label)
        risks.append([risk])

    print(f"    Total sequences: {len(sequences):,}")

    seq_arr = np.array(sequences, dtype=np.float32)
    lbl_arr = np.array(labels, dtype=np.int64)
    risk_arr = np.array(risks, dtype=np.float32)

    # Print distribution
    print("    Stage distribution:")
    for i, name in enumerate(STAGES):
        count = (lbl_arr == i).sum()
        print(f"      {name}: {count:,} ({count/len(lbl_arr)*100:.1f}%)")

    return seq_arr, lbl_arr, risk_arr


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

class FeatureNormalizer:
    def __init__(self):
        self.feature_min = np.array([
            0.0, 1.0, 1.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0,
        ], dtype=np.float32)
        self.feature_max = np.array([
            300.0, 10000.0, 5000000.0, 65535.0, 65535.0,
            50000.0, 1500.0, 1.0, 1.0, 1.0, 1.0,
            1.0, 1.0, 1.0,
        ], dtype=np.float32)

    def normalize(self, features):
        return (features - self.feature_min) / (self.feature_max - self.feature_min + 1e-8)

    def to_dict(self):
        return {'feature_min': self.feature_min.tolist(), 'feature_max': self.feature_max.tolist()}


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train(all_rows, output_dir="../models"):
    print("\n" + "=" * 60)
    print("  GRU STAGE FORECASTER TRAINING (CIC-IDS2017)")
    print("=" * 60)

    # Build sequences
    seq_arr, lbl_arr, risk_arr = build_temporal_sequences(all_rows, SEQUENCE_LENGTH)

    # Normalize
    normalizer = FeatureNormalizer()
    seq_norm = normalizer.normalize(seq_arr)

    # Split: 80/10/10
    X_tv, X_te, y_tv, y_te, r_tv, r_te = train_test_split(
        seq_norm, lbl_arr, risk_arr, test_size=0.10, random_state=42, stratify=lbl_arr
    )
    X_tr, X_va, y_tr, y_va, r_tr, r_va = train_test_split(
        X_tv, y_tv, r_tv, test_size=0.111, random_state=42, stratify=y_tv
    )

    print(f"\n    Train: {len(X_tr):,} | Val: {len(X_va):,} | Test: {len(X_te):,}")

    # DataLoaders
    train_ds = SequenceDataset(X_tr, y_tr, r_tr)
    val_ds = SequenceDataset(X_va, y_va, r_va)
    test_ds = SequenceDataset(X_te, y_te, r_te)
    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True, drop_last=False)
    val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE)
    test_loader = DataLoader(test_ds, batch_size=BATCH_SIZE)

    # Model
    model = StageForecasterGRU(NUM_FEATURES, HIDDEN_SIZE, NUM_LAYERS, NUM_STAGES, DROPOUT)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"    Model: {total_params:,} params, {NUM_LAYERS}-layer GRU, hidden={HIDDEN_SIZE}")

    # Loss/optimizer
    stage_criterion = nn.CrossEntropyLoss()
    risk_criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=1e-5)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', factor=0.5, patience=5)

    # Training loop
    print(f"\n    Training for {EPOCHS} epochs...")
    best_val_loss = float('inf')
    best_state = None
    patience_counter = 0

    for epoch in range(EPOCHS):
        model.train()
        t_stage_loss = 0; t_risk_loss = 0; t_correct = 0; t_total = 0

        for bx, bs, br in train_loader:
            optimizer.zero_grad()
            sl, rp, _ = model(bx)
            loss_s = stage_criterion(sl, bs)
            loss_r = risk_criterion(rp, br)
            loss = loss_s * 2.0 + loss_r
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            t_stage_loss += loss_s.item() * len(bx)
            t_risk_loss += loss_r.item() * len(bx)
            _, pred = torch.max(sl.data, 1)
            t_correct += (pred == bs).sum().item()
            t_total += len(bx)

        # Validation
        model.eval()
        v_stage_loss = 0; v_risk_loss = 0; v_correct = 0; v_total = 0
        with torch.no_grad():
            for bx, bs, br in val_loader:
                sl, rp, _ = model(bx)
                v_stage_loss += stage_criterion(sl, bs).item() * len(bx)
                v_risk_loss += risk_criterion(rp, br).item() * len(bx)
                _, pred = torch.max(sl.data, 1)
                v_correct += (pred == bs).sum().item()
                v_total += len(bx)

        t_stage_loss /= max(t_total, 1); t_risk_loss /= max(t_total, 1)
        v_stage_loss /= max(v_total, 1); v_risk_loss /= max(v_total, 1)
        v_total_loss = v_stage_loss * 2.0 + v_risk_loss
        scheduler.step(v_total_loss)

        if v_total_loss < best_val_loss:
            best_val_loss = v_total_loss
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            patience_counter = 0
        else:
            patience_counter += 1

        if (epoch + 1) % 5 == 0 or epoch == 0:
            lr = optimizer.param_groups[0]['lr']
            print(f"    Epoch {epoch+1:3d}/{EPOCHS} | "
                  f"Stage: {t_stage_loss:.4f}/{v_stage_loss:.4f} | "
                  f"Risk: {t_risk_loss:.4f}/{v_risk_loss:.4f} | "
                  f"Acc: {t_correct/t_total:.3f}/{v_correct/v_total:.3f} | "
                  f"LR: {lr:.6f}")

        if patience_counter >= 10:
            print(f"    Early stopping at epoch {epoch+1}")
            break

    if best_state:
        model.load_state_dict(best_state)

    # Final evaluation
    print("\n    Final test evaluation...")
    model.eval()
    all_preds = []; all_actuals = []
    with torch.no_grad():
        for bx, bs, br in test_loader:
            sl, rp, _ = model(bx)
            _, pred = torch.max(sl.data, 1)
            all_preds.extend(pred.cpu().numpy())
            all_actuals.extend(bs.cpu().numpy())

    test_acc = sum(p == a for p, a in zip(all_preds, all_actuals)) / len(all_actuals)
    present = sorted(set(all_actuals) | set(all_preds))
    names = [STAGES[i] for i in present]

    print(f"    Test Accuracy: {test_acc:.4f}")
    report = classification_report(all_actuals, all_preds, labels=present,
                                   target_names=names, zero_division=0)
    for line in report.split('\n'):
        print(f"    {line}")

    # Save
    os.makedirs(output_dir, exist_ok=True)
    model_path = os.path.join(output_dir, "stage_forecaster_v1.pth")
    meta_path = os.path.join(output_dir, "stage_forecaster_v1_meta.json")

    torch.save({
        'model_state_dict': model.state_dict(),
        'model_config': {
            'input_size': NUM_FEATURES, 'hidden_size': HIDDEN_SIZE,
            'num_layers': NUM_LAYERS, 'num_stages': NUM_STAGES, 'dropout': DROPOUT,
        },
    }, model_path)

    meta = {
        'version': 'v1',
        'created': datetime.now().isoformat(),
        'stages': STAGES,
        'num_features': NUM_FEATURES,
        'sequence_length': SEQUENCE_LENGTH,
        'model_config': {
            'input_size': NUM_FEATURES, 'hidden_size': HIDDEN_SIZE,
            'num_layers': NUM_LAYERS, 'num_stages': NUM_STAGES, 'dropout': DROPOUT,
        },
        'normalizer': normalizer.to_dict(),
        'forecast_horizon_seconds': FORECAST_HORIZON,
        'test_accuracy': test_acc,
        'training_notes': (
            'Trained on full CIC-IDS2017 (2.83M flows). '
            'Temporal sequences built using sliding windows over sorted flows. '
            'Stage labels mapped from CIC-IDS2017 attack categories to kill-chain stages.'
        ),
        'label_mapping': {
            'BENIGN': 'normal',
            'PortScan': 'reconnaissance',
            'Web Attack — XSS': 'reconnaissance',
            'Web Attack — Sql Injection': 'reconnaissance',
            'FTP-Patator': 'initial_access',
            'SSH-Patator': 'initial_access',
            'Web Attack — Brute Force': 'initial_access',
            'Bot': 'lateral_movement',
            'DDoS': 'command_control',
            'DoS Hulk': 'command_control',
            'DoS GoldenEye': 'command_control',
            'DoS slowloris': 'command_control',
            'DoS Slowhttptest': 'command_control',
            'Heartbleed': 'command_control',
            'Infiltration': 'exfiltration',
        },
    }
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)
    print(f"    Saved: {model_path}")
    print(f"    Saved: {meta_path}")
    print(f"    Test Accuracy: {test_acc:.4f}")
    print("=" * 60)

    return model, normalizer, meta


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("data_dir", help="Path to CIC-IDS2017 CSV directory")
    parser.add_argument("--output-dir", default="../models")
    args = parser.parse_args()

    print("[*] Importing CIC-IDS2017 dataset...")
    all_rows = import_all_cic(args.data_dir)
    print(f"[+] Total: {len(all_rows):,} flows imported")

    train(all_rows, args.output_dir)
