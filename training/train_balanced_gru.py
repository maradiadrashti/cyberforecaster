#!/usr/bin/env python3
"""
train_balanced_gru.py - Comprehensive Multi-Class GRU Training on CIC-IDS2017
Trains the PyTorch GRU Stage Forecaster on real attack sequences:
- Normal (Benign) -> Stage 0: normal
- PortScan, XSS, SQLi -> Stage 1: reconnaissance
- FTP-Patator, SSH-Patator, Brute Force -> Stage 2: initial_access
- Bot -> Stage 3: lateral_movement
- DoS (Hulk, GoldenEye, Slowloris, Slowhttptest), DDoS -> Stage 4: command_control
- Infiltration -> Stage 5: exfiltration
"""

import os
import csv
import json
import random
import warnings
from datetime import datetime
from collections import Counter, defaultdict
import numpy as np

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

warnings.filterwarnings('ignore')

STAGES = [
    "normal",
    "reconnaissance",
    "initial_access",
    "lateral_movement",
    "command_control",
    "exfiltration"
]
STAGE_TO_IDX = {s: i for i, s in enumerate(STAGES)}
NUM_STAGES = len(STAGES)
NUM_FEATURES = 14
SEQ_LEN = 10
HIDDEN_SIZE = 64
NUM_LAYERS = 2
DROPOUT = 0.2
BATCH_SIZE = 128
LR = 0.001
EPOCHS = 40

STAGE_RISK_WEIGHTS = [0.0, 0.2, 0.5, 0.7, 0.85, 1.0]

def sf(v):
    """Safe float conversion."""
    if v is None:
        return 0.0
    s = str(v).strip()
    if not s:
        return 0.0
    try:
        fv = float(s)
        return 0.0 if np.isnan(fv) or np.isinf(fv) else fv
    except Exception:
        return 0.0

def map_label_to_stage(label_str: str) -> int:
    """Map CIC-IDS2017 raw label to MITRE stage index 0..5."""
    s = label_str.strip().lower()
    if not s or s == 'benign':
        return 0  # normal
    if 'portscan' in s or 'xss' in s or 'sql injection' in s or 'scan' in s:
        return 1  # reconnaissance
    if 'patator' in s or 'brute force' in s or 'bruteforce' in s:
        return 2  # initial_access
    if 'bot' in s:
        return 3  # lateral_movement
    if 'ddos' in s or 'dos' in s or 'heartbleed' in s:
        return 4  # command_control
    if 'infiltration' in s or 'infilteration' in s:
        return 5  # exfiltration
    return 0

def extract_flow_features(row: dict, rng: np.random.RandomState = None) -> list:
    """
    Extract 14 normalized flow features matching stage_forecaster_infer.py:
    [
        duration, packet_count, byte_count, src_port, dst_port,
        packets_per_second, bytes_per_packet,
        syn_flag, ack_flag, rst_flag, fin_flag,
        protocol_tcp, protocol_udp, protocol_other
    ]
    """
    dur = max(sf(row.get('Flow Duration', 0)) / 1e6, 0.001)
    dur_safe = max(dur, 0.001)

    fp = sf(row.get('Total Fwd Packets', 0))
    bp = sf(row.get('Total Backward Packets', 0))
    packet_count = max(fp + bp, 1.0)

    fb = sf(row.get('Total Length of Fwd Packets', 0))
    bb = sf(row.get('Total Length of Bwd Packets', 0))
    byte_count = max(fb + bb, 1.0)

    dst_port = sf(row.get('Destination Port', 0))
    # Client flows have ephemeral ports (1024..65535)
    src_port = float(rng.randint(1024, 65535)) if rng is not None else float(np.random.randint(1024, 65535))

    syn = 1.0 if sf(row.get('SYN Flag Count', 0)) > 0 else 0.0
    ack = 1.0 if sf(row.get('ACK Flag Count', 0)) > 0 else 0.0
    rst = 1.0 if sf(row.get('RST Flag Count', 0)) > 0 else 0.0
    fin = 1.0 if sf(row.get('FIN Flag Count', 0)) > 0 else 0.0

    pps = min(packet_count / dur_safe, 50000.0)
    bpp = min(byte_count / packet_count, 1500.0)

    # Default to TCP=1, UDP=0, Other=0 for standard CIC-IDS2017 flows
    return [
        dur, packet_count, byte_count, src_port, dst_port,
        pps, bpp,
        syn, ack, rst, fin,
        1.0, 0.0, 0.0
    ]

# Normalization constants
FEATURE_MIN = np.array([0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], dtype=np.float32)
FEATURE_MAX = np.array([300.0, 10000.0, 5000000.0, 65535.0, 65535.0, 50000.0, 1500.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0], dtype=np.float32)

def normalize_sequence(seq: np.ndarray) -> np.ndarray:
    return (seq - FEATURE_MIN) / (FEATURE_MAX - FEATURE_MIN + 1e-8)

class StageForecasterGRU(nn.Module):
    def __init__(self, input_size=NUM_FEATURES, hidden_size=HIDDEN_SIZE, num_layers=NUM_LAYERS,
                 num_classes=NUM_STAGES, dropout=DROPOUT):
        super().__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.gru = nn.GRU(input_size=input_size, hidden_size=hidden_size,
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

    def forward(self, x, hidden=None):
        gru_out, hidden = self.gru(x, hidden)
        last = self.dropout(gru_out[:, -1, :])
        return self.stage_head(last), self.risk_head(last), hidden

class FlowSequenceDataset(Dataset):
    def __init__(self, sequences, labels, risks):
        self.x = torch.tensor(sequences, dtype=torch.float32)
        self.y_stage = torch.tensor(labels, dtype=torch.long)
        self.y_risk = torch.tensor(risks, dtype=torch.float32)

    def __len__(self):
        return len(self.x)

    def __getitem__(self, idx):
        return self.x[idx], self.y_stage[idx], self.y_risk[idx]

def load_and_build_dataset():
    base_dir = r'C:\Users\htc\Downloads\MachineLearningCSV\MachineLearningCVE'
    print(f"Loading CIC-IDS2017 datasets from {base_dir}...")

    flows_by_stage = defaultdict(list)
    file_list = sorted([f for f in os.listdir(base_dir) if f.endswith('.csv')])

    for fname in file_list:
        fpath = os.path.join(base_dir, fname)
        print(f"  Reading {fname}...")
        with open(fpath, 'r', errors='replace') as fh:
            reader = csv.DictReader(fh)
            reader.fieldnames = [k.strip() for k in reader.fieldnames]
            for row in reader:
                row = {k.strip(): v for k, v in row.items()}
                lbl = row.get('Label', '')
                stage = map_label_to_stage(lbl)
                feat = extract_flow_features(row)
                flows_by_stage[stage].append(feat)

    for i, name in enumerate(STAGES):
        print(f"  Stage {i} ({name}): {len(flows_by_stage[i]):,} raw flows")

    print("\nExtracting temporal sequences per attack type...")
    all_sequences = []
    all_labels = []
    all_risks = []

    # Sequence extraction configuration per stage to achieve balance
    # Stage 0 (normal): Sample 12,000 sequences with stride 5
    # Stage 1 (reconnaissance / PortScan): Sample 8,000 sequences with stride 2
    # Stage 2 (initial_access / Brute Force): Sample 8,000 sequences with stride 1 & augmentation
    # Stage 3 (lateral_movement / Bot): Sample 6,000 sequences with stride 1 & jitter
    # Stage 4 (command_control / DoS): Sample 8,000 sequences with stride 5
    # Stage 5 (exfiltration / Infiltration): Sample 5,000 sequences with stride 1 & jitter

    target_seqs = {
        0: 12000,
        1: 8000,
        2: 8000,
        3: 6000,
        4: 8000,
        5: 5000,
    }

    strides = {
        0: 5,
        1: 2,
        2: 1,
        3: 1,
        4: 5,
        5: 1,
    }

    rng = np.random.RandomState(42)

    for stage_idx in range(NUM_STAGES):
        flows = np.array(flows_by_stage[stage_idx], dtype=np.float32)
        n_flows = len(flows)
        stage_name = STAGES[stage_idx]
        print(f"Building sequences for Stage {stage_idx} ({stage_name})...")

        seq_list = []
        if n_flows >= SEQ_LEN:
            stride = strides[stage_idx]
            for start in range(0, n_flows - SEQ_LEN + 1, stride):
                seq_list.append(flows[start:start + SEQ_LEN])

        print(f"  Extracted {len(seq_list):,} natural continuous sequences")

        # If we have fewer than target (e.g. Infiltration or Bot), augment with sequence jitter & noise
        if len(seq_list) < target_seqs[stage_idx]:
            needed = target_seqs[stage_idx] - len(seq_list)
            print(f"  Augmenting {needed:,} sequences for {stage_name}...")
            base_seqs = list(seq_list)
            if not base_seqs and n_flows > 0:
                # Tile flows to at least length 10
                repeats = (SEQ_LEN // n_flows) + 2
                tiled = np.tile(flows, (repeats, 1))
                for start in range(len(tiled) - SEQ_LEN + 1):
                    base_seqs.append(tiled[start:start + SEQ_LEN])

            for _ in range(needed):
                pick = base_seqs[rng.randint(0, len(base_seqs))]
                aug_seq = pick.copy()
                # Apply subtle realistic network jitter (±5% duration, slight packet variance)
                jitter = 1.0 + rng.uniform(-0.08, 0.08, size=aug_seq.shape).astype(np.float32)
                aug_seq[:, :7] = aug_seq[:, :7] * np.maximum(jitter[:, :7], 0.1)
                # Keep flags & protocol binary
                aug_seq[:, 7:] = pick[:, 7:]
                seq_list.append(aug_seq)
        elif len(seq_list) > target_seqs[stage_idx]:
            # Subsample down to target
            indices = rng.choice(len(seq_list), target_seqs[stage_idx], replace=False)
            seq_list = [seq_list[idx] for idx in indices]

        print(f"  Final count for {stage_name}: {len(seq_list):,} sequences")

        risk_val = STAGE_RISK_WEIGHTS[stage_idx]
        for s in seq_list:
            all_sequences.append(s)
            all_labels.append(stage_idx)
            all_risks.append([risk_val])

    all_sequences = np.array(all_sequences, dtype=np.float32)
    all_labels = np.array(all_labels, dtype=np.int64)
    all_risks = np.array(all_risks, dtype=np.float32)

    # Normalize all sequences
    print(f"\nTotal Dataset: {len(all_sequences):,} sequences across {NUM_STAGES} stages.")
    norm_sequences = normalize_sequence(all_sequences)

    return norm_sequences, all_labels, all_risks

def train():
    norm_seqs, labels, risks = load_and_build_dataset()

    # Split train, val, test (70% train, 15% val, 15% test)
    X_train, X_temp, y_train, y_temp, r_train, r_temp = train_test_split(
        norm_seqs, labels, risks, test_size=0.30, random_state=42, stratify=labels
    )
    X_val, X_test, y_val, y_test, r_val, r_test = train_test_split(
        X_temp, y_temp, r_temp, test_size=0.50, random_state=42, stratify=y_temp
    )

    print(f"\nDataset Splits:")
    print(f"  Train: {len(X_train):,} samples")
    print(f"  Val:   {len(X_val):,} samples")
    print(f"  Test:  {len(X_test):,} samples")

    train_ds = FlowSequenceDataset(X_train, y_train, r_train)
    val_ds = FlowSequenceDataset(X_val, y_val, r_val)
    test_ds = FlowSequenceDataset(X_test, y_test, r_test)

    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True, drop_last=True)
    val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE, shuffle=False)
    test_loader = DataLoader(test_ds, batch_size=BATCH_SIZE, shuffle=False)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")

    model = StageForecasterGRU(
        input_size=NUM_FEATURES,
        hidden_size=HIDDEN_SIZE,
        num_layers=NUM_LAYERS,
        num_classes=NUM_STAGES,
        dropout=DROPOUT
    ).to(device)

    # Balanced class weights for cross entropy
    class_counts = Counter(y_train)
    total_samples = len(y_train)
    weights = [total_samples / (NUM_STAGES * class_counts[i]) for i in range(NUM_STAGES)]
    class_weights = torch.tensor(weights, dtype=torch.float32).to(device)

    stage_criterion = nn.CrossEntropyLoss(weight=class_weights)
    risk_criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=LR, weight_decay=1e-5)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', factor=0.5, patience=3)

    best_val_loss = float('inf')
    best_model_state = None

    print("\nStarting GRU training...")
    for epoch in range(1, EPOCHS + 1):
        model.train()
        total_loss = 0.0
        correct_stage = 0
        total_samples_epoch = 0

        for x_b, y_stage_b, y_risk_b in train_loader:
            x_b = x_b.to(device)
            y_stage_b = y_stage_b.to(device)
            y_risk_b = y_risk_b.to(device)

            optimizer.zero_grad()
            stage_out, risk_out, _ = model(x_b)

            l_stage = stage_criterion(stage_out, y_stage_b)
            l_risk = risk_criterion(risk_out, y_risk_b)
            loss = l_stage + 0.5 * l_risk

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            total_loss += loss.item() * len(x_b)
            preds = stage_out.argmax(dim=-1)
            correct_stage += (preds == y_stage_b).sum().item()
            total_samples_epoch += len(x_b)

        train_loss = total_loss / total_samples_epoch
        train_acc = correct_stage / total_samples_epoch

        # Validation
        model.eval()
        val_loss = 0.0
        val_correct = 0
        val_total = 0

        with torch.no_grad():
            for x_b, y_stage_b, y_risk_b in val_loader:
                x_b = x_b.to(device)
                y_stage_b = y_stage_b.to(device)
                y_risk_b = y_risk_b.to(device)

                stage_out, risk_out, _ = model(x_b)
                l_stage = stage_criterion(stage_out, y_stage_b)
                l_risk = risk_criterion(risk_out, y_risk_b)
                v_loss = l_stage + 0.5 * l_risk

                val_loss += v_loss.item() * len(x_b)
                preds = stage_out.argmax(dim=-1)
                val_correct += (preds == y_stage_b).sum().item()
                val_total += len(x_b)

        val_loss /= val_total
        val_acc = val_correct / val_total
        scheduler.step(val_loss)

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_model_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}

        if epoch % 5 == 0 or epoch == 1 or epoch == EPOCHS:
            print(f"Epoch {epoch:02d}/{EPOCHS} | Train Loss: {train_loss:.4f} Acc: {train_acc*100:.2f}% | Val Loss: {val_loss:.4f} Acc: {val_acc*100:.2f}%")

    print("\nTraining completed. Evaluating best checkpoint on Test set...")
    model.load_state_dict(best_model_state)
    model.eval()
    model.to('cpu')

    all_preds = []
    all_targets = []
    with torch.no_grad():
        for x_b, y_stage_b, _ in test_loader:
            stage_out, _, _ = model(x_b)
            preds = stage_out.argmax(dim=-1).numpy()
            all_preds.extend(preds)
            all_targets.extend(y_stage_b.numpy())

    all_preds = np.array(all_preds)
    all_targets = np.array(all_targets)
    test_acc = float((all_preds == all_targets).mean())
    print(f"\nFinal Test Accuracy: {test_acc*100:.2f}%\n")
    print("Classification Report:")
    print(classification_report(all_targets, all_preds, target_names=STAGES, digits=4))

    print("Confusion Matrix:")
    cm = confusion_matrix(all_targets, all_preds)
    print(cm)

    # Save model checkpoint
    model_save_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'stage_forecaster_v1.pth')
    meta_save_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'stage_forecaster_v1_meta.json')

    torch.save({
        'model_state_dict': best_model_state,
        'stages': STAGES,
        'input_size': NUM_FEATURES,
        'hidden_size': HIDDEN_SIZE,
        'num_layers': NUM_LAYERS,
        'dropout': DROPOUT,
    }, model_save_path)
    print(f"\nSaved model weights to: {model_save_path}")

    meta = {
        "version": "v1",
        "created": datetime.utcnow().isoformat(),
        "stages": STAGES,
        "num_features": NUM_FEATURES,
        "sequence_length": SEQ_LEN,
        "model_config": {
            "input_size": NUM_FEATURES,
            "hidden_size": HIDDEN_SIZE,
            "num_layers": NUM_LAYERS,
            "num_stages": NUM_STAGES,
            "dropout": DROPOUT
        },
        "normalizer": {
            "feature_min": FEATURE_MIN.tolist(),
            "feature_max": FEATURE_MAX.tolist()
        },
        "forecast_horizon_seconds": 30,
        "test_accuracy": test_acc,
        "training_notes": "Trained on balanced temporal sequences from CIC-IDS2017 (Benign, PortScan, FTP/SSH-Patator & Web Brute Force, Bot, DoS/DDoS, Infiltration).",
        "label_mapping": {
            "BENIGN": "normal",
            "PortScan": "reconnaissance",
            "FTP-Patator": "initial_access",
            "SSH-Patator": "initial_access",
            "Web Attack - Brute Force": "initial_access",
            "DoS Hulk": "command_control",
            "DDoS": "command_control",
            "DoS GoldenEye": "command_control",
            "DoS slowloris": "command_control",
            "Bot": "lateral_movement",
            "Infiltration": "exfiltration"
        }
    }

    with open(meta_save_path, 'w') as f:
        json.dump(meta, f, indent=2)
    print(f"Saved metadata to: {meta_save_path}")

if __name__ == '__main__':
    train()
