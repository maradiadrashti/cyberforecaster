#!/usr/bin/env python3
"""
train_lstm_world_model.py -- Trains the LSTM "world model" on your labeled
CIC-IDS-2018 data.

WHAT THIS DOES (plain language):
    1. Loads your labeled CSV.
    2. Because attack rows are rare, it keeps ALL attack rows but only
       samples a manageable chunk of the "Benign" rows (so training fits on
       a normal laptop in reasonable time -- this is the "train on a
       representative sample" strategy).
    3. Groups flows by source IP and sorts them by time, so each host has
       its own timeline of behavior -- this is what makes it a WORLD MODEL
       instead of a flat classifier: the LSTM sees a SEQUENCE of past flows
       for a host and learns how that host's behavior evolves.
    4. Cuts each host's timeline into overlapping windows of 10 flows. The
       LSTM's job: given these 10 past flows, predict the CURRENT attack
       stage.
    5. Trains an LSTM (2 layers) with two output heads, same shape as your
       existing model: a stage classifier (6 classes) and a risk score
       (0-1).
    6. Saves the trained weights + a metadata file describing the model,
       in the same format your existing stage_forecaster_infer.py expects.

USAGE:
    pip install torch pandas numpy scikit-learn
    python train_lstm_world_model.py merged_2018_labeled.csv

OUTPUT:
    stage_forecaster_lstm_v1.pth
    stage_forecaster_lstm_v1_meta.json
"""

import sys
import json
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split

# ---- Config -----------------------------------------------------------
FEATURE_COLS = [
    "duration", "packet_count", "byte_count",
    "syn_count", "ack_count", "fin_count", "rst_count",
    "ttl_mean", "ttl_var", "win_mean", "win_var",
    "frag_ratio", "payload_mean", "payload_std", "retransmit_count",
]
# STEP 1: these columns are heavily skewed (a few huge values, mostly small
# ones -- typical for byte/packet counts). Without fixing this, min-max
# normalization squashes almost everything near 0 and the model barely sees
# any difference between most flows. log1p(x) = log(1+x) spreads these out.
LOG_TRANSFORM_COLS = [
    "duration", "packet_count", "byte_count",
    "syn_count", "ack_count", "fin_count", "rst_count",
    "ttl_var", "win_var", "payload_mean", "payload_std", "retransmit_count",
]
STAGES = ["normal", "reconnaissance", "initial_access",
          "lateral_movement", "command_control", "exfiltration"]

# STEP 4: shorter sequences -- with SEQ_LEN=10 many (src,dst) conversation
# pairs get dropped entirely for not having 10 flows. SEQ_LEN=5 keeps far
# more of them, especially short attack bursts like brute-force attempts.
SEQ_LEN = 5             # how many past flows the LSTM looks at
STRIDE = 2              # step between windows (overlap for more training data)
FORECAST_HORIZON = 3    # predict the stage THIS MANY flows into the future
                        # (not the current/last flow) -- this is what makes
                        # it forecasting instead of plain classification
# NOTE: attack/benign row counts are no longer set by fixed caps here --
# the code below always keeps 100% of attack rows and dynamically matches
# benign 1:1 to that count, for a genuine balance at maximum real data volume.
HIDDEN_SIZE = 64       # dropped back down from 128 -- the bigger model was
                        # overfitting fast with only ~1.5M clean sequences
DROPOUT = 0.3           # a bit more dropout to fight overfitting further
NUM_LAYERS = 2
BATCH_SIZE = 256
EPOCHS = 60             # raised again -- running overnight, no time pressure now
LR = 5e-4
EARLY_STOP_PATIENCE = 12  # raised again -- let it genuinely plateau before stopping


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


class FlowSeqDataset(Dataset):
    def __init__(self, X, y_stage, y_risk):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y_stage = torch.tensor(y_stage, dtype=torch.long)
        self.y_risk = torch.tensor(y_risk, dtype=torch.float32)

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        return self.X[idx], self.y_stage[idx], self.y_risk[idx]


def build_sequences(df):
    # Grouping by src_ip ALONE was a bug: one attacker IP can touch many
    # different victim IPs in quick succession, so a single window could
    # accidentally mix flows belonging to different attack stages. Grouping
    # by the (src_ip, dst_ip) PAIR keeps each window to a single
    # conversation/timeline, which is what "state transition" should mean.
    #
    # THIS IS THE REAL FORECASTING FIX: earlier versions predicted the label
    # of the LAST flow inside the input window -- that's just describing the
    # CURRENT state, not forecasting anything. A true world model has to
    # predict a FUTURE state from a PAST window it hasn't seen yet. So now:
    # input = SEQ_LEN flows, target = the flow's stage FORECAST_HORIZON
    # steps AFTER the window ends -- something that hasn't happened yet at
    # the time the window ends. This is what makes K-step forward
    # simulation and an "infiltration probability before it completes"
    # score meaningful, instead of just reporting what's already visible.
    print("[*] Grouping flows by (source IP, destination IP) pair and building FORECASTING sequences ...")
    sequences = []
    stage_labels = []
    risk_labels = []
    n_dropped_mixed = 0

    df = df.sort_values(["src_ip", "dst_ip", "flow_start"])
    for (_src_ip, _dst_ip), group in df.groupby(["src_ip", "dst_ip"]):
        if len(group) < SEQ_LEN + FORECAST_HORIZON:
            continue
        feats = group[FEATURE_COLS].values
        stages = group["attack_stage"].values

        last_start = len(group) - SEQ_LEN - FORECAST_HORIZON + 1
        for start in range(0, last_start, STRIDE):
            window_stages = stages[start:start + SEQ_LEN]
            # Drop "noisy" INPUT windows that mix more than one real stage --
            # this is about keeping the INPUT clean, not the target. The
            # target below is deliberately allowed to be a DIFFERENT stage
            # than the input -- that's the whole point of forecasting.
            if len(set(window_stages)) > 1:
                n_dropped_mixed += 1
                continue
            window = feats[start:start + SEQ_LEN]
            target_idx = start + SEQ_LEN - 1 + FORECAST_HORIZON
            target_stage = stages[target_idx]
            sequences.append(window)
            stage_idx = STAGES.index(target_stage) if target_stage in STAGES else 0
            stage_labels.append(stage_idx)
            risk_labels.append(0.0 if stage_idx == 0 else 1.0)

    print(f"[+] Built {len(sequences):,} clean FORECASTING sequences "
          f"(input = {SEQ_LEN} past flows, target = the stage "
          f"{FORECAST_HORIZON} flows into the future; "
          f"dropped {n_dropped_mixed:,} mixed-label input windows).")
    return np.array(sequences, dtype=np.float32), np.array(stage_labels), np.array(risk_labels, dtype=np.float32)


def main(labeled_csv):
    print(f"[*] Loading {labeled_csv} ...")
    usecols = ["src_ip", "dst_ip", "flow_start", "attack_stage"] + FEATURE_COLS
    df = pd.read_csv(labeled_csv, usecols=usecols)
    print(f"[+] Loaded {len(df):,} total rows.")

    # THE REAL LESSON from two failed attempts now: capping ONLY benign
    # (old bug) made the model think attacks are common (~84% attack) and
    # it over-triggered on everything. Using ALL rows uncapped (last night's
    # run) let "normal" dominate again (~70%) and the model just collapsed
    # to guessing "normal" every time -- binary accuracy LOOKED like 72%
    # but was barely better than that lazy shortcut, and stage accuracy got
    # WORSE. Neither extreme works. The fix: keep EVERY attack row (never
    # throw away the rare, valuable class), and match benign 1:1 to
    # whatever that attack count actually is -- a genuine 50/50 balance
    # that also uses as much real data as possible, not a small fixed cap.
    attack_df = df[df["attack_stage"] != "normal"]
    benign_df = df[df["attack_stage"] == "normal"]
    print(f"[*] Attack rows: {len(attack_df):,} | Benign rows: {len(benign_df):,}")

    print(f"[*] Keeping ALL {len(attack_df):,} attack rows (never downsampled -- "
          f"it's the rare, valuable class).")

    target_benign = len(attack_df)
    if len(benign_df) > target_benign:
        benign_df = benign_df.sample(n=target_benign, random_state=42)
        print(f"[*] Matched benign rows 1:1 with attack rows -> "
              f"downsampled benign to {len(benign_df):,} for a genuine 50/50 balance.")
    else:
        print(f"[*] Using ALL {len(benign_df):,} benign rows -- no downsampling.")

    # Sanity check -- guarantee both classes are genuinely present before
    # we go any further, since training on only one class would be useless.
    assert len(attack_df) > 0, "No attack rows found at all -- check your labeled CSV."
    assert len(benign_df) > 0, "No benign rows found at all -- check your labeled CSV."

    print(f"[*] Final training mix: {len(attack_df):,} attack rows vs "
          f"{len(benign_df):,} benign rows "
          f"({100*len(attack_df)/(len(attack_df)+len(benign_df)):.1f}% attack).")

    df = pd.concat([attack_df, benign_df], ignore_index=True)

    # Clean up any NaN/inf values in features
    df[FEATURE_COLS] = df[FEATURE_COLS].replace([np.inf, -np.inf], 0).fillna(0)

    # STEP 1: log1p-transform the heavily skewed columns so a handful of
    # huge values (e.g. a DDoS flow with a massive byte_count) don't squash
    # every normal-sized value down near 0 once we min-max normalize below.
    for col in LOG_TRANSFORM_COLS:
        df[col] = np.log1p(df[col].clip(lower=0))

    X, y_stage, y_risk = build_sequences(df)
    if len(X) == 0:
        print("[!] No sequences built -- check that src_ip groups have enough rows.")
        sys.exit(1)

    # Normalize features (min-max), save bounds for inference later
    feat_min = X.reshape(-1, X.shape[-1]).min(axis=0)
    feat_max = X.reshape(-1, X.shape[-1]).max(axis=0)
    X_norm = (X - feat_min) / (feat_max - feat_min + 1e-8)

    X_train, X_val, y_stage_train, y_stage_val, y_risk_train, y_risk_val = train_test_split(
        X_norm, y_stage, y_risk, test_size=0.2, random_state=42, stratify=y_stage
    )

    train_ds = FlowSeqDataset(X_train, y_stage_train, y_risk_train)
    val_ds = FlowSeqDataset(X_val, y_stage_val, y_risk_val)
    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE)

    # Class weights so rare attack stages aren't ignored
    class_counts = np.bincount(y_stage_train, minlength=len(STAGES))
    class_weights = 1.0 / (class_counts + 1)
    class_weights = class_weights / class_weights.sum() * len(STAGES)
    class_weights_t = torch.tensor(class_weights, dtype=torch.float32)
    print(f"[*] Class counts (train): {dict(zip(STAGES, class_counts))}")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Training on: {device}")

    model = StageForecasterLSTM(input_size=len(FEATURE_COLS), hidden_size=HIDDEN_SIZE,
                                 num_layers=NUM_LAYERS, num_classes=len(STAGES),
                                 dropout=DROPOUT).to(device)
    stage_criterion = nn.CrossEntropyLoss(weight=class_weights_t.to(device))
    risk_criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=LR)

    best_val_acc = -1.0
    best_state_dict = None
    epochs_since_improve = 0

    for epoch in range(1, EPOCHS + 1):
        model.train()
        total_loss = 0.0
        for xb, yb_stage, yb_risk in train_loader:
            xb, yb_stage, yb_risk = xb.to(device), yb_stage.to(device), yb_risk.to(device)
            optimizer.zero_grad()
            stage_logits, risk_pred = model(xb)
            loss = stage_criterion(stage_logits, yb_stage) + risk_criterion(risk_pred.squeeze(), yb_risk)
            loss.backward()
            # Gradient clipping -- keeps training stable (stops val_accuracy
            # from randomly swinging wildly between epochs).
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
            optimizer.step()
            total_loss += loss.item() * xb.size(0)

        avg_loss = total_loss / len(train_ds)

        # Quick validation accuracy -- STEP 2: report TWO numbers, not one.
        # val_acc = the hard problem (which exact stage out of 6).
        # val_acc_binary = the easier, separate problem (attack vs normal
        # at all), using the model's own risk_head output. Both are honest,
        # legitimate metrics -- report both rather than only the hard one.
        model.eval()
        correct = 0
        correct_binary = 0
        with torch.no_grad():
            for xb, yb_stage, yb_risk in val_loader:
                xb, yb_stage, yb_risk = xb.to(device), yb_stage.to(device), yb_risk.to(device)
                stage_logits, risk_pred = model(xb)
                preds = stage_logits.argmax(dim=1)
                correct += (preds == yb_stage).sum().item()
                preds_binary = (risk_pred.squeeze() > 0.5).float()
                correct_binary += (preds_binary == yb_risk).sum().item()
        val_acc = correct / len(val_ds)
        val_acc_binary = correct_binary / len(val_ds)

        # Track the BEST model seen so far. FIX: previously this only looked
        # at stage_val_accuracy, which meant a checkpoint could get "locked
        # in" even while binary_val_accuracy (the attack/normal detection
        # that matters most for the actual demo) was still improving. Now we
        # track a COMBINED score -- binary accuracy weighted higher, since
        # "is this an attack at all" is the primary job; exact stage is the
        # secondary, harder bonus on top.
        combined_score = (0.7 * val_acc_binary) + (0.3 * val_acc)
        improved = combined_score > best_val_acc
        if improved:
            best_val_acc = combined_score
            best_state_dict = {k: v.clone() for k, v in model.state_dict().items()}
            epochs_since_improve = 0
        else:
            epochs_since_improve += 1

        flag = "  <- best so far" if improved else ""
        print(f"[Epoch {epoch}/{EPOCHS}] train_loss={avg_loss:.4f}  "
              f"stage_val_accuracy={val_acc:.4f}  binary_val_accuracy={val_acc_binary:.4f}{flag}")

        if epochs_since_improve >= EARLY_STOP_PATIENCE:
            print(f"[!] No improvement for {EARLY_STOP_PATIENCE} epochs in a row -- "
                  f"stopping early to avoid overfitting. Best combined score was {best_val_acc:.4f}.")
            break

    # Save the BEST model seen during training (not necessarily the last
    # epoch) + metadata (same format your existing infer script expects)
    model.load_state_dict(best_state_dict)
    print(f"[+] Restoring best model (combined score={best_val_acc:.4f}) before saving.")
    torch.save({"model_state_dict": model.state_dict()}, "stage_forecaster_lstm_v1.pth")

    meta = {
        "model_config": {
            "input_size": len(FEATURE_COLS),
            "hidden_size": HIDDEN_SIZE,
            "num_layers": NUM_LAYERS,
            "num_stages": len(STAGES),
            "dropout": DROPOUT,
        },
        "sequence_length": SEQ_LEN,
        "forecast_horizon": FORECAST_HORIZON,
        "log_transform_columns": LOG_TRANSFORM_COLS,
        "feature_columns": FEATURE_COLS,
        "stages": STAGES,
        "normalizer": {
            "feature_min": feat_min.tolist(),
            "feature_max": feat_max.tolist(),
        },
    }
    with open("stage_forecaster_lstm_v1_meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    print("[+] DONE. Saved stage_forecaster_lstm_v1.pth and stage_forecaster_lstm_v1_meta.json")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python train_lstm_world_model.py <labeled_csv>")
        sys.exit(1)
    main(sys.argv[1])
