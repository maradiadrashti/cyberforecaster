# Cyberforecaster ML Training Pipeline

## Overview

This directory contains the training scripts for Cyberforecaster's two ML models.

### Scripts

- **train_flow_classifier.py** — XGBoost multi-class per-flow attack classifier
- **train_stage_forecaster.py** — GRU sequence model for attack stage forecasting

### Model 1: Flow Classifier (XGBoost)

**Purpose:** Classify every captured network flow in real-time as one of:
benign, port_scan, brute_force, dos_ddos, arp_spoof, exfiltration

**Features (14 total):**
- duration, packet_count, byte_count, src_port, dst_port
- packets_per_second, bytes_per_packet (derived ratios)
- syn_flag, ack_flag, rst_flag, fin_flag
- protocol_tcp, protocol_udp, protocol_other (one-hot)

**Architecture:** XGBoost gradient boosting (chosen over RandomForest for faster
inference ~1-2ms, better handling of class imbalance, and superior tabular data
performance at this scale).

**Class imbalance:** SMOTE oversampling on training set only.

```bash
python training/train_flow_classifier.py labeled_flows.csv public_flows.csv
```

### Model 2: Stage Forecaster (GRU)

**Purpose:** For a given host, predict the current attack stage and project
future risk over 30 seconds.

**Stages:** normal → reconnaissance → initial_access → lateral_movement →
command_control → exfiltration

**Architecture:** 2-layer GRU (hidden=64, dropout=0.2) + classification head
+ regression head.

- Hidden size 64: Double the reference project's 32 for 14 features (vs 6).
  Large enough for stage transitions, small enough for <1ms inference.
- 2 layers: Layer 1 captures per-flow patterns, layer 2 captures temporal
  transitions. 3rd layer risks overfitting on limited data.
- Sequence length 10: ~5 min of traffic context at typical flow rates.

**Training data:** Bootstrapped sequences chaining real labeled flows in
artificial temporal order. TEMPORARY bootstrapping strategy — see training
notes in output metadata.

```bash
python training/train_stage_forecaster.py labeled_flows.csv public_flows.csv
```

### Output

Both scripts save to `models/`:
- `flow_classifier_v1.joblib` + `flow_label_encoder_v1.joblib`
- `stage_forecaster_v1.pth`
- `flow_classifier_infer.py` / `stage_forecaster_infer.py` (auto-generated)

### Hyperparameters

| Parameter | Classifier | Forecaster |
|-----------|-----------|------------|
| Model | XGBoost | GRU (PyTorch) |
| Hidden size | N/A | 64 |
| Layers | N/A | 2 |
| Sequence length | N/A | 10 flows |
| Batch size | N/A | 32 |
| Learning rate | 0.1 | 0.001 |
| Epochs | 300 (n_estimators) | 50 |
| Dropout | N/A | 0.2 |
| Regularization | L1=0.1, L2=1.0 | weight_decay=1e-5 |
