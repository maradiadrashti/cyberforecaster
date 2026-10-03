#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
predict_csv.py -- Command-line inference script for flow CSV files using the trained LSTM model.
Usage:
    python predict_csv.py sample_test_flows.csv
"""

import sys
import os
import json
import pandas as pd
import numpy as np

# Add repo root to path
_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from models.stage_forecaster_lstm_infer import forecast_host, _load_model

REQUIRED_COLUMNS = [
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "flow_start", "flow_end",
    "duration", "packet_count", "byte_count", "syn_count", "ack_count", "fin_count",
    "rst_count", "ttl_mean", "ttl_var", "win_mean", "win_var", "frag_ratio",
    "payload_mean", "payload_std", "retransmit_count"
]


def predict_csv(csv_path: str) -> dict:
    if not os.path.exists(csv_path):
        print(f"Error: File '{csv_path}' not found.", file=sys.stderr)
        sys.exit(1)

    df = pd.read_csv(csv_path)

    # Validate columns
    col_map = {c.strip().lower(): c for c in df.columns}
    missing = [col for col in REQUIRED_COLUMNS if col not in col_map]
    if missing:
        print(f"Error: Missing required columns: {missing}", file=sys.stderr)
        sys.exit(1)

    # Normalize column names in dataframe
    df = df.rename(columns={col_map[col]: col for col in REQUIRED_COLUMNS if col in col_map})

    # Clean numeric columns
    numeric_cols = [c for c in REQUIRED_COLUMNS if c not in ("src_ip", "dst_ip", "protocol")]
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    # Ensure protocol and IPs are strings
    df["src_ip"] = df["src_ip"].astype(str)
    df["dst_ip"] = df["dst_ip"].astype(str)
    df["protocol"] = df["protocol"].astype(str)

    from models.stage_forecaster_lstm_infer import forecast_host, _load_model
    import models.stage_forecaster_lstm_infer as lstm_infer
    _load_model()
    _meta = lstm_infer._meta
    seq_len = _meta.get("sequence_length", 5)

    total_flows = len(df)
    conversation_groups = df.groupby(["src_ip", "dst_ip"])
    total_conversations = len(conversation_groups)

    results = []
    skipped_too_short = 0

    for (src_ip, dst_ip), group in conversation_groups:
        group_sorted = group.sort_values("flow_start")
        flows = group_sorted.to_dict(orient="records")

        if len(flows) < seq_len:
            skipped_too_short += 1
            continue

        fc = forecast_host(dst_ip, flows, src_ip=src_ip)
        results.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "infiltration_probability": fc["risk_score"],
            "predicted_stage": fc["predicted_stage"],
            "stage_probabilities": fc["stage_probs"],
            "flows_used": len(flows),
        })

    out = {
        "status": "success",
        "filename": os.path.basename(csv_path),
        "total_flows": total_flows,
        "total_conversations": total_conversations,
        "conversations_skipped_too_short": skipped_too_short,
        "results": results,
    }
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python predict_csv.py <path_to_flow_csv>")
        sys.exit(1)

    csv_path = sys.argv[1]
    res = predict_csv(csv_path)
    print(json.dumps(res, indent=2))
