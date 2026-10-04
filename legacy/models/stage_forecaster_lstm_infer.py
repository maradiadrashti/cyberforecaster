#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
stage_forecaster_lstm_infer.py -- Standalone inference for the NEW LSTM world
model (trained on CIC-IDS-2018 + CTU-13, 21 flow+packet features, genuine
forward forecasting). This REPLACES stage_forecaster_infer.py (the old GRU
model) as a drop-in: same function name, same call signature, same return
shape -- so capture_server.py needs no other changes besides the import line.

Usage (same as before):
    from models.stage_forecaster_lstm_infer import forecast_host
    result = forecast_host(host_ip, recent_flows, risk_history=..., src_ip=...)
"""

import os
import json
import numpy as np

import torch
import torch.nn as nn

_MODELS_DIR = os.path.dirname(os.path.abspath(__file__))

_model = None
_meta = None


class StageForecasterLSTM(nn.Module):
    """Must match train_lstm_world_model.py exactly."""

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


def _load_model():
    global _model, _meta
    if _model is not None:
        return

    model_path = os.path.join(_MODELS_DIR, "stage_forecaster_lstm_v1.pth")
    meta_path = os.path.join(_MODELS_DIR, "stage_forecaster_lstm_v1_meta.json")

    if not os.path.exists(model_path) or not os.path.exists(meta_path):
        raise FileNotFoundError(
            f"Missing model files in {_MODELS_DIR}. Copy stage_forecaster_lstm_v1.pth "
            f"and stage_forecaster_lstm_v1_meta.json here from your training machine."
        )

    with open(meta_path) as f:
        _meta = json.load(f)

    cfg = _meta["model_config"]
    _model = StageForecasterLSTM(
        input_size=cfg["input_size"], hidden_size=cfg["hidden_size"],
        num_layers=cfg["num_layers"], num_classes=cfg["num_stages"],
        dropout=cfg["dropout"],
    )
    checkpoint = torch.load(model_path, map_location="cpu", weights_only=True)
    _model.load_state_dict(checkpoint["model_state_dict"])
    _model.eval()


# Maps the live capture_server.py window-dict field names to the field
# names the model's feature_columns (from training) actually use. The
# live pipeline calls these "*_flag" (they're per-window counts, not
# single-packet flags); training data used "*_count". Same information,
# different name -- this dict bridges that gap.
_FIELD_ALIASES = {
    "syn_count": "syn_flag",
    "ack_count": "ack_flag",
    "fin_count": "fin_flag",
    "rst_count": "rst_flag",
}


def _flow_to_feature_dict(flow: dict) -> dict:
    """Build a dict keyed by every possible training feature name, pulling
    values from the live window dict (handling the naming differences)."""
    out = dict(flow)
    for train_name, live_name in _FIELD_ALIASES.items():
        if train_name not in out and live_name in flow:
            out[train_name] = flow[live_name]
    return out


def _flows_to_matrix(recent_flows: list, feature_cols: list, log_cols: list,
                      feat_min: np.ndarray, feat_max: np.ndarray, seq_len: int) -> np.ndarray:
    feats_per_flow = []
    for flow in recent_flows:
        fd = _flow_to_feature_dict(flow)
        vec = [float(fd.get(c, 0) or 0) for c in feature_cols]
        feats_per_flow.append(vec)

    if len(feats_per_flow) < seq_len:
        pad_count = seq_len - len(feats_per_flow)
        feats_per_flow = [feats_per_flow[0]] * pad_count + feats_per_flow
    else:
        feats_per_flow = feats_per_flow[-seq_len:]

    arr = np.array(feats_per_flow, dtype=np.float32)
    for i, col in enumerate(feature_cols):
        if col in log_cols:
            arr[:, i] = np.log1p(np.clip(arr[:, i], a_min=0, a_max=None))

    arr_norm = (arr - feat_min) / (feat_max - feat_min + 1e-8)
    return np.clip(arr_norm, 0.0, 1.0)


def forecast_host(host_ip: str, recent_flows: list, forecast_steps: int = 6,
                   risk_history: list = None, src_ip: str = "") -> dict:
    """Same interface as the old GRU forecast_host() -- drop-in replacement."""
    # kept for API compatibility; not used
    try:
        _load_model()
    except Exception as e:
        print(f"[LSTM Infer] Model load failed: {e}")
        return {
            "host": host_ip,
            "model_status": "UNAVAILABLE",
            "windows_collected": len(recent_flows or []),
            "min_windows_required": 5,
            "input_shape": None,
        }

    feature_cols = _meta["feature_columns"]
    log_cols = _meta.get("log_transform_columns", [])
    stages = _meta["stages"]
    seq_len = _meta["sequence_length"]
    horizon = _meta.get("forecast_horizon", 0)
    feat_min = np.array(_meta["normalizer"]["feature_min"], dtype=np.float32)
    feat_max = np.array(_meta["normalizer"]["feature_max"], dtype=np.float32)

    if not recent_flows:
        return {
            "host": host_ip,
            "model_status": "WARMING UP",
            "windows_collected": 0,
            "min_windows_required": seq_len,
            "input_shape": None,
        }

    window_norm = _flows_to_matrix(recent_flows, feature_cols, log_cols, feat_min, feat_max, seq_len)
    x = torch.tensor(window_norm, dtype=torch.float32).unsqueeze(0)

    with torch.no_grad():
        stage_logits, risk_pred = _model(x)

    stage_probs_raw = torch.softmax(stage_logits, dim=-1).squeeze()
    stage_probs = stage_probs_raw.tolist()
    risk_score = float(risk_pred.squeeze().item())

    predicted_idx = int(torch.argmax(stage_probs_raw).item())
    predicted_stage = stages[predicted_idx]
    confidence = float(stage_probs[predicted_idx])

    stage_probs_dict = {stages[i]: round(float(stage_probs[i]), 4) for i in range(len(stages))}

    print(
        f"[LSTM_LIVE_INFERENCE]\nsrc={src_ip or 'unknown'}\ndst={host_ip}"
        f"\ninput_shape=(1,{seq_len},{len(feature_cols)})\nforecast_horizon={horizon}"
        f"\nattack_risk={risk_score:.4f}\npredicted_stage={predicted_stage}\nconfidence={confidence:.4f}",
        flush=True,
    )

    return {
        "host": host_ip,
        "model_status": "TRAINED",
        "input_shape": [1, seq_len, len(feature_cols)],
        "stage_probs": stage_probs_dict,
        "predicted_stage": predicted_stage,
        "confidence": round(confidence, 4),
        "risk_score": round(risk_score, 4),
        "windows_collected": len(recent_flows),
        "min_windows_required": seq_len,
        "forecast_horizon": horizon,
    }


if __name__ == "__main__":
    test_flows = [
        {"src_port": 54321, "dst_port": 80, "duration": 0.1, "packet_count": 5, "byte_count": 300,
         "syn_flag": 1, "ack_flag": 0, "rst_flag": 0, "fin_flag": 0,
         "ttl_mean": 64, "ttl_var": 0, "win_mean": 8192, "win_var": 0,
         "frag_ratio": 0, "payload_mean": 20, "payload_std": 2, "retransmit_count": 0},
    ] * 8
    result = forecast_host("192.168.1.100", test_flows)
    print(json.dumps(result, indent=2))
