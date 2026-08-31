#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
stage_forecaster_infer.py - Standalone inference for the GRU stage forecaster.

Usage:
    from models.stage_forecaster_infer import forecast_host

    result = forecast_host("192.168.1.100", recent_flows=[
        {"src_port": 54321, "dst_port": 80, "protocol": "TCP",
         "packet_count": 15, "byte_count": 4500, "duration": 0.5,
         "syn_flag": 1, "ack_flag": 0, "rst_flag": 0, "fin_flag": 0},
        # ... more flows ...
    ])
"""

import os
import json
import numpy as np

import torch
import torch.nn as nn

_MODELS_DIR = os.path.dirname(os.path.abspath(__file__))

_model = None
_meta = None


class _StageForecasterGRU(nn.Module):
    """GRU model architecture - must match training exactly."""

    def __init__(self, input_size=14, hidden_size=64, num_layers=2,
                 num_classes=6, dropout=0.2):
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


STAGES = ["normal", "reconnaissance", "initial_access",
          "lateral_movement", "command_control", "exfiltration"]

FEATURES = ["duration", "packet_count", "byte_count", "src_port", "dst_port",
            "packets_per_second", "bytes_per_packet",
            "syn_flag", "ack_flag", "rst_flag", "fin_flag",
            "protocol_tcp", "protocol_udp", "protocol_other"]


def _load_model():
    global _model, _meta
    if _model is not None:
        return

    model_path = os.path.join(_MODELS_DIR, "stage_forecaster_v1.pth")
    meta_path = os.path.join(_MODELS_DIR, "stage_forecaster_v1_meta.json")

    with open(meta_path) as f:
        _meta = json.load(f)

    cfg = _meta["model_config"]
    _model = _StageForecasterGRU(
        input_size=cfg["input_size"],
        hidden_size=cfg["hidden_size"],
        num_layers=cfg["num_layers"],
        num_classes=cfg["num_stages"],
        dropout=cfg["dropout"],
    )
    checkpoint = torch.load(model_path, map_location="cpu", weights_only=True)
    _model.load_state_dict(checkpoint["model_state_dict"])
    _model.eval()


def _flow_to_features(flow: dict) -> list:
    """Convert a flow dict to the 14-feature vector."""
    duration = max(float(flow.get("duration", 0)), 0.001)
    packet_count = max(int(flow.get("packet_count", 1)), 1)
    byte_count = int(flow.get("byte_count", 0))
    return [
        duration, packet_count, byte_count,
        int(flow.get("src_port", 0)),
        int(flow.get("dst_port", 0)),
        packet_count / duration,
        byte_count / packet_count,
        int(flow.get("syn_flag", 0)),
        int(flow.get("ack_flag", 0)),
        int(flow.get("rst_flag", 0)),
        int(flow.get("fin_flag", 0)),
        1 if str(flow.get("protocol", "TCP")).upper() == "TCP" else 0,
        1 if str(flow.get("protocol", "TCP")).upper() == "UDP" else 0,
        0 if str(flow.get("protocol", "TCP")).upper() in ("TCP", "UDP") else 1,
    ]


def _normalize(features: np.ndarray) -> np.ndarray:
    norm = _meta["normalizer"]
    fmin = np.array(norm["feature_min"], dtype=np.float32)
    fmax = np.array(norm["feature_max"], dtype=np.float32)
    return (features - fmin) / (fmax - fmin + 1e-8)


def forecast_host(host_ip: str, recent_flows: list[dict], forecast_steps: int = 6, risk_history: list = None) -> dict:
    """
    Forecast the attack stage and risk for a given host.

    Args:
        host_ip: IP address of the host to forecast
        recent_flows: List of recent flow dicts (up to 10 most recent)
        forecast_steps: Number of future timesteps to project risk curve
        risk_history: Optional list of recent historical risk_score floats for host

    Returns:
        Dict with keys:
            host: str
            stage_probs: dict mapping stage name to probability
            predicted_stage: str (highest probability stage)
            risk_score: float (0.0-1.0)
            projected_risk_curve: list of float risk scores for future steps
    """
    _load_model()

    seq_len = _meta["sequence_length"]

    # Convert flows to features
    features_list = [_flow_to_features(f) for f in recent_flows]

    # Pad or truncate to sequence length
    if len(features_list) < seq_len:
        padding = [[0.0] * len(FEATURES)] * (seq_len - len(features_list))
        features_list = padding + features_list
    else:
        features_list = features_list[-seq_len:]

    # Normalize
    features = np.array(features_list, dtype=np.float32)
    features_norm = _normalize(features)
    x = torch.tensor(features_norm, dtype=torch.float32).unsqueeze(0)

    # Predict current stage
    with torch.no_grad():
        stage_probs_tensor, risk_tensor, hidden = _model(x)

    stage_probs = torch.softmax(stage_probs_tensor, dim=-1).squeeze().tolist()
    risk_score = risk_tensor.squeeze().item()

    # Build stage probs dict
    stage_probs_dict = {STAGES[i]: round(p, 4) for i, p in enumerate(stage_probs)}
    predicted_stage = STAGES[int(np.argmax(stage_probs))]

    # Calculate effective risk based on current model predictions
    stage_weights = [0.0, 0.2, 0.5, 0.7, 0.9, 1.0]
    weighted_stage_risk = sum(p * w for p, w in zip(stage_probs, stage_weights))
    effective_risk = round(max(0.0, min(1.0, (risk_score + weighted_stage_risk) / 2.0)), 4)

    # Derive linear trend slope from real historical risk trajectory
    if risk_history and len(risk_history) >= 3:
        y = np.array(list(risk_history) + [effective_risk], dtype=np.float32)
        x_idx = np.arange(len(y), dtype=np.float32)
        slope = float(np.polyfit(x_idx, y, 1)[0])
    else:
        slope = 0.0

    projected_risk = [effective_risk]
    current = effective_risk
    for _ in range(1, forecast_steps):
        current = min(1.0, max(0.0, current + slope))
        projected_risk.append(round(current, 4))

    return {
        "host": host_ip,
        "stage_probs": stage_probs_dict,
        "predicted_stage": predicted_stage,
        "risk_score": round(risk_score, 4),
        "projected_risk_curve": projected_risk,
        "windows_collected": len(recent_flows),
        "min_windows_required": seq_len,
    }


if __name__ == "__main__":
    # Quick self-test
    test_flows = [
        {"src_port": 54321, "dst_port": 80, "protocol": "TCP",
         "packet_count": 5, "byte_count": 300, "duration": 0.1,
         "syn_flag": 1, "ack_flag": 0, "rst_flag": 0, "fin_flag": 0,
         "label": "port_scan"},
    ] * 10

    result = forecast_host("192.168.1.100", test_flows)
    print(json.dumps(result, indent=2))
