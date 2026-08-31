#!/usr/bin/env python3
"""
flow_classifier_infer.py - Standalone inference function for the flow classifier.

Usage:
    from models.flow_classifier_infer import predict_flow

    result = predict_flow({
        'src_port': 54321,
        'dst_port': 80,
        'protocol': 'TCP',
        'packet_count': 15,
        'byte_count': 4500,
        'duration': 0.5,
        'syn_flag': 1,
        'ack_flag': 0,
        'rst_flag': 0,
        'fin_flag': 0,
    })
    # result = ("port_scan", 0.92)
"""

import os
import numpy as np
import joblib

# Path to model artifacts (relative to this file or absolute)
_MODELS_DIR = os.path.dirname(os.path.abspath(__file__))

_model = None
_label_encoder = None
_features = None


def _load_model():
    """Lazy-load model and encoder on first prediction."""
    global _model, _label_encoder, _features

    if _model is not None:
        return

    model_path = os.path.join(_MODELS_DIR, "flow_classifier_v1.joblib")
    encoder_path = os.path.join(_MODELS_DIR, "flow_label_encoder_v1.joblib")
    meta_path = os.path.join(_MODELS_DIR, "flow_classifier_meta.json")

    _model = joblib.load(model_path)
    _label_encoder = joblib.load(encoder_path)

    import json
    with open(meta_path) as f:
        meta = json.load(f)
    _features = meta['features']


def predict_flow(flow_dict: dict) -> tuple[str, float]:
    """
    Predict the attack category and confidence for a single flow.

    Args:
        flow_dict: Dict with keys matching the flow schema:
            src_port, dst_port, protocol, packet_count, byte_count,
            duration, syn_flag, ack_flag, rst_flag, fin_flag

    Returns:
        (label: str, confidence: float)
        Label is one of: benign, port_scan, brute_force, dos_ddos,
                         arp_spoof, exfiltration
        Confidence is the model's probability for the predicted class.

    Target latency: <10ms per prediction (XGBoost typically ~1-2ms).
    """
    _load_model()

    # Feature engineering (must match training pipeline)
    duration = max(float(flow_dict.get('duration', 0)), 0.001)
    packet_count = max(int(flow_dict.get('packet_count', 1)), 1)
    byte_count = int(flow_dict.get('byte_count', 0))

    features = [
        duration,                                         # duration
        packet_count,                                     # packet_count
        byte_count,                                       # byte_count
        int(flow_dict.get('src_port', 0)),                # src_port
        int(flow_dict.get('dst_port', 0)),                # dst_port
        packet_count / duration,                          # packets_per_second
        byte_count / packet_count,                        # bytes_per_packet
        int(flow_dict.get('syn_flag', 0)),                # syn_flag
        int(flow_dict.get('ack_flag', 0)),                # ack_flag
        int(flow_dict.get('rst_flag', 0)),                # rst_flag
        int(flow_dict.get('fin_flag', 0)),                # fin_flag
        1 if str(flow_dict.get('protocol', 'TCP')).upper() == 'TCP' else 0,
        1 if str(flow_dict.get('protocol', 'TCP')).upper() == 'UDP' else 0,
        0 if str(flow_dict.get('protocol', 'TCP')).upper() in ('TCP', 'UDP') else 1,
    ]

    X = np.array([features], dtype=np.float32)

    # Predict
    probabilities = _model.predict_proba(X)[0]
    predicted_idx = int(np.argmax(probabilities))
    confidence = float(probabilities[predicted_idx])
    label = _label_encoder.inverse_transform([predicted_idx])[0]

    return label, confidence


def predict_flow_proba(flow_dict: dict) -> dict[str, float]:
    """
    Get probability distribution over all classes for a single flow.

    Returns:
        Dict mapping class name to probability.
        Example: {"benign": 0.05, "port_scan": 0.92, "brute_force": 0.01, ...}
    """
    _load_model()

    # Reuse the same feature extraction
    duration = max(float(flow_dict.get('duration', 0)), 0.001)
    packet_count = max(int(flow_dict.get('packet_count', 1)), 1)
    byte_count = int(flow_dict.get('byte_count', 0))

    features = [
        duration,
        packet_count,
        byte_count,
        int(flow_dict.get('src_port', 0)),
        int(flow_dict.get('dst_port', 0)),
        packet_count / duration,
        byte_count / packet_count,
        int(flow_dict.get('syn_flag', 0)),
        int(flow_dict.get('ack_flag', 0)),
        int(flow_dict.get('rst_flag', 0)),
        int(flow_dict.get('fin_flag', 0)),
        1 if str(flow_dict.get('protocol', 'TCP')).upper() == 'TCP' else 0,
        1 if str(flow_dict.get('protocol', 'TCP')).upper() == 'UDP' else 0,
        0 if str(flow_dict.get('protocol', 'TCP')).upper() in ('TCP', 'UDP') else 1,
    ]

    X = np.array([features], dtype=np.float32)
    probabilities = _model.predict_proba(X)[0]

    return {
        _label_encoder.inverse_transform([i])[0]: float(p)
        for i, p in enumerate(probabilities)
    }


if __name__ == "__main__":
    # Quick self-test
    test_flow = {
        'src_port': 54321,
        'dst_port': 80,
        'protocol': 'TCP',
        'packet_count': 15,
        'byte_count': 4500,
        'duration': 0.5,
        'syn_flag': 1,
        'ack_flag': 0,
        'rst_flag': 0,
        'fin_flag': 0,
    }
    label, conf = predict_flow(test_flow)
    print(f"Test prediction: {label} ({conf:.4f})")
    probs = predict_flow_proba(test_flow)
    for cls, p in sorted(probs.items(), key=lambda x: -x[1]):
        print(f"  {cls}: {p:.4f}")
