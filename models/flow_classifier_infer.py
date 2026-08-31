#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
import json
import numpy as np
import joblib

_MODELS_DIR = os.path.dirname(os.path.abspath(__file__))
_model = None
_label_encoder = None


def _load_model():
    global _model, _label_encoder
    if _model is not None:
        return
    _model = joblib.load(os.path.join(_MODELS_DIR, "flow_classifier_v1.joblib"))
    _label_encoder = joblib.load(os.path.join(_MODELS_DIR, "flow_label_encoder_v1.joblib"))


def _flow_to_features(flow_dict):
    duration = max(float(flow_dict.get('duration', 0)), 0.001)
    packet_count = max(int(flow_dict.get('packet_count', 1)), 1)
    byte_count = int(flow_dict.get('byte_count', 0))
    proto = str(flow_dict.get('protocol', 'TCP')).upper()
    return [
        duration, packet_count, byte_count,
        int(flow_dict.get('src_port', 0)),
        int(flow_dict.get('dst_port', 0)),
        packet_count / duration,
        byte_count / packet_count,
        int(flow_dict.get('syn_flag', 0)),
        int(flow_dict.get('ack_flag', 0)),
        int(flow_dict.get('rst_flag', 0)),
        int(flow_dict.get('fin_flag', 0)),
        1 if proto == 'TCP' else 0,
        1 if proto == 'UDP' else 0,
        0 if proto in ('TCP', 'UDP') else 1,
    ]


def predict_flow(flow_dict):
    """Predict attack category + confidence for a single flow. Target: <10ms."""
    _load_model()
    X = np.array([_flow_to_features(flow_dict)], dtype=np.float32)
    probs = _model.predict_proba(X)[0]
    idx = int(np.argmax(probs))
    return _label_encoder.inverse_transform([idx])[0], float(probs[idx])


def predict_flow_proba(flow_dict):
    """Get probability distribution over all classes."""
    _load_model()
    X = np.array([_flow_to_features(flow_dict)], dtype=np.float32)
    probs = _model.predict_proba(X)[0]
    return {_label_encoder.inverse_transform([i])[0]: float(p) for i, p in enumerate(probs)}


if __name__ == "__main__":
    test_flow = {'src_port': 54321, 'dst_port': 80, 'protocol': 'TCP',
        'packet_count': 5000, 'byte_count': 2500000, 'duration': 1.0,
        'syn_flag': 1, 'ack_flag': 0, 'rst_flag': 0, 'fin_flag': 0}
    label, conf = predict_flow(test_flow)
    print(f"Prediction: {label} ({conf:.4f})")
    for cls, p in sorted(predict_flow_proba(test_flow).items(), key=lambda x: -x[1]):
        print(f"  {cls}: {p:.4f}")
