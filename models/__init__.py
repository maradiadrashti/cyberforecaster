"""
CyberForecaster models
======================

stage_forecaster_lstm_infer.py  -- LSTM world model (2-layer LSTM, stage + risk heads)
    forecast_host(host_ip, recent_flows, ...) -> current stage, risk, t+1..t+K forecast
    artifacts: stage_forecaster_lstm_v1.pth, stage_forecaster_lstm_v1_meta.json,
               stage_transition_matrix.json (DAPT-2020 kill-chain matrix)

flow_classifier_infer.py        -- XGBoost per-flow classifier for live traffic labels
    predict_flow(flow_dict) -> (label, confidence)

logreg_baseline_v1.joblib       -- logistic-regression benchmark (see evaluation/)

taxonomy.py                     -- MITRE ATT&CK stage names and mappings

Retrain with the scripts in training/ (see training/README.md).
"""
