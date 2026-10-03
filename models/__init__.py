"""
CyberForecaster models
======================

world_model/                    -- WORLD MODEL used for every uploaded file (see capture-service/world_model.py)
    world_model.pt              3 trained copies of a 2-layer LSTM (10 windows x 73 features per source host)
    world_model_meta.json       features, scaling, classes, alert thresholds, tested reliability of the 5/10-minute output
    baseline_lr.json            logistic-regression baseline drawn next to the model on the dashboard
    stage_progression.json      counts of observed stage changes ("what usually follows" tree)

stage_forecaster_lstm_infer.py  -- LIVE TRAFFIC stage model (earlier 15-feature LSTM, 5 flows per conversation)
    forecast_host(host_ip, recent_flows, ...) -> current stage and risk for a live conversation
    files: stage_forecaster_lstm_v1.pth, stage_forecaster_lstm_v1_meta.json

flow_classifier_infer.py        -- XGBoost per-flow classifier for live traffic labels
    predict_flow(flow_dict) -> (label, confidence)

logreg_baseline_v1.joblib       -- logistic-regression benchmark for the live stage model (see evaluation/)

taxonomy.py                     -- MITRE ATT&CK stage names and mappings

Retraining: training/world_model/ (world model) and training/*.py (live models).
"""
