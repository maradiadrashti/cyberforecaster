# training/

Offline training scripts. **You do not need these to run the dashboard** — the trained models are
already in `models/`. Use them to reproduce or retrain.

| Folder / script | Trains | Used by |
| :--- | :--- | :--- |
| [`world_model/`](world_model/README.md) | **The world model** (2-layer LSTM, 10 windows × 73 features per host). | File Upload and Attack Forecast pages |
| `train_live_stage_lstm.py` | Earlier stage LSTM: 5 flows × 15 features per conversation, stage 3 flows ahead. Output: `stage_forecaster_lstm_v1.pth`, `stage_forecaster_lstm_v1_meta.json` | Live Traffic page |
| `train_logreg_baseline.py` | Logistic-regression benchmark for the live stage LSTM (one flow, no memory). Output: `logreg_baseline_v1.joblib`, `logreg_baseline_scaler_v1.joblib`, `logreg_baseline_meta.json` | `evaluation/` |
| `train_flow_classifier.py` | XGBoost per-flow classifier (with SMOTE). Output: `flow_classifier_v1.joblib`, `flow_label_encoder_v1.joblib`, `flow_classifier_meta.json` | Live Traffic page |
| `train_from_cic_ids2017.py` | Same XGBoost classifier, trained directly from the raw CIC-IDS2017 CSVs. | Live Traffic page |

## Retrain the Live Traffic models

1. Build the labelled, merged flow CSV (see [`../data_prep/README.md`](../data_prep/README.md)).
2. Train:

   ```bash
   python training/train_live_stage_lstm.py merged_final_v5.csv
   python training/train_logreg_baseline.py merged_final_v5.csv
   ```

3. Copy the output files into `models/` (replacing the existing ones).
4. Benchmark: `python evaluation/eval_cross_dataset.py <held-out labelled csv>`

Hyper-parameters of the live stage LSTM: `hidden_size=64`, `num_layers=2`, `dropout=0.3`, `seq_len=5`,
`forecast_horizon=3`, Adam, class-weighted cross-entropy (stage) + BCE (risk), gradient clipping `max_norm=5.0`,
early stopping (patience 12).
