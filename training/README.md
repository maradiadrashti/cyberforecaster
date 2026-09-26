# training/

Offline training scripts. **You do not need these to run the dashboard** — the trained models are
already in `models/`. Use them to reproduce or retrain.

| Script | Trains | Output (written to the current directory) |
| :--- | :--- | :--- |
| `train_lstm_world_model.py` | **LSTM world model** — 2-layer LSTM, stage head (6 MITRE stages) + risk head. Input: 5 flows × 15 features; target: the stage 3 flows ahead. | `stage_forecaster_lstm_v1.pth`, `stage_forecaster_lstm_v1_meta.json` |
| `train_logreg_baseline.py` | **Logistic-regression benchmark** on the same 15 features, one flow at a time (no memory). | `logreg_baseline_v1.joblib`, `logreg_baseline_scaler_v1.joblib`, `logreg_baseline_meta.json` |
| `train_flow_classifier.py` | XGBoost per-flow classifier used for live traffic labels (with SMOTE). | `flow_classifier_v1.joblib`, `flow_label_encoder_v1.joblib`, `flow_classifier_meta.json` |
| `train_from_cic_ids2017.py` | Same XGBoost classifier, trained directly from the raw CIC-IDS-2017 CSVs. | same as above |

## Reproduce the world model

1. Build the labeled, merged flow CSV (see [`../data_prep/README.md`](../data_prep/README.md)).
2. Train:

   ```bash
   python training/train_lstm_world_model.py merged_final_v5.csv
   python training/train_logreg_baseline.py  merged_final_v5.csv
   ```

3. Copy the output files into `models/` (replacing the existing ones).
4. Rebuild the kill-chain matrix: `python data_prep/estimate_killchain_matrix.py merged_final_v5.csv`
5. Benchmark: `python evaluation/eval_cross_dataset.py <held-out labeled csv>`

Training the LSTM on the full corpus (~6 GB CSV) takes a few hours on a laptop CPU; a CUDA GPU is
used automatically if available.

## Hyper-parameters (LSTM)

`hidden_size=64`, `num_layers=2`, `dropout=0.3`, `seq_len=5`, `forecast_horizon=3`, Adam,
class-weighted cross-entropy (stage) + BCE (risk), gradient clipping `max_norm=5.0`,
early stopping (patience 12) on `0.7 × binary_val_acc + 0.3 × stage_val_acc`.
