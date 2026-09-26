# evaluation/

| Script | What it does |
| :--- | :--- |
| `eval_cross_dataset.py` | **Benchmark:** LSTM world model vs. logistic-regression baseline on any labeled flow CSV (same 15 features for both). Prints accuracy / precision / recall / F1 / FPR and the exact-stage hit rate; `--out` saves JSON. |
| `evaluate_predictions.py` | Per-stage evaluation of the LSTM on a labeled CSV (confusion matrix, per-class metrics). |
| `results/cic2017_webattacks.json` | Saved benchmark run on CIC-IDS-2017 Web Attacks (170,170 windows). |

```bash
python evaluation/eval_cross_dataset.py path/to/labeled_flows.csv --out evaluation/results/my_run.json
```

Input must be in the app's schema (see `samples/real_sample_v4.csv`). Results and their
interpretation: [`../VALIDATION.md`](../VALIDATION.md).
