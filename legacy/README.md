# legacy/

Code and files the application no longer uses. Nothing here is imported by the backend or the dashboard.
It is kept so earlier work can be looked up; it is not maintained.

| Path | What it was | Replaced by |
|---|---|---|
| `predict_csv.py`, `sample_test_flows.csv` | Command-line forecast for a CSV with the earlier 15-feature model | `python capture-service/world_model.py <file>` |
| `data_prep/estimate_killchain_matrix.py`, `models/stage_transition_matrix.json` | Stage-transition matrix used to roll the earlier model forward `t+1 .. t+5` | The world model's own 60-second outputs; `training/world_model/build_progression.py` for the "what usually follows" tree |
| `data_prep/build_shap_background.py`, `models/shap_background_benign.json` | Background set for SHAP on the earlier model (`/api/explain`, removed) | Occlusion attribution in `capture-service/world_model.py` |
| `tests/test_file_upload_api.py`, `tests/test_upload_pipeline.py` | Tests of the earlier upload response | `training/world_model/checks/` |
| `samples/` | Sample files the world model cannot use: two CSVs without source IPs or flow times, and a PCAP with no IP packets. The upload page refuses them and says why. | `samples/real_sample_v4.csv`, `samples/test_files/` |
| `models/world_model_v2/`, `models/world_model_v3/` | Earlier versions of the world model (file names inside are `world_model_v2.pt` / `world_model_v2_meta.json`) | `models/world_model/` (version 5) |
| `models/world_model_v4/` | Version 4 (73 features, no incoming-traffic features). Better than v5 on test file B, behind it on the held-back data overall: see `docs/RESULTS_world_model_v5.md` | `models/world_model/` (version 5) |

To go back to world model v4: copy `world_model.pt`, `world_model_meta.json` and `baseline_lr.json` from
`legacy/models/world_model_v4/` into `models/world_model/` and restart the backend.

To go back to world model v3: copy the three files from `legacy/models/world_model_v3/` into `models/world_model/`
and rename `world_model_v2.pt` to `world_model.pt` and `world_model_v2_meta.json` to `world_model_meta.json`.
