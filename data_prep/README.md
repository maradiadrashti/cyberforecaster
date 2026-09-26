# data_prep/

Scripts that turn public datasets into the single 15-feature flow schema the models use, label the
MITRE stage of each flow, and learn the kill-chain transition matrix. Offline, one-time.

| Script | Purpose |
| :--- | :--- |
| `../capture-service/extractor/extract_packet_features_v2.py` | PCAP → flow CSV (15 features + IAT mean/std + bwd/fwd ratio). Same extractor the backend uses. |
| `map_dapt_to_schema.py` | Maps DAPT-2020 CICFlowMeter CSVs (`<dapt_dir>/csv/*.pcap_Flow.csv`) to the schema, keeping its stage labels. |
| `label_attacks.py` | Labels flows as attack/normal + MITRE stage using the attacker/victim IPs and time windows published with CIC-IDS-2018. |
| `estimate_killchain_matrix.py` | Follows each attacker host through its attack stages over time and writes `models/stage_transition_matrix.json`. |
| `build_shap_background.py` | Samples 100 real benign 5-flow windows from the labeled corpus and writes `models/shap_background_benign.json` — the reference distribution the dashboard's SHAP explanations are measured against. |
| `extract_real_sample.py` | Cuts a small, real, labeled sample out of the big corpus (how `samples/real_sample_v4.csv` was made). |

## Pipeline

```text
CIC-IDS-2018 PCAPs ─┐
CTU-13 PCAPs ───────┼─ extract_packet_features_v2.py ─▶ flow CSVs ─▶ label_attacks.py ─┐
DAPT-2020 CSVs ─────┴────────────── map_dapt_to_schema.py ───────────────────────────┼─▶ merged_final_v5.csv
                                                                                      │
                               estimate_killchain_matrix.py ◀─────────────────────────┤
                                 └─▶ models/stage_transition_matrix.json              │
                               build_shap_background.py ◀─────────────────────────────┘
                                 └─▶ models/shap_background_benign.json
```

## Schema

`src_ip, dst_ip, src_port, dst_port, protocol, flow_start, flow_end,` + the 15 features
`duration, packet_count, byte_count, syn_count, ack_count, fin_count, rst_count, ttl_mean, ttl_var,
win_mean, win_var, frag_ratio, payload_mean, payload_std, retransmit_count` + `label, attack_stage`.

`attack_stage` ∈ `normal, reconnaissance, initial_access, lateral_movement, command_control, exfiltration`.

## Datasets (not included — download separately)

- CSE-CIC-IDS-2018 — https://www.unb.ca/cic/datasets/ids-2018.html
- CTU-13 — https://www.stratosphereips.org/datasets-ctu13
- DAPT-2020 — https://gitlab.com/asu22/dapt2020
- CIC-IDS-2017 (evaluation only) — https://www.unb.ca/cic/datasets/ids-2017.html
