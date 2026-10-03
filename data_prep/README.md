# data_prep/

Scripts that built the 15-feature flow corpus used by the **Live Traffic** models (the per-flow XGBoost classifier
and the earlier 5-flow stage LSTM). Offline, one-time.

The world model used for uploaded files has its own data pipeline: see
[`../training/world_model/README.md`](../training/world_model/README.md).

| Script | Purpose |
| :--- | :--- |
| `../capture-service/extractor/extract_packet_features_v2.py` | PCAP → flow CSV (15 features + IAT mean/std + bwd/fwd ratio). Same extractor the backend uses. |
| `map_dapt_to_schema.py` | Maps DAPT-2020 CICFlowMeter CSVs (`<dapt_dir>/csv/*.pcap_Flow.csv`) to the schema, keeping its stage labels. |
| `label_attacks.py` | Labels flows as attack/normal + MITRE stage using the attacker/victim IPs and time windows published with CSE-CIC-IDS2018. |
| `extract_real_sample.py` | Cuts a small, real, labelled sample out of the big corpus (how `samples/real_sample_v4.csv` was made). |

## Pipeline

```text
CSE-CIC-IDS2018 PCAPs ─┐
CTU-13 PCAPs ──────────┼─ extract_packet_features_v2.py ─▶ flow CSVs ─▶ label_attacks.py ─┐
DAPT-2020 CSVs ────────┴────────────── map_dapt_to_schema.py ──────────────────────────┴─▶ merged_final_v5.csv
```

## Schema

`src_ip, dst_ip, src_port, dst_port, protocol, flow_start, flow_end,` + the 15 features
`duration, packet_count, byte_count, syn_count, ack_count, fin_count, rst_count, ttl_mean, ttl_var,
win_mean, win_var, frag_ratio, payload_mean, payload_std, retransmit_count` + `label, attack_stage`.

`attack_stage` ∈ `normal, reconnaissance, initial_access, lateral_movement, command_control, exfiltration`.

## Datasets (not included — download separately)

- CSE-CIC-IDS2018 — https://www.unb.ca/cic/datasets/ids-2018.html
- CTU-13 — https://www.stratosphereips.org/datasets-ctu13
- DAPT-2020 — https://gitlab.com/asu22/dapt2020
- CIC-IDS2017 — https://www.unb.ca/cic/datasets/ids-2017.html
