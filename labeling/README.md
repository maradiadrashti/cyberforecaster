# Cyberforecaster ML Labeling Pipeline

## Overview

This directory contains the data labeling pipeline for Cyberforecaster's ML models.

### Scripts

- **generate_labels.py** — Correlate Snort IDS alerts with captured flows to produce labeled training CSV
- **generate_attack_traffic.py** — Run controlled attacks against a test VM for positive training examples
- **import_public_dataset.py** — Import CIC-IDS2017 / UNSW-NB15 public datasets into our unified format

### Quick Start

```bash
# 1. Run attacks against your test VM (while Snort + Cyberforecaster capture)
python labeling/generate_attack_traffic.py 192.168.1.50 --i-own-this-target --attack all

# 2. Label the captured flows using Snort alerts
python labeling/generate_labels.py --snort-alert /var/log/snort/alert --output labeled_flows.csv

# 3. (Optional) Import public datasets for additional training data
python labeling/import_public_dataset.py /path/to/cic-ids2017/ --output public_flows.csv

# 4. Train models
python training/train_flow_classifier.py labeled_flows.csv public_flows.csv
python training/train_stage_forecaster.py labeled_flows.csv public_flows.csv
```

### Unified CSV Format

All labeling scripts output CSVs with this schema:

| Column | Type | Description |
|--------|------|-------------|
| src_ip | string | Source IP address |
| src_port | int | Source port |
| dst_ip | string | Destination IP address |
| dst_port | int | Destination port |
| protocol | string | TCP, UDP, or Other |
| packet_count | int | Total packets in flow |
| byte_count | int | Total bytes in flow |
| duration | float | Flow duration in seconds |
| first_seen | string | ISO timestamp of first packet |
| last_seen | string | ISO timestamp of last packet |
| severity | string | none, low, medium, high, critical |
| attack_type | string | Human-readable attack type |
| interface | string | Capture interface name |
| syn_flag | int | 0/1 SYN flag present |
| ack_flag | int | 0/1 ACK flag present |
| rst_flag | int | 0/1 RST flag present |
| fin_flag | int | 0/1 FIN flag present |
| label | string | **benign / port_scan / brute_force / dos_ddos / arp_spoof / exfiltration** |
| snort_sid | string | (from generate_labels.py) Snort rule SID |
| snort_classification | string | (from generate_labels.py) Snort classification |
