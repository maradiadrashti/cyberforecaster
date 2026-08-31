#!/usr/bin/env python3
"""
import_public_dataset.py — Import public IDS datasets (CIC-IDS2017, UNSW-NB15)
and map them onto Cyberforecaster's unified flow schema.

The goal: supplement real Snort-labeled data with well-known public datasets
so the classifier has enough attack examples to learn from.

COLUMN MAPPING TABLE (CIC-IDS2017 → Cyberforecaster):
-------------------------------------------------------
CIC-IDS2017 Column              → Our Column          Conversion
------------------------------   -------------------  --------------------------
Destination Port                → dst_port            int (direct)
Flow Duration                   → duration            float (microseconds → seconds)
Total Fwd Packets               → (part of)           → packet_count (sum fwd+bwd)
Total Backward Packets          → (part of)           → packet_count (sum fwd+bwd)
Total Length of Fwd Packets     → (part of)           → byte_count (sum fwd+bwd bytes)
Total Length of Bwd Packets     → (part of)           → byte_count (sum fwd+bwd bytes)
Flow Bytes/s                    → (derived)           → byte_count/duration
Flow Packets/s                  → (derived)           → packet_count/duration
FIN Flag Count                  → fin_flag            int
SYN Flag Count                  → syn_flag            int
RST Flag Count                  → rst_flag            int
PSH Flag Count                  → psh_flag            int
ACK Flag Count                  → ack_flag            int
URG Flag Count                  → urg_flag            int
Label                           → label               mapped (see LABEL_MAP below)

Note: CIC-IDS2017 does NOT have src_ip/dst_ip per flow — it uses "Source Port"
as the only endpoint identifier. We set src_ip/dst_ip to "unknown" since the
dataset doesn't provide them (they're per-capture-session, not per-flow).
This is fine for training the classifier on flow statistics.

LABEL MAP (CIC-IDS2017 → our 6 categories):
---------------------------------------------
BENIGN                    → benign
DDoS                      → dos_ddos
DoS Hulk                  → dos_ddos
DoS GoldenEye             → dos_ddos
DoS Slowhttptest          → dos_ddos
DoS slowloris             → dos_ddos
Heartbleed                → dos_ddos
PortScan                  → port_scan
FTP-Patator               → brute_force
SSH-Patator               → brute_force
Web Attack - Brute Force  → brute_force
Web Attack - XSS          → port_scan (recon-like probing)
Web Attack - Sql Injection→ port_scan (recon-like probing)
Bot                       → dos_ddos (botnet traffic is DDoS-like)
Infiltration              → exfiltration

UNSW-NB15 MAPPING (if used):
-----------------------------
Normal                    → benign
Generic                   → dos_ddos
Reconnaissance            → port_scan
Exploits                  → brute_force
Fuzzers                   → port_scan
DoS                       → dos_ddos
Backdoor                  → exfiltration
Shellcode                 → exfiltration
Worms                     → exfiltration
"""

import csv
import os
import sys
import argparse
from typing import Optional


# ---------------------------------------------------------------------------
# CIC-IDS2017 column names (as found in the CSV files)
# ---------------------------------------------------------------------------

CIC_IDS2017_COLUMNS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Total Length of Fwd Packets',
    'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
    'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
    'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
    'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
    'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count',
    'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk',
    'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk',
    'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
    'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean',
    'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std',
    'Idle Max', 'Idle Min', 'Label',
]

# Our unified output columns
OUR_COLUMNS = [
    'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
    'packet_count', 'byte_count', 'duration', 'first_seen', 'last_seen',
    'severity', 'attack_type', 'interface',
    'syn_flag', 'ack_flag', 'rst_flag', 'fin_flag',
    'label',
]


# ---------------------------------------------------------------------------
# Label mapping: CIC-IDS2017 → our categories
# ---------------------------------------------------------------------------

CIC_LABEL_MAP = {
    'benign': 'benign',
    'ddos': 'dos_ddos',
    'dos hulk': 'dos_ddos',
    'dos goldeneye': 'dos_ddos',
    'dos slowhttptest': 'dos_ddos',
    'dos slowloris': 'dos_ddos',
    'heartbleed': 'dos_ddos',
    'portscan': 'port_scan',
    'ftp-patator': 'brute_force',
    'ssh-patator': 'brute_force',
    'web attack — brute force': 'brute_force',
    'web attack — xss': 'port_scan',
    'web attack — sql injection': 'port_scan',
    'bot': 'dos_ddos',
    'infiltration': 'exfiltration',
}

# UNSW-NB15 label mapping
UNSW_LABEL_MAP = {
    'normal': 'benign',
    'generic': 'dos_ddos',
    'reconnaissance': 'port_scan',
    'exploits': 'brute_force',
    'fuzzers': 'port_scan',
    'dos': 'dos_ddos',
    'backdoor': 'exfiltration',
    'shellcode': 'exfiltration',
    'worms': 'exfiltration',
}


def safe_float(val, default=0.0) -> float:
    """Convert to float, handling NaN, inf, empty strings."""
    if val is None or val == '' or val == ' ':
        return default
    try:
        v = float(val)
        if v != v or v == float('inf') or v == float('-inf'):
            return default
        return v
    except (ValueError, TypeError):
        return default


def safe_int(val, default=0) -> int:
    """Convert to int safely."""
    return int(safe_float(val, default))


def map_cic_label(raw_label: str) -> str:
    """Map a CIC-IDS2017 label to our unified category."""
    normalized = raw_label.strip().lower()
    return CIC_LABEL_MAP.get(normalized, 'benign')


def map_unsw_label(raw_label: str) -> str:
    """Map an UNSW-NB15 label to our unified category."""
    normalized = raw_label.strip().lower()
    return UNSW_LABEL_MAP.get(normalized, 'benign')


# ---------------------------------------------------------------------------
# CIC-IDS2017 import
# ---------------------------------------------------------------------------

def import_cic_ids2017(csv_path: str, label_map_func=map_cic_label) -> list[dict]:
    """
    Import a single CIC-IDS2017 CSV file and convert to our schema.
    """
    flows = []
    skipped = 0

    with open(csv_path, 'r', errors='replace') as f:
        reader = csv.DictReader(f)
        # Strip whitespace from column names (CIC-IDS2017 has spaces after commas)
        reader.fieldnames = [fn.strip() for fn in (reader.fieldnames or [])]
        for row in reader:
            # Also strip keys
            row = {k.strip(): v for k, v in row.items()}
            try:
                # Extract and validate the raw label
                raw_label = row.get('Label', 'BENIGN').strip()
                if not raw_label or raw_label == 'Label':
                    skipped += 1
                    continue

                our_label = label_map_func(raw_label)

                # Derive protocol from port numbers and flags
                dst_port = safe_int(row.get('Destination Port', 0))
                syn_count = safe_int(row.get('SYN Flag Count', 0))
                ack_count = safe_int(row.get('ACK Flag Count', 0))
                fin_count = safe_int(row.get('FIN Flag Count', 0))
                rst_count = safe_int(row.get('RST Flag Count', 0))

                # Heuristic: if SYN > 0 and ACK == 0, likely SYN scan
                # But we don't know the exact protocol from CIC data
                protocol = 'TCP'  # CIC-IDS2017 is almost entirely TCP flows

                # Compute total packets and bytes
                fwd_pkts = safe_int(row.get('Total Fwd Packets', 0))
                bwd_pkts = safe_int(row.get('Total Backward Packets', 0))
                packet_count = fwd_pkts + bwd_pkts

                fwd_bytes = safe_float(row.get('Total Length of Fwd Packets', 0))
                bwd_bytes = safe_float(row.get('Total Length of Bwd Packets', 0))
                byte_count = int(fwd_bytes + bwd_bytes)

                duration = safe_float(row.get('Flow Duration', 0))
                # CIC-IDS2017 uses microseconds — convert to seconds
                if duration > 1000000:
                    duration = duration / 1_000_000

                # Determine severity heuristic based on label
                severity_map = {
                    'dos_ddos': 'critical',
                    'exfiltration': 'high',
                    'brute_force': 'high',
                    'port_scan': 'medium',
                    'arp_spoof': 'medium',
                    'benign': 'none',
                }
                severity = severity_map.get(our_label, 'none')

                flow = {
                    'src_ip': 'unknown',  # CIC-IDS2017 doesn't provide per-flow IPs
                    'src_port': 0,
                    'dst_ip': 'unknown',
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'packet_count': max(packet_count, 1),
                    'byte_count': max(byte_count, 1),
                    'duration': round(duration, 6),
                    'first_seen': '',
                    'last_seen': '',
                    'severity': severity,
                    'attack_type': our_label.replace('_', ' ').title(),
                    'interface': 'cic-ids2017',
                    'syn_flag': 1 if syn_count > 0 else 0,
                    'ack_flag': 1 if ack_count > 0 else 0,
                    'rst_flag': 1 if rst_count > 0 else 0,
                    'fin_flag': 1 if fin_count > 0 else 0,
                    'label': our_label,
                }
                flows.append(flow)

            except Exception as e:
                skipped += 1
                continue

    print(f"  [+] Imported {len(flows)} flows from {os.path.basename(csv_path)}"
          f" (skipped {skipped} rows)")
    return flows


# ---------------------------------------------------------------------------
# UNSW-NB15 import (placeholder — needs actual CSV format verification)
# ---------------------------------------------------------------------------

def import_unsw_nb15(csv_path: str) -> list[dict]:
    """
    Import an UNSW-NB15 CSV file and convert to our schema.
    UNSW-NB15 has different column names — we need to map them.
    """
    flows = []
    skipped = 0

    # UNSW-NB15 columns (from their documentation)
    UNSW_COL_MAP = {
        'srcip': 'src_ip',
        'sport': 'src_port',
        'dstip': 'dst_ip',
        'dsport': 'dst_port',
        'proto': 'protocol',
        'state': 'flow_state',
        'spkts': 'packet_count',  # source packets (we'll add dst later)
        'dpkts': '_dpkts',
        'sbytes': 'sbytes',
        'dbytes': 'dbytes',
        'sttl': 'src_ttl',
        'dttl': 'dst_ttl',
        'sload': 'src_load',
        'dload': 'dst_load',
        'swin': 'src_window',
        'dwin': 'dst_window',
        'synack': 'synack',
        'smean': 'smean',
        'dmean': 'dmean',
        'ct_src_ltm': 'ct_src_ltm',
        'ct_dst_ltm': 'ct_dst_ltm',
        'attack_cat': '_attack_cat',
        'label': '_label',  # 0=normal, 1=attack
    }

    with open(csv_path, 'r', errors='replace') as f:
        reader = csv.DictReader(f)

        # Detect column format
        fieldnames = reader.fieldnames or []
        has_unsw_format = any(col.lower() in [k.lower() for k in UNSW_COL_MAP]
                             for col in fieldnames)

        if not has_unsw_format:
            print(f"  [!] {os.path.basename(csv_path)} doesn't look like UNSW-NB15 format")
            print(f"      Columns: {fieldnames[:10]}...")
            return flows

        for row in reader:
            try:
                # Get attack category
                raw_cat = row.get('attack_cat', '').strip()
                raw_label = row.get('label', '0').strip()

                if raw_label == '0' and not raw_cat:
                    our_label = 'benign'
                else:
                    our_label = map_unsw_label(raw_cat) if raw_cat else 'brute_force'

                spkts = safe_int(row.get('spkts', 0))
                dpkts = safe_int(row.get('dpkts', 0))
                sbytes = safe_int(row.get('sbytes', 0))
                dbytes = safe_int(row.get('dbytes', 0))

                flow = {
                    'src_ip': str(row.get('srcip', 'unknown')),
                    'src_port': safe_int(row.get('sport', 0)),
                    'dst_ip': str(row.get('dstip', 'unknown')),
                    'dst_port': safe_int(row.get('dsport', 0)),
                    'protocol': str(row.get('proto', 'tcp')).upper(),
                    'packet_count': spkts + dpkts,
                    'byte_count': sbytes + dbytes,
                    'duration': 0.0,  # UNSW doesn't have direct duration
                    'first_seen': '',
                    'last_seen': '',
                    'severity': 'none' if our_label == 'benign' else 'medium',
                    'attack_type': our_label.replace('_', ' ').title(),
                    'interface': 'unsw-nb15',
                    'syn_flag': 1 if safe_int(row.get('synack', 0)) > 0 else 0,
                    'ack_flag': 1 if safe_int(row.get('ackdat', 0)) > 0 else 0,
                    'rst_flag': 0,
                    'fin_flag': 0,
                    'label': our_label,
                }
                flows.append(flow)
            except Exception:
                skipped += 1
                continue

    print(f"  [+] Imported {len(flows)} flows from {os.path.basename(csv_path)}"
          f" (skipped {skipped} rows)")
    return flows


# ---------------------------------------------------------------------------
# Output writer
# ---------------------------------------------------------------------------

def write_unified_csv(flows: list[dict], output_path: str):
    """Write all imported flows in our unified CSV format."""
    if not flows:
        print("[!] No flows to write.")
        return

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=OUR_COLUMNS,
                                extrasaction='ignore')
        writer.writeheader()
        writer.writerows(flows)

    # Print label distribution
    label_counts = {}
    for flow in flows:
        lbl = flow.get('label', 'unknown')
        label_counts[lbl] = label_counts.get(lbl, 0) + 1

    print(f"\n[+] Wrote {len(flows)} flows to {output_path}")
    print("    Label distribution:")
    for lbl, count in sorted(label_counts.items()):
        print(f"      {lbl}: {count} ({count/len(flows)*100:.1f}%)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Import public IDS datasets into Cyberforecaster's unified format."
    )
    parser.add_argument(
        "input_path",
        help="Path to a CSV file or directory of CSVs"
    )
    parser.add_argument(
        "--dataset", choices=["cic-ids2017", "unsw-nb15", "auto"],
        default="auto",
        help="Dataset type. 'auto' detects from column names (default: auto)"
    )
    parser.add_argument(
        "--output", default="public_dataset_flows.csv",
        help="Output CSV path (default: public_dataset_flows.csv)"
    )
    parser.add_argument(
        "--max-per-label", type=int, default=0,
        help="Max samples per label (0=unlimited). Use to balance classes."
    )

    args = parser.parse_args()

    all_flows = []

    # Collect CSV files
    if os.path.isdir(args.input_path):
        csv_files = [os.path.join(args.input_path, f)
                     for f in os.listdir(args.input_path) if f.endswith('.csv')]
    elif os.path.isfile(args.input_path):
        csv_files = [args.input_path]
    else:
        print(f"[!] Path not found: {args.input_path}")
        sys.exit(1)

    print(f"[*] Found {len(csv_files)} CSV file(s) to import.\n")

    for csv_file in csv_files:
        basename = os.path.basename(csv_file)
        print(f"[*] Processing: {basename}")

        # Auto-detect dataset type from column names
        dataset_type = args.dataset
        if dataset_type == "auto":
            with open(csv_file, 'r', errors='replace') as f:
                first_line = f.readline().lower()
                if 'flow duration' in first_line or 'fwd packet' in first_line:
                    dataset_type = "cic-ids2017"
                elif 'srcip' in first_line or 'spkts' in first_line:
                    dataset_type = "unsw-nb15"
                else:
                    print(f"  [!] Cannot auto-detect format. Skipping.")
                    continue

        if dataset_type == "cic-ids2017":
            flows = import_cic_ids2017(csv_file)
        elif dataset_type == "unsw-nb15":
            flows = import_unsw_nb15(csv_file)
        else:
            print(f"  [!] Unknown dataset type: {dataset_type}")
            continue

        all_flows.extend(flows)
        print()

    # Optional: balance classes
    if args.max_per_label > 0 and all_flows:
        label_buckets = {}
        for flow in all_flows:
            lbl = flow.get('label', 'unknown')
            if lbl not in label_buckets:
                label_buckets[lbl] = []
            label_buckets[lbl].append(flow)

        balanced = []
        for lbl, bucket in label_buckets.items():
            if len(bucket) > args.max_per_label:
                # Take the last N (most recent) samples
                balanced.extend(bucket[-args.max_per_label:])
            else:
                balanced.extend(bucket)
        all_flows = balanced
        print(f"[*] Balanced to {args.max_per_label} max per label → "
              f"{len(all_flows)} total flows")

    # Write output
    write_unified_csv(all_flows, args.output)


if __name__ == "__main__":
    main()
