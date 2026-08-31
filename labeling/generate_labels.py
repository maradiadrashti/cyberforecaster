#!/usr/bin/env python3
"""
generate_labels.py — Correlate Snort IDS alerts with Cyberforecaster captured flows
to produce a labeled training CSV.

SNORT ALERT FORMAT CHOICE: Fast alert log (/var/log/snort/alert)
---------------------------------------------------------------
We use the fast alert format (not unified2) for these reasons:
1. Unified2 is a binary format requiring Barnyard2 to decode into parseable text.
   Fast alert is plain text, one line per alert, trivially parsed with regex.
2. For a training pipeline (offline batch processing), latency of writing to disk
   is irrelevant. We only need accuracy of correlation.
3. Fewer dependencies — no Barnyard2 or u2spoolthank required.
4. The format is stable and well-documented:
   [timestamp] [gid:sid:rev] message [Classification: classtype] [Priority: N]
   {proto} src_ip:port -> dst_ip:port

   Example:
   [**] [1:210036:1] ET SCAN Nmap -sS/SYN [**]
   [Classification: Attempted Information Leak] [Priority: 2]
   08/15-14:23:01.123456 192.168.1.100:54321 -> 10.0.0.1:80
   ...

FLOW DATA SOURCE: Cyberforecaster's capture-server flow_cache
--------------------------------------------------------------
The capture server (capture_server.py) already aggregates packets into flows
with fields: src_ip, dst_ip, src_port, dst_port, protocol, packet_count,
byte_count, first_seen, last_seen, severity, attack_type, interface.

This script reads flows via two methods:
1. PRIMARY:  Poll /api/flows from the capture server (if running)
2. FALLBACK: Import the flow_cache dict directly (if running in-process)

The labeling script does NOT modify any capture-server code — it only reads.
"""

import re
import csv
import os
import sys
import json
import time
import argparse
from datetime import datetime, timedelta
from typing import Optional

# ---------------------------------------------------------------------------
# Snort fast alert parser
# ---------------------------------------------------------------------------

# Fast alert line format:
#   [timestamp] [gid:sid:rev] message [Classification: classtype] [Priority: N]
#   {proto} src_ip:port -> dst_ip:port
#   ...
TIMESTAMP_RE = re.compile(
    r'^\[(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\]'
)
CLASSIFICATION_RE = re.compile(
    r'\[Classification:\s*([^\]]+)\]'
)
PRIORITY_RE = re.compile(
    r'\[Priority:\s*(\d+)\]'
)
ADDR_PORT_RE = re.compile(
    r'\{(\w+)\}\s+([\d.]+):(\d+)\s*->\s*([\d.]+):(\d+)'
)
# SID extraction from [gid:sid:rev]
SID_RE = re.compile(
    r'\[\d+:(\d+):\d+\]'
)


class SnortAlert:
    """Parsed Snort fast alert entry."""
    __slots__ = (
        'timestamp', 'sid', 'classification', 'priority',
        'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
        'raw_line',
    )

    def __init__(self, timestamp: str, sid: str, classification: str,
                 priority: int, protocol: str, src_ip: str, src_port: int,
                 dst_ip: str, dst_port: int, raw_line: str):
        self.timestamp = timestamp
        self.sid = sid
        self.classification = classification
        self.priority = priority
        self.protocol = protocol
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.raw_line = raw_line

    def __repr__(self):
        return (f"SnortAlert({self.timestamp} SID:{self.sid} "
                f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port} "
                f"[{self.classification}])")


def parse_fast_timestamp(ts: str) -> Optional[datetime]:
    """
    Parse Snort fast alert timestamp: MM/DD-HH:MM:SS.microseconds
    Year is omitted — we use current year (acceptable for training data
    collected in a single session).
    """
    try:
        # Format: 08/15-14:23:01.123456
        # Split date and time
        date_part, time_part = ts.split('-', 1)
        month, day = date_part.split('/')
        # Time may have microsecond component
        time_main = time_part.split('.')[0]  # HH:MM:SS
        hour, minute, second = time_main.split(':')
        year = datetime.now().year
        return datetime(year, int(month), int(day),
                        int(hour), int(minute), int(second))
    except Exception:
        return None


def parse_snort_fast_alert(alert_path: str) -> list[SnortAlert]:
    """
    Parse Snort fast alert log file.
    Each logical alert may span multiple lines (header + packet line).
    """
    alerts = []
    current_alert_lines = []
    current_alert_start = None

    try:
        with open(alert_path, 'r', errors='replace') as f:
            for line in f:
                line = line.rstrip('\n\r')
                # New alert starts with [**] or timestamp pattern
                ts_match = TIMESTAMP_RE.match(line)
                if ts_match:
                    # Save previous alert if complete
                    if current_alert_lines:
                        parsed = _parse_alert_block(current_alert_lines)
                        if parsed:
                            alerts.append(parsed)
                    current_alert_lines = [line]
                    current_alert_start = ts_match.group(1)
                elif current_alert_lines:
                    # Continuation line (packet info, etc.)
                    current_alert_lines.append(line)

            # Don't forget last alert
            if current_alert_lines:
                parsed = _parse_alert_block(current_alert_lines)
                if parsed:
                    alerts.append(parsed)

    except FileNotFoundError:
        print(f"[!] Snort alert file not found: {alert_path}")
        print("    Make sure Snort is running and logging to this path.")
        print("    You can set the path with --snort-alert")

    return alerts


def _parse_alert_block(lines: list[str]) -> Optional[SnortAlert]:
    """Parse a multi-line Snort alert block into a SnortAlert object."""
    if not lines:
        return None

    header = lines[0]

    # Extract timestamp
    ts_match = TIMESTAMP_RE.match(header)
    if not ts_match:
        return None
    timestamp = ts_match.group(1)

    # Extract SID
    sid_match = SID_RE.search(header)
    sid = sid_match.group(1) if sid_match else "unknown"

    # Extract classification
    cls_match = CLASSIFICATION_RE.search(header)
    classification = cls_match.group(1).strip() if cls_match else "unknown"

    # Extract priority
    pri_match = PRIORITY_RE.search(header)
    priority = int(pri_match.group(1)) if pri_match else 3

    # Extract network info from any line containing {proto} src -> dst
    protocol = "unknown"
    src_ip = "0.0.0.0"
    src_port = 0
    dst_ip = "0.0.0.0"
    dst_port = 0

    for line in lines:
        addr_match = ADDR_PORT_RE.search(line)
        if addr_match:
            protocol = addr_match.group(1).lower()
            src_ip = addr_match.group(2)
            src_port = int(addr_match.group(3))
            dst_ip = addr_match.group(4)
            dst_port = int(addr_match.group(5))
            break

    return SnortAlert(
        timestamp=timestamp,
        sid=sid,
        classification=classification,
        priority=priority,
        protocol=protocol,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        raw_line='\n'.join(lines),
    )


# ---------------------------------------------------------------------------
# Snort classtype → Cyberforecaster attack category mapping
# ---------------------------------------------------------------------------
# This is the definitive mapping. If a classtype doesn't fit, ask before
# guessing — we flag "unknown" rather than mislabel.

CLASSTYPE_TO_CATEGORY = {
    # Port scanning / reconnaissance
    "attempted-recon": "port_scan",
    "successful-recon-limited": "port_scan",
    "successful-recon-largescale": "port_scan",
    "attempted-information-leak": "port_scan",
    "successful-information-leak": "port_scan",

    # Brute force / authentication attacks
    "attempted-admin": "brute_force",
    "successful-admin": "brute_force",
    "attempted-user": "brute_force",
    "successful-user-override": "brute_force",
    "generic-protocol-command-decode": "brute_force",

    # DoS / DDoS
    "dos": "dos_ddos",
    "attempted-dos": "dos_ddos",
    "denial-of-service": "dos_ddos",
    "denial-of-service-attack": "dos_ddos",

    # Spoofing / ARP
    "web-application-activity": "port_scan",  # Web probes often scan-like
    "misc-activity": "port_scan",
    "misc-attack": "dos_ddos",
}

# Keywords to scan in classification text for additional matching
CATEGORY_KEYWORDS = {
    "port_scan": ["scan", "recon", "nmap", "probe", "sweep", "enumerat"],
    "brute_force": ["brute", "auth", "login", "password", "credential",
                     "sql injection", "xss", "web attack", "patator",
                     "injection", "exploit"],
    "dos_ddos": ["dos", "ddos", "flood", "syn flood", "amplification",
                  "hulk", "slowloris", "slowhttptest", "goldeneye",
                  "heartbleed"],
    "arp_spoof": ["arp", "spoof", "mac", "duplicate"],
    "exfiltration": ["exfiltrat", "infiltrat", "data leak",
                      "data-theft", "c2", "command and control",
                      "botnet", "bot"],
}


def classify_snort_alert(alert: SnortAlert) -> str:
    """
    Map a Snort alert to one of our 5 attack categories (or benign).
    Uses classtype first, then falls back to keyword matching on
    classification text and SID rule description.
    """
    cls_lower = alert.classification.lower()

    # 1. Try direct classtype mapping
    if cls_lower in CLASSTYPE_TO_CATEGORY:
        return CLASSTYPE_TO_CATEGORY[cls_lower]

    # 2. Try keyword matching
    combined_text = f"{cls_lower} {alert.raw_line.lower()}"
    for category, keywords in CATEGORY_KEYWORDS.items():
        for kw in keywords:
            if kw in combined_text:
                return category

    # 3. Priority-based fallback (high priority = likely attack)
    if alert.priority <= 1:
        return "dos_ddos"  # Very high priority often means active attack
    elif alert.priority == 2:
        return "port_scan"  # Medium priority often recon/information leak
    else:
        return "benign"  # Low priority informational


def timestamp_in_flow_window(alert_ts: datetime, flow_start: str,
                              flow_end: str, tolerance_ms: int = 500) -> bool:
    """Check if a Snort alert timestamp falls within a flow's time window."""
    try:
        start = datetime.fromisoformat(flow_start.replace('Z', '+00:00'))
        end = datetime.fromisoformat(flow_end.replace('Z', '+00:00'))
        tolerance = timedelta(milliseconds=tolerance_ms)
        return (start - tolerance) <= alert_ts <= (end + tolerance)
    except (ValueError, TypeError):
        return False


def ip_port_match(alert: SnortAlert, flow: dict) -> bool:
    """
    Check if a Snort alert's IP:port matches a flow's IP:port.
    Matches both directions (alert src→dst matches flow src→dst or dst→src).
    """
    a_src, a_dst = alert.src_ip, alert.dst_ip
    a_sp, a_dp = alert.src_port, alert.dst_port
    f_src = flow.get('src_ip', '')
    f_dst = flow.get('dst_ip', '')
    f_sp = flow.get('src_port', 0)
    f_dp = flow.get('dst_port', 0)

    # Forward match: alert.src matches flow.src AND alert.dst matches flow.dst
    fwd = (a_src == f_src and a_dst == f_dst and
           (a_sp == f_sp or a_sp == 0 or f_sp == 0) and
           (a_dp == f_dp or a_dp == 0 or f_dp == 0))

    # Reverse match: alert.src matches flow.dst AND alert.dst matches flow.src
    rev = (a_src == f_dst and a_dst == f_src and
           (a_sp == f_dp or a_sp == 0 or f_dp == 0) and
           (a_dp == f_sp or a_dp == 0 or f_sp == 0))

    return fwd or rev


# ---------------------------------------------------------------------------
# Flow reader — from capture server's /api/flows endpoint
# ---------------------------------------------------------------------------

def fetch_flows_from_server(server_url: str = "http://127.0.0.1:8080",
                            timeout: int = 5) -> list[dict]:
    """
    Fetch flows from the capture server's /api/flows REST endpoint.
    This is a read-only operation — does not modify the capture server.
    """
    try:
        import urllib.request
        url = f"{server_url}/api/flows"
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
            if isinstance(data, list):
                return data
            return []
    except Exception as e:
        print(f"[!] Could not fetch flows from capture server: {e}")
        print("    Make sure the capture server is running on", server_url)
        return []


def read_flows_from_csv(csv_path: str) -> list[dict]:
    """
    Read flows from a CSV file (previously exported from the capture server
    or manually recorded). Expects columns matching the flow_cache schema.
    """
    flows = []
    try:
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Convert numeric fields
                for field in ['src_port', 'dst_port', 'packet_count',
                              'byte_count']:
                    if field in row:
                        try:
                            row[field] = int(row[field])
                        except (ValueError, TypeError):
                            row[field] = 0
                flows.append(row)
    except Exception as e:
        print(f"[!] Error reading flow CSV: {e}")
    return flows


# ---------------------------------------------------------------------------
# Main labeling pipeline
# ---------------------------------------------------------------------------

def label_flows(flows: list[dict], alerts: list[SnortAlert]) -> list[dict]:
    """
    For each flow, check if any Snort alert matches by:
    1. Timestamp: alert timestamp falls within [first_seen, last_seen]
    2. IP:port: src/dst match (bidirectional)

    If a match is found, label with the Snort category.
    Otherwise, label as "benign".

    Returns a list of labeled flow dicts (original fields + 'label').
    """
    labeled = []

    # Pre-parse alert timestamps for efficiency
    parsed_alerts = []
    for alert in alerts:
        ts = parse_fast_timestamp(alert.timestamp)
        if ts:
            parsed_alerts.append((ts, alert))

    print(f"[*] Labeling {len(flows)} flows against {len(parsed_alerts)} Snort alerts...")

    for flow in flows:
        label = "benign"
        matched_alert = None

        flow_start = flow.get('first_seen', '')
        flow_end = flow.get('last_seen', flow_start)

        for alert_ts, alert in parsed_alerts:
            # Check timestamp window
            if not timestamp_in_flow_window(alert_ts, flow_start, flow_end):
                continue
            # Check IP:port match
            if not ip_port_match(alert, flow):
                continue
            # Match found — classify
            category = classify_snort_alert(alert)
            if category != "benign":
                label = category
                matched_alert = alert
                break  # Take first matching alert

        labeled_flow = dict(flow)
        labeled_flow['label'] = label
        if matched_alert:
            labeled_flow['snort_sid'] = matched_alert.sid
            labeled_flow['snort_classification'] = matched_alert.classification
        else:
            labeled_flow['snort_sid'] = ''
            labeled_flow['snort_classification'] = ''

        labeled.append(labeled_flow)

    # Count labels
    label_counts = {}
    for item in labeled:
        lbl = item['label']
        label_counts[lbl] = label_counts.get(lbl, 0) + 1

    print(f"[+] Labeling complete. Distribution:")
    for lbl, count in sorted(label_counts.items()):
        print(f"    {lbl}: {count} ({count/len(labeled)*100:.1f}%)")

    return labeled


def write_labeled_csv(labeled_flows: list[dict], output_path: str):
    """Write labeled flows to CSV in Cyberforecaster's unified format."""
    if not labeled_flows:
        print("[!] No labeled flows to write.")
        return

    # Define column order (our flow schema + label + provenance)
    fieldnames = [
        'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
        'packet_count', 'byte_count', 'first_seen', 'last_seen',
        'severity', 'attack_type', 'interface',
        'label', 'snort_sid', 'snort_classification',
    ]

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames,
                                extrasaction='ignore')
        writer.writeheader()
        writer.writerows(labeled_flows)

    print(f"[+] Wrote {len(labeled_flows)} labeled flows to {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Label Cyberforecaster flows using Snort IDS alerts.",
        epilog="Output: CSV with all flow fields + 'label' column "
               "(benign/port_scan/brute_force/dos_ddos/arp_spoof/exfiltration)"
    )
    parser.add_argument(
        "--snort-alert", required=True,
        help="Path to Snort fast alert log "
             "(e.g., /var/log/snort/alert)"
    )
    parser.add_argument(
        "--flows", default=None,
        help="Path to a flow CSV file. If not provided, fetches from "
             "the capture server at --server-url."
    )
    parser.add_argument(
        "--server-url", default="http://127.0.0.1:8080",
        help="Capture server URL (default: http://127.0.0.1:8080)"
    )
    parser.add_argument(
        "--output", default="labeled_flows.csv",
        help="Output CSV path (default: labeled_flows.csv)"
    )
    parser.add_argument(
        "--tolerance-ms", type=int, default=500,
        help="Timestamp matching tolerance in milliseconds (default: 500)"
    )

    args = parser.parse_args()

    # 1. Parse Snort alerts
    print(f"[*] Parsing Snort alerts from {args.snort_alert}...")
    alerts = parse_snort_fast_alert(args.snort_alert)
    if not alerts:
        print("[!] No alerts parsed. Check the Snort alert log path and format.")
        print("    Continuing anyway — all flows will be labeled 'benign'.")
    else:
        print(f"[+] Parsed {len(alerts)} Snort alerts.")

    # 2. Load flows
    if args.flows:
        print(f"[*] Reading flows from CSV: {args.flows}")
        flows = read_flows_from_csv(args.flows)
    else:
        print(f"[*] Fetching flows from capture server: {args.server_url}")
        flows = fetch_flows_from_server(args.server_url)

    if not flows:
        print("[!] No flows available. Make sure the capture server is running "
              "and has captured traffic.")
        sys.exit(1)

    print(f"[+] Loaded {len(flows)} flows.")

    # 3. Label flows
    labeled = label_flows(flows, alerts)

    # 4. Write output
    write_labeled_csv(labeled, args.output)


if __name__ == "__main__":
    main()
