#!/usr/bin/env python3
"""
models/taxonomy.py — Centralized Canonical Attack Taxonomy and Label Mapping

Defines canonical attack categories, human-readable display names, dataset label
mappings (CIC-IDS2017, UNSW-NB15, Snort), and utility functions for consistent label
resolution across training, inference, capture service, and frontend contracts.
"""

from typing import Dict, Optional, Set

# ---------------------------------------------------------------------------
# Canonical Internal Categories
# ---------------------------------------------------------------------------
LABEL_BENIGN = "benign"
LABEL_PORT_SCAN = "port_scan"
LABEL_BRUTE_FORCE = "brute_force"
LABEL_DOS_DDOS = "dos_ddos"
LABEL_EXFILTRATION = "exfiltration"
LABEL_UNKNOWN = "unknown"

CANONICAL_LABELS = [
    LABEL_BENIGN,
    LABEL_PORT_SCAN,
    LABEL_BRUTE_FORCE,
    LABEL_DOS_DDOS,
    LABEL_EXFILTRATION,
    LABEL_UNKNOWN,
]

# Display Names for API and Frontend
DISPLAY_NAMES: Dict[str, str] = {
    LABEL_BENIGN: "Benign",
    LABEL_PORT_SCAN: "Port Scan",
    LABEL_BRUTE_FORCE: "Brute Force",
    LABEL_DOS_DDOS: "DDoS",
    LABEL_EXFILTRATION: "Data Exfiltration",
    LABEL_UNKNOWN: "Unknown / Insufficient Evidence",
}

# Standard Authentication / Remote Access Service Ports
AUTH_PORTS: Set[int] = {21, 22, 23, 110, 1433, 2222, 3306, 3389, 5432, 5900, 6379, 27017}

# Standard System & Well-Known Infrastructure Ports
WELL_KNOWN_PORTS: Set[int] = {
    53, 80, 123, 137, 138, 139, 443, 445, 1900, 3000, 5000, 5173,
    5353, 5355, 8000, 8080, 8443, 8545, 9090
}


# ---------------------------------------------------------------------------
# Dataset Label Resolution Tables
# ---------------------------------------------------------------------------

CIC_IDS2017_MAPPING: Dict[str, str] = {
    "benign": LABEL_BENIGN,
    "portscan": LABEL_PORT_SCAN,
    "ftp-patator": LABEL_BRUTE_FORCE,
    "ssh-patator": LABEL_BRUTE_FORCE,
    "web attack — brute force": LABEL_BRUTE_FORCE,
    "web attack - brute force": LABEL_BRUTE_FORCE,
    "dos hulk": LABEL_DOS_DDOS,
    "dos goldeneye": LABEL_DOS_DDOS,
    "dos slowloris": LABEL_DOS_DDOS,
    "dos slowhttptest": LABEL_DOS_DDOS,
    "ddos": LABEL_DOS_DDOS,
    "heartbleed": LABEL_DOS_DDOS,
    "bot": LABEL_DOS_DDOS,
    "infiltration": LABEL_EXFILTRATION,
    "web attack — xss": LABEL_PORT_SCAN,
    "web attack - xss": LABEL_PORT_SCAN,
    "web attack — sql injection": LABEL_PORT_SCAN,
    "web attack - sql injection": LABEL_PORT_SCAN,
}

UNSW_NB15_MAPPING: Dict[str, str] = {
    "normal": LABEL_BENIGN,
    "reconnaissance": LABEL_PORT_SCAN,
    "fuzzers": LABEL_PORT_SCAN,
    "exploits": LABEL_BRUTE_FORCE,
    "dos": LABEL_DOS_DDOS,
    "generic": LABEL_DOS_DDOS,
    "backdoor": LABEL_EXFILTRATION,
    "shellcode": LABEL_EXFILTRATION,
    "worms": LABEL_EXFILTRATION,
}


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def normalize_label(raw_label: Optional[str]) -> str:
    """Map any raw dataset or model label string to the canonical label key."""
    if not raw_label:
        return LABEL_UNKNOWN

    s = str(raw_label).strip().lower()

    if s in CANONICAL_LABELS:
        return s

    if s in CIC_IDS2017_MAPPING:
        return CIC_IDS2017_MAPPING[s]

    if s in UNSW_NB15_MAPPING:
        return UNSW_NB15_MAPPING[s]

    # Partial substring fallbacks
    if "patator" in s or "brute force" in s or "bruteforce" in s:
        return LABEL_BRUTE_FORCE
    if "portscan" in s or "port_scan" in s or "recon" in s or "scan" in s:
        return LABEL_PORT_SCAN
    if "dos" in s or "ddos" in s or "flood" in s:
        return LABEL_DOS_DDOS
    if "infiltrat" in s or "exfiltrat" in s or "theft" in s:
        return LABEL_EXFILTRATION
    if "benign" in s or "normal" in s:
        return LABEL_BENIGN

    return LABEL_UNKNOWN


def to_display_name(label_key: Optional[str]) -> str:
    """Convert an internal label key to a clean human-readable display string."""
    canonical = normalize_label(label_key)
    return DISPLAY_NAMES.get(canonical, DISPLAY_NAMES[LABEL_UNKNOWN])


def is_auth_port(port: int) -> bool:
    """Check if a port corresponds to an authentication/remote access service."""
    return port in AUTH_PORTS
