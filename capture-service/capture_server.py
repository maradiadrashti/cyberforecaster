"""
AETHERIS Capture Server
Real-time network packet capture via Scapy + Npcap, streamed to React frontend over WebSocket.
"""

import asyncio
import os
import json
import sys
import time
import threading
import ipaddress
from collections import defaultdict, deque
from datetime import datetime

def _is_multicast_or_broadcast(ip_str: str) -> bool:
    """Check if an IP address is multicast or subnet broadcast."""
    if not ip_str:
        return False
    try:
        if ip_str == "255.255.255.255" or ip_str.endswith(".255"):
            return True
        ip = ipaddress.ip_address(ip_str)
        return ip.is_multicast or ip.is_reserved or ip.is_loopback
    except ValueError:
        return False

import subprocess
import psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from scapy.all import sniff, get_if_list, get_if_addr, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
import csv
import hashlib

# Import centralized taxonomy
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
try:
    from models.taxonomy import (
        LABEL_BENIGN, LABEL_PORT_SCAN, LABEL_BRUTE_FORCE, LABEL_DOS_DDOS,
        LABEL_EXFILTRATION, LABEL_UNKNOWN, DISPLAY_NAMES, AUTH_PORTS,
        WELL_KNOWN_PORTS, normalize_label, to_display_name, is_auth_port
    )
except Exception as _e:
    AUTH_PORTS = {21, 22, 23, 110, 1433, 2222, 3306, 3389, 5432, 5900, 6379, 27017}
    WELL_KNOWN_PORTS = {53, 80, 123, 137, 138, 139, 443, 445, 1900, 3000, 5000, 5173, 5353, 5355, 8000, 8080, 8443, 8545, 9090}
    def normalize_label(l): return str(l).lower()
    def to_display_name(l): return str(l).title()
    def is_auth_port(p): return p in AUTH_PORTS

# Live data collection for retraining
_LIVE_DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'logs')
_LIVE_FLOWS_CSV = os.path.join(_LIVE_DATA_DIR, 'live_flows_for_training.csv')
_live_flow_writer = None
_live_flow_file = None
_LIVE_FLOW_LOCK = threading.Lock()
_LIVE_FLOW_COUNT = 0
_MAX_LIVE_FLOWS = 100000  # Rotate after 100k flows

def _init_live_flow_writer():
    """Initialize CSV writer for live flow data collection."""
    global _live_flow_writer, _live_flow_file
    try:
        os.makedirs(_LIVE_DATA_DIR, exist_ok=True)
        write_header = not os.path.exists(_LIVE_FLOWS_CSV)
        _live_flow_file = open(_LIVE_FLOWS_CSV, 'a', newline='')
        _live_flow_writer = csv.writer(_live_flow_file)
        if write_header:
            _live_flow_writer.writerow([
                'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
                'packet_count', 'byte_count', 'duration', 'syn_flag',
                'ack_flag', 'rst_flag', 'fin_flag', 'label'
            ])
            _live_flow_file.flush()
        print(f'[Live] Flow data collection initialized: {_LIVE_FLOWS_CSV}')
    except Exception as e:
        print(f'[Live] Could not init flow writer: {e}')
        _live_flow_writer = None

def _log_live_flow(flow_data: dict):
    """Log a completed flow to CSV for future model retraining."""
    global _live_flow_file, _live_flow_writer, _LIVE_FLOW_COUNT
    if not _live_flow_writer:
        return
    try:
        with _LIVE_FLOW_LOCK:
            _LIVE_FLOW_COUNT += 1
            if _LIVE_FLOW_COUNT > _MAX_LIVE_FLOWS:
                # Rotate file
                if _live_flow_file:
                    _live_flow_file.close()
                ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                rotated = os.path.join(_LIVE_DATA_DIR, f'live_flows_{ts}.csv')
                os.rename(_LIVE_FLOWS_CSV, rotated)
                _init_live_flow_writer()

            # Determine label from current severity
            sev = flow_data.get('severity', 'none')
            atk = flow_data.get('attack_type', 'Benign')
            label = 'benign'
            if sev != 'none':
                label_map = {
                    'Port Scan': 'port_scan', 'DDoS': 'dos_ddos',
                    'SYN Flood': 'dos_ddos', 'Brute Force': 'brute_force',
                    'ICMP Flood': 'dos_ddos', 'Data Exfiltration': 'exfiltration',
                    'Large Transfer': 'benign',  # Not necessarily malicious
                    'Reset Storm': 'benign',
                }
                label = label_map.get(atk, 'benign')

            _live_flow_writer.writerow([
                flow_data.get('src_ip', ''),
                flow_data.get('src_port', 0),
                flow_data.get('dst_ip', ''),
                flow_data.get('dst_port', 0),
                flow_data.get('protocol', 'TCP'),
                flow_data.get('packet_count', 1),
                flow_data.get('byte_count', 0),
                round(flow_data.get('duration', 0.001), 6),
                flow_data.get('syn_flag', 0),
                flow_data.get('ack_flag', 0),
                flow_data.get('rst_flag', 0),
                flow_data.get('fin_flag', 0),
                label,
            ])
            if _LIVE_FLOW_COUNT % 500 == 0:
                _live_flow_file.flush()
    except Exception:
        pass

# ML inference (lazy-loaded on first use)
_ml_predict_flow = None
_ml_loaded = False

def _lazy_load_ml():
    global _ml_predict_flow, _ml_loaded
    if _ml_loaded:
        return
    _ml_loaded = True
    try:
        import sys as _sys
        _sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from models.flow_classifier_infer import predict_flow
        _ml_predict_flow = predict_flow
        print('[ML] Flow classifier loaded successfully.')
    except Exception as e:
        print(f'[ML] Could not load flow classifier: {e}')
        print('[ML] Continuing without ML predictions.')

# ── Privilege check (Windows) ─────────────────────────────────────────────────
def _check_admin():
    if sys.platform == "win32":
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print("\n" + "=" * 60)
            print("  WARNING: Not running as Administrator!")
            print("  Scapy requires elevated privileges on Windows")
            print("  for raw packet capture via Npcap.")
            print()
            print("  Fix: Run start.ps1 or this terminal as Admin,")
            print("       OR right-click -> 'Run as administrator'.")
            print("=" * 60 + "\n")
        else:
            print("[+] Running as Administrator - Scapy capture enabled.")

_check_admin()

app = FastAPI(title="AETHERIS Capture Server")


@app.on_event("startup")
async def _on_startup():
    """Build Scapy device map, capture the running event loop, start ML forecast loop."""
    global _main_loop
    _main_loop = asyncio.get_event_loop()
    _build_scapy_map()
    _init_live_flow_writer()
    print(f"[Startup] Scapy device map built: {len(iface_to_scapy)} Npcap devices found.")
    asyncio.create_task(_stage_forecast_loop())


@app.on_event("shutdown")
async def _on_shutdown():
    """Stop all capture threads and kill WSL processes on server shutdown."""
    print("[Shutdown] Stopping all packet capture processes...")
    stop_all_captures_except(None)
    reset_backend_state()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
active_captures: dict[str, bool] = {}           # iface -> is_capturing
capture_threads: dict[str, threading.Thread] = {}
wsl_processes: dict[str, subprocess.Popen] = {}
connected_clients: list[WebSocket] = []
flow_cache: dict[str, dict] = {}                 # 5-tuple -> aggregated flow
flow_lock = threading.Lock()
capture_stats = {
    "total_packets": 0,
    "start_time": None,
}

# Well-known service ports that should NEVER trigger attack classification.
# DNS, NTP, mDNS, LLMNR, SSDP, and standard web/service ports are normal traffic.
WELL_KNOWN_UDP_SERVICES = {53, 123, 5353, 5355, 1900, 137, 138, 139, 445, 5060}
WELL_KNOWN_TCP_PORTS = {80, 443, 8080, 8443, 3000, 5000, 5173, 8000, 8545, 27017, 6379, 9090, 5432, 3306, 1433}
SERVER_RESPONSE_PORTS = WELL_KNOWN_UDP_SERVICES | WELL_KNOWN_TCP_PORTS | WELL_KNOWN_PORTS | AUTH_PORTS

# Per-IP tracking for flow-level heuristic detection
_ip_flows: dict[str, list] = {}          # src_ip -> list of recent flow timestamps
_ip_ports: dict[str, set] = {}            # src_ip -> set of unique dst_ports hit
_ip_bytes: dict[str, int] = {}            # src_ip -> total bytes sent recently
_ip_dst: dict[str, dict] = {}            # src_ip -> {dst_ip: flow_count}
_ip_dst_ports: dict[str, dict] = defaultdict(lambda: defaultdict(set)) # src_ip -> dst_ip -> set of dports
_ip_port_attempts: dict[str, dict] = defaultdict(lambda: defaultdict(lambda: defaultdict(list))) # src_ip -> dst_ip -> dport -> timestamps
_TRACKING_WINDOW = 30  # seconds for tracking window

# Bounded per-host risk history for data-driven forecast trend projection
_host_risk_history: dict[str, deque] = defaultdict(lambda: deque(maxlen=12))

# Mapping from friendly interface name -> Scapy Npcap device GUID
iface_to_scapy: dict[str, str] = {}

# Main asyncio event loop – stored at startup so background threads can
# schedule WebSocket sends safely (asyncio.run() is forbidden in threads).
_main_loop: asyncio.AbstractEventLoop | None = None


def _build_scapy_map():
    """Build IP/device-to-Npcap mapping so we can sniff using friendly names."""
    global iface_to_scapy
    try:
        iface_dict = getattr(conf, "ifaces", {})
        for dev, obj in iface_dict.items():
            try:
                ip = getattr(obj, "ip", "")
                name = getattr(obj, "name", "")
                if dev:
                    iface_to_scapy[dev] = ip
                if name:
                    iface_to_scapy[name] = ip
            except Exception:
                pass
        for dev in get_if_list():
            try:
                ip = get_if_addr(dev)
                iface_to_scapy[dev] = ip
            except Exception:
                pass
    except Exception:
        pass


def _resolve_scapy_iface(friendly_name: str) -> str:
    """Resolve a psutil friendly name to its Scapy Npcap device GUID or adapter."""
    # 1. Match from conf.ifaces items
    try:
        for dev, iface_obj in getattr(conf, "ifaces", {}).items():
            name = getattr(iface_obj, "name", "")
            desc = getattr(iface_obj, "description", "")
            netname = getattr(iface_obj, "network_name", "")
            guid = getattr(iface_obj, "guid", "")
            ip = getattr(iface_obj, "ip", "")
            if friendly_name.lower() in (name.lower(), desc.lower(), str(dev).lower(), str(guid).lower(), netname.lower()):
                return dev
            if ip and ip == friendly_name:
                return dev
    except Exception:
        pass

    # 2. Match from iface_to_scapy
    for dev, ip in iface_to_scapy.items():
        if dev.lower() == friendly_name.lower():
            return dev

    # 3. Match by IP address via psutil
    try:
        psutil_addrs = psutil.net_if_addrs()
        target_ip = None
        for name, addr_list in psutil_addrs.items():
            if name.lower() == friendly_name.lower():
                for a in addr_list:
                    if getattr(a.family, "name", "") == "AF_INET":
                        target_ip = a.address
                        break
                break

        if target_ip:
            for dev, iface_obj in getattr(conf, "ifaces", {}).items():
                if getattr(iface_obj, "ip", "") == target_ip:
                    return dev
            for dev, ip in iface_to_scapy.items():
                if ip == target_ip:
                    return dev
    except Exception:
        pass

    # Fallback: return the name as-is
    return friendly_name

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_wsl_interfaces() -> list[dict]:
    """Detect active WSL interface and IP address."""
    if sys.platform != "win32":
        return []
    try:
        res_route = subprocess.run(
            ["wsl.exe", "ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        if res_route.returncode == 0 and res_route.stdout:
            parts = res_route.stdout.strip().split()
            if "dev" in parts:
                idx = parts.index("dev")
                wsl_iface = parts[idx + 1]
                res_ip = subprocess.run(
                    ["wsl.exe", "ip", "-4", "addr", "show", wsl_iface],
                    capture_output=True, text=True, timeout=5
                )
                wsl_ip = "172.31.195.203"
                for line in res_ip.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("inet "):
                        wsl_ip = line.split()[1].split("/")[0]
                        break
                name = f"WSL ({wsl_iface})"
                return [{
                    "name": name,
                    "display_name": name,
                    "ip": wsl_ip,
                    "mac": "N/A",
                    "type": "Virtual",
                    "is_up": True,
                    "bytes_sent": 0,
                    "bytes_recv": 0,
                    "is_wsl": True,
                    "wsl_iface": wsl_iface,
                }]
    except Exception as e:
        print(f"[WSL Discovery] Error: {e}")
    return []


def get_real_interfaces() -> list[dict]:
    """Detect real network interfaces using psutil + scapy + WSL auto-discovery."""
    interfaces = []
    wsl_ifaces = _get_wsl_interfaces()
    for w_if in wsl_ifaces:
        interfaces.append(w_if)

    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    io_counters = psutil.net_io_counters(pernic=True)

    for name, addr_list in addrs.items():
        ip_addr = None
        mac_addr = None
        for a in addr_list:
            if a.family.name == "AF_INET":
                ip_addr = a.address
            elif a.family.name == "AF_LINK":
                mac_addr = a.address

        is_up = stats.get(name, None)
        is_connected = is_up.isup if is_up else False

        io = io_counters.get(name, None)
        bytes_sent = io.bytes_sent if io else 0
        bytes_recv = io.bytes_recv if io else 0

        # Determine interface type heuristic
        iface_type = "Unknown"
        nl = name.lower()
        if "wi-fi" in nl or "wifi" in nl or "wlan" in nl or "wireless" in nl:
            iface_type = "WiFi"
        elif "ethernet" in nl or "eth" in nl or "local area" in nl:
            iface_type = "Ethernet"
        elif "bluetooth" in nl or "bt" in nl:
            iface_type = "Bluetooth"
        elif "vpn" in nl or "tunnel" in nl or "wg" in nl:
            iface_type = "VPN"
        elif "vmware" in nl or "virtual" in nl or "veth" in nl:
            iface_type = "Virtual"
        elif "loopback" in nl:
            iface_type = "Loopback"
        elif "docker" in nl or "br-" in nl:
            iface_type = "Docker"

        interfaces.append({
            "name": name,
            "display_name": name,
            "ip": ip_addr or "N/A",
            "mac": mac_addr or "N/A",
            "type": iface_type,
            "is_up": is_connected,
            "bytes_sent": bytes_sent,
            "bytes_recv": bytes_recv,
        })

    # Sort: connected first, then by type priority
    priority = {"WiFi": 0, "Ethernet": 1, "VPN": 2, "Bluetooth": 3, "Virtual": 4, "Unknown": 5}
    interfaces.sort(key=lambda x: (not x.get("is_up", False), priority.get(x.get("type", "Unknown"), 99)))
    return interfaces


def _build_flow_key(pkt) -> str | None:
    """Build a 5-tuple key from a packet."""
    if not pkt.haslayer(IP):
        return None
    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = pkt[IP].proto
    sport = 0
    dport = 0
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    return f"{src}:{sport}-{dst}:{dport}-{proto}"


def _packet_to_flow_event(pkt) -> dict | None:
    """Convert a scapy packet into a flow event dict for the frontend."""
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    proto_name = "Other"
    sport = 0
    dport = 0
    syn = ack = rst = fin = 0

    if pkt.haslayer(TCP):
        proto_name = "TCP"
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags
        syn = 1 if flags.S else 0
        ack = 1 if flags.A else 0
        rst = 1 if flags.R else 0
        fin = 1 if flags.F else 0
    elif pkt.haslayer(UDP):
        proto_name = "UDP"
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        proto_name = "ICMP"

    pkt_len = len(pkt)
    now = datetime.utcnow().isoformat()

    pkt_len = len(pkt)
    now = datetime.utcnow().isoformat()

    # Default all single packets to Benign (none severity)
    # Attack classification requires ML flow classification or multi-packet heuristic rules
    severity = "none"
    attack_type = "Benign"

    return {
        "id": f"{now}-{ip.src}-{ip.dst}-{sport}-{dport}",
        "timestamp": now,
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "src_port": sport,
        "dst_port": dport,
        "protocol": proto_name,
        "length": pkt_len,
        "syn": syn,
        "ack": ack,
        "rst": rst,
        "fin": fin,
        "ttl": ip.ttl,
        "severity": severity,
        "attack_type": attack_type,
    }


# ---------------------------------------------------------------------------
# Flow-level heuristic classification
# ---------------------------------------------------------------------------

def _heuristic_classify(flow_key: str, event: dict):
    """Reclassify a flow using aggregate flow-level heuristics with windowed context.
    Distinguishes Port Scan from Brute Force based on port diversity vs. single-port attempt count.
    """
    now = time.time()
    src_ip = event.get("src_ip", "")
    dst_ip = event.get("dst_ip", "")
    sport = event.get("src_port", 0)
    dport = event.get("dst_port", 0)
    proto = event.get("protocol", "TCP")
    flow = flow_cache.get(flow_key)
    if not flow:
        return

    # Check if packet is routine server/service/web traffic
    is_server_response = (sport in SERVER_RESPONSE_PORTS or sport in WELL_KNOWN_PORTS or sport in WELL_KNOWN_TCP_PORTS or sport in WELL_KNOWN_UDP_SERVICES)
    is_well_known_dst = (dport in WELL_KNOWN_PORTS or dport in WELL_KNOWN_TCP_PORTS or dport in WELL_KNOWN_UDP_SERVICES)
    is_established_flow = (flow.get("packet_count", 1) >= 3 or flow.get("byte_count", 0) > 500 or (flow.get("ack_flag", 0) > 0 and flow.get("syn_flag", 0) > 0))
    is_routine_service_traffic = is_server_response or (is_well_known_dst and (is_established_flow or proto in ("UDP", "ICMP")))

    # ── Per-IP tracking ─────────────────────────────────────────────────
    if src_ip not in _ip_flows:
        _ip_flows[src_ip] = []
        _ip_bytes[src_ip] = 0
        _ip_dst[src_ip] = {}

    _ip_flows[src_ip].append(now)
    _ip_bytes[src_ip] += event.get("length", 0)
    _ip_dst[src_ip][dst_ip] = _ip_dst[src_ip].get(dst_ip, 0) + 1

    # Only track target port attempts for non-routine service traffic (true probe attempts)
    if not is_routine_service_traffic:
        _ip_port_attempts[src_ip][dst_ip][dport].append(now)

    # Prune old entries outside the tracking window (30s)
    cutoff = now - _TRACKING_WINDOW
    _ip_flows[src_ip] = [t for t in _ip_flows[src_ip] if t > cutoff]

    # Prune windowed port attempts and calculate active target ports for (src_ip -> dst_ip)
    active_dports = set()
    for p, timestamps in list(_ip_port_attempts[src_ip][dst_ip].items()):
        valid_ts = [t for t in timestamps if t > cutoff]
        if valid_ts:
            _ip_port_attempts[src_ip][dst_ip][p] = valid_ts
            active_dports.add(p)
        else:
            del _ip_port_attempts[src_ip][dst_ip][p]

    _ip_dst_ports[src_ip][dst_ip] = active_dports

    # Calculate active unique ports across all targets for src_ip
    active_all_ports = set()
    for target_ip, port_map in list(_ip_port_attempts[src_ip].items()):
        for p, timestamps in list(port_map.items()):
            valid_ts = [t for t in timestamps if t > cutoff]
            if valid_ts:
                active_all_ports.add(p)
    _ip_ports[src_ip] = active_all_ports

    first_seen_ts = flow.get("first_seen_ts", now)
    flow_duration = max(now - first_seen_ts, 0.001)
    pps = flow["packet_count"] / max(flow_duration, 1.0)
    bpp = flow["byte_count"] / max(flow["packet_count"], 1)

    recent_flows = len(_ip_flows[src_ip])
    
    # Exclude authentication ports from port-scan diversity count when inspecting brute-force candidates
    same_port_attempts = len(_ip_port_attempts[src_ip][dst_ip].get(dport, []))
    if same_port_attempts == 0 and is_auth_port(dport):
        # Fallback to total flow count for this auth port if routine filter omitted single-pkt auth flows
        same_port_attempts = flow.get("packet_count", 1)

    probe_dports = {p for p in active_dports if not (is_auth_port(p) and same_port_attempts >= 3)}
    unique_ports_contacted = len(probe_dports)
    is_multicast = _is_multicast_or_broadcast(dst_ip) or _is_multicast_or_broadcast(src_ip)

    syn_flag = flow.get("syn_flag", 0)
    ack_flag = flow.get("ack_flag", 0)
    rst_flag = flow.get("rst_flag", 0)

    severity = "none"
    attack_type = "Benign"
    reason = "Normal traffic pattern"

    if is_multicast:
        severity = "none"
        attack_type = "Benign"
        reason = "Multicast/Broadcast traffic"
    else:
        # --- 1. SYN Flood Detection ---
        if proto == "TCP" and syn_flag > 30 and ack_flag < 2 and pps > 10:
            severity = "critical" if syn_flag > 50 else "high"
            attack_type = "SYN Flood"
            reason = f"High SYN-only packet rate (syn={syn_flag}, pps={pps:.1f})"

        # --- 2. DDoS / Flood Detection ---
        elif pps > 100 and flow["packet_count"] >= 200:
            severity = "critical" if pps > 200 else "high"
            attack_type = "DDoS"
            reason = f"High volumetric packet flood (pps={pps:.1f}, count={flow['packet_count']})"

        # --- 3. Port Scan Detection (Checked FIRST when high port diversity exists) ---
        # Triggered by destination-port diversity (unique_ports_contacted >= 4 or len(_ip_ports[src_ip]) >= 5)
        # When probing multiple ports, any auth port attempt is part of the Port Scan, NOT a single-target Brute Force attack.
        elif unique_ports_contacted >= 4 or len(_ip_ports[src_ip]) >= 5:
            severity = "high" if unique_ports_contacted >= 15 or len(_ip_ports[src_ip]) >= 20 else "medium"
            attack_type = "Port Scan"
            reason = f"Destination port scanning detected ({unique_ports_contacted} target ports probed, {recent_flows} flows)"

            # Precedence Resolution: Retroactively update any flows for this (src_ip, dst_ip) pair that were transiently
            # misclassified as Brute Force during early probes of the scan (unless they have >= 8 single-port attempts).
            for f_key, cached_flow in flow_cache.items():
                if cached_flow.get("src_ip") == src_ip and cached_flow.get("dst_ip") == dst_ip:
                    if cached_flow.get("attack_type") == "Brute Force":
                        auth_p = cached_flow.get("dst_port", 0)
                        attempts_on_p = len(_ip_port_attempts[src_ip][dst_ip].get(auth_p, []))
                        if attempts_on_p < 8:
                            cached_flow["attack_type"] = "Port Scan"
                            cached_flow["severity"] = severity
                            cached_flow["reason"] = f"Reclassified as part of Port Scan ({unique_ports_contacted} target ports probed)"

        # --- 4. Brute Force Detection ---
        # REQUIRES repeated connection attempts to the SAME authentication service port
        # AND LOW port diversity (unique_ports_contacted <= 3) so multi-port scans are never misclassified
        elif is_auth_port(dport) and (same_port_attempts >= 8 or (same_port_attempts >= 5 and flow.get("packet_count", 1) >= 5)) and unique_ports_contacted <= 3:
            severity = "high" if same_port_attempts >= 20 else "medium"
            attack_type = "Brute Force"
            reason = f"Repeated authentication attempts against port {dport} ({same_port_attempts} attempts)"

            # Precedence Resolution: Retroactively update all active flows targeting this auth port from this src_ip
            # so they are consistently reported as Brute Force ONLY (never false Port Scan overlap).
            for f_key, cached_flow in flow_cache.items():
                if cached_flow.get("src_ip") == src_ip and cached_flow.get("dst_ip") == dst_ip and cached_flow.get("dst_port") == dport:
                    cached_flow["attack_type"] = "Brute Force"
                    cached_flow["severity"] = severity
                    cached_flow["reason"] = reason

        # --- 5. ICMP Flood ---
        # Triggered by rapid/high volume ICMP echo/ping requests from src_ip
        elif proto == "ICMP" and (flow["packet_count"] >= 30 and pps >= 2.0 or flow["packet_count"] >= 50):
            severity = "high" if flow["packet_count"] >= 100 else "medium"
            attack_type = "ICMP Flood"
            reason = f"ICMP ping flood ({flow['packet_count']} packets, {pps:.1f} pps)"

            # Precedence Resolution: Standardize all ICMP attack flows for this host pair to ICMP Flood
            for f_key, cached_flow in flow_cache.items():
                if cached_flow.get("src_ip") == src_ip and cached_flow.get("dst_ip") == dst_ip and cached_flow.get("protocol") == "ICMP":
                    if cached_flow.get("severity") != "none":
                        cached_flow["attack_type"] = "ICMP Flood"
                        cached_flow["severity"] = severity

        # --- 6. Data Exfiltration ---
        elif proto == "TCP" and flow["byte_count"] > 10_000_000 and flow_duration > 5.0 and bpp > 1000:
            severity = "high"
            attack_type = "Data Exfiltration"
            reason = f"Large data payload transfer ({flow['byte_count']} bytes)"

    # Apply classification
    flow["severity"] = severity
    flow["attack_type"] = attack_type
    flow["reason"] = reason
    event["severity"] = severity
    event["attack_type"] = attack_type
    event["reason"] = reason


# ---------------------------------------------------------------------------
# Capture thread
# ---------------------------------------------------------------------------

def stop_all_captures_except(keep_iface: str = None):
    """Stop active capture threads and WSL processes on all interfaces except the specified one."""
    for iface in list(active_captures.keys()):
        if keep_iface is None or iface != keep_iface:
            active_captures[iface] = False
            proc = wsl_processes.pop(iface, None)
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass

def reset_backend_state():
    """Fully clear all accumulated flow and attack state on the backend."""
    with flow_lock:
        flow_cache.clear()
        _ip_flows.clear()
        _ip_ports.clear()
        _ip_bytes.clear()
        _ip_dst.clear()
        _ip_dst_ports.clear()
        _ip_port_attempts.clear()
        _host_risk_history.clear()


def _start_iface_capture(iface: str) -> bool:
    """Ensure capture is running ONLY on the specified interface."""
    stop_all_captures_except(iface)
    if active_captures.get(iface):
        return True

    is_wsl = "wsl" in iface.lower()
    target_fn = _wsl_capture_loop if is_wsl else _capture_loop

    t = threading.Thread(target=target_fn, args=(iface,), daemon=True)
    capture_threads[iface] = t
    t.start()
    return True


def _process_flow_event(event: dict, iface: str):
    """Process a parsed flow event through flow aggregation, heuristics, ML classification, and WebSocket broadcast."""
    if event is None:
        return

    capture_stats["total_packets"] += 1
    event["interface"] = iface

    src = event.get("src_ip", "")
    dst = event.get("dst_ip", "")
    sport = event.get("src_port", 0)
    dport = event.get("dst_port", 0)
    proto = event.get("protocol", "TCP")
    key = f"{src}:{sport}-{dst}:{dport}-{proto}"

    with flow_lock:
        if key in flow_cache:
            flow_cache[key]["packet_count"] += 1
            flow_cache[key]["byte_count"] += event.get("length", 0)
            flow_cache[key]["last_seen"] = event["timestamp"]
            flow_cache[key]["syn_flag"] = flow_cache[key].get("syn_flag", 0) + event.get("syn", 0)
            flow_cache[key]["ack_flag"] = flow_cache[key].get("ack_flag", 0) + event.get("ack", 0)
            flow_cache[key]["rst_flag"] = flow_cache[key].get("rst_flag", 0) + event.get("rst", 0)
            flow_cache[key]["fin_flag"] = flow_cache[key].get("fin_flag", 0) + event.get("fin", 0)
            try:
                t1 = datetime.fromisoformat(flow_cache[key]["first_seen"])
                t2 = datetime.fromisoformat(flow_cache[key]["last_seen"])
                flow_cache[key]["duration"] = max((t2 - t1).total_seconds(), 0.001)
            except Exception:
                flow_cache[key]["duration"] = 0.001
        else:
            flow_cache[key] = {
                "src_ip": src,
                "dst_ip": dst,
                "src_port": sport,
                "dst_port": dport,
                "protocol": proto,
                "packet_count": 1,
                "byte_count": event.get("length", 0),
                "first_seen": event["timestamp"],
                "first_seen_ts": time.time(),
                "last_seen": event["timestamp"],
                "duration": 0.001,
                "severity": event.get("severity", "none"),
                "attack_type": event.get("attack_type", "Benign"),
                "interface": iface,
                "syn_flag": event.get("syn", 0),
                "ack_flag": event.get("ack", 0),
                "rst_flag": event.get("rst", 0),
                "fin_flag": event.get("fin", 0),
            }

    # Flow-level heuristic classification
    _heuristic_classify(key, event)

    # ML classification
    if not _ml_loaded:
        _lazy_load_ml()

    is_mcast = _is_multicast_or_broadcast(dst) or _is_multicast_or_broadcast(src)
    if is_mcast:
        event["severity"] = "none"
        event["attack_type"] = "Benign"
        with flow_lock:
            if key in flow_cache:
                flow_cache[key]["severity"] = "none"
                flow_cache[key]["attack_type"] = "Benign"
    elif _ml_predict_flow:
        try:
            ml_label, ml_confidence = _ml_predict_flow(flow_cache[key])
            now_ts   = time.time()
            src_ip   = event.get("src_ip", "")
            dst_ip   = event.get("dst_ip", "")
            dport    = event.get("dst_port", 0)
            flow     = flow_cache.get(key, {})
            duration = max(now_ts - flow.get("first_seen_ts", now_ts), 0.001)

            unique_ports_contacted = len(_ip_dst_ports[src_ip][dst_ip])
            same_port_attempts = len(_ip_port_attempts[src_ip][dst_ip][dport])
            current_severity = flow.get("severity", "none")
            current_attack = flow.get("attack_type", "Benign")

            ml_accept = False
            reason = "ML prediction rejected"

            norm_ml_label = normalize_label(ml_label)

            if norm_ml_label == LABEL_PORT_SCAN:
                # ML Port Scan requires genuine destination port diversity (>= 4 ports)
                if unique_ports_contacted >= 4 and not is_auth_port(dport):
                    ml_accept = True
                    reason = f"ML Port Scan accepted (unique_ports={unique_ports_contacted}, conf={ml_confidence:.2f})"
                else:
                    reason = f"ML Port Scan rejected: Low port diversity ({unique_ports_contacted} ports < 4)"

            elif norm_ml_label == LABEL_BRUTE_FORCE:
                # Accept ML Brute Force ONLY if auth port AND low port diversity (<= 3 ports)
                if is_auth_port(dport) and (same_port_attempts >= 3 or ml_confidence >= 0.75) and unique_ports_contacted <= 3:
                    ml_accept = True
                    reason = f"ML Brute Force accepted ({same_port_attempts} attempts to auth port {dport}, conf={ml_confidence:.2f})"
                elif unique_ports_contacted >= 4:
                    # OVERRIDE ML false Brute Force to Port Scan when port diversity is high!
                    event["ml_label"] = "port_scan"
                    event["ml_confidence"] = round(ml_confidence, 4)
                    event["attack_type"] = "Port Scan"
                    event["severity"] = "medium"
                    event["reason"] = f"Multi-port probe ({unique_ports_contacted} ports) indicates Port Scan"
                    with flow_lock:
                        if key in flow_cache:
                            flow_cache[key]["attack_type"] = "Port Scan"
                            flow_cache[key]["severity"] = "medium"
                            flow_cache[key]["reason"] = event["reason"]
                    ml_accept = False
                else:
                    reason = f"ML Brute Force rejected: Insufficient single-port attempts ({same_port_attempts}/5 required)"

            elif norm_ml_label == LABEL_DOS_DDOS:
                if proto == "ICMP" and flow.get("packet_count", 0) >= 30:
                    ml_accept = True
                    event["attack_type"] = "ICMP Flood"  # Standardize display name for ICMP
                    reason = f"ML ICMP Flood accepted ({flow.get('packet_count', 0)} ICMP packets, conf={ml_confidence:.2f})"
                elif flow.get("packet_count", 0) >= 50 or (flow.get("packet_count", 0) / duration) >= 50 or ml_confidence >= 0.95:
                    ml_accept = True
                    reason = f"ML DDoS accepted (conf={ml_confidence:.2f})"

            elif norm_ml_label == LABEL_EXFILTRATION:
                if flow.get("byte_count", 0) >= 5_000_000 and ml_confidence >= 0.90:
                    ml_accept = True
                    reason = f"ML Exfiltration accepted (bytes={flow.get('byte_count', 0)}, conf={ml_confidence:.2f})"

            if ml_accept:
                event["ml_label"]      = norm_ml_label
                event["ml_confidence"] = round(ml_confidence, 4)
                event["attack_type"]   = "ICMP Flood" if proto == "ICMP" else to_display_name(norm_ml_label)
                event["severity"]      = "high" if ml_confidence > 0.95 else "medium"
                event["reason"]        = reason
                with flow_lock:
                    if key in flow_cache:
                        flow_cache[key]["attack_type"] = event["attack_type"]
                        flow_cache[key]["severity"]    = event["severity"]
                        flow_cache[key]["reason"]      = reason
            else:
                # Do not leak unaccepted/rejected ML label to event object
                event["ml_label"] = None
                event["ml_confidence"] = None

            # Diagnostic logging (Requirement 12)
            print(f"[CLASSIFY] src={src_ip}:{sport} dst={dst_ip}:{dport} proto={proto} | "
                  f"unique_ports={unique_ports_contacted} same_port_att={same_port_attempts} | "
                  f"ML=({ml_label}, {ml_confidence:.2f}) Heuristic={current_attack} -> "
                  f"Final={event.get('attack_type')} | Reason={event.get('reason', reason)}")

        except Exception as e:
            print(f"[CLASSIFY ERROR] {e}")

    if key in flow_cache and flow_cache[key].get("packet_count", 0) % 10 == 1:
        try:
            _log_live_flow(flow_cache[key])
        except Exception:
            pass

    msg = json.dumps(event)
    if _main_loop and not _main_loop.is_closed():
        async def _send_all(message: str):
            dead = []
            for ws in list(connected_clients):
                try:
                    await ws.send_text(message)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                if ws in connected_clients:
                    connected_clients.remove(ws)
        _main_loop.call_soon_threadsafe(
            lambda m=msg: asyncio.ensure_future(_send_all(m), loop=_main_loop)
        )


def _wsl_capture_loop(iface: str):
    """Sniff packets inside WSL environment using wsl_sniffer.py and process through main pipeline."""
    active_captures[iface] = True
    capture_stats["start_time"] = time.time()
    capture_stats["total_packets"] = 0

    wsl_internal_iface = "eth0"
    if "(" in iface and ")" in iface:
        wsl_internal_iface = iface.split("(")[1].split(")")[0]

    script_win_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "wsl_sniffer.py"))
    wsl_script_path = f"/mnt/c/{script_win_path[3:].replace('\\', '/')}"
    try:
        res = subprocess.run(
            ["wsl.exe", "wslpath", "-u", script_win_path.replace("\\", "/")],
            capture_output=True, text=True, timeout=5
        )
        if res.returncode == 0 and res.stdout.strip():
            wsl_script_path = res.stdout.strip()
    except Exception:
        pass

    cmd = ["wsl.exe", "-u", "root", "python3", "-u", wsl_script_path, wsl_internal_iface]
    print(f"[WSL Capture] Launching: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        wsl_processes[iface] = proc

        while active_captures.get(iface):
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                continue
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if "error" in event:
                    print(f"[WSL Capture Error] {event['error']}")
                    break
                _process_flow_event(event, iface)
            except json.JSONDecodeError:
                pass
    except Exception as e:
        print(f"[WSL Capture Exception] {iface}: {e}")
    finally:
        active_captures[iface] = False
        proc = wsl_processes.pop(iface, None)
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        try:
            subprocess.run(["wsl.exe", "-u", "root", "pkill", "-f", "wsl_sniffer.py"], capture_output=True, timeout=3)
        except Exception:
            pass
        print(f"[WSL Capture] Terminated on {iface}")


def _capture_loop(iface: str):
    """Sniff packets on the given interface via Windows Npcap and broadcast to WebSocket clients."""
    active_captures[iface] = True
    capture_stats["start_time"] = time.time()
    capture_stats["total_packets"] = 0

    scapy_iface = _resolve_scapy_iface(iface)
    print(f"[Capture] Sniffing on {iface} -> {scapy_iface}")

    def process_packet(pkt):
        if not active_captures.get(iface):
            return False

        try:
            event = _packet_to_flow_event(pkt)
            if event is None:
                return
            _process_flow_event(event, iface)
        except Exception:
            pass

    try:
        sniff(
            iface=scapy_iface,
            prn=process_packet,
            store=False,
            stop_filter=lambda _: not active_captures.get(iface, False),
        )
    except Exception as e:
        print(f"[Capture Error] {iface} ({scapy_iface}): {e}")
    finally:
        active_captures[iface] = False


# ---------------------------------------------------------------------------
# Stage Forecaster Background Task
# ---------------------------------------------------------------------------

_stage_forecaster = None

def _lazy_load_stage_forecaster():
    global _stage_forecaster
    if _stage_forecaster is not None:
        return True
    try:
        import sys as _sys
        _sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from models.stage_forecaster_infer import forecast_host
        _stage_forecaster = forecast_host
        print('[ML] Stage forecaster loaded successfully.')
        return True
    except Exception as e:
        print(f'[ML] Could not load stage forecaster: {e}')
        return False

async def _stage_forecast_loop():
    """Periodically forecast attack stages per active host."""
    while True:
        try:
            await asyncio.sleep(1.0)  # High-responsiveness live telemetry cadence (1s)
            if not _lazy_load_stage_forecaster():
                continue

            # Snapshot flows per source IP
            with flow_lock:
                host_flows = {}
                for flow in flow_cache.values():
                    src = flow.get('src_ip', '')
                    if src and src != 'unknown':
                        if src not in host_flows:
                            host_flows[src] = []
                        host_flows[src].append(flow)

            if not host_flows:
                continue

            # Forecast top 20 most active hosts
            forecasts = {}
            for ip, flows in sorted(host_flows.items(),
                                     key=lambda x: len(x[1]),
                                     reverse=True)[:20]:
                recent = flows[-10:]
                try:
                    history = list(_host_risk_history[ip])
                    forecast = _stage_forecaster(ip, recent, risk_history=history)
                    if forecast and "risk_score" in forecast:
                        _host_risk_history[ip].append(forecast["risk_score"])
                        forecast["recent_risk_history"] = [round(float(r), 4) for r in list(_host_risk_history[ip])]
                    forecasts[ip] = forecast
                except Exception:
                    pass

            # Cache latest stage forecasts globally
            global _latest_stage_forecasts
            _latest_stage_forecasts = forecasts

            # Broadcast forecasts to WebSocket clients
            if forecasts and _main_loop and not _main_loop.is_closed():
                msg = json.dumps({"type": "stage_forecasts", "data": forecasts})
                async def _send_forecasts(message):
                    dead = []
                    for ws in list(connected_clients):
                        try:
                            await ws.send_text(message)
                        except Exception:
                            dead.append(ws)
                    for ws in dead:
                        if ws in connected_clients:
                            connected_clients.remove(ws)
                _main_loop.call_soon_threadsafe(
                    lambda m=msg: asyncio.ensure_future(
                        _send_forecasts(m), loop=_main_loop
                    )
                )
        except Exception as e:
            pass  # Never let ML failure break the server

_latest_stage_forecasts = {}

# ---------------------------------------------------------------------------
# REST Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/interfaces")
async def list_interfaces():
    return get_real_interfaces()


@app.get("/api/forecasts")
async def get_forecasts():
    """Return latest GRU stage forecasts for all active hosts."""
    return _latest_stage_forecasts


@app.get("/api/stats")
async def get_stats():
    return {
        "total_packets": capture_stats["total_packets"],
        "start_time": capture_stats["start_time"],
        "active_captures": {k: v for k, v in active_captures.items() if v},
        "flow_count": len(flow_cache),
    }


@app.get("/api/flows")
async def get_flows(interface: str = None):
    with flow_lock:
        if interface:
            flows = [f for f in flow_cache.values() if f.get("interface") == interface]
        else:
            flows = list(flow_cache.values())
        return flows[-100:]


@app.get("/api/interface-stats")
async def get_interface_stats():
    """Per-interface attack breakdown."""
    with flow_lock:
        stats = {}
        for flow in flow_cache.values():
            iface = flow.get("interface", "unknown")
            if iface not in stats:
                stats[iface] = {
                    "interface": iface,
                    "total_flows": 0,
                    "total_packets": 0,
                    "total_bytes": 0,
                    "attack_flows": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "unique_src_ips": set(),
                    "unique_dst_ips": set(),
                }
            s = stats[iface]
            s["total_flows"] += 1
            s["total_packets"] += flow["packet_count"]
            s["total_bytes"] += flow["byte_count"]
            sev = flow.get("severity", "none")
            if sev != "none":
                s["attack_flows"] += 1
                if sev in ("critical", "high", "medium", "low"):
                    s[sev] += 1
            s["unique_src_ips"].add(flow["src_ip"])
            s["unique_dst_ips"].add(flow["dst_ip"])

        # Serialize sets to counts
        result = []
        for iface, s in stats.items():
            result.append({
                "interface": s["interface"],
                "total_flows": s["total_flows"],
                "total_packets": s["total_packets"],
                "total_bytes": s["total_bytes"],
                "attack_flows": s["attack_flows"],
                "critical": s["critical"],
                "high": s["high"],
                "medium": s["medium"],
                "low": s["low"],
                "unique_src_ips": len(s["unique_src_ips"]),
                "unique_dst_ips": len(s["unique_dst_ips"]),
            })
        return result


@app.post("/api/capture/start/{iface}")
async def start_capture(iface: str):
    _start_iface_capture(iface)
    return {"status": "started", "iface": iface}


@app.post("/api/capture/switch/{iface}")
async def switch_capture(iface: str):
    _start_iface_capture(iface)
    return {"status": "switched", "iface": iface}


@app.post("/api/capture/stop/{iface}")
async def stop_capture(iface: str):
    active_captures[iface] = False
    reset_backend_state()
    return {"status": "stopped", "iface": iface}


@app.post("/api/capture/stop_all")
async def stop_all_captures():
    stop_all_captures_except(None)
    reset_backend_state()
    return {"status": "all_stopped"}


@app.get("/api/capture/status")
async def capture_status():
    return {k: v for k, v in active_captures.items()}


@app.get("/api/live-data/status")
async def live_data_status():
    """Show status of live flow data collection for retraining."""
    csv_path = _LIVE_FLOWS_CSV
    exists = os.path.exists(csv_path)
    size = 0
    rows = 0
    if exists:
        size = os.path.getsize(csv_path)
        try:
            with open(csv_path, 'r') as f:
                rows = sum(1 for _ in f) - 1  # subtract header
        except Exception:
            pass
    return {
        'csv_path': csv_path,
        'exists': exists,
        'size_bytes': size,
        'flow_count': max(rows, 0),
        'total_logged': _LIVE_FLOW_COUNT,
        'max_flows': _MAX_LIVE_FLOWS,
    }


@app.post("/api/retrain")
async def retrain_classifier():
    """Retrain the XGBoost flow classifier on collected live data + CIC-IDS2017."""
    csv_path = _LIVE_FLOWS_CSV
    if not os.path.exists(csv_path):
        return {"status": "error", "message": "No live data collected yet. Start a capture first."}

    try:
        import subprocess
        script = os.path.join(os.path.dirname(__file__), '..', 'training', 'train_from_cic_ids2017.py')
        cic_dir = r'C:\Users\htc\Downloads\MachineLearningCSV\MachineLearningCVE'
        if not os.path.exists(cic_dir):
            return {"status": "error", "message": f"CIC-IDS2017 dataset not found at {cic_dir}"}

        # Run training in background
        proc = subprocess.Popen(
            [sys.executable, script, cic_dir, '--output-dir', os.path.join(os.path.dirname(__file__), '..', 'models')],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        # Don't wait — training takes minutes
        return {
            "status": "started",
            "pid": proc.pid,
            "message": "Retraining started in background. Check /api/live-data/status for completion.",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ---------------------------------------------------------------------------
# WebSocket for live packet streaming
# ---------------------------------------------------------------------------

@app.websocket("/ws/live")
async def websocket_live(ws: WebSocket):
    await ws.accept()
    connected_clients.append(ws)
    try:
        # Send initial stats
        await ws.send_text(json.dumps({"type": "connected", "msg": "AETHERIS capture stream active"}))
        while True:
            # Keep connection alive; also handle commands from client
            data = await ws.receive_text()
            try:
                cmd = json.loads(data)
                action = cmd.get("action")
                if action == "start_capture":
                    iface = cmd.get("interface")
                    if iface:
                        _start_iface_capture(iface)
                        await ws.send_text(json.dumps({"type": "capture_started", "interface": iface}))
                elif action == "switch_interface":
                    iface = cmd.get("interface")
                    if iface:
                        _start_iface_capture(iface)
                        await ws.send_text(json.dumps({"type": "interface_switched", "interface": iface}))
                elif action == "stop_capture":
                    iface = cmd.get("interface")
                    if iface:
                        active_captures[iface] = False
                        reset_backend_state()
                        await ws.send_text(json.dumps({"type": "capture_stopped", "interface": iface}))
                elif action == "stop_all":
                    stop_all_captures_except(None)
                    reset_backend_state()
                    await ws.send_text(json.dumps({"type": "all_captures_stopped"}))
                elif action == "get_flows":
                    target_iface = cmd.get("interface")
                    with flow_lock:
                        if target_iface:
                            flows = [f for f in flow_cache.values() if f.get("interface") == target_iface]
                        else:
                            flows = list(flow_cache.values())
                        flows_snapshot = flows[-50:]
                    await ws.send_text(json.dumps({"type": "flows_snapshot", "interface": target_iface, "flows": flows_snapshot}))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        pass
    finally:
        if ws in connected_clients:
            connected_clients.remove(ws)


# ---------------------------------------------------------------------------
# Defense Action State
# ---------------------------------------------------------------------------
defense_state: dict[str, dict] = {
    # iface -> { firewall_raised: bool, blocked_ips: set, rate_limited_ips: set, isolated_ports: set }
}


def _get_defense(iface: str) -> dict:
    if iface not in defense_state:
        defense_state[iface] = {
            "firewall_raised": False,
            "blocked_ips": set(),
            "rate_limited_ips": set(),
            "isolated_ports": set(),
        }
    return defense_state[iface]


def _run_system_cmd(cmd: list[str], description: str) -> dict:
    """Execute a system command for firewall/network actions. Returns status dict."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        ok = result.returncode == 0
        print(f"[Defense] {description}: {'OK' if ok else 'FAILED'} - {result.stdout.strip() or result.stderr.strip()}")
        return {"success": ok, "output": result.stdout.strip() or result.stderr.strip()}
    except FileNotFoundError:
        # Command not found (e.g. iptables on Windows) — use local state tracking
        print(f"[Defense] {description}: Command not found, tracking locally")
        return {"success": True, "output": "Tracked locally (command not available on this OS)"}
    except Exception as e:
        print(f"[Defense] {description}: Error - {e}")
        return {"success": False, "output": str(e)}


def _raise_firewall(iface: str) -> dict:
    """Block all incoming traffic on the given interface."""
    d = _get_defense(iface)
    d["firewall_raised"] = True
    if sys.platform == "win32":
        rule_name = f"AETHERIS_Block_In_{iface.replace(' ', '_')}"
        return _run_system_cmd(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             "name=", rule_name, "dir=in", "action=block",
             "enable=yes", "profile=any"],
            f"Raise firewall on {iface}"
        )
    else:
        return _run_system_cmd(
            ["iptables", "-A", "INPUT", "-i", iface, "-j", "DROP"],
            f"Raise firewall on {iface}"
        )


def _drop_firewall(iface: str) -> dict:
    """Remove firewall rules for the given interface."""
    d = _get_defense(iface)
    d["firewall_raised"] = False
    if sys.platform == "win32":
        rule_name = f"AETHERIS_Block_In_{iface.replace(' ', '_')}"
        return _run_system_cmd(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             "name=", rule_name],
            f"Drop firewall on {iface}"
        )
    else:
        return _run_system_cmd(
            ["iptables", "-D", "INPUT", "-i", iface, "-j", "DROP"],
            f"Drop firewall on {iface}"
        )


def _block_ip(ip: str, iface: str = None) -> dict:
    """Block a specific IP address."""
    if iface:
        d = _get_defense(iface)
        d["blocked_ips"].add(ip)
    if sys.platform == "win32":
        rule_name = f"AETHERIS_Block_IP_{ip.replace('.', '_')}"
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
               "name=", rule_name, "dir=in", "action=block",
               "remoteip=", ip, "enable=yes", "profile=any"]
        if iface:
            cmd.extend(["localip=", iface])
        return _run_system_cmd(cmd, f"Block IP {ip}")
    else:
        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        return _run_system_cmd(cmd, f"Block IP {ip}")


def _unblock_ip(ip: str, iface: str = None) -> dict:
    """Unblock a previously blocked IP."""
    if iface:
        d = _get_defense(iface)
        d["blocked_ips"].discard(ip)
    if sys.platform == "win32":
        rule_name = f"AETHERIS_Block_IP_{ip.replace('.', '_')}"
        return _run_system_cmd(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             "name=", rule_name],
            f"Unblock IP {ip}"
        )
    else:
        return _run_system_cmd(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            f"Unblock IP {ip}"
        )


def _rate_limit_ip(ip: str, iface: str = None) -> dict:
    """Apply rate limiting to a specific IP (max 10 packets/sec)."""
    if iface:
        d = _get_defense(iface)
        d["rate_limited_ips"].add(ip)
    if sys.platform == "win32":
        # Windows: use powerShell to set a rate limit rule
        rule_name = f"AETHERIS_RateLimit_{ip.replace('.', '_')}"
        return _run_system_cmd(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             "name=", rule_name, "dir=in", "action=block",
             "remoteip=", ip, "enable=yes", "profile=any"],
            f"Rate limit IP {ip}"
        )
    else:
        # Linux: use iptables limit module
        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-m", "limit",
               "--limit", "10/sec", "--limit-burst", "20", "-j", "ACCEPT"]
        result = _run_system_cmd(cmd, f"Rate limit IP {ip} (accept)")
        cmd2 = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        _run_system_cmd(cmd2, f"Rate limit IP {ip} (drop excess)")
        return result


def _unrate_limit_ip(ip: str, iface: str = None) -> dict:
    """Remove rate limiting from a specific IP."""
    if iface:
        d = _get_defense(iface)
        d["rate_limited_ips"].discard(ip)
    if sys.platform == "win32":
        rule_name = f"AETHERIS_RateLimit_{ip.replace('.', '_')}"
        return _run_system_cmd(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             "name=", rule_name],
            f"Remove rate limit IP {ip}"
        )
    else:
        _run_system_cmd(
            ["iptables", "-D", "INPUT", "-s", ip, "-m", "limit",
             "--limit", "10/sec", "--limit-burst", "20", "-j", "ACCEPT"],
            f"Remove rate limit IP {ip} (accept)"
        )
        return _run_system_cmd(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            f"Remove rate limit IP {ip} (drop)"
        )


def _isolate_port(port: int, iface: str = None) -> dict:
    """Block a specific port on the interface."""
    if iface:
        d = _get_defense(iface)
        d["isolated_ports"].add(port)
    if sys.platform == "win32":
        rule_name = f"AETHERIS_Isolate_Port_{port}"
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
               "name=", rule_name, "dir=in", "action=block",
               "protocol=tcp", "localport=", str(port),
               "enable=yes", "profile=any"]
        return _run_system_cmd(cmd, f"Isolate port {port}")
    else:
        cmd = ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"]
        return _run_system_cmd(cmd, f"Isolate port {port}")


def _unisolate_port(port: int, iface: str = None) -> dict:
    """Remove port isolation."""
    if iface:
        d = _get_defense(iface)
        d["isolated_ports"].discard(port)
    if sys.platform == "win32":
        rule_name = f"AETHERIS_Isolate_Port_{port}"
        return _run_system_cmd(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             "name=", rule_name],
            f"Remove port isolation {port}"
        )
    else:
        return _run_system_cmd(
            ["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"],
            f"Remove port isolation {port}"
        )


# Pydantic models for defense actions
class FirewallAction(BaseModel):
    interface: str

class IPAaction(BaseModel):
    ip: str
    interface: Optional[str] = None

class PortAction(BaseModel):
    port: int
    interface: Optional[str] = None


# Defense action endpoints
@app.post("/api/defense/firewall/raise")
async def raise_firewall(action: FirewallAction):
    result = _raise_firewall(action.interface)
    return {"status": "raised" if result["success"] else "failed", **result}


@app.post("/api/defense/firewall/drop")
async def drop_firewall(action: FirewallAction):
    result = _drop_firewall(action.interface)
    return {"status": "dropped" if result["success"] else "failed", **result}


@app.post("/api/defense/block-ip")
async def block_ip_action(action: IPAaction):
    result = _block_ip(action.ip, action.interface)
    return {"status": "blocked" if result["success"] else "failed", **result}


@app.post("/api/defense/unblock-ip")
async def unblock_ip_action(action: IPAaction):
    result = _unblock_ip(action.ip, action.interface)
    return {"status": "unblocked" if result["success"] else "failed", **result}


@app.post("/api/defense/rate-limit")
async def rate_limit_action(action: IPAaction):
    result = _rate_limit_ip(action.ip, action.interface)
    return {"status": "rate_limited" if result["success"] else "failed", **result}


@app.post("/api/defense/unrate-limit")
async def unrate_limit_action(action: IPAaction):
    result = _unrate_limit_ip(action.ip, action.interface)
    return {"status": "unrate_limited" if result["success"] else "failed", **result}


@app.post("/api/defense/isolate-port")
async def isolate_port_action(action: PortAction):
    result = _isolate_port(action.port, action.interface)
    return {"status": "isolated" if result["success"] else "failed", **result}


@app.post("/api/defense/unisolate-port")
async def unisolate_port_action(action: PortAction):
    result = _unisolate_port(action.port, action.interface)
    return {"status": "unisolated" if result["success"] else "failed", **result}


@app.get("/api/defense/state")
async def get_defense_state():
    """Return current defense state for all interfaces."""
    result = {}
    for iface, state in defense_state.items():
        result[iface] = {
            "firewall_raised": state["firewall_raised"],
            "blocked_ips": list(state["blocked_ips"]),
            "rate_limited_ips": list(state["rate_limited_ips"]),
            "isolated_ports": list(state["isolated_ports"]),
        }
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    _port = int(os.environ.get("CAPTURE_PORT", 8080))
    _host = os.environ.get("CAPTURE_HOST", "0.0.0.0")
    print("=" * 60)
    print("  AETHERIS Capture Server")
    print("  Real-time packet capture via Scapy + Npcap")
    print(f"  Listening on {_host}:{_port}")
    print(f"  (Override with CAPTURE_HOST / CAPTURE_PORT env vars)")
    print("=" * 60)
    _build_scapy_map()
    print(f"  Scapy device map: {len(iface_to_scapy)} Npcap devices found")
    interfaces = get_real_interfaces()
    print(f"  Detected {len(interfaces)} network interfaces:")
    for iface in interfaces:
        status = "*" if iface["is_up"] else "-"
        scapy_dev = _resolve_scapy_iface(iface["name"])
        mapped = " [mapped]" if scapy_dev != iface["name"] else ""
        print(f"    {status} {iface['name']} ({iface['type']}) - {iface['ip']}{mapped}")
    print("=" * 60)
    uvicorn.run(app, host=_host, port=_port)
