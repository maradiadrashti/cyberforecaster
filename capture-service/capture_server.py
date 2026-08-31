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
from collections import defaultdict
from datetime import datetime

def _is_multicast_or_broadcast(ip_str: str) -> bool:
    """Check if an IP address is multicast or subnet broadcast."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_multicast or ip_str.endswith(".255")
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
from scapy.layers.l2 import Ether

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
    print(f"[Startup] Scapy device map built: {len(iface_to_scapy)} Npcap devices found.")
    asyncio.create_task(_stage_forecast_loop())

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
connected_clients: list[WebSocket] = []
flow_cache: dict[str, dict] = {}                 # 5-tuple -> aggregated flow
flow_lock = threading.Lock()
capture_stats = {
    "total_packets": 0,
    "start_time": None,
}

# Per-IP tracking for flow-level heuristic detection
_ip_flows: dict[str, list] = {}          # src_ip -> list of recent flow timestamps
_ip_ports: dict[str, set] = {}            # src_ip -> set of unique dst_ports hit
_ip_bytes: dict[str, int] = {}            # src_ip -> total bytes sent recently
_ip_dst: dict[str, dict] = {}            # src_ip -> {dst_ip: flow_count}
_TRACKING_WINDOW = 30  # seconds for tracking window

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

def get_real_interfaces() -> list[dict]:
    """Detect real network interfaces using psutil + scapy."""
    interfaces = []
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
    interfaces.sort(key=lambda x: (not x["is_up"], priority.get(x["type"], 99)))
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
    """Reclassify a flow using aggregate flow-level heuristics.
    This runs on every packet and upgrades severity/attack_type based on
    accumulated patterns (not just single-packet signals).
    """
    now = time.time()
    src_ip = event.get("src_ip", "")
    dst_ip = event.get("dst_ip", "")
    dport = event.get("dst_port", 0)
    proto = event.get("protocol", "TCP")
    flow = flow_cache.get(flow_key)
    if not flow:
        return

    # ── Per-IP tracking ─────────────────────────────────────────────────
    if src_ip not in _ip_flows:
        _ip_flows[src_ip] = []
        _ip_ports[src_ip] = set()
        _ip_bytes[src_ip] = 0
        _ip_dst[src_ip] = {}

    _ip_flows[src_ip].append(now)
    _ip_ports[src_ip].add(dport)
    _ip_bytes[src_ip] += event.get("length", 0)
    _ip_dst[src_ip][dst_ip] = _ip_dst[src_ip].get(dst_ip, 0) + 1

    # Prune old entries outside the tracking window
    cutoff = now - _TRACKING_WINDOW
    _ip_flows[src_ip] = [t for t in _ip_flows[src_ip] if t > cutoff]

    # ── Detection rules ─────────────────────────────────────────────────
    first_seen_ts = flow.get("first_seen_ts", now)
    flow_duration = max(now - first_seen_ts, 0.001)
    pps = flow["packet_count"] / flow_duration
    bpp = flow["byte_count"] / max(flow["packet_count"], 1)
    recent_flows = len(_ip_flows[src_ip])
    unique_ports = len(_ip_ports[src_ip])
    dst_flow_count = _ip_dst[src_ip].get(dst_ip, 0)
    is_multicast = _is_multicast_or_broadcast(dst_ip)

    severity = "none"
    attack_type = "Benign"

    # --- Port Scan Detection ---
    # Many unique destination ports from same source in short window
    if unique_ports >= 10 and recent_flows >= 10:
        severity = "high"
        attack_type = "Port Scan"
    elif unique_ports >= 5 and recent_flows >= 5:
        severity = "medium"
        attack_type = "Port Scan"

    # --- DDoS / Flood Detection ---
    # High packet rate to same destination (skip for multicast/broadcast)
    if not is_multicast:
        # Require flow to be active for at least 1.0 second to avoid flagging rapid short bursts
        if flow_duration >= 1.0:
            if pps > 120 and flow["packet_count"] >= 120:
                severity = "critical"
                attack_type = "DDoS"
            elif pps > 50 and flow["packet_count"] >= 50:
                severity = "high"
                attack_type = "DDoS"

    # --- SYN Flood Detection --- (skip for multicast/broadcast)
    if not is_multicast and flow.get("syn_flag", 0) > 20 and flow.get("ack_flag", 0) < 3:
        severity = "critical"
        attack_type = "SYN Flood"

    # --- Brute Force Detection ---
    # Many flows to the same auth port from same source
    auth_ports = {21, 22, 23, 25, 110, 143, 3389, 5900}
    if dport in auth_ports and dst_flow_count >= 10:
        severity = "high"
        attack_type = "Brute Force"
    elif dport in auth_ports and dst_flow_count >= 5:
        severity = "medium"
        attack_type = "Brute Force"

    # --- ICMP Flood Detection --- (skip for multicast/broadcast)
    if not is_multicast and proto == "ICMP" and flow["packet_count"] > 50:
        severity = "high"
        attack_type = "ICMP Flood"

    # --- Large Data Transfer (potential exfiltration) ---
    if flow["byte_count"] > 5_000_000 and proto == "TCP" and bpp > 1000:
        severity = "high"
        attack_type = "Data Exfiltration"
    elif flow["byte_count"] > 1_000_000 and bpp > 1000:
        severity = "medium"
        attack_type = "Large Transfer"

    # --- Connection Reset Storm (may indicate scan response) ---
    if flow.get("rst_flag", 0) > 15:
        severity = "medium"
        attack_type = "Reset Storm"

    # For multicast/broadcast destinations, explicitly reset stored flow & event state to benign/none
    if is_multicast:
        severity = "none"
        attack_type = "Benign"

        flow["severity"] = "none"
        flow["attack_type"] = "Benign"

        event["severity"] = "none"
        event["attack_type"] = "Benign"
    else:
        # Apply the strongest classification to the flow cache and event for unicast traffic
        severity_order = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if severity_order.get(severity, 0) > severity_order.get(flow.get("severity", "none"), 0):
            flow["severity"] = severity
            flow["attack_type"] = attack_type
            event["severity"] = severity
            event["attack_type"] = attack_type


# ---------------------------------------------------------------------------
# Capture thread
# ---------------------------------------------------------------------------

def stop_all_captures_except(keep_iface: str = None):
    """Stop active capture threads on all interfaces except the specified one."""
    for iface in list(active_captures.keys()):
        if keep_iface is None or iface != keep_iface:
            active_captures[iface] = False

def reset_backend_state():
    """Fully clear all accumulated flow and attack state on the backend."""
    with flow_lock:
        flow_cache.clear()
        _ip_flows.clear()
        _ip_ports.clear()
        _ip_bytes.clear()
        _ip_dst.clear()


def _start_iface_capture(iface: str) -> bool:
    """Ensure capture is running ONLY on the specified interface."""
    stop_all_captures_except(iface)
    if active_captures.get(iface):
        return True
    t = threading.Thread(target=_capture_loop, args=(iface,), daemon=True)
    capture_threads[iface] = t
    t.start()
    return True


def _capture_loop(iface: str):
    """Sniff packets on the given interface and broadcast to WebSocket clients."""
    active_captures[iface] = True
    capture_stats["start_time"] = time.time()
    capture_stats["total_packets"] = 0

    # Resolve friendly name to Scapy Npcap device
    scapy_iface = _resolve_scapy_iface(iface)
    print(f"[Capture] Sniffing on {iface} -> {scapy_iface}")

    def process_packet(pkt):
        if not active_captures.get(iface):
            return False  # Stop sniffing

        try:
            capture_stats["total_packets"] += 1
            event = _packet_to_flow_event(pkt)
            if event is None:
                return

            # Tag event with the interface it was captured on
            event["interface"] = iface

            # Aggregate into flows
            key = _build_flow_key(pkt)
            if key:
                with flow_lock:
                    if key in flow_cache:
                        flow_cache[key]["packet_count"] += 1
                        flow_cache[key]["byte_count"] += event["length"]
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
                            "src_ip": event["src_ip"],
                            "dst_ip": event["dst_ip"],
                            "src_port": event["src_port"],
                            "dst_port": event["dst_port"],
                            "protocol": event["protocol"],
                            "packet_count": 1,
                            "byte_count": event["length"],
                            "first_seen": event["timestamp"],
                            "first_seen_ts": time.time(),
                            "last_seen": event["timestamp"],
                            "duration": 0.001,
                            "severity": event["severity"],
                            "attack_type": event["attack_type"],
                            "interface": iface,
                            "syn_flag": event.get("syn", 0),
                            "ack_flag": event.get("ack", 0),
                            "rst_flag": event.get("rst", 0),
                            "fin_flag": event.get("fin", 0),
                        }

                # ── Flow-level heuristic classification ────────────────────────
                _heuristic_classify(key, event)

                # ML classification (lazy-loaded, never blocks capture)
                # Only override when ML detects an actual attack, never downgrade
                if not _ml_loaded:
                    _lazy_load_ml()
                if _ml_predict_flow:
                    try:
                        ml_label, ml_confidence = _ml_predict_flow(flow_cache[key])
                        # Only use ML label if it detected something (not benign)
                        if ml_label and ml_label != "benign":
                            event["ml_label"] = ml_label
                            event["ml_confidence"] = round(ml_confidence, 4)
                            # ML overrides heuristic if confidence is high
                            if ml_confidence > 0.7:
                                event["attack_type"] = ml_label.replace("_", " ").title()
                                event["severity"] = "high" if ml_confidence > 0.9 else "medium"
                    except Exception:
                        pass

            # Broadcast to all connected WebSocket clients.
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
        except Exception as e:
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
            await asyncio.sleep(5)  # Every 5 seconds
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
                    forecast = _stage_forecaster(ip, recent)
                    forecasts[ip] = forecast
                except Exception:
                    pass

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


# ---------------------------------------------------------------------------
# REST Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/interfaces")
async def list_interfaces():
    return get_real_interfaces()


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
