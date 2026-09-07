"""
WSL Native Packet Sniffer for CyberForecaster.
Runs inside WSL environment using Python + Scapy.
Streams raw flow packet events over stdout as JSON lines.
"""

import sys
import os
import json
import time
import subprocess
from datetime import datetime, timezone

def get_wsl_default_iface() -> str:
    """Auto-detect active WSL interface with default route."""
    try:
        res = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        parts = res.stdout.strip().split()
        if "dev" in parts:
            idx = parts.index("dev")
            return parts[idx + 1]
    except Exception:
        pass
    return "eth0"

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] else get_wsl_default_iface()

    try:
        from scapy.all import sniff
        from scapy.layers.inet import IP, TCP, UDP, ICMP
    except ImportError as e:
        print(json.dumps({"error": f"Scapy not installed in WSL: {e}"}), flush=True)
        sys.exit(1)

    def process_packet(pkt):
        try:
            if not pkt.haslayer(IP):
                return
            ip = pkt[IP]
            proto_name = "Other"
            sport = 0
            dport = 0
            syn = ack = rst = fin = 0

            if pkt.haslayer(TCP):
                proto_name = "TCP"
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
                flags = pkt[TCP].flags
                syn = 1 if flags.S else 0
                ack = 1 if flags.A else 0
                rst = 1 if flags.R else 0
                fin = 1 if flags.F else 0
            elif pkt.haslayer(UDP):
                proto_name = "UDP"
                sport = int(pkt[UDP].sport)
                dport = int(pkt[UDP].dport)
            elif pkt.haslayer(ICMP):
                proto_name = "ICMP"

            pkt_len = len(pkt)
            now = datetime.now(timezone.utc).isoformat()

            event = {
                "id": f"{now}-{ip.src}-{ip.dst}-{sport}-{dport}",
                "timestamp": now,
                "src_ip": str(ip.src),
                "dst_ip": str(ip.dst),
                "src_port": sport,
                "dst_port": dport,
                "protocol": proto_name,
                "length": pkt_len,
                "syn": syn,
                "ack": ack,
                "rst": rst,
                "fin": fin,
                "ttl": int(ip.ttl),
                "severity": "none",
                "attack_type": "Benign",
            }
            print(json.dumps(event), flush=True)
        except Exception:
            pass

    try:
        sniff(iface=iface, prn=process_packet, store=False)
    except Exception as e:
        print(json.dumps({"error": f"WSL Sniff error on interface {iface}: {e}"}), flush=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
