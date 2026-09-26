#!/usr/bin/env python3
import sys
import os
import socket
import csv
import zipfile
import statistics as stats
from collections import defaultdict

try:
    import dpkt
except ImportError:
    print("Missing dependency. Run this first:\n    pip install dpkt")
    sys.exit(1)


def ip_to_str(addr):
    try:
        return socket.inet_ntoa(addr)
    except Exception:
        try:
            return socket.inet_ntop(socket.AF_INET6, addr)
        except Exception:
            return "0.0.0.0"


def _iter_capture_streams(input_path):
    if os.path.isdir(input_path):
        names = [n for n in sorted(os.listdir(input_path))
                  if os.path.isfile(os.path.join(input_path, n)) and os.path.getsize(os.path.join(input_path, n)) > 0]
        if not names:
            raise ValueError(f"{input_path} is a folder but has no files in it.")
        print(f"[*] {input_path} contains {len(names):,} capture file(s) -- processing all of them.")
        for name in names:
            yield name, open(os.path.join(input_path, name), "rb")
    elif input_path.lower().endswith(".zip"):
        zf = zipfile.ZipFile(input_path, "r")
        names = [n for n in zf.namelist() if not n.endswith("/") and zf.getinfo(n).file_size > 0]
        if not names:
            raise ValueError(f"{input_path} is an empty zip file.")
        print(f"[*] {input_path} contains {len(names):,} capture file(s) -- processing all of them.")
        for name in names:
            yield name, zf.open(name, "r")
    else:
        yield os.path.basename(input_path), open(input_path, "rb")


def _process_one_stream(f, flows, n_read_start):
    n_read = n_read_start
    n_kept = 0
    try:
        reader = dpkt.pcap.Reader(f)
    except ValueError:
        try:
            f.seek(0)
        except Exception:
            pass
        reader = dpkt.pcapng.Reader(f)

    for ts, buf in reader:
        n_read += 1
        if n_read % 2_000_000 == 0:
            print(f"    ...{n_read:,} packets read total, {len(flows):,} flows so far")

        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
        except Exception:
            continue

        src = ip_to_str(ip.src)
        dst = ip_to_str(ip.dst)
        proto = ip.p

        sport = dport = 0
        window = None
        seq = None
        payload_len = 0
        proto_name = "OTHER"
        tcp_flags = None

        if proto == 6 and isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            sport, dport = tcp.sport, tcp.dport
            window = tcp.win
            seq = tcp.seq
            payload_len = len(tcp.data)
            proto_name = "TCP"
            tcp_flags = tcp.flags
        elif proto == 17 and isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            sport, dport = udp.sport, udp.dport
            payload_len = len(udp.data)
            proto_name = "UDP"

        key = (src, dst, sport, dport, proto_name)
        fl = flows[key]
        n_kept += 1

        fl["n_pkts"] += 1
        fl["ttls"].append(ip.ttl)
        fl["total_bytes"] += (payload_len + len(buf))

        frag_offset = ip.off & dpkt.ip.IP_OFFMASK
        more_frags = bool(ip.off & dpkt.ip.IP_MF)
        if frag_offset > 0 or more_frags:
            fl["n_frag"] += 1

        fl["payload_sizes"].append(payload_len)
        if window is not None:
            fl["wins"].append(window)
        if seq is not None and payload_len > 0:
            fl["seq_payloads"][seq].add(bytes(ip.data.data[:16]))

        if tcp_flags is not None:
            if tcp_flags & dpkt.tcp.TH_SYN:
                fl["syn_count"] += 1
            if tcp_flags & dpkt.tcp.TH_ACK:
                fl["ack_count"] += 1
            if tcp_flags & dpkt.tcp.TH_FIN:
                fl["fin_count"] += 1
            if tcp_flags & dpkt.tcp.TH_RST:
                fl["rst_count"] += 1

        if fl["first_ts"] is None:
            fl["first_ts"] = ts
        else:
            gap = ts - fl["prev_ts"]
            if gap >= 0:
                fl["iat_n"] += 1
                fl["iat_sum"] += gap
                fl["iat_sq"] += gap * gap
        fl["prev_ts"] = ts
        fl["last_ts"] = ts

    return n_read, n_kept


def extract(pcap_path, output_csv):
    flows = defaultdict(lambda: {
        "ttls": [], "wins": [], "n_pkts": 0, "n_frag": 0,
        "payload_sizes": [], "seq_payloads": defaultdict(set),
        "first_ts": None, "last_ts": None,
        "total_bytes": 0,
        "syn_count": 0, "ack_count": 0, "fin_count": 0, "rst_count": 0,
        "prev_ts": None, "iat_n": 0, "iat_sum": 0.0, "iat_sq": 0.0,
    })

    print(f"[*] Opening {pcap_path} ...")
    n_read = 0
    n_kept = 0
    n_files = 0
    n_files_failed = 0

    for name, f in _iter_capture_streams(pcap_path):
        n_files += 1
        print(f"[*] ({n_files}) Processing '{name}' ...")
        try:
            with f:
                n_read, kept = _process_one_stream(f, flows, n_read)
                n_kept += kept
        except Exception as e:
            n_files_failed += 1
            print(f"    !! Skipped '{name}' -- could not read it ({e})")
            continue

    print(f"[+] Processed {n_files:,} capture file(s) ({n_files_failed:,} skipped/unreadable).")
    print(f"[+] Finished reading {n_read:,} packets ({n_kept:,} were IP/TCP/UDP).")
    print(f"[+] Found {len(flows):,} unique flows.")
    print(f"[*] Writing features to {output_csv} ...")

    fieldnames = [
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "flow_start", "flow_end", "duration", "packet_count", "byte_count",
        "syn_count", "ack_count", "fin_count", "rst_count",
        "ttl_mean", "ttl_var", "win_mean", "win_var",
        "frag_ratio", "payload_mean", "payload_std", "retransmit_count",
        "iat_mean", "iat_std", "bwd_fwd_ratio",
    ]

    with open(output_csv, "w", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()

        for (src, dst, sport, dport, proto), fl in flows.items():
            n = fl["n_pkts"]
            ttls = fl["ttls"] or [0]
            wins = fl["wins"] or [0]
            payloads = fl["payload_sizes"] or [0]
            retrans = sum(1 for _seq, payset in fl["seq_payloads"].items() if len(payset) > 1)
            duration = (fl["last_ts"] - fl["first_ts"]) if (fl["first_ts"] is not None and fl["last_ts"] is not None) else 0.0

            # Inter-arrival-time (IAT) statistics for this flow
            iat_n = fl["iat_n"]
            if iat_n > 0:
                iat_mean = fl["iat_sum"] / iat_n
                iat_var = fl["iat_sq"] / iat_n - iat_mean * iat_mean
                iat_std = iat_var ** 0.5 if iat_var > 0 else 0.0
            else:
                iat_mean = 0.0
                iat_std = 0.0

            # Bidirectional flow ratio: reverse-direction packets / this-direction packets
            rev_fl = flows.get((dst, src, dport, sport, proto))
            rev_pkts = rev_fl["n_pkts"] if rev_fl else 0
            bwd_fwd_ratio = (rev_pkts / n) if n else 0.0

            writer.writerow({
                "src_ip": src, "dst_ip": dst,
                "src_port": sport, "dst_port": dport,
                "protocol": proto,
                "flow_start": fl["first_ts"], "flow_end": fl["last_ts"],
                "duration": round(duration, 6),
                "packet_count": n,
                "byte_count": fl["total_bytes"],
                "syn_count": fl["syn_count"], "ack_count": fl["ack_count"],
                "fin_count": fl["fin_count"], "rst_count": fl["rst_count"],
                "ttl_mean": round(stats.mean(ttls), 3),
                "ttl_var": round(stats.pvariance(ttls), 3) if len(ttls) > 1 else 0.0,
                "win_mean": round(stats.mean(wins), 3) if wins else 0.0,
                "win_var": round(stats.pvariance(wins), 3) if len(wins) > 1 else 0.0,
                "frag_ratio": round(fl["n_frag"] / n, 4) if n else 0.0,
                "payload_mean": round(stats.mean(payloads), 3),
                "payload_std": round(stats.pstdev(payloads), 3) if len(payloads) > 1 else 0.0,
                "retransmit_count": retrans,
                "iat_mean": round(iat_mean, 6),
                "iat_std": round(iat_std, 6),
                "bwd_fwd_ratio": round(bwd_fwd_ratio, 4),
            })

    print(f"[+] Wrote {len(flows):,} rows to {output_csv}")
    print("[+] DONE. This CSV has BOTH packet-level and flow-level features.")
    print("[+] You do NOT need to send the raw .pcap or logs.zip -- only this CSV.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print('Usage: python extract_packet_features_v2.py "<path_to_pcap>" "<output_csv_path>"')
        sys.exit(1)
    extract(sys.argv[1], sys.argv[2])
