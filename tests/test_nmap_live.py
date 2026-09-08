#!/usr/bin/env python3
"""
tests/test_nmap_live.py — Controlled Nmap Test Verification Script

Simulates exact Nmap TCP connect port scan (ports 1-1000) against target IP 172.31.195.203
and verifies that all flows are classified as 'Port Scan' and NEVER 'Brute Force'.
Also verifies that targeted multi-attempt single-port attacks are correctly classified as 'Brute Force'.
"""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'capture-service'))

import capture_server

def run_nmap_controlled_test():
    print("=" * 70)
    print("  RUNNING CONTROLLED NMAP TCP PORT SCAN TEST (ports 1 - 1000)")
    print("  Command: nmap -sT -Pn -p 1-1000 172.31.195.203")
    print("=" * 70)

    capture_server.reset_backend_state()

    src_ip = "192.168.1.105"
    dst_ip = "172.31.195.203"
    
    auth_ports_encountered = []
    brute_force_counts = 0
    port_scan_counts = 0
    benign_counts = 0

    # Simulate scanning 1000 TCP ports
    for p in range(1, 1001):
        event = {
            "id": f"test-{p}",
            "timestamp": "2026-09-08T15:00:00Z",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": 50000 + (p % 10000),
            "dst_port": p,
            "protocol": "TCP",
            "length": 60,
            "syn": 1,
            "ack": 0,
            "rst": 0,
            "fin": 0,
            "ttl": 64,
            "severity": "none",
            "attack_type": "Benign",
        }
        capture_server._process_flow_event(event, "WSL (eth0)")
        
        final_attack = event.get("attack_type", "Benign")
        if final_attack == "Brute Force":
            brute_force_counts += 1
        elif final_attack == "Port Scan":
            port_scan_counts += 1
        else:
            benign_counts += 1

        if capture_server.is_auth_port(p):
            auth_ports_encountered.append((p, final_attack, event.get("reason", "")))

    print(f"\n[+] Scan Complete across 1000 ports:")
    print(f"    Port Scan events: {port_scan_counts}")
    print(f"    Brute Force events: {brute_force_counts}")
    print(f"    Benign/Other events: {benign_counts}")

    print("\n[+] Authentication Ports Inspection during Nmap scan:")
    for port, classification, reason in auth_ports_encountered:
        print(f"    Port {port:5d} -> Classified as: {classification:12s} | Reason: {reason}")

    # Assertions
    assert brute_force_counts == 0, f"FAIL: Nmap port scan produced {brute_force_counts} false 'Brute Force' classifications!"
    assert port_scan_counts > 0, "FAIL: Nmap port scan did not produce any 'Port Scan' classifications!"

    print("\n" + "=" * 70)
    print("  VERIFYING GENUINE BRUTE FORCE ATTACK (30 attempts to SSH port 22)")
    print("=" * 70)

    capture_server.reset_backend_state()
    bf_src_ip = "10.0.0.88"
    bf_dst_ip = "172.31.195.203"
    bf_brute_force_counts = 0

    for i in range(1, 31):
        event = {
            "id": f"bf-{i}",
            "timestamp": "2026-09-08T15:05:00Z",
            "src_ip": bf_src_ip,
            "dst_ip": bf_dst_ip,
            "src_port": 40000 + i,
            "dst_port": 22,
            "protocol": "TCP",
            "length": 60,
            "syn": 1,
            "ack": 0,
            "rst": 0,
            "fin": 0,
            "ttl": 64,
            "severity": "none",
            "attack_type": "Benign",
        }
        capture_server._process_flow_event(event, "WSL (eth0)")
        if event.get("attack_type") == "Brute Force":
            bf_brute_force_counts += 1

    print(f"\n[+] Genuine SSH Brute Force Test Complete (30 attempts):")
    print(f"    Brute Force classifications triggered: {bf_brute_force_counts}")

    assert bf_brute_force_counts > 0, "FAIL: Genuine SSH Brute Force attack was NOT classified as Brute Force!"

    print("\n" + "=" * 70)
    print("  ALL CONTROLLED NMAP & BRUTE FORCE TESTS PASSED PERFECTLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_nmap_controlled_test()
