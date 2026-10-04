#!/usr/bin/env python3
"""
tests/test_live_ip_attribution.py — Real live IP attribution regression test.

Verifies that the live pipeline uses REAL observed IP addresses everywhere:
1. Real flow 10.100.10.77 -> 10.100.17.65 (neither in seeded demo hosts)
   is preserved end-to-end (flow cache, live hosts registry).
2. NO demo IP fallback (192.168.1.10/.15/.20/.45/.50) is ever introduced for
   live traffic.
3. World model forecast updates carry hostIp = targetIp = real destination IP,
   sourceIp = real source IP, and model = 'world_model_v4'.
"""

import sys
import os
import time
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'capture-service'))

import capture_server
from capture_server import (
    LIVE_HOSTS_DB, _register_live_host, _live_pair_key,
    _broadcast_world_model_forecasts,
)

DEMO_IPS = {"192.168.1.10", "192.168.1.15", "192.168.1.20", "192.168.1.45", "192.168.1.50"}
ATTACKER = "10.100.10.77"
TARGET = "10.100.17.65"


def _feed_scan_flow(src_ip, dst_ip, sport, dport, iface="WiFi"):
    """Feed one SYN packet event through the real pipeline."""
    event = {
        "id": f"live-{src_ip}-{sport}-{dst_ip}-{dport}-{time.time_ns()}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": sport, "dst_port": dport,
        "protocol": "TCP", "length": 60,
        "syn": 1, "ack": 0, "rst": 0, "fin": 0,
        "ttl": 64, "severity": "none", "attack_type": "Benign",
    }
    capture_server._process_flow_event(event, iface)
    return event


def test_real_pair_preserved_and_no_demo_fallback():
    """Real attacker -> target pair is preserved; no demo IP substitution anywhere."""
    capture_server.reset_backend_state()

    # Feed real scan traffic: 10.100.10.77 -> 10.100.17.65 (neither is a demo host)
    for p in range(20, 30):
        _feed_scan_flow(ATTACKER, TARGET, 40000 + p, p)

    # Flows in cache keep real IPs
    with capture_server.flow_lock:
        flows = list(capture_server.flow_cache.values())
    assert flows, "FAIL: no flows cached from real traffic"
    for f in flows:
        assert f["src_ip"] == ATTACKER, f"FAIL: src_ip corrupted: {f['src_ip']}"
        assert f["dst_ip"] == TARGET, f"FAIL: dst_ip corrupted: {f['dst_ip']}"

    # Live hosts registry contains the real IPs with correct roles
    assert ATTACKER in LIVE_HOSTS_DB, f"FAIL: real source {ATTACKER} not registered in LIVE_HOSTS_DB"
    assert TARGET in LIVE_HOSTS_DB, f"FAIL: real target {TARGET} not registered in LIVE_HOSTS_DB"
    assert LIVE_HOSTS_DB[ATTACKER]["ip"] == ATTACKER
    assert LIVE_HOSTS_DB[TARGET]["ip"] == TARGET
    assert LIVE_HOSTS_DB[ATTACKER].get("firstSeen") and LIVE_HOSTS_DB[ATTACKER].get("lastSeen")

    # NO demo host may be registered by live traffic
    for demo in DEMO_IPS:
        assert demo not in LIVE_HOSTS_DB, (
            f"FAIL: demo IP {demo} leaked into LIVE_HOSTS_DB from live capture"
        )

    # Flow cache must contain no demo IPs either
    with capture_server.flow_lock:
        for f in capture_server.flow_cache.values():
            assert f["src_ip"] not in DEMO_IPS and f["dst_ip"] not in DEMO_IPS, (
                f"FAIL: demo IP substitution in live flow cache: {f['src_ip']} -> {f['dst_ip']}"
            )

    print("  PASS: real pair 10.100.10.77 -> 10.100.17.65 preserved; zero demo-IP fallback")


def test_world_model_forecast_broadcast_has_real_ips():
    """World model broadcast produces forecast payloads with ONLY real IPs and correct model mapping."""
    capture_server.reset_backend_state()

    # Feed flows to register pair
    for p in range(20, 25):
        _feed_scan_flow(ATTACKER, TARGET, 40000 + p, p)

    # Mock world model result for ATTACKER
    mock_res = {
        "chart": {
            "threshold": 0.694,
            "classes": ["normal", "reconnaissance", "initial_access", "command_control", "lateral_movement", "exfiltration", "other"],
            "hosts": {
                ATTACKER: {
                    "risk_60s": [0.1, 0.2, 0.85],
                    "alert": [False, False, True],
                    "stage_now": ["normal", "normal", "reconnaissance"],
                    "likely_attack_stage": ["reconnaissance", "reconnaissance", "reconnaissance"],
                    "likely_attack_stage_prob": [0.7, 0.75, 0.92],
                    "stage_dist_last": [0.05, 0.92, 0.01, 0.01, 0.0, 0.01, 0.0],
                }
            }
        }
    }

    _broadcast_world_model_forecasts(mock_res)

    key = f"{ATTACKER}>{TARGET}"
    assert key in capture_server._latest_stage_forecasts, (
        f"FAIL: no forecast cached under real pair key {key}"
    )
    fc = capture_server._latest_stage_forecasts[key]

    assert fc.get("hostIp") == TARGET, f"FAIL: hostIp={fc.get('hostIp')}"
    assert fc.get("targetIp") == TARGET, f"FAIL: targetIp={fc.get('targetIp')}"
    assert fc.get("sourceIp") == ATTACKER, f"FAIL: sourceIp={fc.get('sourceIp')}"
    assert fc.get("model") == "world_model_v4"
    assert fc.get("alert_threshold") == 0.694
    assert fc.get("risk_score") == 0.85
    assert fc.get("predicted_stage") == "reconnaissance"
    assert fc.get("confidence") == 0.92
    assert fc.get("windows_collected") == 3
    assert fc.get("recent_risk_history") == [0.1, 0.2, 0.85]

    # No demo IP anywhere in the serialized forecast
    blob = json.dumps(fc)
    for demo in DEMO_IPS:
        assert demo not in blob, f"FAIL: demo IP {demo} found inside forecast payload"

    print("  PASS: world model broadcast carries real IPs and correct payload fields")


if __name__ == "__main__":
    print("=" * 60)
    print("  LIVE IP ATTRIBUTION REGRESSION TESTS")
    print("=" * 60)

    tests = [
        test_real_pair_preserved_and_no_demo_fallback,
        test_world_model_forecast_broadcast_has_real_ips,
    ]

    passed = 0
    failed = 0
    for t in tests:
        print(f"\n[*] {t.__name__}")
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"  FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR: {e}")
            failed += 1

    print(f"\n{'=' * 60}")
    print(f"  Results: {passed} passed, {failed} failed")
    print(f"{'=' * 60}")
    sys.exit(1 if failed else 0)
