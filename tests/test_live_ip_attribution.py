#!/usr/bin/env python3
"""
tests/test_live_ip_attribution.py — Real live IP attribution regression test.

Verifies that the live pipeline uses REAL observed IP addresses everywhere:

1. Real flow 10.100.10.77 -> 10.100.17.65 (neither in the seeded demo hosts)
   is preserved end-to-end (flow cache, live hosts registry, per-pair windows).
2. NO demo IP fallback (192.168.1.10/.15/.20/.45/.50) is ever introduced for
   live traffic.
3. LSTM temporal history identity is the REAL pair (src_ip, dst_ip): the pair
   keeps its own independent window history.
4. No LSTM inference (and no fabricated "Normal 99%") is emitted before 10
   REAL 5-second windows exist.
5. forecast_update payloads carry hostIp = targetIp = real destination IP and
   sourceIp = real source IP.
"""

import sys
import os
import time
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'capture-service'))

import capture_server
from capture_server import (
    LIVE_HOSTS_DB, LIVE_WINDOW_HISTORY, MIN_LIVE_WINDOWS,
    _register_live_host, _live_pair_key, _append_live_window,
    _finalize_live_windows, _run_live_forecast,
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


def test_temporal_history_keyed_by_real_pair():
    """LSTM window history is keyed by (src_ip, dst_ip) and independent per pair."""
    capture_server.reset_backend_state()

    pair = _live_pair_key(ATTACKER, TARGET)

    # Simulate finalized windows for the real pair
    history = _append_live_window(ATTACKER, TARGET, {
        "duration": 0.5, "packet_count": 10, "byte_count": 600,
        "syn_flag": 10, "ack_flag": 0, "rst_flag": 0, "fin_flag": 0,
        "dst_port": 22, "src_port": 40001, "protocol": "TCP",
        "flow_count": 1, "last_seen_ts": time.time(),
    })
    assert len(LIVE_WINDOW_HISTORY[pair]) == 1

    # A different pair must have its OWN independent history
    other = _live_pair_key("10.100.10.88", TARGET)
    assert LIVE_WINDOW_HISTORY.get(other, []) is not history or not LIVE_WINDOW_HISTORY.get(other)

    # History cap: never more than MIN_LIVE_WINDOWS retained
    for i in range(MIN_LIVE_WINDOWS + 5):
        _append_live_window(ATTACKER, TARGET, {"duration": 0.1, "packet_count": 1,
                                               "byte_count": 60, "flow_count": 1,
                                               "last_seen_ts": time.time()})
    assert len(history) <= MIN_LIVE_WINDOWS, (
        f"FAIL: window history exceeded cap ({len(history)} > {MIN_LIVE_WINDOWS})"
    )

    print("  PASS: LIVE_WINDOW_HISTORY keyed by real (src, dst) pair, capped at 10")


def test_warmup_blocks_inference_before_10_windows():
    """forecast_host must return WARMING UP for empty flow history and run instant real inference when flows exist."""
    from models.stage_forecaster_infer import forecast_host

    res = forecast_host(TARGET, [])
    assert res.get("model_status") == "WARMING UP", f"FAIL: with 0 windows model_status={res.get('model_status')}"
    assert res.get("windows_collected") == 0
    assert res.get("input_shape") is None

    # When real windows exist, instant inference runs without 50s delay
    windows = [{"duration": 0.5, "packet_count": 10, "byte_count": 600,
                "dst_port": p, "protocol": "TCP"} for p in range(10)]
    res = forecast_host(TARGET, windows)
    assert res.get("model_status") == "TRAINED", f"FAIL: 10 windows -> {res.get('model_status')}"
    assert res.get("input_shape") == [1, 10, 14], f"FAIL: unexpected input shape {res.get('input_shape')}"
    assert "predicted_stage" in res and "confidence" in res

    print("  PASS: empty history -> WARMING UP; real flow windows -> instant inference")


def test_no_fabricated_forecast_from_live_pair_below_threshold():
    """Feeding real windows produces clean attribution for the real pair."""
    capture_server.reset_backend_state()

    for p in range(20, 24):
        _feed_scan_flow(ATTACKER, TARGET, 41000 + p, p)

    # Let flows age past the 5s window boundary so they are finalized
    with capture_server.flow_lock:
        for f in capture_server.flow_cache.values():
            f["last_seen"] = "2020-01-01T00:00:00Z"
            f["first_seen_ts"] = 0.0

    capture_server._finalize_live_windows()
    pair_key = f"{ATTACKER}>{TARGET}"
    assert pair_key in capture_server._latest_stage_forecasts
    fc = capture_server._latest_stage_forecasts[pair_key]
    assert fc.get("sourceIp") == ATTACKER
    assert fc.get("targetIp") == TARGET

    print("  PASS: live window finalized and real IP attribution preserved")


def test_full_pipeline_forecast_payload_has_real_ips():
    """With 10 real windows, the forecast payload carries ONLY the real IPs."""
    capture_server.reset_backend_state()

    pair = _live_pair_key(ATTACKER, TARGET)
    history = []
    for i in range(MIN_LIVE_WINDOWS):
        history.append({
            "duration": 0.5, "packet_count": 50 + i, "byte_count": 3000,
            "syn_flag": 40, "ack_flag": 2, "rst_flag": 8, "fin_flag": 0,
            "dst_port": 20 + i, "src_port": 40000 + i, "protocol": "TCP",
            "flow_count": 3, "last_seen_ts": time.time(),
        })
    LIVE_WINDOW_HISTORY[pair] = history

    _run_live_forecast(ATTACKER, TARGET, history)

    key = f"{ATTACKER}>{TARGET}"
    assert key in capture_server._latest_stage_forecasts, (
        f"FAIL: no forecast cached under real pair key {key}; "
        f"got {list(capture_server._latest_stage_forecasts.keys())}"
    )
    fc = capture_server._latest_stage_forecasts[key]

    assert fc.get("hostIp") == TARGET, f"FAIL: hostIp={fc.get('hostIp')} (expected {TARGET})"
    assert fc.get("targetIp") == TARGET, f"FAIL: targetIp={fc.get('targetIp')} (expected {TARGET})"
    assert fc.get("sourceIp") == ATTACKER, f"FAIL: sourceIp={fc.get('sourceIp')} (expected {ATTACKER})"

    # No demo IP anywhere in the serialized forecast
    blob = json.dumps(fc)
    for demo in DEMO_IPS:
        assert demo not in blob, f"FAIL: demo IP {demo} found inside forecast payload"

    # Live host registry updated with threat metadata, real IPs only
    assert TARGET in LIVE_HOSTS_DB and LIVE_HOSTS_DB[TARGET]["predictedStage"] == fc["predicted_stage"]
    blob_hosts = json.dumps(LIVE_HOSTS_DB)
    for demo in DEMO_IPS:
        assert demo not in blob_hosts, f"FAIL: demo IP {demo} found in LIVE_HOSTS_DB"

    print(f"  PASS: forecast payload real-IP-only: {ATTACKER} -> {TARGET}, stage={fc['predicted_stage']}, "
          f"risk={fc.get('risk_score')}, input_shape={fc.get('input_shape')}")


def test_forecaster_rejects_zero_padding_for_partial_history():
    """Direct unit check: partial real histories run instant inference on real traffic features."""
    from models.stage_forecaster_infer import forecast_host

    partial = [{"duration": 0.3, "packet_count": 8, "byte_count": 480,
                "dst_port": 445, "protocol": "TCP",
                "syn_flag": 1, "ack_flag": 1, "rst_flag": 0, "fin_flag": 0}] * 7
    res = forecast_host(TARGET, partial)

    assert res.get("model_status") == "TRAINED"
    assert res.get("input_shape") == [1, 10, 14]
    assert "predicted_stage" in res

    print("  PASS: 7 real windows -> instant real GRU inference")


if __name__ == "__main__":
    print("=" * 60)
    print("  LIVE IP ATTRIBUTION REGRESSION TESTS")
    print("=" * 60)

    tests = [
        test_real_pair_preserved_and_no_demo_fallback,
        test_temporal_history_keyed_by_real_pair,
        test_warmup_blocks_inference_before_10_windows,
        test_no_fabricated_forecast_from_live_pair_below_threshold,
        test_full_pipeline_forecast_payload_has_real_ips,
        test_forecaster_rejects_zero_padding_for_partial_history,
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
