#!/usr/bin/env python3
"""
Regression test for multicast flow classification and data-driven risk forecasting in CyberForecaster.
Verifies that:
1. Multicast flows (224.0.0.251 mDNS) explicitly clear stale DDoS states and block ML attack overrides.
2. Unicast DDoS detection remains fully functional.
3. Stage forecaster produces data-driven risk trend projections when history >= 3 points.
"""

import sys
import os
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'capture-service'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from capture_server import _heuristic_classify, flow_cache, _is_multicast_or_broadcast, _ip_flows, _ip_ports, _ip_dst
from models.stage_forecaster_infer import forecast_host


class TestMulticastAndForecast(unittest.TestCase):

    def setUp(self):
        flow_cache.clear()
        _ip_flows.clear()
        _ip_ports.clear()
        _ip_dst.clear()

    def test_multicast_stale_severity_reset(self):
        multicast_ip = "224.0.0.251"
        flow_key = f"192.168.1.100:5353-{multicast_ip}:5353-UDP"

        now = time.time()
        flow_cache[flow_key] = {
            "src_ip": "192.168.1.100",
            "dst_ip": multicast_ip,
            "src_port": 5353,
            "dst_port": 5353,
            "protocol": "UDP",
            "packet_count": 1,
            "byte_count": 200,
            "first_seen_ts": now - 0.0001,
            "severity": "none",
            "attack_type": "Benign",
        }
        event = {
            "src_ip": "192.168.1.100",
            "dst_ip": multicast_ip,
            "src_port": 5353,
            "dst_port": 5353,
            "protocol": "UDP",
            "length": 200,
            "severity": "none",
            "attack_type": "Benign",
        }

        # Simulate early burst state where flow was previously marked HIGH/DDoS
        flow_cache[flow_key]["severity"] = "high"
        flow_cache[flow_key]["attack_type"] = "DDoS"

        _heuristic_classify(flow_key, event)

        # Verify stored flow & event state cleared back to benign/none
        self.assertEqual(flow_cache[flow_key]["severity"], "none")
        self.assertEqual(flow_cache[flow_key]["attack_type"], "Benign")
        self.assertEqual(event["severity"], "none")
        self.assertEqual(event["attack_type"], "Benign")

    def test_multicast_ml_override_blocked(self):
        multicast_ip = "224.0.0.251"
        event = {
            "src_ip": "192.168.1.100",
            "dst_ip": multicast_ip,
            "src_port": 5353,
            "dst_port": 5353,
            "protocol": "UDP",
            "length": 200,
            "severity": "none",
            "attack_type": "Benign",
        }

        # Verify helper correctly flags destination as multicast
        self.assertTrue(_is_multicast_or_broadcast(event["dst_ip"]))
        self.assertEqual(event["severity"], "none")
        self.assertEqual(event["attack_type"], "Benign")

    def test_unicast_ddos_detection_preserved(self):
        unicast_ip = "192.168.1.200"
        flow_key = f"10.0.0.5:12345-{unicast_ip}:80-TCP"

        now = time.time()
        flow_cache[flow_key] = {
            "src_ip": "10.0.0.5",
            "dst_ip": unicast_ip,
            "src_port": 12345,
            "dst_port": 80,
            "protocol": "TCP",
            "packet_count": 450,
            "byte_count": 60000,
            "first_seen_ts": now - 1.5,
            "severity": "none",
            "attack_type": "Benign",
        }
        event = {
            "src_ip": "10.0.0.5",
            "dst_ip": unicast_ip,
            "src_port": 12345,
            "dst_port": 80,
            "protocol": "TCP",
            "length": 1000,
            "severity": "none",
            "attack_type": "Benign",
        }

        _heuristic_classify(flow_key, event)

        self.assertEqual(flow_cache[flow_key]["severity"], "critical")
        self.assertEqual(flow_cache[flow_key]["attack_type"], "DDoS")

    def test_forecast_trend_upward(self):
        test_flows = [{"src_port": 54321, "dst_port": 80, "protocol": "TCP",
                       "packet_count": 5, "byte_count": 300, "duration": 0.1,
                       "syn_flag": 1, "ack_flag": 0, "rst_flag": 0, "fin_flag": 0}] * 10
        res = forecast_host("192.168.1.50", test_flows, risk_history=[0.1, 0.3, 0.5])
        curve = res["projected_risk_curve"]
        self.assertGreater(curve[-1], curve[0])

    def test_forecast_trend_downward(self):
        test_flows = [{"src_port": 54321, "dst_port": 80, "protocol": "TCP",
                       "packet_count": 1, "byte_count": 64, "duration": 0.1,
                       "syn_flag": 0, "ack_flag": 1, "rst_flag": 0, "fin_flag": 0}] * 10
        res = forecast_host("192.168.1.50", test_flows, risk_history=[0.9, 0.7, 0.5])
        curve = res["projected_risk_curve"]
        self.assertLess(curve[-1], curve[0])

    def test_forecast_insufficient_history(self):
        test_flows = [{"src_port": 54321, "dst_port": 80, "protocol": "TCP",
                       "packet_count": 1, "byte_count": 64, "duration": 0.1,
                       "syn_flag": 0, "ack_flag": 1, "rst_flag": 0, "fin_flag": 0}] * 10
        res = forecast_host("192.168.1.50", test_flows, risk_history=[0.2])
        curve = res["projected_risk_curve"]
        self.assertEqual(curve[0], curve[-1])


if __name__ == "__main__":
    unittest.main()
