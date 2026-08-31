#!/usr/bin/env python3
"""
Regression test for multicast flow classification state reset in CyberForecaster.
Verifies that multicast flows (e.g., 224.0.0.251 mDNS) explicitly clear any stale
HIGH/DDoS severity state and remain benign.
"""

import sys
import os
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'capture-service'))
from capture_server import _heuristic_classify, flow_cache, _is_multicast_or_broadcast, _ip_flows, _ip_ports, _ip_dst


class TestMulticastClassification(unittest.TestCase):

    def setUp(self):
        flow_cache.clear()
        _ip_flows.clear()
        _ip_ports.clear()
        _ip_dst.clear()

    def test_multicast_stale_severity_reset(self):
        multicast_ip = "224.0.0.251"
        flow_key = f"192.168.1.100:5353-{multicast_ip}:5353-UDP"

        # 1. Create a multicast flow entry
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

        # 2. Simulate an early burst state where the flow was previously marked HIGH/DDoS
        flow_cache[flow_key]["severity"] = "high"
        flow_cache[flow_key]["attack_type"] = "DDoS"

        # 3. Process subsequent normal multicast packet
        _heuristic_classify(flow_key, event)

        # 4. Verify stored flow & event state cleared back to benign/none
        self.assertEqual(flow_cache[flow_key]["severity"], "none")
        self.assertEqual(flow_cache[flow_key]["attack_type"], "Benign")
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
            "first_seen_ts": now - 1.5,  # 300 PPS (> 120 PPS threshold, duration >= 1.0s)
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

        # Verify unicast attack detection still escalates to DDoS critical
        self.assertEqual(flow_cache[flow_key]["severity"], "critical")
        self.assertEqual(flow_cache[flow_key]["attack_type"], "DDoS")


if __name__ == "__main__":
    unittest.main()
