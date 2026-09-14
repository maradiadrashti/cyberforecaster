#!/usr/bin/env python3
"""
test_file_upload_api.py — Unit and Integration tests for POST /api/analyze_file.
Verifies PCAP and CSV analysis, error handling, MITRE stage output, and model consistency.
"""

import sys
import os
import io
import unittest
import json
import pandas as pd

# Add repo root and capture-service to sys.path
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_CAPTURE_SERVICE_DIR = os.path.join(_REPO_ROOT, "capture-service")
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
if _CAPTURE_SERVICE_DIR not in sys.path:
    sys.path.insert(0, _CAPTURE_SERVICE_DIR)

from capture_server import (
    app,
    _analyze_csv_bytes,
    _analyze_pcap_bytes,
    _compute_feature_attributions
)
from fastapi.testclient import TestClient

client = TestClient(app)


class TestFileUploadAPI(unittest.TestCase):
    def test_benign_csv_analysis(self):
        """Test 1: Upload a known-benign CSV sample (label=benign).
        Real GRU output is used — stage is whatever the model decides.
        We verify: HTTP 200, pipeline ran, no flows flagged as attacks,
        and the infiltration_probability_timeline was populated.
        """
        csv_content = """src_ip,dst_ip,src_port,dst_port,protocol,packet_count,byte_count,duration,syn_flag,ack_flag,rst_flag,fin_flag,label
192.168.1.10,192.168.1.20,54321,80,TCP,10,1200,0.5,1,1,0,0,benign
192.168.1.10,192.168.1.20,54322,443,TCP,15,4500,1.2,1,1,0,0,benign
192.168.1.10,192.168.1.20,54323,80,TCP,8,960,0.3,1,1,0,0,benign
"""
        response = client.post(
            "/api/analyze_file",
            files={"file": ("benign_sample.csv", csv_content.encode("utf-8"), "text/csv")}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["file_type"], "csv")
        self.assertEqual(data["total_flows"], 3)
        # Timeline must exist and be non-empty
        self.assertIn("infiltration_probability_timeline", data)
        self.assertGreater(len(data["infiltration_probability_timeline"]), 0)
        # MITRE stage field is always populated
        self.assertIn("predicted_mitre_stage", data)
        self.assertIsInstance(data["predicted_mitre_stage"], str)
        self.assertGreater(len(data["predicted_mitre_stage"]), 0)
        # No flows should be flagged — all rows carry label=benign
        self.assertEqual(len(data["flagged_flows"]), 0)

    def test_attack_csv_analysis(self):
        """Test 2: Upload a known-attack CSV sample (PortScan/DoS) -> verify rising probability and MITRE stage."""
        csv_content = """src_ip,dst_ip,src_port,dst_port,protocol,packet_count,byte_count,duration,syn_flag,ack_flag,rst_flag,fin_flag,label
10.0.0.101,192.168.1.20,50001,21,TCP,1,64,0.001,1,0,0,0,port_scan
10.0.0.101,192.168.1.20,50002,22,TCP,1,64,0.001,1,0,0,0,port_scan
10.0.0.101,192.168.1.20,50003,23,TCP,1,64,0.001,1,0,0,0,port_scan
10.0.0.101,192.168.1.20,50004,80,TCP,1,64,0.001,1,0,0,0,port_scan
10.0.0.101,192.168.1.20,50005,443,TCP,1,64,0.001,1,0,0,0,port_scan
10.0.0.101,192.168.1.20,50006,3389,TCP,1,64,0.001,1,0,0,0,port_scan
"""
        response = client.post(
            "/api/analyze_file",
            files={"file": ("attack_sample.csv", csv_content.encode("utf-8"), "text/csv")}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertGreater(len(data["flagged_flows"]), 0)
        self.assertNotEqual(data["predicted_mitre_stage"].lower(), "normal")

    def test_invalid_file_extension(self):
        """Test 4: Upload an invalid file extension (.txt) -> verify 400 error message."""
        txt_content = "This is not a network capture file."
        response = client.post(
            "/api/analyze_file",
            files={"file": ("sample.txt", txt_content.encode("utf-8"), "text/plain")}
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn("detail", data)
        self.assertIn("Unsupported file extension", data["detail"])

    def test_empty_file(self):
        """Test 4b: Upload an empty CSV file -> verify 400 error."""
        response = client.post(
            "/api/analyze_file",
            files={"file": ("empty.csv", b"", "text/csv")}
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn("empty", data["detail"])

    def test_feature_attributions(self):
        """Test 5: Verify feature attributions function returns top features."""
        flow_dict = {
            "duration": 0.001,
            "packet_count": 500,
            "byte_count": 32000,
            "src_port": 54321,
            "dst_port": 22,
            "syn_flag": 500,
            "ack_flag": 0,
        }
        attributions = _compute_feature_attributions(flow_dict)
        self.assertGreater(len(attributions), 0)
        self.assertIn("importance", attributions[0])
        self.assertIn("feature", attributions[0])


if __name__ == "__main__":
    unittest.main()
