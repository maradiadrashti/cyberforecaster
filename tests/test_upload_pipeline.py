#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_upload_pipeline.py -- Automated verification for POST /api/upload and GET /api/forecast/latest.
"""

import sys
import os
import unittest
import json

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_CAPTURE_SERVICE_DIR = os.path.join(_REPO_ROOT, "capture-service")
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
if _CAPTURE_SERVICE_DIR not in sys.path:
    sys.path.insert(0, _CAPTURE_SERVICE_DIR)

from capture_server import app
from fastapi.testclient import TestClient
from predict_csv import predict_csv

client = TestClient(app)


class TestUploadPipeline(unittest.TestCase):
    def test_01_forecast_latest_no_upload(self):
        import capture_server
        capture_server._latest_forecast_result = {"status": "no_upload"}
        if os.path.exists(capture_server._LATEST_FORECAST_FILE):
            try:
                os.remove(capture_server._LATEST_FORECAST_FILE)
            except Exception:
                pass
        res = client.get("/api/forecast/latest")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("status"), "no_upload")

    def test_02_upload_csv_missing_columns(self):
        invalid_csv = "src_ip,dst_ip,duration\n192.168.1.1,10.0.0.1,0.5\n"
        res = client.post(
            "/api/upload",
            files={"file": ("invalid.csv", invalid_csv.encode("utf-8"), "text/csv")}
        )
        self.assertEqual(res.status_code, 400)
        data = res.json()
        self.assertIn("detail", data)
        self.assertIn("Missing required columns", data["detail"])

    def test_03_upload_valid_sample_test_flows(self):
        sample_path = os.path.join(_REPO_ROOT, "sample_test_flows.csv")
        cli_result = predict_csv(sample_path)

        with open(sample_path, "rb") as f:
            content = f.read()

        res = client.post(
            "/api/upload",
            files={"file": ("sample_test_flows.csv", content, "text/csv")}
        )
        self.assertEqual(res.status_code, 200)
        api_result = res.json()

        self.assertEqual(api_result["status"], "success")
        self.assertEqual(api_result["total_flows"], cli_result["total_flows"])
        self.assertEqual(api_result["total_conversations"], cli_result["total_conversations"])
        self.assertEqual(len(api_result["results"]), len(cli_result["results"]))

        # Compare side-by-side per conversation
        cli_map = {(r["src_ip"], r["dst_ip"]): r for r in cli_result["results"]}
        api_map = {(r["src_ip"], r["dst_ip"]): r for r in api_result["results"]}

        for key in cli_map:
            cli_res = cli_map[key]
            api_res = api_map[key]

            print(f"Comparing conversation {key}:")
            print(f"  CLI: infiltration_prob={cli_res['infiltration_probability']:.4f}, stage={cli_res['predicted_stage']}")
            print(f"  API: infiltration_prob={api_res['infiltration_probability']:.4f}, stage={api_res['predicted_stage']}")

            self.assertEqual(round(cli_res["infiltration_probability"], 4), round(api_res["infiltration_probability"], 4))
            self.assertEqual(cli_res["predicted_stage"], api_res["predicted_stage"])

    def test_04_forecast_latest_after_upload(self):
        res = client.get("/api/forecast/latest")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("status"), "success")
        self.assertIn("results", data)
        self.assertGreater(len(data["results"]), 0)


if __name__ == "__main__":
    unittest.main()
