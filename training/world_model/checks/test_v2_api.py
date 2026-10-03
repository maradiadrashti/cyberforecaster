"""End-to-end check of the dashboard server's v2 endpoints (run on the PC that runs the server)."""
import os as _os
from pathlib import Path as _P
REPO = _P(_os.environ.get("CYBERFORECASTER_REPO") or _P(__file__).resolve().parents[3])   # repository root
import json, sys, time, uuid, urllib.request, urllib.error
BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
SAMPLE = str(REPO / "samples" / "real_sample_v4.csv")

def get(path):
    with urllib.request.urlopen(BASE + path, timeout=60) as r:
        return r.status, json.loads(r.read().decode("utf-8"))

def post_file(path, filename, data):
    b = uuid.uuid4().hex
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + data + f"\r\n--{b}--\r\n".encode()
    req = urllib.request.Request(BASE + path, data=body, headers={"Content-Type": f"multipart/form-data; boundary={b}"})
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8") or "{}")

def brief(v):
    c = v.get("chart") or {}
    out = {"status": v.get("status"), "reason": v.get("reason"), "file": v.get("file"), "format": v.get("format_detected"),
           "flows": v.get("flows"), "windows": v.get("windows"), "hosts": v.get("hosts"), "network": v.get("network"),
           "threshold": (v.get("model") or {}).get("alert_threshold_risk_60s"), "copies": (v.get("model") or {}).get("copies_averaged"),
           "baseline_available": c.get("baseline_available"), "stage_steps": c.get("stage_steps"), "chart_hosts": len(c.get("hosts") or {})}
    if c.get("host_order"):
        h = c["hosts"][c["host_order"][0]]
        out["top_host"] = c["host_order"][0]
        out["top_host_last"] = {"risk_60s": h["risk_60s"][-1], "baseline": (h["baseline_risk_60s"] or [None])[-1],
                                "stage_forecast": h["stage_forecast"][-1], "prob": h["stage_forecast_prob"][-1]}
        out["cone_last"] = {"curve": h.get("forecast_curve", [[None]])[-1], "min": (h.get("forecast_curve_min") or [[None]])[-1], "max": (h.get("forecast_curve_max") or [[None]])[-1]}
        at = h.get("attribution_last") or {}
        out["attribution_last"] = {"error": at.get("error"), "method": at.get("method"), "top": [(f["feature"], f["contribution"], f["value"]) for f in (at.get("features") or [])[:5]], "by_group": at.get("by_group")}
        out["stage_dist_last_now"] = (h.get("stage_dist_last") or [None])[0]; out["classes"] = c.get("classes")
    return out

try:
    print("1) GET /api/v2/forecast/latest ->", get("/api/v2/forecast/latest")[1].get("status"))
except Exception as e:
    print("SERVER NOT REACHABLE:", repr(e)); sys.exit(3)
data = open(SAMPLE, "rb").read()
t = time.time(); st, v = post_file("/api/v2/upload", "real_sample_v4.csv", data)
print(f"2) POST /api/v2/upload -> HTTP {st} in {time.time()-t:.1f}s"); print(json.dumps(brief(v) if st == 200 else v, indent=1))
t = time.time(); st, v1 = post_file("/api/upload", "real_sample_v4.csv", data)
print(f"3) POST /api/upload (old endpoint) -> HTTP {st} in {time.time()-t:.1f}s  status={v1.get('status')} results={len(v1.get('results', []))} detail={v1.get('detail')}")
for i in range(60):
    _, v = get("/api/v2/forecast/latest")
    if v.get("status") != "running":
        break
    time.sleep(2)
print(f"4) v2 result started by the old upload endpoint (after {i*2}s):"); print(json.dumps(brief(v), indent=1))
print("bytes of v2 JSON:", len(json.dumps(v)))

# restart-survival: the result must be on disk
import os
p = str(REPO / "logs" / "latest_forecast_v2.json")
print("5) saved to disk:", os.path.exists(p), os.path.getsize(p) if os.path.exists(p) else 0, "bytes")
_, v = get("/api/v2/forecast/latest"); f = v["chart"]["hosts"][v["chart"]["host_order"][0]]["attribution_last"]["features"][0]
print("6) attribution description:", f.get("feature"), "->", f.get("description"))

for hh in v["chart"]["host_order"]:
    pg = v["chart"]["hosts"][hh].get("progression") or {}
    print("7) progression", hh, pg.get("available"), [(x["label"], x["stage"], x["prob"], x.get("observed"), x.get("observed_total"), x.get("typical_delay")) for x in pg.get("steps", [])] or pg.get("reason"), "nodes:", len(pg.get("nodes", [])))

so = v["chart"].get("start_outlook") or {}
h0 = v["chart"]["hosts"][v["chart"]["host_order"][0]]
print("8) start outlook:", so.get("model"), so.get("horizons_seconds"), "tested 300:", (so.get("tested") or {}).get("300"),
      "| limits:", (so.get("limits") or "")[:80], "| top host values:", {k: x[-3:] for k, x in (h0.get("start_soon") or {}).items()})
print("9) likely stage prob + second choice present:", "likely_attack_stage_prob" in h0, "stage_forecast_second" in h0)

# a labelled test file through the normal upload endpoint (as the page does it)
B = str(REPO / "samples" / "test_files" / "B_cic2018_ftp_bruteforce_onset.csv")
t = time.time(); st, v1 = post_file("/api/upload", "B_cic2018_ftp_bruteforce_onset.csv", open(B, "rb").read())
_, vb = get("/api/v2/forecast/latest")
print(f"10) POST /api/upload file B -> HTTP {st} in {time.time()-t:.1f}s  status={v1.get('status')} listed={v1.get('conversations_listed')} world_model={v1.get('world_model_status')}")
print("    first conversations:", [(c["src_ip"], c["dst_ip"], c.get("infiltration_probability"), c.get("predicted_stage"), c.get("model")) for c in v1.get("results", [])[:3]])
print("    v2 check:", json.dumps(vb.get("check_against_labels_in_file")), "seconds:", vb.get("processing_seconds"))

