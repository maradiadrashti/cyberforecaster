r"""Feeds a real packet capture into the live-capture packet buffer and runs one cycle of the live world-model
worker, then compares what the Live Telemetry page would receive with a direct run of the model on the same file."""
import sys, os, json
REPO = r"C:\Users\htc\OneDrive\Desktop\cyberforecaster"
os.chdir(os.path.join(REPO, "capture-service")); sys.path.insert(0, os.getcwd())
PCAP = os.path.join(REPO, "samples", "darpa2000_lldos_inside_slice.pcap")
import capture_server as cs, world_model as wm
from scapy.utils import rdpcap
pk = rdpcap(PCAP); print("packets read:", len(pk))
last = float(pk[-1].time); pk10 = [p for p in pk if float(p.time) >= last - 600.0]; print("packets in the last 10 minutes:", len(pk10))
with cs._raw_packet_lock:
    cs._raw_packet_buffer.clear(); cs._raw_packet_buffer.extend(pk)
print("buffer holds:", len(cs._raw_packet_buffer), "(buffer limit:", getattr(cs._raw_packet_buffer, "maxlen", None), ")")
sent = []
cs._broadcast_ws_sync = lambda payload: sent.append(payload)
cs._run_live_world_model_cycle()
upd = [m["data"] for m in sent if m["type"] == "live_forecast_update"]; al = [m["data"] for m in sent if m["type"] == "live_forecast_alert"]
print("messages:", len(upd), "updates,", len(al), "alerts; model label:", sorted({u.get("model") for u in upd}), "threshold:", sorted({u.get("alert_threshold") for u in upd}))
# direct run on the same 10 minutes
import tempfile
from scapy.utils import wrpcap
tmp = os.path.join(tempfile.gettempdir(), "live_sim_direct.pcap"); wrpcap(tmp, cs._normalize_scapy_packets(pk10))
res = wm.analyze(tmp); os.remove(tmp); H = res["chart"]["hosts"]; thr = res["chart"]["threshold"]
bad = 0; n = 0
for u in upd:
    h = H.get(u["sourceIp"])
    if h is None or u.get("risk_score") is None: continue
    n += 1
    exp_stage = h["likely_attack_stage"][-1] if h["alert"][-1] else h["stage_now"][-1]
    ok = abs(u["risk_score"] - h["risk_60s"][-1]) < 1e-3 and u["predicted_stage"] == exp_stage and u["windows_collected"] == len(h["risk_60s"])
    if not ok: bad += 1; print("MISMATCH", u["sourceIp"], u["risk_score"], h["risk_60s"][-1], u["predicted_stage"], exp_stage)
print(f"updates checked against the direct run: {n}, mismatches: {bad}")
print("alerts sent only at or above the threshold:", all(a["riskScore"] >= thr for a in al), "| hosts at or above threshold in direct run:", sum(1 for h in H.values() if h["risk_60s"][-1] >= thr), "| alert messages:", len(al))
print("updates without a risk value (COLLECTING):", sum(1 for u in upd if u.get("risk_score") is None))
print("example:", json.dumps(upd[0])[:600] if upd else None)
print("LIVE SIM:", "OK" if upd and bad == 0 else "PROBLEM")
