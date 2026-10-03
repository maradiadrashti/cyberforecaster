"""Starts the dashboard server on a spare port, uploads test files A-D through the page's upload endpoint and saves
what the page would receive (conversation list + world-model result) for each file. Then stops the server."""
import os as _os
from pathlib import Path as _P
REPO = _P(_os.environ.get("CYBERFORECASTER_REPO") or _P(__file__).resolve().parents[3])   # repository root
import subprocess, sys, time, urllib.request, os, json, uuid
PORT = "8091"; BASE = f"http://127.0.0.1:{PORT}"
CWD = str(REPO / "capture-service")
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "audit"); os.makedirs(OUT, exist_ok=True)
T = str(REPO / "samples" / "test_files")
FILES = ["A_cic2017_friday_ddos_onset.csv", "B_cic2018_ftp_bruteforce_onset.csv", "C_ctu13_botnet_c2_forecast.csv", "D_unraveled_exfiltration_forecast.csv"]
L = str(REPO / "logs")
keep = {}
for n in ("latest_forecast.json", "latest_forecast_v2.json"):          # the user's own latest result is put back afterwards
    p = os.path.join(L, n)
    keep[n] = open(p, "rb").read() if os.path.exists(p) else None
log = open(os.path.join(HERE, "logs", "audit_server.txt"), "w", encoding="utf-8", errors="replace")
srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "capture_server:app", "--host", "127.0.0.1", "--port", PORT],
                       cwd=CWD, stdout=log, stderr=subprocess.STDOUT, env=dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1"))
def get(path):
    with urllib.request.urlopen(BASE + path, timeout=120) as r:
        return json.loads(r.read().decode("utf-8"))
def post(path, filename, data):
    b = uuid.uuid4().hex
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode() + data + f"\r\n--{b}--\r\n".encode()
    req = urllib.request.Request(BASE + path, data=body, headers={"Content-Type": f"multipart/form-data; boundary={b}"})
    with urllib.request.urlopen(req, timeout=900) as r:
        return r.status, json.loads(r.read().decode("utf-8"))
try:
    ok = False
    for i in range(90):
        if srv.poll() is not None:
            print("server exited early", srv.returncode); break
        try:
            get("/api/v2/forecast/latest"); ok = True; break
        except Exception:
            time.sleep(2)
    print("server reachable:", ok, flush=True)
    for f in FILES if ok else []:
        t = time.time()
        st, v1 = post("/api/upload", f, open(os.path.join(T, f), "rb").read())
        v2 = get("/api/v2/forecast/latest"); l1 = get("/api/forecast/latest")
        tag = f[0]
        json.dump(l1, open(os.path.join(OUT, f"{tag}_v1.json"), "w")); json.dump(v2, open(os.path.join(OUT, f"{tag}_v2.json"), "w"))
        print(f"{f}: HTTP {st} in {time.time() - t:.1f}s  conversations {len(l1.get('results', []))}  v2 {v2.get('status')} file {v2.get('file')}  "
              f"same response as /latest: {json.dumps(v1, sort_keys=True) == json.dumps(l1, sort_keys=True)}", flush=True)
finally:
    srv.terminate()
    try:
        srv.wait(20)
    except Exception:
        srv.kill()
    log.close()
    for n, b in keep.items():
        if b is not None:
            open(os.path.join(L, n), "wb").write(b)
    print("server stopped; the page's latest result was put back", flush=True)
