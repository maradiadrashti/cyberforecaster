"""Starts the dashboard server on a spare port, runs test_v2_api.py against it, then stops it again."""
import os as _os
from pathlib import Path as _P
REPO = _P(_os.environ.get("CYBERFORECASTER_REPO") or _P(__file__).resolve().parents[3])   # repository root
import subprocess, sys, time, urllib.request, os
PORT = "8091"
CWD = str(REPO / "capture-service")
HERE = os.path.dirname(os.path.abspath(__file__))
log = open(os.path.join(HERE, "logs", "api_test_server.txt"), "w", encoding="utf-8", errors="replace")
srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "capture_server:app", "--host", "127.0.0.1", "--port", PORT],
                       cwd=CWD, stdout=log, stderr=subprocess.STDOUT, env=dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1"))
code = 1
try:
    ok = False
    for i in range(90):
        if srv.poll() is not None:
            print("server exited early with code", srv.returncode); break
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/api/v2/forecast/latest", timeout=3).read(); ok = True; break
        except Exception:
            time.sleep(2)
    print("server reachable:", ok, f"(after ~{i*2}s)", flush=True)
    if ok:
        code = subprocess.call([sys.executable, os.path.join(HERE, "test_v2_api.py"), f"http://127.0.0.1:{PORT}"])
finally:
    srv.terminate()
    try:
        srv.wait(20)
    except Exception:
        srv.kill()
    log.close()
    print("server stopped", flush=True)
    print("---- last lines of the server log ----")
    print("".join(open(os.path.join(HERE, "logs", "api_test_server.txt"), encoding="utf-8", errors="replace").readlines()[-25:]))
sys.exit(code)
