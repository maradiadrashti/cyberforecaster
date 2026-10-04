r"""Quick checks before committing: backend compiles and loads the model, dashboard builds, demo file runs."""
import subprocess, sys, os
REPO = r"C:\Users\htc\OneDrive\Desktop\cyberforecaster"; PY = sys.executable; ok = True
def step(name, cmd, cwd=REPO, shell=False, timeout=900):
    global ok
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, shell=shell, timeout=timeout, errors="replace")
    good = p.returncode == 0; ok = ok and good
    print(f"===== {name}: {'OK' if good else 'NOT OK'}\n{(p.stdout + p.stderr)[-1500:]}", flush=True)
step("compile backend", [PY, "-m", "py_compile", os.path.join(REPO, "capture-service", "capture_server.py"), os.path.join(REPO, "capture-service", "world_model.py")])
step("import backend", [PY, "-c", "import capture_server; print('routes', len(capture_server.app.routes))"], cwd=os.path.join(REPO, "capture-service"))
step("model on demo file", [PY, os.path.join(REPO, "capture-service", "world_model.py"), os.path.join(REPO, "samples", "demo_unraveled_5_stages.csv"), "--out", os.path.join(os.path.dirname(os.path.abspath(__file__)), "release_out")])
step("dashboard build", "npm run build", cwd=os.path.join(REPO, "client"), shell=True)
print("PRE-PUSH CHECK:", "ALL OK" if ok else "PROBLEMS FOUND")
sys.exit(0 if ok else 1)
