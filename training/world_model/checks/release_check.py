r"""Checks run on this PC after the repository clean-up, before anything is committed.
Each step prints its output; the last lines say which steps passed."""
import subprocess, sys, os, time
REPO = r"C:\Users\htc\OneDrive\Desktop\cyberforecaster"
HERE = os.path.dirname(os.path.abspath(__file__))
CHK = os.path.join(REPO, "training", "world_model", "checks")
AUD = os.path.join(HERE, "audit")
res = []
def step(name, cmd, cwd=HERE, timeout=1800, shell=False, env=None, must=True, bad_words=("FAIL",)):
    print(f"\n===== {name} =====\n$ {cmd}", flush=True); t = time.time()
    try:
        e = dict(os.environ); e.update(env or {}); e["GIT_TERMINAL_PROMPT"] = "0"
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, shell=shell, env=e, errors="replace")
        out = (p.stdout or "") + (("\n[stderr]\n" + p.stderr) if p.stderr.strip() else "")
        ok = p.returncode == 0 and not any(("  " + w + " ") in (p.stdout or "") for w in bad_words)
    except Exception as ex:
        out, ok = repr(ex), False
    tail = out if len(out) < 6000 else out[:1500] + "\n...\n" + out[-4000:]
    print(tail, flush=True); print(f"-> {'OK' if ok else 'NOT OK'} ({time.time() - t:.0f} s)", flush=True)
    res.append((name, ok, must)); return ok
PY = sys.executable
step("versions", [PY, "pip_freeze.py"])
step("compile backend", [PY, "-m", "py_compile", os.path.join(REPO, "capture-service", "capture_server.py"), os.path.join(REPO, "capture-service", "world_model.py")])
step("command line on sample", [PY, os.path.join(REPO, "capture-service", "world_model.py"), os.path.join(REPO, "samples", "real_sample_v4.csv"), "--out", os.path.join(HERE, "release_out")])
step("upload A-D through the real server", [PY, "run_upload_all.py"], timeout=2400)
import shutil
STEMS = {"A": "A_cic2017_friday_ddos_onset", "B": "B_cic2018_ftp_bruteforce_onset", "C": "C_ctu13_botnet_c2_forecast", "D": "D_unraveled_exfiltration_forecast"}
for t in "ABCD":
    if os.path.exists(os.path.join(AUD, f"{t}_v2.json")):
        shutil.copyfile(os.path.join(AUD, f"{t}_v2.json"), os.path.join(AUD, STEMS[t] + ".json"))
    step(f"backend audit {t}", [PY, os.path.join(CHK, "audit_backend.py"), STEMS[t]], cwd=AUD)
step("model audit (separate code)", [PY, "audit_model.py"], timeout=2400)
step("dashboard build", "npm run build", cwd=os.path.join(REPO, "client"), shell=True, timeout=900)
for t in "ABCD":
    step(f"page audit {t}", ["node", os.path.join(CHK, "audit_page.cjs"), os.path.join(AUD, t), os.path.join(AUD, f"{t}_v2")], env={"ALLW": "1"}, timeout=2400)
print("\n===== SUMMARY =====")
for n, ok, must in res: print(f"  {'OK    ' if ok else ('NOT OK' if must else 'not ok (optional)')}  {n}")
print("RELEASE CHECK:", "ALL OK" if all(ok for _, ok, m in res if m) else "PROBLEMS FOUND")
