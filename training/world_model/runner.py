r"""
Job runner - lets Claude start trainings on this PC without you typing each command.

Start it ONCE and leave the window open:      python D:\ml-data\processed\runner.py

It watches D:\ml-data\processed\jobs\ for *.job files (written by Claude), runs them one after another,
saves each job's output in D:\ml-data\processed\logs\<job>.txt and keeps the PC awake while it works.
It only runs what is in the job files. To stop it: close the window (or create a file jobs\STOP).
"""
import sys, os, json, time, subprocess, datetime
from pathlib import Path

DIR = Path(__file__).resolve().parent
JOBS, LOGS = DIR / "jobs", DIR / "logs"
JOBS.mkdir(exist_ok=True)
LOGS.mkdir(exist_ok=True)


def keep_awake(on=True):
    try:
        import ctypes
        ctypes.windll.kernel32.SetThreadExecutionState(0x80000000 | (0x00000001 if on else 0))
    except Exception:
        pass


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def beat(state, job=""):
    try:
        (JOBS / "heartbeat.json").write_text(json.dumps({"time": now(), "epoch": time.time(), "state": state, "job": job}))
    except Exception:
        pass


def pending():
    return [j for j in sorted(JOBS.glob("*.job")) if not (JOBS / (j.stem + ".done")).exists()]


def run(job):
    name = job.stem
    try:
        spec = json.loads(job.read_text(encoding="utf-8"))
        cmd = [sys.executable if c == "python" else c for c in spec["cmd"]]
        cwd = spec.get("cwd", str(DIR))
    except Exception as e:
        (JOBS / (name + ".done")).write_text(json.dumps({"exit": -1, "error": f"bad job file: {e!r}", "ended": now()}))
        return
    print(f"[{now()}] START {name}: {' '.join(spec['cmd'])}", flush=True)
    t0 = time.time()
    env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
    code = -1
    with open(LOGS / (name + ".txt"), "w", encoding="utf-8", errors="replace") as log:
        log.write(f"# {now()}  {' '.join(spec['cmd'])}\n")
        log.flush()
        try:
            p = subprocess.Popen(cmd, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, env=env)
            while p.poll() is None:
                beat("running", name)
                if (JOBS / "STOP").exists() or (JOBS / (name + ".kill")).exists():
                    p.terminate()
                    log.write(f"\n# {now()} terminated on request\n")
                    break
                time.sleep(15)
            code = p.wait()
        except Exception as e:
            log.write(f"\n# runner could not start the job: {e!r}\n")
    (JOBS / (name + ".done")).write_text(json.dumps({"exit": code, "minutes": round((time.time() - t0) / 60, 1), "ended": now()}))
    print(f"[{now()}] {'done  ' if code == 0 else 'FAILED'} {name}  (exit {code}, {(time.time() - t0) / 60:.0f} min)", flush=True)


if __name__ == "__main__":
    print("Job runner started. Leave this window open. Jobs folder:", JOBS, flush=True)
    keep_awake(True)
    idle_said = False
    while not (JOBS / "STOP").exists():
        todo = pending()
        if todo:
            idle_said = False
            run(todo[0])
        else:
            if not idle_said:
                print(f"[{now()}] no jobs waiting - Claude will add more when needed. Keep this window open.", flush=True)
                idle_said = True
            beat("idle")
            time.sleep(20)
    keep_awake(False)
    print("STOP file found - runner finished.")
