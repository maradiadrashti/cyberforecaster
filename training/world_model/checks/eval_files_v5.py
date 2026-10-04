r"""Runs world model v4 and v5 on the SAME four labelled test files (B and C are the complete time slices from
testfiles_v5) and prints one table per file. False alarms are split into clean hosts and quiet windows of hosts
that are attacking somewhere else in the file."""
import sys, json
from pathlib import Path
import numpy as np, pandas as pd
HERE = Path(__file__).resolve().parent
REPO = Path(r"C:\Users\htc\OneDrive\Desktop\cyberforecaster")
sys.path.insert(0, str(REPO / "capture-service"))
import world_model as wm
MODELS = {"v4": Path(sys.argv[1]), "v5": Path(sys.argv[2])}
T = REPO / "samples" / "test_files"; N = HERE / "testfiles_v5"
FILES = {"A": T / "A_cic2017_friday_ddos_onset.csv", "B": N / "B_cic2018_ftp_bruteforce_onset.csv",
         "C": N / "C_ctu13_botnet_c2_forecast.csv", "D": T / "D_unraveled_exfiltration_forecast.csv"}
RES = {}
for tag, path in FILES.items():
    flows, kind, notes = wm.load_flows(str(path)); W, has = wm.build_windows(flows)
    sid = W["stage_id"].to_numpy(); host = W["host_ip"].to_numpy(); win = W["win"].to_numpy(np.int64)
    att, norm = sid > 0, sid == 0
    dirty = set(host[sid != 0]); on_dirty = np.array([h in dirty for h in host])
    RES[tag] = {"flows": int(len(flows)), "hosts": int(len(set(host))), "attack_windows": int(att.sum()), "normal_windows": int(norm.sum())}
    for mv, md in MODELS.items():
        wm.MODEL_DIR = md; wm._MODEL = None
        meta, risk, stage, hist_len, base, extra = wm.run_model(W)
        K, CL = meta["K"], meta["classes"]; thr = wm._threshold(meta, "all"); r60 = risk[:, K - 1]; al = r60 >= thr
        likely = stage[:, :, 1:].mean(1).argmax(1) + 1
        st_ok = att & (sid < len(CL))
        soon = extra.get("soon"); s5 = soon[:, 0] if soon is not None and soon.size else np.zeros(len(W)); t5 = meta["soon"]["300"]["threshold"]
        # attack starts: an attack window of a host whose previous 30 windows-of-time (5 min) hold no attack window and at least one window
        order = np.lexsort((win, host)); starts = warned60 = warned300 = 0; first_starts = first_warn = 0; seen = set()
        hs, ws, ss = host[order], win[order], sid[order]; a_, s_ = al[order], s5[order]
        for i in range(len(order)):
            if ss[i] <= 0: continue
            j = i - 1; prev = []
            while j >= 0 and hs[j] == hs[i] and ws[j] >= ws[i] - 30: prev.append(j); j -= 1
            if not prev or any(ss[p] != 0 for p in prev): continue
            starts += 1; w60 = any(a_[p] for p in prev if ws[p] >= ws[i] - 6); w300 = any(s_[p] >= t5 for p in prev)
            warned60 += w60; warned300 += w300
            if hs[i] not in seen: first_starts += 1; first_warn += (w60 or w300)
            seen.add(hs[i])
        flagged = set(host[al]); att_hosts = set(host[att])
        RES[tag][mv] = {
            "threshold": round(float(thr), 4),
            "attack_windows_alerted": round(float(al[att].mean()), 4) if att.any() else None,
            "false_alarms_all_normal_windows": round(float(al[norm].mean()), 4),
            "false_alarms_clean_hosts": round(float(al[norm & ~on_dirty].mean()), 4) if (norm & ~on_dirty).any() else None,
            "clean_host_windows": int((norm & ~on_dirty).sum()),
            "alerts_in_quiet_windows_of_attacking_hosts": round(float(al[norm & on_dirty].mean()), 4) if (norm & on_dirty).any() else None,
            "quiet_windows_of_attacking_hosts": int((norm & on_dirty).sum()),
            "averaged_stage_correct_on_attack_windows": round(float((likely[st_ok] == sid[st_ok]).mean()), 4) if st_ok.any() else None,
            "attacking_hosts": len(att_hosts), "attacking_hosts_flagged": len(att_hosts & flagged),
            "clean_hosts": len(set(host) - dirty), "clean_hosts_flagged": len(flagged - dirty),
            "attack_starts_after_5_quiet_minutes": starts, "warned_by_60s_alert": int(warned60), "warned_by_5min_output": int(warned300),
            "first_starts_of_a_host": first_starts, "first_starts_warned": int(first_warn)}
        print(tag, mv, json.dumps(RES[tag][mv]), flush=True)
(HERE / "eval_files_v5.json").write_text(json.dumps(RES, indent=1)); print("saved")
