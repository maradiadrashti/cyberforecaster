import sys, json
from pathlib import Path
import numpy as np, pandas as pd
HERE = Path(__file__).resolve().parent; REPO = Path(r"C:\Users\htc\OneDrive\Desktop\cyberforecaster")
sys.path.insert(0, str(REPO / "capture-service")); import world_model as wm
WP = pd.read_pickle(HERE / "windows_v5.pkl")
FE = json.loads((HERE / "feature_groups_v5.json").read_text())["features"]
T = REPO / "samples" / "test_files"; N = HERE / "testfiles_v5"
for tag, path, src, hosts in [("B", N / "B_cic2018_ftp_bruteforce_onset.csv", "merged", ["18.221.219.4", "172.31.69.25"]),
                              ("C", N / "C_ctu13_botnet_c2_forecast.csv", "merged", ["147.32.84.165"]),
                              ("D", T / "D_unraveled_exfiltration_forecast.csv", "unraveled", ["10.1.3.8", "10.1.3.17"])]:
    flows, kind, notes = wm.load_flows(str(path)); W, has = wm.build_windows(flows)
    for ip in hosts:
        a = W[W.host_ip == ip].set_index("t0"); b = WP[(WP.source == src) & (WP.host_ip == ip)].set_index("t0")
        common = a.index.intersection(b.index); common = common[(common > a.index.min() + 300) & (common < a.index.max())]
        xa, xb = a.loc[common, FE].to_numpy(float), b.loc[common, FE].to_numpy(float)
        same = np.isclose(xa, xb, rtol=1e-4, atol=1e-5, equal_nan=True)
        bad = [FE[j] for j in np.where(~same.all(0))[0]]
        print(f"{tag} {ip}: upload windows {len(a)}, training windows {len(b)}, common (after first 5 min) {len(common)}, differing cells {int((~same).sum())} of {same.size}; features that differ: {bad[:20]}", flush=True)
        for f in bad[:4]:
            j = FE.index(f); k = np.where(~same[:, j])[0][:3]; print("    ", f, "upload", xa[k, j], "training", xb[k, j])
    if tag == "B":
        sid = W.stage_id.to_numpy()
        for mv, md in [("v4", REPO / "models" / "world_model"), ("v5", HERE / "model_v5_unseen-none")]:
            wm.MODEL_DIR = md; wm._MODEL = None
            meta, risk, stage, hl, base, extra = wm.run_model(W); K = meta["K"]; CL = meta["classes"]
            likely = stage[:, :, 1:].mean(1).argmax(1) + 1
            for ip in hosts:
                m = (W.host_ip == ip).to_numpy(); idx = np.where(m)[0]
                print(mv, ip, "threshold", round(wm._threshold(meta, "all"), 3))
                print("   label :", "".join("A" if s > 0 else "." if s == 0 else "?" for s in sid[idx]))
                print("   risk  :", " ".join(f"{risk[i, K - 1]:.2f}" for i in idx))
                print("   stage :", " ".join(CL[likely[i]][:4] for i in idx))
