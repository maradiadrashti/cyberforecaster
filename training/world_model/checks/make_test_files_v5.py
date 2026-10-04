r"""Rebuilds test files B and C WITHOUT thinning out hosts, so the traffic every host receives is complete
(the incoming-traffic features need all flows of the time slice). Output: D:\ml-data\processed\testfiles_v5\ """
import pandas as pd, os
SRC = r"D:\ml-data\merged_final_v5.csv"
OUT = r"D:\ml-data\processed\testfiles_v5"; os.makedirs(OUT, exist_ok=True)
SL = {"B_cic2018_ftp_bruteforce_onset.csv": (1518618360.0, 1518619140.0),      # 14 Feb 2018, 14:26-14:39 UTC
      "C_ctu13_botnet_c2_forecast.csv": (1312976400.0, 1312977180.0)}          # 10 Aug 2011, 11:40-11:53 UTC
first = {k: True for k in SL}; n = {k: 0 for k in SL}; seen = 0
for ch in pd.read_csv(SRC, chunksize=1_000_000, low_memory=False):
    seen += len(ch); t = pd.to_numeric(ch["flow_start"], errors="coerce")
    for k, (a, b) in SL.items():
        x = ch[(t >= a) & (t < b)]
        if len(x):
            x.to_csv(os.path.join(OUT, k), mode="w" if first[k] else "a", header=first[k], index=False); first[k] = False; n[k] += len(x)
    print(f"read {seen:,}  kept {n}", flush=True)
for k in SL:
    p = os.path.join(OUT, k); d = pd.read_csv(p, low_memory=False)
    print(k, f"{len(d):,} flows, {os.path.getsize(p) / 1e6:.1f} MB, source hosts {d.src_ip.nunique():,}", d.attack_stage.value_counts().to_dict())
