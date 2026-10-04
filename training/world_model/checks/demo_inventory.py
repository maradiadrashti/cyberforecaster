r"""Lists, for the Unraveled and DAPT2020 hosts that go through more than one attack stage, in which 1-hour blocks
each stage happens, whether that hour was held back from training, and how many flows the whole network has in it."""
import pandas as pd, numpy as np, json
from pathlib import Path
HERE = Path(__file__).resolve().parent
W = pd.read_pickle(HERE / "windows_v5.pkl"); W = W[W["t0"] < 1.7e9]
ST = ["normal", "reconnaissance", "initial_access", "command_control", "lateral_movement", "exfiltration", "other"]
W["blk"] = (W.t0 // 3600).astype("int64"); fold = ((W.blk * 2654435761) % 2**32) % 10
W["split"] = np.where(fold < 6, "train", np.where(fold < 8, "val", "test"))
out = {}
for sub in ["unraveled"]:
    U = W[(W["sub"] == sub)]; A = U[(U.stage_id >= 1) & (U.stage_id <= 5)]
    ns = A.groupby("host_ip").stage_id.nunique(); multi = list(ns[ns >= 2].index)
    print(sub, "hosts with attack windows", A.host_ip.nunique(), "with 2+ stages", len(multi))
    tot = U.groupby("blk").n_flows.sum()      # flows of kept hosts per hour (lower bound of the full hour)
    for h in multi:
        g = A[A.host_ip == h].groupby(["blk", "split", "stage_id"]).size().reset_index(name="w")
        print("\n", h, {ST[s]: int(n) for s, n in A[A.host_ip == h].stage_id.value_counts().items()})
        for b, gg in g.groupby("blk"):
            print("   ", pd.to_datetime(b * 3600, unit="s"), gg.split.iloc[0], {ST[s]: int(w) for s, w in zip(gg.stage_id, gg.w)}, "kept-host flows in hour", int(tot.get(b, 0)))
