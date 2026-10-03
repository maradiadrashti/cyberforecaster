r"""
Stage-progression statistics, measured from the training windows (nothing here is typed in by hand).

    python build_progression.py [path to windows.pkl]      -> stage_progression.json

For every attacker host the stages are listed in the order the host FIRST reached them
(e.g. reconnaissance -> initial_access -> lateral_movement). Every step of such a list is one
observed "progression". The file stores, per stage, how many hosts reached it, how many of them went
on to a new stage, which stage that was, and how long it took.

UNSW-NB15 is left out: its four attacker machines run several attack types at the same time, so the
order of stages there is not a progression of one attack. Set INCLUDE_UNSW = True to see the difference.
"""
import sys, json, collections
from pathlib import Path
import numpy as np
import pandas as pd

INCLUDE_UNSW = False
STAGES = ["normal", "reconnaissance", "initial_access", "command_control", "lateral_movement", "exfiltration"]
src = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(r"D:\ml-data\processed\windows.pkl")
W = pd.read_pickle(src)[["source", "sub", "host_ip", "t0", "stage_id"]]
W = W[(W.t0 < 1.7e9) & (W.stage_id >= 1) & (W.stage_id <= 5)].sort_values(["source", "host_ip", "t0"])
if not INCLUDE_UNSW:
    W = W[W["sub"] != "unsw"]

reached, moved, first = collections.Counter(), collections.Counter(), collections.Counter()
trans, delays, by_ds = collections.Counter(), collections.defaultdict(list), collections.defaultdict(collections.Counter)
hosts = 0
for (_, host), d in W.groupby(["source", "host_ip"], sort=False):
    hosts += 1
    fv = d.drop_duplicates("stage_id")                       # first window of each stage, in time order
    st, t, sub = fv.stage_id.tolist(), fv.t0.tolist(), d["sub"].iloc[0]
    first[st[0]] += 1
    for i, s in enumerate(st):
        reached[s] += 1
        if i + 1 < len(st):
            moved[s] += 1
            trans[(s, st[i + 1])] += 1
            delays[(s, st[i + 1])].append(t[i + 1] - t[i])
            by_ds[(s, st[i + 1])][sub] += 1

out = {
    "what": "order in which attacker hosts first reached each stage, measured on the training windows",
    "datasets": sorted(W["sub"].unique().tolist()), "unsw_included": INCLUDE_UNSW,
    "attacker_hosts": hosts, "hosts_with_a_progression": int(sum(1 for _ in [0]) and len({h for h in []})),
    "total_progressions": int(sum(trans.values())),
    "first_stage": {STAGES[s]: int(n) for s, n in first.items()},
    "stages": {STAGES[s]: {"hosts_reached": int(reached[s]), "hosts_moved_on": int(moved[s]),
                           "next": {STAGES[b]: {"count": int(n), "median_delay_min": round(float(np.median(delays[(a, b)])) / 60, 1),
                                                "min_delay_min": round(float(np.min(delays[(a, b)])) / 60, 1),
                                                "max_delay_min": round(float(np.max(delays[(a, b)])) / 60, 1),
                                                "datasets": dict(by_ds[(a, b)])}
                                    for (a, b), n in sorted(trans.items(), key=lambda x: -x[1]) if a == s}}
               for s in range(1, 6)},
}
multi = W.groupby(["source", "host_ip"])["stage_id"].nunique()
out["hosts_with_a_progression"] = int((multi >= 2).sum())
Path("stage_progression.json").write_text(json.dumps(out, indent=1))
print(json.dumps(out, indent=1))
