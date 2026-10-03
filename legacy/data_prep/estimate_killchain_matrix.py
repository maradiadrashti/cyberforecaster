#!/usr/bin/env python3
"""
estimate_killchain_matrix.py -- Build the kill-chain stage-transition matrix
P(next stage | current stage) used for the dashboard's t+1 ... t+K forecast.

The matrix combines two clearly separated sources:

  1. DATA   -- transition COUNTS learned from real attackers: every attacker
               host is followed through its attack stages over time (benign
               flows skipped) and each change of stage is counted.
  2. PRIOR  -- an explicit MITRE ATT&CK kill-chain prior. ATT&CK orders the
               tactics Reconnaissance -> Initial Access -> Lateral Movement ->
               Command and Control -> Exfiltration. For each attack stage the
               prior says "stay in this stage (40%) or advance to the next one
               (60%)". It is added as PRIOR_WEIGHT pseudo-counts per row.

Why the prior is needed: the public data only contains 11 stage transitions
(all from DAPT-2020) and none that leave Command & Control, so a data-only
matrix cannot forecast anything after C&C. With the prior, rows that have
real data are dominated by the data, and rows without data (C&C) follow the
ATT&CK ordering. The output JSON stores the raw counts, the prior and the
weight so anyone can see which part comes from where.

    row_i = normalize( counts_i + PRIOR_WEIGHT * prior_i + ALPHA )   for attack stages
    Normal and Exfiltration stay absorbing (identity rows): a normal
    conversation is never forecast to become an attack, and Exfiltration is
    the last stage.

USAGE
    python data_prep/estimate_killchain_matrix.py C:\\ml-data\\dapt_mapped_v1.csv
    (writes models/stage_transition_matrix.json)
"""
import csv
import json
import os
import sys

import numpy as np

STAGES = ["normal", "reconnaissance", "initial_access", "lateral_movement",
          "command_control", "exfiltration"]
IDX = {s: i for i, s in enumerate(STAGES)}

ALPHA = 0.25          # light uniform smoothing on attack rows
PRIOR_WEIGHT = 2.0    # pseudo-counts of the ATT&CK prior per attack row
PRIOR_STAY, PRIOR_ADVANCE = 0.4, 0.6
ABSORBING = {"normal", "exfiltration"}


def attck_prior():
    """Stay-or-advance prior along the ATT&CK tactic order of our stages."""
    P = np.zeros((6, 6))
    for i, s in enumerate(STAGES):
        if s in ABSORBING:
            P[i, i] = 1.0
        else:
            P[i, i] = PRIOR_STAY
            P[i, i + 1] = PRIOR_ADVANCE
    return P


def count_transitions(csv_path):
    host = {}
    with open(csv_path, encoding="utf-8", errors="ignore", newline="") as f:
        r = csv.reader(f)
        h = [c.strip() for c in next(r)]
        si, fi, ti = h.index("src_ip"), h.index("flow_start"), h.index("attack_stage")
        for row in r:
            if len(row) <= max(si, fi, ti):
                continue
            st = IDX.get(row[ti].strip().lower())
            if not st:               # skip benign / unknown: chain attack stages only
                continue
            try:
                fs = float(row[fi])
            except ValueError:
                fs = 0.0
            host.setdefault(row[si], []).append((fs, st))

    counts = np.zeros((6, 6), dtype=np.int64)
    n_chain = 0
    for flows in host.values():
        flows.sort(key=lambda x: x[0])
        seq = []
        for _, st in flows:
            if not seq or seq[-1] != st:
                seq.append(st)
        if len(seq) > 1:
            n_chain += 1
        for a, b in zip(seq, seq[1:]):
            counts[a, b] += 1
    return counts, n_chain, len(host)


def build_matrix(counts):
    prior = attck_prior()
    M = np.zeros((6, 6))
    for i, s in enumerate(STAGES):
        if s in ABSORBING:
            M[i, i] = 1.0
        else:
            row = counts[i] + PRIOR_WEIGHT * prior[i] + ALPHA
            M[i] = row / row.sum()
    return M, prior


def main(csv_path, out_path=None):
    counts, n_chain, n_hosts = count_transitions(csv_path)
    M, prior = build_matrix(counts)
    if out_path is None:
        out_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models",
                                                "stage_transition_matrix.json"))
    out = {
        "stages": STAGES,
        "matrix": [[round(float(v), 6) for v in r] for r in M],
        "counts": counts.tolist(),
        "n_transitions": int(counts.sum()),
        "attacker_hosts": n_hosts,
        "attacker_hosts_with_transition": n_chain,
        "source_file": os.path.basename(csv_path),
        "mode": "killchain_host_attackonly + attck_prior",
        "prior": prior.tolist(),
        "prior_weight": PRIOR_WEIGHT,
        "alpha": ALPHA,
        "method": "row_i = normalize(counts_i + prior_weight * prior_i + alpha) for attack stages; "
                  "normal and exfiltration are absorbing. Counts are learned from data; the prior is "
                  "the MITRE ATT&CK tactic order (stay 0.4 / advance to next stage 0.6).",
    }
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

    print(f"[+] {n_hosts} attacker hosts, {n_chain} with a multi-stage chain, "
          f"{int(counts.sum())} transitions (data).")
    print(f"[+] Saved {out_path}\n")
    print("P(next|cur)".ljust(20) + "".join(s[:11].rjust(12) for s in STAGES))
    for i, s in enumerate(STAGES):
        print(s[:18].ljust(20) + "".join(f"{M[i][j]:12.3f}" for j in range(6)))
    print("\nObserved transition counts (data):")
    for i, s in enumerate(STAGES):
        offs = [(STAGES[j], int(counts[i][j])) for j in range(6) if counts[i][j] > 0]
        if offs:
            print(f"  {s} -> " + ", ".join(f"{a}:{c}" for a, c in offs))


if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv) > 1 else r"C:\ml-data\dapt_mapped_v1.csv"
    o = sys.argv[2] if len(sys.argv) > 2 else None
    main(p, o)
