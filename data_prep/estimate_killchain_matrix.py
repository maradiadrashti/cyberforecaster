#!/usr/bin/env python3
"""
estimate_killchain_matrix.py -- Learn a KILL-CHAIN stage-transition matrix
P(next stage | current stage) by following each ATTACKER HOST's progression
through ATTACK stages over time (benign flows skipped), so the K-step
forecast shows real escalation (recon -> foothold -> lateral -> exfil)
instead of staying flat. Output format matches the per-conversation matrix,
so the backend reads it unchanged.

USAGE (PowerShell):
    python estimate_killchain_matrix.py C:\\ml-data\\merged_final_v5.csv
"""
import os, sys, csv, json
import numpy as np

STAGES=["normal","reconnaissance","initial_access","lateral_movement","command_control","exfiltration"]
IDX={s:i for i,s in enumerate(STAGES)}
ALPHA=0.25   # light smoothing: high-but-not-certain probabilities

def main(csv_path, out_path=None):
    if not os.path.exists(csv_path): raise FileNotFoundError(csv_path)
    print(f"Reading {csv_path} (attacker-host kill-chain, benign flows skipped) ...")
    host=dict(); n=0
    with open(csv_path,encoding="utf-8",errors="ignore",newline="") as f:
        r=csv.reader(f); h=[c.strip() for c in next(r)]
        si=h.index("src_ip"); fi=h.index("flow_start"); ti=h.index("attack_stage")
        for row in r:
            n+=1
            if len(row)<=max(si,fi,ti): continue
            st=IDX.get(row[ti].strip().lower())
            if st is None or st==0:   # skip benign: chain attack stages only
                continue
            try: fs=float(row[fi])
            except: fs=0.0
            host.setdefault(row[si],[]).append((fs,st))
            if n%10_000_000==0: print(f"  {n:,} rows...")
    print(f"  {n:,} rows scanned; {len(host):,} attacker hosts. Building chains...")

    counts=np.zeros((6,6),dtype=np.int64); ntr=0; nchain=0
    for ip,flows in host.items():
        flows.sort(key=lambda x:x[0])
        seq=[]
        for _,st in flows:
            if not seq or seq[-1]!=st: seq.append(st)
        if len(seq)>1: nchain+=1
        for a,b in zip(seq,seq[1:]):
            counts[a,b]+=1; ntr+=1

    M=np.zeros((6,6))
    for i in range(6):
        if STAGES[i]=="normal" or counts[i].sum()==0:
            M[i,i]=1.0                                  # normal stays normal; terminal stages stay put
        else:
            sm=counts[i]+ALPHA
            M[i]=sm/sm.sum()                            # high-but-honest transition probs
    if out_path is None:
        out_path=os.path.abspath(os.path.join(os.path.dirname(__file__),"..","models","stage_transition_matrix.json"))
    os.makedirs(os.path.dirname(out_path),exist_ok=True)
    json.dump({"stages":STAGES,"matrix":M.tolist(),"counts":counts.tolist(),
               "source_file":os.path.abspath(csv_path),"n_transitions":int(ntr),
               "mode":"killchain_host_attackonly"}, open(out_path,"w"), indent=2)

    print(f"\n[+] {nchain:,} attacker hosts had a multi-stage chain; {ntr:,} transitions.")
    print(f"[+] Saved {out_path}\n")
    print("KILL-CHAIN  P(next|cur)".ljust(24)+"".join(s[:11].rjust(12) for s in STAGES))
    for i,s in enumerate(STAGES):
        print(s[:22].ljust(24)+"".join(f"{M[i][j]:12.3f}" for j in range(6)))
    print("\nRAW transition counts:")
    for i,s in enumerate(STAGES):
        offs=[(STAGES[j],int(counts[i][j])) for j in range(6) if counts[i][j]>0]
        if offs: print(f"  {s} -> "+", ".join(f"{a}:{c}" for a,c in offs))

if __name__=="__main__":
    p=sys.argv[1] if len(sys.argv)>1 else r"C:\ml-data\merged_final_v5.csv"
    o=sys.argv[2] if len(sys.argv)>2 else None
    main(p,o)
