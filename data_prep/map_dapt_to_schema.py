#!/usr/bin/env python3
"""map_dapt_to_schema.py -- DAPT-2020 CICFlowMeter CSVs -> CyberForecaster
15-feature schema (24 cols) with 6-stage labels. Robust to files with or
without a header row; Stage/Activity read by fixed position (last two cols)."""
import os, sys, glob, csv, calendar
from datetime import datetime

OUT_COLS = ["src_ip","dst_ip","src_port","dst_port","protocol","flow_start","flow_end",
            "duration","packet_count","byte_count","syn_count","ack_count","fin_count",
            "rst_count","ttl_mean","ttl_var","win_mean","win_var","frag_ratio",
            "payload_mean","payload_std","retransmit_count","label","attack_stage"]
STAGE_MAP = {"benign":"normal","":"normal",
    "reconnaissance":"reconnaissance","establish foothold":"initial_access",
    "lateral movement":"lateral_movement","data exfiltration":"exfiltration",
    "command and control":"command_control","command & control":"command_control"}

def norm(s): return "".join(ch for ch in s.strip().lower() if ch.isalnum())
def num(v):
    try:
        f=float(v)
        return 0.0 if (f!=f or f in (float("inf"),float("-inf"))) else f
    except Exception: return 0.0
def parse_ts(v):
    v=v.strip()
    for fmt in ("%d/%m/%Y %I:%M:%S %p","%d/%m/%Y %H:%M:%S","%m/%d/%Y %I:%M:%S %p","%Y-%m-%d %H:%M:%S"):
        try: return float(calendar.timegm(datetime.strptime(v,fmt).timetuple()))
        except Exception: continue
    return 0.0
def proto_name(v):
    v=str(v).strip()
    return {"6":"TCP","17":"UDP","1":"ICMP"}.get(v,"TCP" if v.upper()=="TCP" else (v.upper() or "OTHER"))

def build_idx(header):
    cn={norm(h):i for i,h in enumerate(header)}
    def find(*cands):
        for c in cands:
            n=norm(c)
            if n in cn: return cn[n]
        for c in cands:
            n=norm(c)
            for k,i in cn.items():
                if k.startswith(n): return i
        return None
    return {
        "src":find("Src IP"),"dst":find("Dst IP"),"sp":find("Src Port"),"dp":find("Dst Port"),
        "pr":find("Protocol"),"ts":find("Timestamp"),"dur":find("Flow Duration"),
        "fp":find("Total Fwd Packet","Total Fwd Packets"),"bp":find("Total Bwd packets","Total Bwd Packets"),
        "flb":find("Total Length of Fwd Packet"),"blb":find("Total Length of Bwd Packet"),
        "syn":find("SYN Flag Count"),"ack":find("ACK Flag Count"),
        "fin":find("FIN Flag Count"),"rst":find("RST Flag Count"),
        "win":find("FWD Init Win Bytes","Init_Win_bytes_forward"),
        "pmean":find("Average Packet Size","Packet Length Mean"),"pstd":find("Packet Length Std"),
    }

def main(dapt_dir,out_path):
    files=sorted(glob.glob(os.path.join(dapt_dir,"csv","*.pcap_Flow.csv")))
    if not files: print(f"[!] No csv/*.pcap_Flow.csv under {dapt_dir}"); sys.exit(1)
    # canonical column map from the first file that HAS a header
    canon=None
    for path in files:
        with open(path,encoding="utf-8",errors="ignore",newline="") as f:
            line=f.readline()
        if "Src IP" in line:
            canon=build_idx(next(csv.reader([line]))); break
    if canon is None: print("[!] No headered file found to learn layout"); sys.exit(1)

    stage_counts={}; n_out=0; per_file={}
    with open(out_path,"w",newline="",encoding="utf-8") as fout:
        w=csv.writer(fout); w.writerow(OUT_COLS)
        for path in files:
            with open(path,encoding="utf-8",errors="ignore",newline="") as fin:
                r=csv.reader(fin); rows=iter(r)
                first=next(rows)
                if len(first)>=8 and any("Src IP"==c for c in first):
                    idx=build_idx(first)            # has header
                    data_first=None
                else:
                    idx=canon                       # headerless: reuse canonical layout
                    data_first=first
                def emit(row):
                    nonlocal n_out
                    if not row or len(row)<8: return
                    stage_raw=row[-1].strip().lower()        # Stage = LAST column (fixed)
                    stage=STAGE_MAP.get(stage_raw,"normal")
                    stage_counts[stage]=stage_counts.get(stage,0)+1
                    per_file[os.path.basename(path)]=per_file.get(os.path.basename(path),{})
                    per_file[os.path.basename(path)][stage]=per_file[os.path.basename(path)].get(stage,0)+1
                    g=lambda k,d="": row[idx[k]] if (idx.get(k) is not None and idx[k]<len(row)) else d
                    dur_s=num(g("dur"))/1_000_000.0
                    fs=parse_ts(g("ts"))
                    pkts=num(g("fp"))+num(g("bp")); byts=num(g("flb"))+num(g("blb"))
                    act=row[-2].strip() if len(row)>=2 else ""
                    label=act or ("Benign" if stage=="normal" else stage_raw.title())
                    w.writerow([g("src").strip(),g("dst").strip(),int(num(g("sp"))),int(num(g("dp"))),
                        proto_name(g("pr")),f"{fs:.3f}",f"{fs+dur_s:.3f}",f"{dur_s:.6f}",
                        int(pkts),int(byts),int(num(g("syn"))),int(num(g("ack"))),
                        int(num(g("fin"))),int(num(g("rst"))),0,0,round(num(g("win")),3),0,0.0,
                        round(num(g("pmean")),3),round(num(g("pstd")),3),0,label,stage]); n_out+=1
                if data_first is not None: emit(data_first)
                for row in rows: emit(row)
            print(f"    processed {os.path.basename(path)}: "+", ".join(f"{k}={v}" for k,v in sorted(per_file.get(os.path.basename(path),{}).items())))
    print(f"\n[+] Wrote {n_out:,} rows to {out_path}")
    print("[+] attack_stage counts:")
    for k,v in sorted(stage_counts.items(),key=lambda x:-x[1]): print(f"      {k:<18} {v:,}")

if __name__=="__main__":
    dapt=sys.argv[1] if len(sys.argv)>1 else r"C:\ml-data\dapt2020-main"
    out =sys.argv[2] if len(sys.argv)>2 else r"C:\ml-data\dapt_mapped_v1.csv"
    main(dapt,out)
