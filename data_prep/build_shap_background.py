#!/usr/bin/env python3
"""
build_shap_background.py -- Build the SHAP reference ("background") dataset.

SHAP explains a prediction relative to a reference: the average model output on
a background dataset. For an attack-risk model the meaningful reference is
"ordinary benign traffic", so this script samples REAL benign 5-flow windows
from the labeled training corpus and saves them, normalized exactly the way the
model sees them, to models/shap_background_benign.json.

  * A window = 5 consecutive benign flows (sorted by flow_start) between the
    same src_ip -> dst_ip pair -- the same windowing the model is trained on.
  * Windows are taken from random positions across the whole corpus and from
    as many different conversations as possible (at most one per pair).
  * Pure standard library, reads the big CSV by seeking, so it runs in seconds
    even on a multi-GB file.

USAGE
    python data_prep/build_shap_background.py C:\\ml-data\\merged_final_v5.csv
    python data_prep/build_shap_background.py merged.csv --n 100 --seed 42
"""
import argparse
import csv
import io
import json
import math
import os
import random

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
META_PATH = os.path.join(REPO_ROOT, "models", "stage_forecaster_lstm_v1_meta.json")
OUT_PATH = os.path.join(REPO_ROOT, "models", "shap_background_benign.json")


def normalize(window, feat, log_cols, fmin, fmax):
    out = []
    for row in window:
        vec = []
        for i, c in enumerate(feat):
            try:
                v = float(row.get(c) or 0.0)
            except ValueError:
                v = 0.0
            if not math.isfinite(v):
                v = 0.0
            if c in log_cols:
                v = math.log1p(max(v, 0.0))
            v = (v - fmin[i]) / (fmax[i] - fmin[i] + 1e-8)
            vec.append(round(min(max(v, 0.0), 1.0), 6))
        out.append(vec)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--n", type=int, default=100, help="number of background windows")
    ap.add_argument("--chunks", type=int, default=400, help="random positions to sample")
    ap.add_argument("--chunk-bytes", type=int, default=512 * 1024)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    meta = json.load(open(META_PATH))
    feat = meta["feature_columns"]
    log_cols = set(meta["log_transform_columns"])
    fmin = meta["normalizer"]["feature_min"]
    fmax = meta["normalizer"]["feature_max"]
    seq = meta.get("sequence_length", 5)

    rng = random.Random(args.seed)
    size = os.path.getsize(args.csv)
    with open(args.csv, "rb") as fh:
        header = fh.readline().decode("utf-8-sig").strip().split(",")
        candidates = {}  # (src, dst) -> window
        offsets = sorted(rng.randrange(len(",".join(header)) + 1, max(size - args.chunk_bytes, 2))
                         for _ in range(args.chunks))
        for off in offsets:
            fh.seek(off)
            fh.readline()  # skip the partial line
            blob = fh.read(args.chunk_bytes).decode("utf-8", errors="replace")
            blob = blob[: blob.rfind("\n")]
            rows = list(csv.DictReader(io.StringIO(blob), fieldnames=header))
            by_pair = {}
            for r in rows:
                if (r.get("attack_stage") or "").strip() != "normal":
                    continue
                by_pair.setdefault((r["src_ip"], r["dst_ip"]), []).append(r)
            for pair, fl in by_pair.items():
                if pair in candidates or len(fl) < seq:
                    continue
                fl.sort(key=lambda r: float(r.get("flow_start") or 0))
                start = rng.randrange(0, len(fl) - seq + 1)
                candidates[pair] = fl[start:start + seq]

    pairs = sorted(candidates)
    rng.shuffle(pairs)
    chosen = pairs[: args.n]
    if len(chosen) < args.n:
        print(f"[!] only {len(chosen)} distinct benign conversations found; increase --chunks")
    windows = [normalize(candidates[p], feat, log_cols, fmin, fmax) for p in chosen]

    out = {
        "description": "Real benign 5-flow windows (normalized model input) used as the SHAP reference distribution.",
        "source_file": os.path.basename(args.csv),
        "n_windows": len(windows),
        "sequence_length": seq,
        "feature_columns": feat,
        "seed": args.seed,
        "windows": windows,
    }
    with open(OUT_PATH, "w") as f:
        json.dump(out, f)
    print(f"[+] wrote {len(windows)} benign windows from {len(windows)} distinct conversations -> {OUT_PATH}")


if __name__ == "__main__":
    main()
