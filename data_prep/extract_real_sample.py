#!/usr/bin/env python3
"""
extract_real_sample.py -- Pulls a small, GENUINE sample straight out of your
real labeled dataset (e.g. merged_final_v3.csv), instead of using invented
numbers. This guarantees the sample reflects the exact real-world patterns
your model was actually trained on, for each attack stage.

It picks a handful of real (src_ip, dst_ip) conversations for each
attack_stage that has enough consecutive same-label flows to build a
forecasting window (>= 8 flows), and writes them all out to one small csv.

USAGE:
    python extract_real_sample.py merged_final_v3.csv real_sample.csv
    python extract_real_sample.py merged_final_v3.csv real_sample.csv --per-stage 3
"""

import sys
import argparse
import pandas as pd


def main(input_csv, output_csv, per_stage):
    print(f"[*] Scanning {input_csv} for real conversations per attack stage "
          f"(this reads the file in chunks so it doesn't need to fit in memory)...")

    MIN_LEN = 8  # seq_len(5) + horizon(3)
    found = {}   # stage -> list of DataFrames (each one full conversation)
    seen_groups_per_stage = {}

    chunk_iter = pd.read_csv(input_csv, chunksize=500_000)
    for chunk_num, chunk in enumerate(chunk_iter, start=1):
        for (src_ip, dst_ip), group in chunk.groupby(["src_ip", "dst_ip"]):
            if len(group) < MIN_LEN:
                continue
            stages_here = group["attack_stage"].unique()
            if len(stages_here) != 1:
                continue  # only want clean, single-label conversations
            stage = stages_here[0]

            found.setdefault(stage, [])
            if len(found[stage]) >= per_stage:
                continue

            key = (src_ip, dst_ip)
            seen_groups_per_stage.setdefault(stage, set())
            if key in seen_groups_per_stage[stage]:
                continue
            seen_groups_per_stage[stage].add(key)

            found[stage].append(group.sort_values("flow_start").head(MIN_LEN + 2))

        done_stages = [s for s, lst in found.items() if len(lst) >= per_stage]
        print(f"    ...scanned chunk {chunk_num} "
              f"({sum(len(v) for v in found.values())} conversations found so far "
              f"across {len(found)} stages)")

        # stop early once every stage we've SEEN AT LEAST ONCE has enough --
        # note: this can't know about stages it hasn't encountered yet, so it
        # will scan the whole file if a stage is rare (e.g. reconnaissance).
        if chunk_num >= 200:  # hard safety cap so this never runs forever
            print("[*] Hit safety scan limit -- stopping early with what's found.")
            break

    if not found:
        print("[!] No clean conversations found at all. Check the file has "
              "src_ip/dst_ip/flow_start/attack_stage columns.")
        sys.exit(1)

    print("\n[+] Found real examples for these stages:")
    for stage, lst in found.items():
        print(f"      {stage}: {len(lst)} conversation(s)")

    missing_common = [s for s in ["normal", "initial_access", "lateral_movement", "command_control"]
                       if s not in found]
    if missing_common:
        print(f"[!] Note: found nothing for {missing_common} in the scanned portion -- "
              f"they may be rarer/later in the file. Re-run with a higher --chunks-limit "
              f"if you need them.")

    all_groups = [g for lst in found.values() for g in lst]
    out_df = pd.concat(all_groups, ignore_index=True)
    out_df.to_csv(output_csv, index=False)
    print(f"\n[+] Wrote {len(out_df):,} real rows ({len(all_groups)} conversations) to {output_csv}")
    print("[+] This is REAL data the model was trained on the same DISTRIBUTION of -- "
          "use this with evaluate_predictions.py for a meaningful right/wrong check.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_csv")
    parser.add_argument("output_csv")
    parser.add_argument("--per-stage", type=int, default=3, help="How many conversations to grab per attack stage")
    args = parser.parse_args()
    main(args.input_csv, args.output_csv, args.per_stage)
