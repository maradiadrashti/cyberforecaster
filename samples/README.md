# samples/

Files you can upload on the dashboard's **File Upload** page straight after cloning.

| File | What it is |
|---|---|
| `real_sample_v4.csv` | 108 labelled flows from 7 hosts, cut from the CSE-CIC-IDS2018 part of the training data. A quick smoke test: it is small and its hosts have only a few windows each. |
| `darpa2000_lldos_inside_slice.pcap` | 15 minutes (7 March 2000, 14:40–14:55 UTC) cut from the public DARPA 2000 LLDOS 1.0 "inside" capture: 51,704 packets, 10,012 flows, 91 hosts, 11 MB. Use it to try the PCAP path. This network is **not** in the training data and the file has no labels, so the result (12 hosts flagged) is not checked against ground truth. |
| `test_files/` | Four labelled files cut from hours that were held back from training. Use these to see the model work; expected results are in [`test_files/README.md`](test_files/README.md). |

The upload page accepts `.csv`, `.pcap` and `.pcapng`. A CSV must contain source IP, destination IP and a time for
every flow (the model works per source host, on the order of events). Files without them are refused with the reason.
