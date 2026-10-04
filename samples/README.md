# samples/

Files you can upload on the dashboard's **File Upload** page straight after cloning.

| File | What it is |
|---|---|
| `real_sample_v4.csv` | 108 labelled flows from 7 hosts, cut from the CSE-CIC-IDS2018 part of the training data. A quick smoke test: it is small and its hosts have only a few windows each. |
| `darpa2000_lldos_inside_slice.pcap` | 15 minutes (7 March 2000, 14:40–14:55 UTC) cut from the public DARPA 2000 LLDOS 1.0 "inside" capture: 51,704 packets, 10,012 flows, 91 hosts, 11 MB. Use it to try the PCAP path. This network is **not** in the training data and the file has no labels, so the dashboard cannot score it. The complete capture was scored separately against the dataset's attack-phase lists: see `docs/RESULTS_world_model_v5.md` (the model is weak on it). |
| `demo_unraveled_heldback.csv` (13 MB) | **Demo file.** Four complete hours of the Unraveled network (22, 25, 30 June and 2 July 2021), all held back from training. 68,054 flows, 89 hosts, four attack stages: reconnaissance (10.8.10.87), lateral movement (192.168.0.11), command and control and exfiltration (10.1.3.8, 10.1.3.17). Model result: 90% of attack windows alerted, stage correct on 96%, the four attacking hosts are the four highest-risk hosts; 13% of the windows of clean hosts are false alarms. |
| `demo_unraveled_5_stages.csv` (18 MB) | The same four hours plus 29 June 06:00, which adds initial access (10.8.10.87). **That fifth hour was part of the training data**, so the model has seen it. 91,851 flows, all five stages. Model result: 94% of attack windows alerted, stage correct on 97%; 15% false alarms on clean hosts. |
| `test_files/` | Four labelled files cut from hours that were held back from training. Use these to see the model work; expected results are in [`test_files/README.md`](test_files/README.md). |

The upload page accepts `.csv`, `.pcap` and `.pcapng`. A CSV must contain source IP, destination IP and a time for
every flow (the model works per source host, on the order of events). Files without them are refused with the reason.
