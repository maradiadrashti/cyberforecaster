# samples/

Small files you can upload on the dashboard's **File Upload** page straight after cloning.

| File | What it is | What to expect |
| :--- | :--- | :--- |
| `real_sample_v4.csv` | 108 real labeled flows (11 conversations) cut from the CSE-CIC-IDS-2018 part of the training corpus, already in the app's schema. | A mix of normal and attack conversations; the highest-risk one opens first on **Attack Forecast**. |
| `cic2017_webattacks_sample.csv` | 500 flows from **CIC-IDS-2017 Web Attacks** (250 benign, 250 attack; 2 conversations) in the app's schema — a dataset the LSTM never trained on. IPs are reconstructed (the public CSV has none): attacks use the documented attacker → victim pair, benign flows an invented sender. | Attack conversations forecast as **Initial Access**. |
| `cicflowmeter_raw_sample.csv` | 150 **raw CICFlowMeter** rows (80 benign, 70 web brute-force) with the original 80+ column names. | Shows the CSV adapter: converted to the schema automatically on upload (TTL imputed to 64, with a warning in the backend log). |
| `test_sample.pcap` | A tiny PCAP. | Exercises the PCAP → flow extraction path. |

`../sample_test_flows.csv` is used by `predict_csv.py` and the automated tests.
