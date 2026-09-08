#!/usr/bin/env python3
"""GRU Stage Forecaster training on CIC-IDS2017 — fast version with 200K subsample."""

import os, csv, json, warnings
from datetime import datetime
from collections import Counter
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import torch, torch.nn as nn, torch.optim as optim
from torch.utils.data import Dataset, DataLoader

warnings.filterwarnings('ignore')

STAGES = ['normal','reconnaissance','initial_access','lateral_movement','command_control','exfiltration']
NUM_STAGES = 6; NUM_F = 14; SEQ = 10; HIDDEN = 64; LAYERS = 2; DROP = 0.2
BATCH = 128; LR = 0.001; EPOCHS = 40

def sf(v):
    if v is None or v.strip() == '': return 0.0
    try:
        fv = float(v)
        return 0.0 if fv != fv or abs(fv) == float('inf') else fv
    except: return 0.0

def map_stage(raw):
    s = raw.strip().lower()
    if s in ('benign', ''): return 0
    if 'portscan' in s or 'xss' in s or 'sql injection' in s: return 1
    if 'patator' in s or 'brute force' in s: return 2
    if 'bot' in s: return 3
    if 'ddos' in s or 'dos' in s or 'heartbleed' in s: return 4
    if 'infiltration' in s: return 5
    return 0

# ── Import CIC-IDS2017 ───────────────────────────────────────────────────
print('Importing CIC-IDS2017...')
base = r'C:\Users\htc\Downloads\MachineLearningCSV\MachineLearningCVE'
all_f, all_s = [], []
for fname in sorted(os.listdir(base)):
    if not fname.endswith('.csv'): continue
    with open(os.path.join(base, fname), 'r', errors='replace') as fh:
        reader = csv.DictReader(fh)
        reader.fieldnames = [k.strip() for k in reader.fieldnames]
        cnt = 0
        for row in reader:
            row = {k.strip(): v for k, v in row.items()}
            stage = map_stage(row.get('Label', ''))
            dur = sf(row.get('Flow Duration', 0))
            if dur > 1e6: dur /= 1e6
            fp, bp = sf(row.get('Total Fwd Packets', 0)), sf(row.get('Total Backward Packets', 0))
            pkts = max(fp + bp, 1)
            fb, bb = sf(row.get('Total Length of Fwd Packets', 0)), sf(row.get('Total Length of Bwd Packets', 0))
            byte_count = max(fb + bb, 1)
            dur_safe = max(dur, 0.001)
            all_f.append([
                dur, pkts, byte_count, 0, sf(row.get('Destination Port', 0)),
                pkts/dur_safe, byte_count/pkts,
                1 if sf(row.get('SYN Flag Count', 0)) > 0 else 0,
                1 if sf(row.get('ACK Flag Count', 0)) > 0 else 0,
                1 if sf(row.get('RST Flag Count', 0)) > 0 else 0,
                1 if sf(row.get('FIN Flag Count', 0)) > 0 else 0,
                1, 0, 0,
            ])
            all_s.append(stage); cnt += 1
    print(f'  {fname}: {cnt:,}')

all_f = np.array(all_f, dtype=np.float32)
all_s = np.array(all_s, dtype=np.int64)
print(f'Total: {len(all_f):,}')
for i, n in enumerate(STAGES):
    c = (all_s == i).sum()
    print(f'  {n}: {c:,} ({c/len(all_s)*100:.1f}%)')

# ── Stratified subsample 200K ────────────────────────────────────────────
target = 200000
idx_per_class = {}
rng = np.random.RandomState(42)
for i in range(NUM_STAGES):
    cls_idx = np.where(all_s == i)[0]
    n = min(len(cls_idx), max(1, int(target * len(cls_idx) / len(all_s))))
    idx_per_class[i] = rng.choice(cls_idx, n, replace=False)
sel = np.concatenate(list(idx_per_class.values()))
rng.shuffle(sel)
X_all, y_all = all_f[sel], all_s[sel]
print(f'Sampled: {len(X_all):,}')

# ── Build sequences ───────────────────────────────────────────────────────
print('Building temporal sequences...')
stage_w = [0.0, 0.2, 0.5, 0.7, 0.8, 1.0]
order = np.argsort(X_all[:, 0])  # sort by duration
X_sorted, y_sorted = X_all[order], y_all[order]
seqs, labels, risks = [], [], []
step = SEQ  # no overlap for speed
for start in range(0, len(X_sorted) - SEQ + 1, step):
    w = X_sorted[start:start+SEQ]
    ws = y_sorted[start:start+SEQ]
    cnts = Counter(ws)
    maj = cnts.most_common(1)[0][0]
    label = maj if maj > 0 else max(ws)
    risk = sum(stage_w[s] for s in ws) / len(ws)
    seqs.append(w); labels.append(label); risks.append([risk])

seqs = np.array(seqs, dtype=np.float32)
labels = np.array(labels, dtype=np.int64)
risks = np.array(risks, dtype=np.float32)
print(f'Sequences: {len(seqs):,}')
for i, n in enumerate(STAGES):
    c = (labels == i).sum()
    print(f'  {n}: {c:,} ({c/len(labels)*100:.1f}%)')

# ── Normalize ─────────────────────────────────────────────────────────────
fmin = np.array([0,1,1,0,0,0,0,0,0,0,0,0,0,0], dtype=np.float32)
fmax = np.array([300,10000,5000000,65535,65535,50000,1500,1,1,1,1,1,1,1], dtype=np.float32)
seqs_n = (seqs - fmin) / (fmax - fmin + 1e-8)

# ── Split ─────────────────────────────────────────────────────────────────
# Check if stratified split is possible (need >=2 samples per class)
min_class = min(Counter(labels).values())
stratify_arg = labels if min_class >= 2 else None
if stratify_arg is None:
    print('  Warning: some classes have <2 samples, using random split')
Xtr, Xte, ytr, yte, rtr, rte = train_test_split(seqs_n, labels, risks, test_size=0.15, random_state=42, stratify=stratify_arg)
min_class_tr = min(Counter(ytr).values()) if len(ytr) > 0 else 0
stratify_arg2 = ytr if min_class_tr >= 2 else None
Xtr, Xva, ytr, yva, rtr, rva = train_test_split(Xtr, ytr, rtr, test_size=0.176, random_state=42, stratify=stratify_arg2)
print(f'Train: {len(Xtr):,} | Val: {len(Xva):,} | Test: {len(Xte):,}')

# ── Model ─────────────────────────────────────────────────────────────────
class GRU(nn.Module):
    def __init__(self):
        super().__init__()
        self.gru = nn.GRU(NUM_F, HIDDEN, LAYERS, batch_first=True, dropout=DROP if LAYERS > 1 else 0)
        self.drop = nn.Dropout(DROP)
        self.stage_head = nn.Sequential(nn.Linear(HIDDEN, 32), nn.ReLU(), nn.Dropout(DROP), nn.Linear(32, NUM_STAGES))
        self.risk_head = nn.Sequential(nn.Linear(HIDDEN, 16), nn.ReLU(), nn.Linear(16, 1), nn.Sigmoid())
    def forward(self, x, h=None):
        o, h = self.gru(x, h)
        l = self.drop(o[:, -1, :])
        return self.stage_head(l), self.risk_head(l), h

model = GRU()
print(f'Model: {sum(p.numel() for p in model.parameters()):,} params')

sc = nn.CrossEntropyLoss()
rc = nn.MSELoss()
opt = optim.Adam(model.parameters(), lr=LR, weight_decay=1e-5)
sched = optim.lr_scheduler.ReduceLROnPlateau(opt, 'min', 0.5, 5)

class DS(Dataset):
    def __init__(s, a, b, c): s.x = torch.tensor(a); s.y = torch.tensor(b); s.r = torch.tensor(c)
    def __len__(s): return len(s.x)
    def __getitem__(s, i): return s.x[i], s.y[i], s.r[i]

tl = DataLoader(DS(Xtr, ytr, rtr), BATCH, shuffle=True)
vl = DataLoader(DS(Xva, yva, rva), BATCH)
tesl = DataLoader(DS(Xte, yte, rte), BATCH)

# ── Train ─────────────────────────────────────────────────────────────────
print(f'Training {EPOCHS} epochs...')
best_vl = float('inf'); best_st = None; pc = 0

for ep in range(EPOCHS):
    model.train(); tc = 0; tt = 0
    for bx, bs, br in tl:
        opt.zero_grad()
        sl, rp, _ = model(bx)
        loss = sc(sl, bs) * 2 + rc(rp, br)
        loss.backward(); torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0); opt.step()
        _, p = torch.max(sl.data, 1); tc += (p == bs).sum().item(); tt += len(bx)

    model.eval(); vc = 0; vt = 0; vs = 0; vr = 0
    with torch.no_grad():
        for bx, bs, br in vl:
            sl, rp, _ = model(bx)
            vs += sc(sl, bs).item() * len(bx); vr += rc(rp, br).item() * len(bx)
            _, p = torch.max(sl.data, 1); vc += (p == bs).sum().item(); vt += len(bx)

    vtl = vs / max(vt, 1) * 2 + vr / max(vt, 1)
    sched.step(vtl)
    if vtl < best_vl:
        best_vl = vtl
        best_st = {k: v.clone() for k, v in model.state_dict().items()}
        pc = 0
    else:
        pc += 1
    if (ep + 1) % 5 == 0 or ep == 0:
        print(f'  Ep {ep+1:3d}/{EPOCHS} TrAcc:{tc/tt:.3f} VaAcc:{vc/vt:.3f} LR:{opt.param_groups[0]["lr"]:.6f}')
    if pc >= 10:
        print(f'  Early stop at {ep+1}')
        break

if best_st:
    model.load_state_dict(best_st)

# ── Test ──────────────────────────────────────────────────────────────────
model.eval(); ap = []; aa = []
with torch.no_grad():
    for bx, bs, _ in tesl:
        sl, _, _ = model(bx)
        _, p = torch.max(sl.data, 1)
        ap.extend(p.cpu().numpy()); aa.extend(bs.cpu().numpy())
acc = sum(p == a for p, a in zip(ap, aa)) / len(aa)
print(f'\nTest Accuracy: {acc:.4f}')
pres = sorted(set(aa) | set(ap))
nms = [STAGES[i] for i in pres]
report = classification_report(aa, ap, labels=pres, target_names=nms, zero_division=0)
for l in report.split('\n'):
    print(f'  {l}')

# ── Save ──────────────────────────────────────────────────────────────────
out = '../models'
os.makedirs(out, exist_ok=True)
torch.save({
    'model_state_dict': model.state_dict(),
    'model_config': {'input_size': NUM_F, 'hidden_size': HIDDEN, 'num_layers': LAYERS, 'num_stages': NUM_STAGES, 'dropout': DROP},
}, os.path.join(out, 'stage_forecaster_v1.pth'))

meta = {
    'version': 'v1', 'created': datetime.now().isoformat(), 'stages': STAGES,
    'num_features': NUM_F, 'sequence_length': SEQ,
    'model_config': {'input_size': NUM_F, 'hidden_size': HIDDEN, 'num_layers': LAYERS, 'num_stages': NUM_STAGES, 'dropout': DROP},
    'normalizer': {'feature_min': fmin.tolist(), 'feature_max': fmax.tolist()},
    'forecast_horizon_seconds': 30, 'test_accuracy': acc,
    'training_notes': 'Trained on CIC-IDS2017 (2.83M flows, 200K subsample). Temporal sequences via sliding windows over duration-sorted flows.',
    'label_mapping': {
        'BENIGN': 'normal', 'PortScan': 'reconnaissance',
        'FTP-Patator': 'initial_access', 'SSH-Patator': 'initial_access',
        'DDoS': 'command_control', 'DoS Hulk': 'command_control',
        'Bot': 'lateral_movement', 'Infiltration': 'exfiltration',
    },
}
with open(os.path.join(out, 'stage_forecaster_v1_meta.json'), 'w') as f:
    json.dump(meta, f, indent=2)
print(f'\nSaved to {out}')
print(f'Test Accuracy: {acc:.4f}')
