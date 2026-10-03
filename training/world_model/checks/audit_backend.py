"""Backend consistency audit (no PyTorch): everything in the saved result that can be recomputed without the
neural network is recomputed with separate code and compared."""
import os as _os
from pathlib import Path as _P
REPO = _P(_os.environ.get("CYBERFORECASTER_REPO") or _P(__file__).resolve().parents[3])   # repository root
import json, sys, math
from pathlib import Path
import numpy as np, pandas as pd
import sys
sys.path.insert(0, str(REPO / 'capture-service'))
import world_model as f
MD = REPO / 'models' / 'world_model'
f.MODEL_DIR = MD
meta = json.load(open(MD / 'world_model_meta.json')); bl = json.load(open(MD / 'baseline_lr.json')); PR = json.load(open(MD / 'stage_progression.json'))
FE, L, K, CL = meta['features'], meta['L'], meta['K'], meta['classes']
T = REPO / 'samples' / 'test_files'
name = sys.argv[1]; R = json.load(open(name + '.json')); C = R['chart']; thr = C['threshold']
fails, checks = [], {}
def chk(k, ok, detail=''):
    c = checks.setdefault(k, [0, 0]); c[0] += 1
    if not ok:
        c[1] += 1
        if len([x for x in fails if x[0] == k]) < 3: fails.append((k, detail))
def close(a, b, tol=2e-4): return (a is None and b is None) or (a is not None and b is not None and abs(float(a) - float(b)) <= tol)

fl, kind, notes = f.load_flows(str(T / (name + '.csv'))); W, has_labels = f.build_windows(fl)
# ---- independent standardisation + history indexing
X = W[FE].to_numpy(np.float64).copy()
for j in meta['log_idx']: X[:, j] = np.log1p(np.clip(X[:, j], 0, None))
Xs = (X - np.array(meta['mean'])) / np.array(meta['std']); Xs = np.clip(Xs, -6, 6); Xs[np.isnan(Xs)] = 0.0
hosts = W['host_ip'].to_numpy(); win = W['win'].to_numpy()
seg = np.zeros(len(W), int)
for i in range(1, len(W)):
    seg[i] = seg[i - 1] if (hosts[i] == hosts[i - 1] and win[i] - win[i - 1] <= 12) else i
def hist(i): return [max(i - L + 1 + k, seg[i]) for k in range(L)]
coef = np.array(bl['coef']); names = {-1: 'ambiguous', **{i: s for i, s in enumerate(f.STAGES)}}
thr_meta = [v for k, v in meta['thresholds'].items() if k.startswith('WORLD MODEL (ensemble') and k.endswith(f'|{K}|all')][0]
chk('alert threshold = value saved at training', close(thr, thr_meta, 1e-9), f'{thr} vs {thr_meta}')
chk('windows / hosts / flows counts', R['windows'] == len(W) and R['hosts'] == W.host_ip.nunique() and R['flows'] == len(fl))
ca = R.get('check_against_labels_in_file') or {}
if has_labels:
    chk('label counts', ca.get('windows_truly_attack') == int((W.stage_id >= 1).sum()) and ca.get('windows_truly_normal') == int((W.stage_id == 0).sum()), str(ca))
peaks = {}
for ip, H in C['hosts'].items():
    idx = np.where(hosts == ip)[0]; n = len(idx)
    chk('host window count', n == len(H['time']) == len(H['risk_60s']), ip)
    tt = pd.to_datetime(W['t0'].to_numpy()[idx], unit='s').strftime('%Y-%m-%d %H:%M:%S').tolist()
    chk('window times', tt == H['time'], ip)
    chk('flows per window', [int(x) for x in W['n_flows'].to_numpy()[idx]] == H['flows'], ip)
    if has_labels: chk('true stage per window', [names[int(s)] for s in W['stage_id'].to_numpy()[idx]] == H['true_stage'], ip)
    peaks[ip] = max(H['risk_60s'])
    for a, i in enumerate(idx):
        z = float(Xs[hist(i)].reshape(-1) @ coef + bl['intercept']); b = 1 / (1 + math.exp(-max(-30, min(30, z))))
        chk('baseline line (recomputed from saved coefficients)', close(H['baseline_risk_60s'][a], b, 2e-4), f"{ip} w{a}: {H['baseline_risk_60s'][a]} vs {b:.4f}")
        r60, cur = H['risk_60s'][a], H['forecast_curve'][a]
        if abs(r60 - thr) > 1e-4: chk('alert flag = risk at or above threshold', H['alert'][a] == (r60 >= thr), f'{ip} w{a} {r60}')
        chk('risk 10 s = first forecast step; risk 60 s = last', close(H['risk_10s'][a], cur[0]) and close(r60, cur[-1]), f'{ip} w{a}')
        chk('forecast steps never decrease', all(cur[k] <= cur[k + 1] + 1e-4 for k in range(K - 1)), f'{ip} w{a} {cur}')
        lo, hi = H['forecast_curve_min'][a], H['forecast_curve_max'][a]
        chk('forecast inside the range of the 3 copies', all(lo[k] - 2e-4 <= cur[k] <= hi[k] + 2e-4 for k in range(K)), f'{ip} w{a}')
        chk('stage now = first stage step', H['stage_now'][a] == H['stage_forecast'][a][0], f'{ip} w{a}')
        chk('short-history flag', H['short_history'][a] == ((i - seg[i] + 1) < L), f'{ip} w{a}')
        for Hs, arr in (H.get('start_soon') or {}).items(): chk('start-soon values between 0 and 1', 0 <= arr[a] <= 1)
    for tag, a in (('last', n - 1), ('peak', H['peak_window_index'])):
        D = np.array(H['stage_dist_' + tag])
        chk('peak window holds the highest risk', tag == 'last' or H['risk_60s'][a] == max(H['risk_60s']), ip)
        chk('stage per step = most probable class', [CL[j] for j in D.argmax(1)] == H['stage_forecast'][a], f'{ip} {tag}')
        chk('stage probability per step', all(close(H['stage_forecast_prob'][a][k], D[k].max(), 1.1e-3) for k in range(K + 1)), f'{ip} {tag}')
        s2 = np.sort(D, 1)[:, -2]
        chk('second choice probability', all(close(H['stage_forecast_second_prob'][a][k], s2[k], 1.1e-3) for k in range(K + 1)), f'{ip} {tag}')
        chk('stage probabilities sum to 1', all(abs(D[k].sum() - 1) < 6e-3 for k in range(K + 1)), f'{ip} {tag} {D.sum(1)}')
        av = D[:, 1:].mean(0); order = np.argsort(-av)
        if av[order[0]] - av[order[1]] > 2e-3:
            chk('averaged stage (shown when alerting)', CL[order[0] + 1] == H['likely_attack_stage'][a], f"{ip} {tag}: {CL[order[0]+1]} vs {H['likely_attack_stage'][a]}")
        chk('averaged stage probability', close(H['likely_attack_stage_prob'][a], av.max(), 1.5e-3), f"{ip} {tag}: {H['likely_attack_stage_prob'][a]} vs {av.max():.4f}")
    # ---- attribution inputs
    for tag, a in (('last', n - 1), ('peak', H['peak_window_index'])):
        A = H.get('attribution_' + tag) or {}
        if A.get('error') or not A.get('features'): chk('attribution present', False, f"{ip} {tag} {A.get('error')}"); continue
        i = idx[a]
        chk('attribution risk = risk of that window', close(A['risk_60s'], H['risk_60s'][a], 2e-4), f"{ip} {tag}: {A['risk_60s']} vs {H['risk_60s'][a]}")
        cs = [abs(x['contribution']) for x in A['features']]
        chk('attribution sorted by size', all(cs[k] >= cs[k + 1] - 1e-9 for k in range(len(cs) - 1)), f'{ip} {tag}')
        tot = sum(abs(v) for v in A['by_group'].values())
        for x in A['features']:
            j = FE.index(x['feature']); raw = W[FE].to_numpy()[i, j]
            chk('attribution: observed feature value', (x['value'] is None and not np.isfinite(raw)) or (x['value'] is not None and abs(x['value'] - raw) <= 1e-4 + 1e-4 * abs(raw)), f"{ip} {tag} {x['feature']}: {x['value']} vs {raw}")
            chk('attribution: standardised value', close(x['standardised'], Xs[i, j], 1.1e-3), f"{ip} {tag} {x['feature']}")
            chk('attribution: group label', x['feature'] in meta['groups'].get(x['group'], []), f"{ip} {x['feature']} {x['group']}")
            chk('attribution: share between 0 and 1', 0 <= x['share'] <= 1)
        r = [x['share'] / abs(x['contribution']) for x in A['features'] if abs(x['contribution']) > 0.003]
        if len(r) > 1: chk('attribution: shares proportional to contributions', max(r) / min(r) < 1.15, f'{ip} {tag} {r[:3]}')
    # ---- progression (tree + MITRE cards), recomputed from the counts file
    P = H['progression']; D = np.array(H['stage_dist_last']); row = D[0] if D[0][1:].sum() >= 0.5 else D[-1]
    chk('tree shown only when an attack stage is seen', P.get('available') == (row[1:].sum() >= 0.5) or abs(row[1:].sum() - 0.5) < 2e-3, f'{ip} {row[1:].sum():.3f}')
    if P.get('available'):
        av = D[:, 1:].mean(0); st = sorted(((CL[j + 1], av[j]) for j in range(len(av))), key=lambda t: -t[1]); st = [s for s in st if s[1] / av.sum() >= 0.10][:2]
        roots = [nd for nd in P['nodes'] if nd['parent'] is None]
        chk('tree: starting stages and their probability', [s[0] for s in st] == [nd['stage'] for nd in roots] and all(close(s[1], nd['prob'], 1.1e-3) for s, nd in zip(st, roots)) or (len(st) > 1 and abs(st[0][1] - st[1][1]) < 2e-3), f"{ip}: {st} vs {[(n_['stage'], n_['prob']) for n_ in roots]}")
        byid = {nd['id']: nd for nd in P['nodes']}
        for nd in P['nodes']:
            if nd['parent'] is None: continue
            par = byid[nd['parent']]; path = []; q = par
            while q is not None: path.append(q['stage']); q = byid.get(q['parent']) if q['parent'] is not None else None
            cand = {b: v for b, v in PR['stages'].get(par['stage'], {}).get('next', {}).items() if b not in path}
            tot = sum(v['count'] for v in cand.values()); v = cand.get(nd['stage'])
            chk('tree: branch counts, probability and delay from the counts file', v is not None and nd['observed'] == v['count'] and nd['observed_total'] == tot and close(nd['prob'], v['count'] / tot, 6e-4) and close(nd['median_delay_min'], v['median_delay_min'], 0.06), f"{ip} {par['stage']}->{nd['stage']}")
        mp = P['most_likely_path']; ok = True
        for a_, b_ in zip(mp, mp[1:]):
            kids = [nd for nd in P['nodes'] if nd['parent'] == a_]; ok &= byid[b_]['prob'] == max(k_['prob'] for k_ in kids)
        chk('tree: gold path follows the most frequent branch', ok and [s['stage'] for s in P['steps']] == [byid[i]['stage'] for i in mp], ip)
        chk('MITRE cards = gold path', all(close(s['prob'], byid[i]['prob'], 1e-9) and s.get('observed') == byid[i].get('observed') for s, i in zip(P['steps'], mp)), ip)
        for s in P['steps']: chk('MITRE mapping exists for every stage shown', s['stage'] in C['mitre'], s['stage'])
order = sorted(peaks, key=lambda h: -peaks[h])
chk('host order = highest peak risk first', all(peaks[a] >= peaks[b] - 1e-9 for a, b in zip(C['host_order'], C['host_order'][1:])) and set(order) == set(C['host_order']))
for th in R['top_hosts']:
    if th['host_ip'] in C['hosts']:
        H = C['hosts'][th['host_ip']]
        chk('top-host table', close(th['peak_risk_60s'], max(H['risk_60s']), 2e-4) and th['alert_windows'] == sum(H['alert']) and th['windows'] == len(H['time']), th['host_ip'])
print(f"\n=== {name}: {len(C['hosts'])} hosts, {sum(len(h['time']) for h in C['hosts'].values())} windows checked")
for k, (n_, bad) in checks.items(): print(f"  {'OK  ' if bad == 0 else 'FAIL'} {k}: {n_ - bad}/{n_}")
for k, d in fails: print('   !!', k, '|', d)
