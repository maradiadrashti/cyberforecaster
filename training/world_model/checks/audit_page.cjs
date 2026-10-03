// Usage: node audit_page.cjs <prefix of *_v1.json> <path of the world-model result without .json>
//   (both files come from checks/run_upload_all.py). Set ALLW=1 to check every window of every charted host.
// Page audit: render the real page with the real backend output and compare every displayed value with an
// independent calculation from the backend JSON.
const fs=require('fs'),path=require('path'),Module=require('module');
const REPO=process.env.CYBERFORECASTER_REPO||path.resolve(__dirname,'..','..','..');
const NM=path.join(REPO,'client','node_modules')+path.sep;
const {transform}=require(NM+'sucrase'); const React=require(NM+'react'); const {renderToString}=require(NM+'react-dom/server');
const tag=process.argv[2], stem=process.argv[3];
global.__v1=JSON.parse(fs.readFileSync(tag+'_v1.json','utf8')); if(process.env.NOFLOWS) 0; global.__v2=JSON.parse(fs.readFileSync(stem+'.json','utf8')); global.__v2.status='success';
let src=fs.readFileSync(process.env.JSX||path.join(REPO,'client','src','pages','AttackForecast.jsx'),'utf8');
const R=(a,b)=>{ if(!src.includes(a)) throw new Error('harness: marker not found: '+a); src=src.replace(a,b); };
R('const [latestData, setLatestData] = useState(null);','const [latestData, setLatestData] = useState(global.__v1);');
R('const [v2Data, setV2Data] = useState(null);','const [v2Data, setV2Data] = useState(global.__v2);');
R('const [selectedWindowIdx, setSelectedWindowIdx] = useState(null);','const [selectedWindowIdx, setSelectedWindowIdx] = useState(global.__w);');
R('const [loading, setLoading] = useState(true);','const [loading, setLoading] = useState(false);');
R('const [selectedPairKey, setSelectedPairKey] = useState("");','const [selectedPairKey, setSelectedPairKey] = useState(global.__key);');
let code=transform(src,{transforms:['jsx','imports'],jsxRuntime:'automatic',production:true}).code.replace(/import\.meta\.env/g,'({})');
require(NM+'react/jsx-runtime'); require(NM+'lucide-react');
const oR=Module._resolveFilename; Module._resolveFilename=function(q,...a){ if(q.startsWith('.')||q.endsWith('.css')) return '__stub__'; return oR.call(this,q,...a)};
const oL=Module._load; Module._load=function(q,...a){ if(q.startsWith('.')||q.endsWith('.css')) return new Proxy({}, {get:(t,k)=>k==='__esModule'?true:(()=>null)}); return oL.call(this,q,...a)};
const m=new Module('af'); m.paths=[NM]; m._compile(code,NM+'af.cjs'); const AF=m.exports.default;

const C=global.__v2.chart, thr=C.threshold, CL=C.classes;
const dec=s=>s.replace(/&amp;/g,'&').replace(/&gt;/g,'>').replace(/&lt;/g,'<').replace(/&#x27;/g,"'").replace(/&quot;/g,'"');
const toks=h=>dec(h.replace(/<!-- -->/g,'').replace(/<!--.*?-->/g,'')).split(/<[^>]+>/).map(s=>s.trim()).filter(Boolean);
const after=(T,label,n=1)=>{const i=T.indexOf(label); return i<0?null:T.slice(i+1,i+1+n)};
const disp=k=>{ if(!k) return 'No attack stage'; const s=String(k).toLowerCase().trim(); if(s==='normal') return 'No attack stage';
  return ({command_control:'Command and Control',lateral_movement:'Lateral Movement',initial_access:'Initial Access',reconnaissance:'Reconnaissance',exfiltration:'Exfiltration'})[s]||k; };
const ends=d=>{ const o=[]; const mm=d.match(/M ([\d.\-]+),([\d.\-]+)/); if(!mm) return o; o.push([+mm[1],+mm[2]]); const re=/C [\d.\-]+,[\d.\-]+ [\d.\-]+,[\d.\-]+ ([\d.\-]+),([\d.\-]+)/g; let x; while((x=re.exec(d))) o.push([+x[1],+x[2]]); return o; };
const Y=v=>26+(1-Math.max(0,Math.min(1,v)))*206;
const fmtDelay=m=>{ if(m==null||isNaN(m)) return ''; if(m<60) return `${Math.round(m)} min`; if(m<1440) return `about ${Math.round(m/60)} h`; const d=Math.round(m/1440); return `about ${d} day${d===1?'':'s'}`; };
const stat={}, fails=[];
const chk=(k,ok,detail)=>{ const s=stat[k]||(stat[k]=[0,0]); s[0]++; if(!ok){ s[1]++; if(fails.filter(f=>f[0]===k).length<3) fails.push([k,detail]); } };
const near=(a,b,t=0.11)=>Math.abs(a-b)<=t;

const convs=global.__v1.results; let renders=0;
const hostsSeen=new Set();
for(const c of convs){
  const key=c.src_ip+'>'+c.dst_ip;
  let hostIp=null; if(C.hosts[c.src_ip]) hostIp=c.src_ip; else if(C.hosts[c.dst_ip]) hostIp=c.dst_ip; else hostIp=C.host_order[0];
  const H=C.hosts[hostIp]; const n=H.time.length;
  let ws=[null,0,H.peak_window_index,Math.floor(n/2)];
  if(process.env.ALLW && !hostsSeen.has(hostIp)) ws=[null,...Array(n).keys()];
  hostsSeen.add(hostIp);
  for(const wsel of [...new Set(ws)]){
    global.__key=key; global.__w=wsel; const w=(wsel===null)?n-1:wsel; renders++;
    let html; try{ html=renderToString(React.createElement(AF,{isActive:true,onToggleSidebar:()=>{}})); }catch(e){ chk('page renders without error',false,key+' w'+w+' '+e.message); continue; }
    chk('page renders without error',true);
    const T=toks(html); const risk=H.risk_60s[w];
    // ---- tiles
    const s5=H.start_soon?.['300']?.[w], s10=H.start_soon?.['600']?.[w], lvl=C.start_outlook?.tested?.['300']?.threshold;
    let threat = risk>=thr?'HIGH RISK': risk>=0.5?'ELEVATED': (Number.isFinite(s5)&&typeof lvl==='number'&&s5>=lvl)?'WATCH':'NORMAL';
    chk('tile: threat level',(after(T,'THREAT LEVEL')||[])[0]===threat,`${key} w${w}: page ${after(T,'THREAT LEVEL')} expected ${threat} (risk ${risk})`);
    const ap=after(T,'ATTACK PROBABILITY',2)||[];
    chk('tile: attack probability',ap[0]===(risk*100).toFixed(1)+'%',`${key} w${w}: page ${ap[0]} expected ${(risk*100).toFixed(1)}%`);
    const sub=Number.isFinite(s5)?`next 60 s · 5 min ${(s5*100).toFixed(0)}%`+(Number.isFinite(s10)?` · 10 min ${(s10*100).toFixed(0)}%`:''):'next 60 s';
    chk('tile: 5 / 10 minute values',T.includes(sub),`${key} w${w}: expected "${sub}" got "${ap[1]}"`);
    let conf, confSub='';
    const sf=H.stage_forecast[w], sp=H.stage_forecast_prob[w];
    if(risk>=thr){ conf=(H.likely_attack_stage_prob[w]*100).toFixed(1)+'%'; confSub='average over now to +60 s'; }
    else { let i=sf.findIndex(s=>s!=='normal'); if(i<0){ conf=(sp[0]*100).toFixed(1)+'%'; confSub='no attack stage'; } else conf=(sp[i]*100).toFixed(1)+'%'; }
    const mc=after(T,'MODEL CONFIDENCE',2)||[];
    chk('tile: model confidence',mc[0]===conf,`${key} w${w}: page ${mc[0]} expected ${conf}`);
    // ---- chart
    chk('chart: alert threshold label',T.some(t=>t===`Alert threshold (${thr.toFixed(2)})`),key);
    const w0=Math.max(0,w-11); const obs=[]; for(let i=w0;i<=w;i++) obs.push(i);
    const N=obs.length+6; const X=i=>N===1?52+764/2:52+(i/(N-1))*764;
    const wm=[...obs.map(i=>H.risk_60s[i]),...H.forecast_curve[w]].map((v,i)=>[X(i),Y(v)]);
    const lr=obs.map((i,k)=>[X(k),Y(H.baseline_risk_60s[i])]);
    const up=[[X(obs.length-1),Y(H.risk_60s[w])],...H.forecast_curve_max[w].map((v,k)=>[X(obs.length+k),Y(v)])];
    const lo=[[X(obs.length-1),Y(H.risk_60s[w])],...H.forecast_curve_min[w].map((v,k)=>[X(obs.length+k),Y(v)])];
    const paths=[...html.matchAll(/<path[^>]* d="([^"]+)"/g)].map(x=>ends(x[1]));
    const has=P=>paths.some(q=>q.length===P.length&&q.every((p,i)=>near(p[0],P[i][0])&&near(p[1],P[i][1])));
    chk('chart: model line (12 observed + 6 forecast points)',has(wm),`${key} w${w}`);
    chk('chart: baseline line',lr.length<2||has(lr),`${key} w${w}`);
    chk('chart: range upper edge',has(up),`${key} w${w}`); chk('chart: range lower edge',has(lo),`${key} w${w}`);
    const nAtt=obs.filter(i=>H.true_stage&&H.true_stage[i]&&!['normal','ambiguous'].includes(H.true_stage[i])).length;
    chk('chart: labelled-malicious shading',(html.match(/fill="rgba\(208,59,59,0\.13\)"/g)||[]).length===nAtt,`${key} w${w}: expected ${nAtt}`);
    chk('chart: selected window time shown',T.includes(H.time[w].split(' ').pop()),`${key} w${w}`);
    // ---- tree + MITRE cards (always for the latest window)
    const P=H.progression; const text=T.join(' | ');
    if(P&&P.available){
      for(const nd of P.nodes){
        chk('tree: stage name and probability',T.includes(disp(nd.stage))&&text.includes(`${Math.round(nd.prob*100)}%`),`${key} ${nd.stage} ${nd.prob}`);
        if(nd.parent!==null) chk('tree: "seen X of Y times" and delay',text.includes(`seen ${nd.observed} of ${nd.observed_total} times`)&&text.includes(fmtDelay(nd.median_delay_min)),`${key} ${nd.stage} seen ${nd.observed} of ${nd.observed_total} ${fmtDelay(nd.median_delay_min)}`);
      }
      P.steps.forEach((s,i)=>{ const mi=C.mitre[s.stage]||{}; const ok=T.includes(disp(s.stage))&&(!mi.tactic_id||T.includes(mi.tactic_id))&&T.includes(`${Math.round(s.prob*100)}%`)&&
          (s.basis==='model'?T.includes("Model's current reading"):text.includes(`Seen ${s.observed} of ${s.observed_total} times`));
        chk('MITRE card: stage, tactic id, probability, basis',ok,`${key} step ${i} ${s.stage}`); });
    } else chk('tree: "no progression" message when no attack stage',text.includes((P&&P.reason)||'no progression'),key);
    // ---- attribution (latest window)
    const A=H.attribution_last;
    if(A&&A.features&&!A.error&&A.risk_60s>=0.05){
      A.features.slice(0,7).forEach(f=>{ const cs=f.contribution>=0?`+${f.contribution.toFixed(3)}`:f.contribution.toFixed(3);
        chk('attribution: feature, contribution, share',T.includes(f.feature)&&T.includes(cs)&&text.includes(`${(f.share*100).toFixed(1)}%`),`${key} ${f.feature} ${cs} ${(f.share*100).toFixed(1)}%`); });
      const f0=A.features[0];
      chk('attribution: main feature panel (description, observed value)',text.includes(f0.description)&&(f0.value==null||text.includes(`(Observed value: ${f0.value})`))&&T.includes(f0.contribution>=0?'INCREASES RISK':'DECREASES RISK'),`${key} ${f0.feature}`);
    } else chk('attribution: message when not available or risk near zero',text.includes('nothing to attribute')||text.includes('not available'),key);
    // ---- recommended actions (must describe the latest window, like the attribution above them)
    const rl=H.risk_60s[n-1]; const lt=rl>=thr?'HIGH RISK':rl>=0.5?'ELEVATED':'NORMAL'; const show=lt!=='NORMAL';
    chk('actions: shown exactly when the latest window is HIGH RISK / ELEVATED',text.includes('iptables -A INPUT -s')===show,`${key} w${w} latest ${lt}`);
    chk('page shows the forecast of the conversation SOURCE host',hostIp===c.src_ip,`${key}: page shows host ${hostIp}`);
    if(show){ chk('actions: block rule names the source host',text.includes(`iptables -A INPUT -s ${c.src_ip} -j DROP`)&&text.includes(`1. Block Source IP (${c.src_ip})`),key);
      chk('actions: target host = destination of the conversation',text.includes(`2. Isolate Target Host (${c.dst_ip})`),key);
      let sk=null; if(rl>=thr&&H.likely_attack_stage[n-1]) sk=H.likely_attack_stage[n-1]; else sk=(H.stage_forecast[n-1]||[]).find(x=>x&&x!=='normal')||null;
      const nx=(P&&P.available&&P.steps&&P.steps[1])?P.steps[1].stage:null;
      const sent=nx?`Restrict lateral egress traffic to prevent progression to ${disp(nx)}.`:sk?`Restrict lateral egress traffic to contain the ${disp(sk)} activity.`:'Restrict lateral egress traffic from this host.';
      chk('actions: stage named in action 2 (next stage of the tree, else current stage)',text.includes(sent),`${key}: expected "${sent}"`);
    }
    // ---- flows table
    (c.flows||[]).slice(0,5).forEach(fl=>chk('flow table: source, destination, packets',T.includes(String(fl.src_ip))&&T.includes(String(fl.dst_ip))&&T.includes(String(fl.packet_count)),key));
    chk('flow table: rows belong to the selected conversation',(c.flows||[]).every(fl=>fl.src_ip===c.src_ip&&fl.dst_ip===c.dst_ip),key);
  }
}
// dropdown labels (one render)
{ global.__key=convs[0].src_ip+'>'+convs[0].dst_ip; global.__w=null; const html=renderToString(React.createElement(AF,{isActive:true,onToggleSidebar:()=>{}})); const DT=dec(html.replace(/<!-- -->/g,''));
  for(const c of convs){ const cH=C.hosts[c.src_ip]||C.hosts[c.dst_ip]; let exp;
    if(!cH) exp=`${c.src_ip} ➔ ${c.dst_ip} (no forecast for this host)`;
    else { const r=cH.risk_60s[cH.risk_60s.length-1]; const st=(r>=thr&&cH.likely_attack_stage[cH.risk_60s.length-1])?cH.likely_attack_stage[cH.risk_60s.length-1]:cH.stage_forecast[cH.stage_forecast.length-1][0];
      exp=`${c.src_ip} ➔ ${c.dst_ip} (Risk: ${(r*100).toFixed(1)}% | Stage: ${st.toUpperCase().replace(/_/g,' ')})`; }
    chk('dropdown: label per conversation',DT.includes(exp),exp);
    chk('dropdown: every entry has its own source-host forecast',!!C.hosts[c.src_ip],`${c.src_ip} ➔ ${c.dst_ip}`);
  } }
console.log(`\n=== ${stem}: ${convs.length} conversations, ${hostsSeen.size} charted hosts, ${renders} page renders`);
for(const [k,[n,b]] of Object.entries(stat)) console.log(`  ${b===0?'OK  ':'FAIL'} ${k}: ${n-b}/${n}`);
for(const [k,d] of fails) console.log('   !!',k,'|',d);
