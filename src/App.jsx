import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react'

/* ═══════════════════════════════════════════════════════════════  DATA ENGINE  ═══ */
const ATTACK_TYPES_ALL = ['BENIGN','DDoS','Bot','PortScan','Brute Force-Web','Web Attacks-BF','Infiltration']
const COMMON_PORTS = [80,443,22,3389,8080,6667,25,3306,21,53,8443]
const ATTACK_COLORS = {BENIGN:'#00e676',DDoS:'#ff3b5e',Bot:'#a855f7',PortScan:'#ffb800','Brute Force-Web':'#ff3b5e','Web Attacks-BF':'#4a9eff',Infiltration:'#ffb800'}
const ATTACK_BADGE = {BENIGN:'b-green',DDoS:'b-red',Bot:'b-purple',PortScan:'b-amber','Brute Force-Web':'b-red','Web Attacks-BF':'b-blue',Infiltration:'b-amber'}
function randIP(){return`${192+(Math.random()>.5?1:0)}.168.${Math.floor(Math.random()*20)}.${Math.floor(Math.random()*254)+1}`}
function pick(arr){return arr[Math.floor(Math.random()*arr.length)]}
function generateFlows(n=150){
  return Array.from({length:n},(_,i)=>{
    const benign=Math.random()<0.37,atk=benign?'BENIGN':pick(ATTACK_TYPES_ALL.slice(1))
    const bps=atk==='DDoS'?+(3e6+Math.random()*2e6).toFixed(0):atk==='BENIGN'?+(800+Math.random()*6e4).toFixed(0):+(8e3+Math.random()*9e5).toFixed(0)
    const conf=benign?0:+(65+Math.random()*34).toFixed(1),score=benign?+(Math.random()*0.14).toFixed(3):+(0.55+Math.random()*0.45).toFixed(3)
    return{id:i,src:randIP(),dst:randIP(),dport:pick(COMMON_PORTS),atk,conf,bps,pps:+(bps/64).toFixed(1),score:parseFloat(score),dur:+(Math.random()*300).toFixed(1),synFlags:(atk==='DDoS'||atk==='PortScan')?1:0,rstFlags:atk==='PortScan'?1:0,status:benign?'PASS':parseFloat(score)>0.85?'BLOCKED':'MONITOR'}
  })
}
const FLOWS=generateFlows(150)
const ATTACK_PROFILES={
  ALL:{type:'Bot',conf:89,port:8080,dur:'61.7s',bps:'7.12e+5',score:'1.000',feats:{'Flow bytes/s':'7.12e+5','Packets/s':'29561','SYN flags':'0','RST':'0','IAT Std':'6.30s','Label':'Bot'}},
  DDoS:{type:'DDoS',conf:97,port:443,dur:'2.1s',bps:'4.55e+6',score:'0.982',feats:{'Flow bytes/s':'4.55e+6','Packets/s':'98234','SYN flags':'1','RST':'0','IAT Std':'0.01s','Label':'DDoS'}},
  PortScan:{type:'PortScan',conf:76,port:3389,dur:'120s',bps:'1.2e+3',score:'0.762',feats:{'Flow bytes/s':'1.2e+3','Packets/s':'45.3','SYN flags':'1','RST':'1','IAT Std':'22.4s','Label':'PortScan'}},
  BruteForce:{type:'Brute Force',conf:84,port:22,dur:'18.3s',bps:'3.4e+4',score:'0.841',feats:{'Flow bytes/s':'3.4e+4','Packets/s':'210.9','SYN flags':'1','RST':'0','IAT Std':'0.92s','Label':'BruteForce'}},
  Bot:{type:'Bot',conf:91,port:6667,dur:'305s',bps:'8.9e+4',score:'0.994',feats:{'Flow bytes/s':'8.9e+4','Packets/s':'1234.6','SYN flags':'0','RST':'0','IAT Std':'1.22s','Label':'Bot'}},
}
const CICIDS_LABELS=[{name:'PortScan',color:'#ffb800',pct:.18},{name:'BENIGN',color:'#00e676',pct:.32},{name:'Brute Force-Web',color:'#00e5cc',pct:.12},{name:'DDoS',color:'#ff3b5e',pct:.19},{name:'Bot',color:'#a855f7',pct:.10},{name:'Web Attacks-BF',color:'#4a9eff',pct:.09}]
const TOP_PORTS=[{port:443,pct:75,flows:20},{port:3389,pct:65,flows:17},{port:138,pct:67,flows:15},{port:137,pct:67,flows:12},{port:25,pct:78,flows:9}]
const FEATURE_IMPORTANCE=[{label:'Flow Bytes/s',pct:100,color:'#ff3b5e'},{label:'Flow Packets/s',pct:88,color:'#ff3b5e'},{label:'RST Flag Count',pct:86,color:'#ff3b5e'},{label:'SYN Flag Count',pct:75,color:'#ffb800'},{label:'IAT Mean',pct:62,color:'#4a9eff'},{label:'Pkt Length Std',pct:48,color:'#ffb800'},{label:'Active Mean',pct:41,color:'#4a9eff'}]
const ML_MODELS=[
  {name:'Random Forest Classifier',type:'SUPERVISED ENSEMBLE',color:'#00e5cc',metrics:[{l:'Accuracy',v:97.4},{l:'Precision',v:96.8},{l:'Recall',v:98.8},{l:'F1-Score',v:97.8}],desc:'200 trees, max_depth=20. Trained on CICIDS-2017/2018 (2.8M flows). Primary classifier for 7 attack categories. SMOTE oversampling.'},
  {name:'XGBoost Threat Scorer',type:'GRADIENT BOOSTING',color:'#4a9eff',metrics:[{l:'Accuracy',v:98.1},{l:'AUC-ROC',v:99.8},{l:'Speed',v:92},{l:'Log Loss',v:4}],desc:'500 estimators, depth=6, lr=0.1. Best on DDoS+Bot detection. GPU-accelerated inference on 78-feature CICIDS input vector.'},
  {name:'Isolation Forest',type:'UNSUPERVISED ANOMALY',color:'#ff3b5e',metrics:[{l:'Anomaly Det.',v:97},{l:'FPR',v:2.1},{l:'Coverage',v:94},{l:'Contamination',v:1}],desc:'100 estimators, contamination=0.01. Zero-day attack detection without labels. Sub-sampling 256 for real-time speed.'},
  {name:'LSTM Sequence Model',type:'DEEP LEARNING',color:'#a855f7',metrics:[{l:'Accuracy',v:96.2},{l:'Val Acc',v:95.8},{l:'Val Loss',v:76},{l:'Epochs',v:100}],desc:'Bidirectional LSTM (128 units). Detects multi-step attack campaigns across 60-step flow sequences.'},
  {name:'K-Means Clusterer',type:'UNSUPERVISED CLUSTERING',color:'#ffb800',metrics:[{l:'Clusters',v:70},{l:'Silhouette',v:82},{l:'Coverage',v:96},{l:'Speed',v:95}],desc:'7 clusters → CICIDS attack families. Initial traffic segmentation + feature-space visualization.'},
  {name:'Ensemble Voter',type:'META-CLASSIFIER',color:'#00e676',metrics:[{l:'Accuracy',v:98.6},{l:'Confidence',v:99.1},{l:'TPR',v:99.4},{l:'FPR',v:1.2}],desc:'Weighted soft voting: RF(0.35)+XGB(0.35)+LSTM(0.20)+IF(0.10). Threshold 0.85 triggers auto-block.'},
]
const LOG_POOL=[
  {agent:'MONITOR',lvl:'INFO',t:'Flow ingestion: 2847 flows/sec — CICIDS pipeline active'},
  {agent:'MONITOR',lvl:'OK',t:'Feature extraction complete: 78 features/record'},
  {agent:'MONITOR',lvl:'INFO',t:'Buffer utilization 23% — all network interfaces nominal'},
  {agent:'ANALYZER',lvl:'INFO',t:'Correlation: sliding window 60s — 14,200 events/min'},
  {agent:'ANALYZER',lvl:'WARN',t:'Anomalous sequence: 192.168.10.5 — 3 failed auth in 2s'},
  {agent:'ANALYZER',lvl:'INFO',t:'Temporal pattern matched: T1078.003 (Valid Accounts)'},
  {agent:'THREAT',lvl:'ERR',t:'Bot detected: 192.168.10.51 → port 8080 — score 0.994'},
  {agent:'THREAT',lvl:'WARN',t:'PortScan: 172.31.1.20 — sequential probe 20 ports/sec'},
  {agent:'THREAT',lvl:'ERR',t:'DDoS: port 443 — 98,234 pkts/sec — threshold exceeded'},
  {agent:'THREAT',lvl:'OK',t:'Signature DB: 2,341 rules — no updates pending'},
  {agent:'ML',lvl:'INFO',t:'Random Forest: Bot prediction — 97.1% confidence'},
  {agent:'ML',lvl:'OK',t:'XGBoost ensemble: DDoS confirmed — AUC-ROC 0.998'},
  {agent:'ML',lvl:'WARN',t:'Novel pattern — Isolation Forest anomaly score 0.994'},
  {agent:'ML',lvl:'OK',t:'Model retrained — accuracy delta +0.3% (97.7%)'},
  {agent:'DECISION',lvl:'OK',t:'BLOCK: 192.168.10.51 — Bot, score > 0.85 threshold'},
  {agent:'DECISION',lvl:'INFO',t:'MONITOR: 172.31.1.20 — PortScan, score 0.762'},
  {agent:'DECISION',lvl:'INFO',t:'MITRE tactic mapped: TA0011 — Command and Control'},
  {agent:'RESPONSE',lvl:'OK',t:'Firewall rule added: DROP 192.168.10.51 (99ms)'},
  {agent:'RESPONSE',lvl:'OK',t:'SOC alert dispatched: #INC-2024-8823 — severity HIGH'},
  {agent:'RESPONSE',lvl:'WARN',t:'Rate limit: 172.31.1.20 capped at 50 req/min'},
  {agent:'LEARN',lvl:'OK',t:'512 verified samples queued — active learning pipeline'},
  {agent:'LEARN',lvl:'INFO',t:'False positive rate: 2.1% → 1.8% (last cycle)'},
  {agent:'REPORT',lvl:'OK',t:'Incident #INC-2024-8823 report generated — SIEM synced'},
  {agent:'REPORT',lvl:'INFO',t:'Dashboard updated: 150 CICIDS flows — THREAT LEVEL HIGH'},
]
const PRESET_FLOWS=[
  {label:'DDoS Attack',flowBytes:4550000,flowPkts:98234,synFlags:1,rstFlags:0,iatMean:0.01,pktLenStd:12,activeMean:0.01,duration:2.1},
  {label:'Bot C2',flowBytes:89000,flowPkts:1234,synFlags:0,rstFlags:0,iatMean:1.22,pktLenStd:80,activeMean:2.1,duration:305},
  {label:'Port Scan',flowBytes:1200,flowPkts:45,synFlags:1,rstFlags:1,iatMean:22.4,pktLenStd:5,activeMean:0.5,duration:120},
  {label:'Brute Force',flowBytes:34000,flowPkts:210,synFlags:1,rstFlags:0,iatMean:0.92,pktLenStd:60,activeMean:0.9,duration:18.3},
  {label:'Benign Traffic',flowBytes:5200,flowPkts:32,synFlags:0,rstFlags:0,iatMean:8.5,pktLenStd:200,activeMean:5.0,duration:45},
]
const FIELD_DEFS=[
  {k:'flowBytes',l:'Flow Bytes/s',min:0,max:5000000,step:1000,unit:'B/s'},
  {k:'flowPkts',l:'Flow Packets/s',min:0,max:100000,step:10,unit:'pkt/s'},
  {k:'synFlags',l:'SYN Flag Count',min:0,max:1,step:1,unit:''},
  {k:'rstFlags',l:'RST Flag Count',min:0,max:1,step:1,unit:''},
  {k:'iatMean',l:'IAT Mean (s)',min:0,max:60,step:0.01,unit:'s'},
  {k:'pktLenStd',l:'Pkt Length Std',min:0,max:800,step:1,unit:''},
  {k:'activeMean',l:'Active Mean (s)',min:0,max:20,step:0.1,unit:'s'},
  {k:'duration',l:'Flow Duration',min:0,max:600,step:0.1,unit:'s'},
]

/* ═══════════════════════════════════════════════════════════════  CSS  ═══ */
const GLOBAL_CSS=`
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#080c10;--bg2:#0d1117;--bg3:#111820;--bg4:#162030;
  --cyan:#00e5cc;--cyan2:#00b89a;--red:#ff3b5e;--amber:#ffb800;
  --green:#00e676;--blue:#4a9eff;--purple:#a855f7;
  --text:#d0e4f7;--text2:#8ba8c8;--text3:#4a6080;
  --border:#1e3a5a;--border2:#0f2540;
}
html,body,#root{height:100%;background:var(--bg);color:var(--text);font-family:'Rajdhani',sans-serif;font-size:14px;overflow-x:hidden}
.mono{font-family:'Share Tech Mono',monospace!important}
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:var(--bg)}::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
.panel{background:var(--bg2);border:1px solid var(--border2);border-radius:2px;padding:14px;position:relative;overflow:hidden}
.panel::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.p-cyan::before{background:var(--cyan)}.p-red::before{background:var(--red)}.p-amber::before{background:var(--amber)}.p-blue::before{background:var(--blue)}.p-green::before{background:var(--green)}.p-purple::before{background:var(--purple)}
.panel-corner{position:absolute;top:0;right:0;width:12px;height:12px;border-top:2px solid;border-right:2px solid;opacity:.4;pointer-events:none}
.panel-corner-bl{position:absolute;bottom:0;left:0;width:12px;height:12px;border-bottom:2px solid;border-left:2px solid;opacity:.4;pointer-events:none}
.ptitle{font-size:11px;font-weight:700;letter-spacing:2px;color:var(--text2);text-transform:uppercase;margin-bottom:12px}
.badge{padding:2px 8px;border-radius:1px;font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase;display:inline-block;white-space:nowrap}
.b-red{background:rgba(255,59,94,.18);color:#ff7a8a;border:1px solid rgba(255,59,94,.4)}
.b-amber{background:rgba(255,184,0,.18);color:#ffd24d;border:1px solid rgba(255,184,0,.4)}
.b-blue{background:rgba(74,158,255,.18);color:#7bc3ff;border:1px solid rgba(74,158,255,.4)}
.b-green{background:rgba(0,230,118,.18);color:#4dff9b;border:1px solid rgba(0,230,118,.4)}
.b-purple{background:rgba(168,85,247,.18);color:#c99dff;border:1px solid rgba(168,85,247,.4)}
.b-cyan{background:rgba(0,229,204,.14);color:#00e5cc;border:1px solid rgba(0,229,204,.4)}
.pill{padding:4px 12px;border-radius:2px;font-weight:700;letter-spacing:1px;text-transform:uppercase;font-size:11px;font-family:'Rajdhani',sans-serif;white-space:nowrap}
.pill-green{background:rgba(0,230,118,.18);color:#4dff9b;border:1px solid rgba(0,230,118,.4)}
.pill-red{background:rgba(255,59,94,.18);color:#ff7a8a;border:1px solid rgba(255,59,94,.4)}
.pill-amber{background:rgba(255,184,0,.18);color:#ffd24d;border:1px solid rgba(255,184,0,.4)}
.mcell{background:var(--bg3);border:1px solid var(--border2);padding:8px;border-radius:1px}
.mc-lbl{font-size:10px;letter-spacing:1.5px;color:var(--text2);margin-bottom:3px;text-transform:uppercase}
.mc-val{font-size:18px;font-weight:700;color:var(--cyan);font-family:'Share Tech Mono',monospace}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:var(--bg3);color:var(--text2);padding:8px 10px;text-align:left;font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;border-bottom:1px solid var(--border2);white-space:nowrap;cursor:pointer;user-select:none}
th:hover{color:var(--cyan)}
td{padding:7px 10px;border-bottom:1px solid rgba(30,58,90,.35);font-family:'Share Tech Mono',monospace;color:var(--text);font-size:12px}
tr:hover td{background:rgba(0,229,204,.03)}
.live-dot{width:8px;height:8px;border-radius:50%;background:var(--green);flex-shrink:0;box-shadow:0 0 6px rgba(0,230,118,.6)}
@keyframes tick{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}
.ticker-inner{display:inline-block;animation:tick 40s linear infinite}
@keyframes ld-flash{0%,100%{opacity:0}50%{opacity:1}}
.ld-overlay{position:fixed;inset:0;pointer-events:none;z-index:9999;border:3px solid #ff3b5e;animation:ld-flash .5s ease-in-out infinite}
.ld-corner{position:fixed;width:50px;height:50px;z-index:9999;pointer-events:none;animation:ld-flash .5s ease-in-out infinite}
.ld-tl{top:0;left:0;border-top:4px solid #ff3b5e;border-left:4px solid #ff3b5e}
.ld-tr{top:0;right:0;border-top:4px solid #ff3b5e;border-right:4px solid #ff3b5e}
.ld-bl{bottom:0;left:0;border-bottom:4px solid #ff3b5e;border-left:4px solid #ff3b5e}
.ld-br{bottom:0;right:0;border-bottom:4px solid #ff3b5e;border-right:4px solid #ff3b5e}
input[type=range]{-webkit-appearance:none;appearance:none;height:3px;background:var(--bg4);border-radius:0;outline:none;cursor:pointer;width:100%}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:12px;height:12px;background:var(--cyan);border-radius:0;cursor:pointer}
`

/* ═══════════════════════════════════════════════════════════════  CANVAS  ═══ */
function Donut(){
  const ref=useRef(null)
  useEffect(()=>{
    const c=ref.current;if(!c)return
    const ctx=c.getContext('2d'),cx=90,cy=90,r=70,ir=52
    ctx.clearRect(0,0,180,180);let start=-Math.PI/2
    CICIDS_LABELS.forEach(l=>{const end=start+l.pct*2*Math.PI;ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,r,start,end);ctx.closePath();ctx.fillStyle=l.color;ctx.fill();start=end})
    ctx.beginPath();ctx.arc(cx,cy,ir,0,Math.PI*2);ctx.fillStyle='#0d1117';ctx.fill()
    ctx.fillStyle='#d0e4f7';ctx.font='600 13px Rajdhani,sans-serif';ctx.textAlign='center'
    ctx.fillText('CICIDS',cx,cy-4);ctx.fillText('2018',cx,cy+13)
  },[])
  return <canvas ref={ref} width={180} height={180} style={{flexShrink:0}}/>
}
function LineChart({benign,threat}){
  const ref=useRef(null)
  useEffect(()=>{
    const c=ref.current;if(!c)return
    const W=c.width,H=c.height,ctx=c.getContext('2d'),pad={l:50,r:20,t:15,b:30},inner={w:W-pad.l-pad.r,h:H-pad.t-pad.b}
    ctx.clearRect(0,0,W,H)
    const all=[...benign,...threat],maxV=Math.max(...all)*1.1||1
    const px=i=>pad.l+i*(inner.w/(benign.length-1)),py=v=>pad.t+inner.h*(1-v/maxV)
    ctx.strokeStyle='rgba(30,58,90,.5)';ctx.lineWidth=0.5
    for(let i=0;i<=4;i++){const y=pad.t+inner.h*(i/4);ctx.beginPath();ctx.moveTo(pad.l,y);ctx.lineTo(pad.l+inner.w,y);ctx.stroke();ctx.fillStyle='#8ba8c8';ctx.font='10px Share Tech Mono,monospace';ctx.textAlign='right';ctx.fillText(Math.round(maxV*(1-i/4)/1000)+'K',pad.l-5,y+4)}
    ctx.fillStyle='#8ba8c8';ctx.font='10px Share Tech Mono,monospace';ctx.textAlign='center'
    for(let i=0;i<benign.length;i+=4)ctx.fillText(`${i*3}m`,px(i),H-8)
    function drawLine(data,color){
      ctx.beginPath();data.forEach((v,i)=>{i===0?ctx.moveTo(px(i),py(v)):ctx.lineTo(px(i),py(v))})
      const tmp=new Path2D();data.forEach((v,i)=>{i===0?tmp.moveTo(px(i),py(v)):tmp.lineTo(px(i),py(v))})
      tmp.lineTo(px(data.length-1),pad.t+inner.h);tmp.lineTo(px(0),pad.t+inner.h);tmp.closePath()
      const grad=ctx.createLinearGradient(0,pad.t,0,pad.t+inner.h)
      const rgba=color.replace('rgb(','rgba(').replace(')',',0.15)')
      grad.addColorStop(0,rgba);grad.addColorStop(1,color.replace('rgb(','rgba(').replace(')',',0)'))
      ctx.fillStyle=grad;ctx.fill(tmp);ctx.strokeStyle=color;ctx.lineWidth=1.5;ctx.lineJoin='round';ctx.stroke()
    }
    drawLine(benign,'rgb(74,158,255)');drawLine(threat,'rgb(255,59,94)')
  },[benign,threat])
  return <canvas ref={ref} width={640} height={145} style={{width:'100%',height:'145px'}}/>
}

/* ═══════════════════════════════════════════════════════════════  APP  ═══ */
export default function App(){
  const [page,setPage]=useState('dashboard')
  const [logs,setLogs]=useState([])
  const [fps,setFps]=useState(2847)
  const [clock,setClock]=useState('')
  const [tickets,setTickets]=useState([])
  const [reports,setReports]=useState([])
  const [lockdown,setLockdown]=useState(false)
  const [ldTimer,setLdTimer]=useState(0)
  const logIdx=useRef(0),ticketId=useRef(1),reportId=useRef(1),styleInjected=useRef(false)

  if(!styleInjected.current){const el=document.createElement('style');el.textContent=GLOBAL_CSS;document.head.appendChild(el);styleInjected.current=true}

  useEffect(()=>{const t=()=>setClock(new Date().toUTCString().slice(17,25)+' UTC');t();const id=setInterval(t,1000);return()=>clearInterval(id)},[])
  useEffect(()=>{
    const seed=Array.from({length:18},(_,i)=>{const m=LOG_POOL[i%LOG_POOL.length];return{id:i,time:new Date(Date.now()-(18-i)*2800).toTimeString().slice(0,8),...m}}).reverse()
    setLogs(seed);logIdx.current=18
    const id=setInterval(()=>{const m=LOG_POOL[logIdx.current%LOG_POOL.length];logIdx.current++;setLogs(p=>[{id:logIdx.current,time:new Date().toTimeString().slice(0,8),...m},...p.slice(0,199)])},2500)
    return()=>clearInterval(id)
  },[])
  useEffect(()=>{const id=setInterval(()=>setFps(2600+Math.floor(Math.random()*600)),3200);return()=>clearInterval(id)},[])
  useEffect(()=>{
    if(!lockdown)return
    setLdTimer(30)
    const id=setInterval(()=>setLdTimer(t=>{if(t<=1){clearInterval(id);setLockdown(false);return 0}return t-1}),1000)
    return()=>clearInterval(id)
  },[lockdown])

  function handleIR(action,profile){
    if(action==='investigate'){
      const id=`TKT-${String(ticketId.current).padStart(4,'0')}`;ticketId.current++
      setTickets(t=>[{id,status:'OPEN',type:profile?.type||'Bot',port:profile?.port||8080,score:profile?.score||'0.994',src:randIP(),ts:new Date().toUTCString().slice(0,25)+' UTC',notes:[]},...t])
      setLogs(p=>[{id:Date.now(),time:new Date().toTimeString().slice(0,8),agent:'DECISION',lvl:'OK',t:`Investigation ticket ${id} opened — forensic agent spawned`},...p.slice(0,199)])
      setPage('agents')
    } else if(action==='report'){
      const rid=`RPT-${String(reportId.current).padStart(4,'0')}`;reportId.current++
      const threats=FLOWS.filter(f=>f.atk!=='BENIGN'),blocked=FLOWS.filter(f=>f.status==='BLOCKED')
      const topAtkEntry=Object.entries(FLOWS.reduce((acc,f)=>{acc[f.atk]=(acc[f.atk]||0)+1;return acc},{})).sort((a,b)=>b[1]-a[1])[0]
      setReports(r=>[{id:rid,ts:new Date().toUTCString().slice(0,25)+' UTC',totalFlows:FLOWS.length,threats:threats.length,blocked:blocked.length,benign:FLOWS.filter(f=>f.atk==='BENIGN').length,avgScore:(FLOWS.reduce((s,f)=>s+f.score,0)/FLOWS.length).toFixed(3),topThreat:topAtkEntry?topAtkEntry[0]:'None',topPort:TOP_PORTS[0].port,topPortFlows:TOP_PORTS[0].flows,modelAcc:98.6,fpRate:1.2,status:'GENERATED'},...r])
      setLogs(p=>[{id:Date.now(),time:new Date().toTimeString().slice(0,8),agent:'REPORT',lvl:'OK',t:`Network report ${rid} generated — ${FLOWS.length} flows analysed`},...p.slice(0,199)])
      setPage('reports')
    } else if(action==='lockdown'){
      setLockdown(true)
      setLogs(p=>[{id:Date.now(),time:new Date().toTimeString().slice(0,8),agent:'RESPONSE',lvl:'ERR',t:'⚠ FORCE LOCKDOWN ACTIVATED — ALL CONNECTIONS SEVERED — 30s isolation'},...p.slice(0,199)])
    } else if(action==='escalate'){
      setLogs(p=>[{id:Date.now(),time:new Date().toTimeString().slice(0,8),agent:'DECISION',lvl:'WARN',t:'Escalated to SOC — P1 incident assigned — on-call notified'},...p.slice(0,199)])
    }
  }

  const PAGES=['dashboard','agents','anomaly','logs','ml','reports']
  const PAGE_LABELS={dashboard:'DASHBOARD',agents:'AGENTS MANAGER',anomaly:'ANOMALY ANALYSIS',logs:'LOG FEED',ml:'ML MODELS',reports:'REPORTS'}
  const openTickets=tickets.filter(t=>t.status==='OPEN').length

  return (
    <div style={{display:'flex',flexDirection:'column',minHeight:'100vh'}}>
      {lockdown&&<>
        <div className="ld-overlay"/>
        <div className="ld-corner ld-tl"/><div className="ld-corner ld-tr"/><div className="ld-corner ld-bl"/><div className="ld-corner ld-br"/>
        <div style={{position:'fixed',top:'50%',left:'50%',transform:'translate(-50%,-50%)',zIndex:9998,background:'rgba(8,12,16,.92)',border:'2px solid #ff3b5e',padding:'24px 48px',borderRadius:2,textAlign:'center',backdropFilter:'blur(4px)'}}>
          <div style={{fontSize:24,fontWeight:700,color:'#ff7a8a',letterSpacing:4,fontFamily:'Share Tech Mono',marginBottom:6}}>⚠ LOCKDOWN ACTIVE</div>
          <div style={{fontSize:13,color:'#ff7a8a',letterSpacing:2,marginBottom:4}}>ALL CONNECTIONS SEVERED</div>
          <div style={{fontSize:20,fontWeight:700,color:'#ff3b5e',fontFamily:'Share Tech Mono',marginBottom:16}}>RESUMING IN {ldTimer}s</div>
          <button onClick={()=>setLockdown(false)} style={{background:'rgba(255,59,94,.15)',border:'1px solid #ff3b5e',color:'#ff7a8a',padding:'8px 24px',fontFamily:'Rajdhani,sans-serif',fontSize:12,fontWeight:700,letterSpacing:2,cursor:'pointer',textTransform:'uppercase',borderRadius:1}}>CANCEL LOCKDOWN</button>
        </div>
      </>}

      <header style={{background:'var(--bg2)',borderBottom:'1px solid var(--border2)',padding:'0 20px',display:'flex',alignItems:'center',gap:16,height:54,flexShrink:0,position:'sticky',top:0,zIndex:100}}>
        <div style={{display:'flex',alignItems:'center',gap:10,fontWeight:700,fontSize:20,letterSpacing:2,color:'#fff',whiteSpace:'nowrap'}}>
          <div style={{width:32,height:32,background:'var(--cyan)',clipPath:'polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%)',display:'flex',alignItems:'center',justifyContent:'center',fontSize:14,color:'#000',fontWeight:900,flexShrink:0}}>⬡</div>
          CIPHER<span style={{color:'var(--cyan)'}}>NEST</span>
        </div>
        <nav style={{display:'flex',gap:2,margin:'0 8px',overflowX:'auto',scrollbarWidth:'none'}}>
          {PAGES.map(p=>(
            <button key={p} onClick={()=>setPage(p)} style={{background:'none',border:'none',borderBottom:`2px solid ${page===p?'var(--cyan)':'transparent'}`,color:page===p?'var(--cyan)':'var(--text2)',padding:'6px 14px',fontFamily:'Rajdhani,sans-serif',fontSize:13,fontWeight:600,letterSpacing:'1.5px',cursor:'pointer',textTransform:'uppercase',whiteSpace:'nowrap',height:54,transition:'all .2s',position:'relative'}}>
              {PAGE_LABELS[p]}
              {p==='agents'&&openTickets>0&&<span style={{marginLeft:4,background:'var(--red)',color:'#fff',borderRadius:'50%',width:15,height:15,display:'inline-flex',alignItems:'center',justifyContent:'center',fontSize:8,fontWeight:700,verticalAlign:'middle'}}>{openTickets}</span>}
              {p==='reports'&&reports.length>0&&<span style={{marginLeft:4,background:'var(--amber)',color:'#000',borderRadius:'50%',width:15,height:15,display:'inline-flex',alignItems:'center',justifyContent:'center',fontSize:8,fontWeight:700,verticalAlign:'middle'}}>{reports.length}</span>}
            </button>
          ))}
        </nav>
        <div style={{marginLeft:'auto',display:'flex',alignItems:'center',gap:10,flexShrink:0}}>
          <div className="live-dot"/>
          <span className="mono" style={{color:'var(--text2)',fontSize:12}}>{clock}</span>
          <span className="pill pill-green" style={{fontSize:10}}>ALL SYSTEMS NOMINAL</span>
          <span className="pill pill-red" style={{fontSize:10,background:lockdown?'rgba(255,59,94,.35)':undefined}}>{lockdown?'⚠ LOCKDOWN':'THREAT: HIGH'}</span>
        </div>
      </header>

      <div style={{background:'#060a0e',borderBottom:'1px solid var(--border2)',padding:'5px 0',overflow:'hidden',whiteSpace:'nowrap',fontFamily:'Share Tech Mono,monospace',fontSize:11,color:lockdown?'#ff7a8a':'var(--text2)'}}>
        <div className="ticker-inner">
          {[...[`LIVE MODE — CICIDS-2018 — ${fps} flows/sec`,lockdown?'⚠ LOCKDOWN ACTIVE — ALL CONNECTIONS SEVERED':'THREAT: Bot detected port 8080 confidence 89%','ML: Ensemble accuracy 98.6%','BLOCKED: IP 192.168.10.51 (Bot score 0.994)','ALERT: DDoS pattern in subnet 172.31.0.0/24','LEARN: Model updated +512 samples','MITRE ATT&CK: TA0011 C2 channel detected','SOC ALERT: #INC-2024-8823 dispatched P1'],...[`LIVE MODE — CICIDS-2018 — ${fps} flows/sec`,lockdown?'⚠ LOCKDOWN ACTIVE — ALL CONNECTIONS SEVERED':'THREAT: Bot detected port 8080 confidence 89%','ML: Ensemble accuracy 98.6%','BLOCKED: IP 192.168.10.51 (Bot score 0.994)','ALERT: DDoS pattern in subnet 172.31.0.0/24','LEARN: Model updated +512 samples','MITRE ATT&CK: TA0011 C2 channel detected','SOC ALERT: #INC-2024-8823 dispatched P1']].join('  •  ')}&nbsp;&nbsp;
        </div>
      </div>

      <main style={{flex:1,padding:16,display:'flex',flexDirection:'column',gap:14}}>
        {page==='dashboard'&&<PageDashboard onIR={handleIR} lockdown={lockdown}/>}
        {page==='agents'&&<PageAgents tickets={tickets} setTickets={setTickets}/>}
        {page==='anomaly'&&<PageAnomaly/>}
        {page==='logs'&&<PageLogs logs={logs}/>}
        {page==='ml'&&<PageML/>}
        {page==='reports'&&<PageReports reports={reports}/>}
      </main>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════  DASHBOARD  ═══ */
function PageDashboard({onIR,lockdown}){
  const [filter,setFilter]=useState('ALL')
  const profile=ATTACK_PROFILES[filter]||ATTACK_PROFILES.ALL
  const tlBenign=useMemo(()=>Array.from({length:20},()=>Math.round(800+Math.random()*500)),[])
  const tlThreat=useMemo(()=>Array.from({length:20},(_,i)=>i<12?Math.round(Math.random()*200):Math.round(2000+Math.random()*2500)),[])
  const FILTERS=[{k:'ALL',l:'ALL TRAFFIC'},{k:'DDoS',l:'DDoS'},{k:'PortScan',l:'PORT SCAN'},{k:'BruteForce',l:'BRUTE FORCE'},{k:'Bot',l:'BOT'}]
  const IR_BTNS=[{k:'investigate',icon:'▣',l:'REQUEST INVESTIGATION',danger:false},{k:'lockdown',icon:'⊗',l:'FORCE LOCKDOWN',danger:true},{k:'report',icon:'◈',l:'GENERATE REPORT',danger:false},{k:'escalate',icon:'▲',l:'ESCALATE TO SOC',danger:true}]
  return (
    <div style={{display:'flex',flexDirection:'column',gap:14}}>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14}}>
        <div className="panel p-cyan">
          <div className="panel-corner" style={{borderColor:'var(--cyan)'}}/>
          <div className="panel-corner-bl" style={{borderColor:'var(--cyan)'}}/>
          <div className="ptitle">⬡ AI Threat Engine</div>
          <div style={{display:'flex',gap:2,marginBottom:12,flexWrap:'wrap'}}>
            {FILTERS.map(f=><button key={f.k} onClick={()=>setFilter(f.k)} style={{background:filter===f.k?'rgba(0,229,204,.14)':'var(--bg3)',border:`1px solid ${filter===f.k?'var(--cyan)':'var(--border)'}`,color:filter===f.k?'var(--cyan)':'var(--text2)',padding:'5px 12px',fontSize:11,fontWeight:700,letterSpacing:1,cursor:'pointer',borderRadius:1,textTransform:'uppercase',fontFamily:'Rajdhani,sans-serif',transition:'all .15s'}}>{f.l}</button>)}
          </div>
          <div style={{border:'1px solid var(--red)',background:'rgba(255,59,94,.06)',borderRadius:2,padding:'10px 12px',marginBottom:10}}>
            <div style={{fontSize:10,letterSpacing:2,color:'#ff7a8a',marginBottom:6,fontWeight:700}}>⚠ THREAT DETECTED</div>
            <div style={{fontSize:14,color:'var(--text)'}}>Attack Type: <strong style={{color:'#ff7a8a'}}>{profile.type}</strong></div>
            <div style={{display:'flex',alignItems:'center',gap:10,marginTop:6}}>
              <span style={{fontSize:12,color:'var(--text2)'}}>Confidence:</span>
              <span className="mono" style={{color:'#ff7a8a',fontWeight:700}}>{profile.conf}%</span>
              <div style={{flex:1,height:6,background:'var(--bg4)',overflow:'hidden'}}><div style={{height:'100%',width:`${profile.conf}%`,background:'linear-gradient(90deg,var(--red),var(--amber))',transition:'width .5s'}}/></div>
            </div>
          </div>
          <div style={{border:'1px solid var(--cyan2)',background:'rgba(0,229,204,.04)',borderRadius:2,padding:'8px 12px',marginBottom:10}}>
            <div style={{fontSize:10,letterSpacing:2,color:'var(--cyan2)',marginBottom:5,fontWeight:700}}>CICIDS FEATURE ANALYSIS</div>
            <div className="mono" style={{fontSize:11,color:'var(--text2)',lineHeight:1.9}}>
              {Object.entries(profile.feats).map(([k,v])=><span key={k}>{k}: <strong style={{color:'var(--cyan)'}}>{v}</strong>{'  '}</span>)}
              <br/>Anomaly pattern matches known threat signature.
            </div>
          </div>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:8,marginBottom:10}}>
            {[['THREAT PORT',profile.port],['FLOW DURATION',profile.dur],['FLOW BYTES/S',profile.bps],['ANOMALY SCORE',profile.score]].map(([l,v])=>(
              <div key={l} className="mcell"><div className="mc-lbl">{l}</div><div className="mc-val">{v}</div></div>
            ))}
          </div>
          <div className="ptitle" style={{marginTop:14}}>⬡ Incident Response</div>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:6}}>
            {IR_BTNS.map(b=><IRButton key={b.k} icon={b.icon} label={b.l} danger={b.danger} onClick={()=>onIR(b.k,profile)} disabled={lockdown&&b.k!=='lockdown'}/>)}
          </div>
        </div>
        <div className="panel p-blue">
          <div className="panel-corner" style={{borderColor:'var(--blue)'}}/>
          <div className="ptitle">⬡ Label Distribution</div>
          <div style={{display:'flex',gap:20,alignItems:'flex-start'}}>
            <Donut/>
            <div style={{flex:1,minWidth:0}}>
              <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:4,marginBottom:14}}>
                {CICIDS_LABELS.map(l=><div key={l.name} style={{display:'flex',alignItems:'center',gap:6,fontSize:11,color:'var(--text)'}}><div style={{width:8,height:8,borderRadius:'50%',background:l.color,flexShrink:0}}/>{l.name}</div>)}
              </div>
              <div className="ptitle">⬡ Top Attack Ports</div>
              {TOP_PORTS.map(p=>(
                <div key={p.port} style={{display:'flex',alignItems:'center',gap:8,marginBottom:7,fontSize:12}}>
                  <span className="mono" style={{minWidth:36,color:'var(--text)'}}>{p.port}</span>
                  <div style={{flex:1,height:6,background:'var(--bg4)'}}><div style={{height:'100%',width:`${p.pct}%`,background:'var(--red)',transition:'width .5s'}}/></div>
                  <span className="mono" style={{minWidth:32,textAlign:'right',color:'#ff7a8a',fontSize:11}}>{p.pct}%</span>
                  <span className="mono" style={{color:'var(--text2)',fontSize:11,minWidth:50,textAlign:'right'}}>{p.flows} flows</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14}}>
        <div className="panel p-green">
          <div className="panel-corner" style={{borderColor:'var(--green)'}}/>
          <div className="ptitle">⬡ Flow Bytes/s Over Time</div>
          <div style={{display:'flex',gap:14,marginBottom:8,fontSize:11,color:'var(--text2)'}}>
            {[['var(--blue)','Flow KB/s (Benign)'],['var(--red)','Flow KB/s (Threat)']].map(([c,l])=><span key={l} style={{display:'flex',alignItems:'center',gap:5}}><span style={{width:10,height:2,background:c,display:'inline-block'}}/>{l}</span>)}
          </div>
          <LineChart benign={tlBenign} threat={tlThreat}/>
        </div>
        <div className="panel p-red">
          <div className="panel-corner" style={{borderColor:'var(--red)'}}/>
          <div className="ptitle">⬡ Anomaly Feature Importance</div>
          {FEATURE_IMPORTANCE.map(f=>(
            <div key={f.label} style={{display:'flex',alignItems:'center',gap:8,marginBottom:9,fontSize:12}}>
              <span style={{minWidth:130,color:'var(--text)',flexShrink:0}}>{f.label}</span>
              <div style={{flex:1,height:5,background:'var(--bg4)'}}><div style={{height:'100%',width:`${f.pct}%`,background:f.color}}/></div>
              <span className="mono" style={{minWidth:36,textAlign:'right',color:f.color,fontSize:11}}>{f.pct}%</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
function IRButton({icon,label,danger,onClick,disabled}){
  const [h,setH]=useState(false)
  const c=disabled?'var(--text3)':h?(danger?'#ff7a8a':'var(--cyan)'):'var(--text2)'
  const bg=disabled?'var(--bg4)':h?(danger?'rgba(255,59,94,.08)':'rgba(0,229,204,.08)'):'var(--bg3)'
  const bc=disabled?'var(--border2)':h?(danger?'var(--red)':'var(--cyan)'):'var(--border)'
  return <button onClick={disabled?undefined:onClick} onMouseEnter={()=>setH(true)} onMouseLeave={()=>setH(false)} style={{background:bg,border:`1px solid ${bc}`,padding:'8px 12px',fontSize:11,fontWeight:700,letterSpacing:1,color:c,cursor:disabled?'not-allowed':'pointer',textTransform:'uppercase',display:'flex',alignItems:'center',gap:6,borderRadius:1,fontFamily:'Rajdhani,sans-serif',transition:'all .2s',opacity:disabled?.5:1}}>{icon} {label}</button>
}

/* ═══════════════════════════════════════════════════════════════  AGENTS MANAGER  ═══ */
const AGENTS_DATA=[
  {id:'monitor',name:'Monitoring Agent',icon:'◉',accentColor:'#00e5cc',leftBg:'#00e5cc',description:'Captures and preprocesses raw CICIDS-2018 network flow features. Extracts all 78 features per flow including bytes/s, packets/s, flag counts, IAT statistics, and flow duration.',metrics:[{v:'2847',l:'Flows/s'},{v:'78',l:'Features'},{v:'4ms',l:'Latency'}],logs:[{lvl:'OK',t:'Flow ingestion pipeline active — 2847 flows/sec'},{lvl:'INFO',t:'CICIDS feature extraction: 78 features per record'},{lvl:'OK',t:'Preprocessing: normalization + standardization complete'},{lvl:'INFO',t:'Interfaces: eth0, eth1, eth2 — all sensors nominal'}]},
  {id:'log',name:'Log Analysis Agent',icon:'≡',accentColor:'#4a9eff',leftBg:'#4a9eff',description:'Parses and correlates system logs with CICIDS flow metadata using sliding-window analysis (60s/300s/3600s). Identifies anomalous sequences and temporal patterns.',metrics:[{v:'14.2K',l:'Logs/min'},{v:'99.1%',l:'Parse Rate'},{v:'12ms',l:'Lag'}],logs:[{lvl:'OK',t:'Log correlation engine ready — 8,420 pattern entries loaded'},{lvl:'INFO',t:'Sliding window: 60s / 300s / 3600s all active'},{lvl:'WARN',t:'Anomalous sequence: 192.168.10.5 — 3 failed auth in 2s'},{lvl:'OK',t:'Temporal pattern DB updated: +47 new patterns indexed'}]},
  {id:'threat',name:'Threat Detection Agent',icon:'⚠',accentColor:'#ff3b5e',leftBg:'#ff3b5e',description:'Rule-based and signature-driven threat classification against CICIDS-2018 attack signatures. Detects DDoS, PortScan, Brute Force, Web Attacks, Bot and Infiltration patterns.',metrics:[{v:'97.4%',l:'Accuracy'},{v:'2.1%',l:'FPR'},{v:'98.8%',l:'Recall'}],logs:[{lvl:'ERR',t:'Bot detected — 192.168.10.51:8080 — score 0.994'},{lvl:'WARN',t:'PortScan: 172.31.1.20 → /24 subnet sequential probe'},{lvl:'ERR',t:'DDoS: port 443 — 98,234 pkt/sec threshold exceeded'},{lvl:'OK',t:'Signature DB: 2,341 rules active — all up to date'}]},
  {id:'decision',name:'Decision Agent',icon:'▣',accentColor:'#00e676',leftBg:'#00e676',description:'Orchestrates automated response using MITRE ATT&CK framework. Evaluates threat severity, confidence, and asset criticality. Policy: score>0.85 triggers auto-block.',metrics:[{v:'1.2s',l:'Resp Time'},{v:'94',l:'Decisions'},{v:'99.8%',l:'Uptime'}],logs:[{lvl:'OK',t:'MITRE ATT&CK: 14 tactics, 196 techniques loaded'},{lvl:'INFO',t:'Policy: threat_score > 0.85 → auto-block firewall rule'},{lvl:'OK',t:'Decision: BLOCK 192.168.10.51 — Bot, score 0.994'},{lvl:'INFO',t:'Decision: MONITOR 172.31.1.20 — PortScan, score 0.762'}]},
  {id:'response',name:'Response Agent',icon:'⊗',accentColor:'#a855f7',leftBg:'#a855f7',description:'Executes automated mitigations: IP blocking via firewall API, endpoint isolation, rate limiting, and P1 SOC alert dispatch. Sub-100ms block SLA.',metrics:[{v:'47',l:'IPs Blocked'},{v:'3',l:'Isolated'},{v:'99ms',l:'Block Time'}],logs:[{lvl:'OK',t:'Firewall API: connected — iptables + pfSense sync active'},{lvl:'OK',t:'BLOCKED: 192.168.10.51 — Bot, score 0.994 (47ms)'},{lvl:'WARN',t:'Rate-limited: 172.31.1.20 — PortScan — 50 req/min cap'},{lvl:'OK',t:'SOC alert dispatched: #INC-2024-8823 — Priority P1'}]},
]
const LVL_C={OK:'#4dff9b',WARN:'#ffd24d',ERR:'#ff7a8a',INFO:'#00e5cc'}
function PageAgents({tickets,setTickets}){
  const [tab,setTab]=useState('tickets')
  const closeTicket=id=>setTickets(t=>t.map(tk=>tk.id===id?{...tk,status:'CLOSED'}:tk))
  const addNote=(id,note)=>setTickets(t=>t.map(tk=>tk.id===id?{...tk,notes:[...tk.notes,{text:note,ts:new Date().toTimeString().slice(0,8)}]}:tk))
  const openCount=tickets.filter(t=>t.status==='OPEN').length
  return (
    <div>
      <div style={{display:'flex',gap:2,marginBottom:14,borderBottom:'1px solid var(--border2)'}}>
        {[['tickets',`INVESTIGATION TICKETS${openCount>0?` (${openCount})`:''}`,],['agents','AGENT STATUS']].map(([k,l])=>(
          <button key={k} onClick={()=>setTab(k)} style={{background:'none',border:'none',borderBottom:`2px solid ${tab===k?'var(--cyan)':'transparent'}`,color:tab===k?'var(--cyan)':'var(--text2)',padding:'8px 18px',fontFamily:'Rajdhani,sans-serif',fontSize:12,fontWeight:700,letterSpacing:'1.5px',cursor:'pointer',textTransform:'uppercase',transition:'all .2s',marginBottom:'-1px'}}>{l}</button>
        ))}
      </div>
      {tab==='tickets'&&(
        <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(340px,1fr))',gap:14}}>
          {tickets.length===0&&(
            <div className="panel" style={{gridColumn:'1/-1',display:'flex',alignItems:'center',justifyContent:'center',height:220,border:'1px dashed var(--border2)'}}>
              <div style={{textAlign:'center',color:'var(--text2)'}}>
                <div style={{fontSize:32,marginBottom:10,opacity:.25}}>▣</div>
                <div style={{fontSize:12,letterSpacing:1,marginBottom:4}}>No investigation tickets open</div>
                <div style={{fontSize:11,color:'var(--text3)'}}>Use "Request Investigation" on the Dashboard to create one</div>
              </div>
            </div>
          )}
          {tickets.map(tk=><TicketCard key={tk.id} ticket={tk} onClose={()=>closeTicket(tk.id)} onNote={n=>addNote(tk.id,n)}/>)}
        </div>
      )}
      {tab==='agents'&&(
        <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(300px,1fr))',gap:14}}>
          {AGENTS_DATA.map(a=><AgentCard key={a.id} agent={a}/>)}
        </div>
      )}
    </div>
  )
}
function TicketCard({ticket:tk,onClose,onNote}){
  const [note,setNote]=useState('')
  const sc=tk.status==='OPEN'?'rgba(255,59,94,.5)':'var(--border2)'
  return (
    <div style={{background:'var(--bg2)',border:`1px solid ${sc}`,borderRadius:2,padding:14,borderLeft:`3px solid ${tk.status==='OPEN'?'var(--red)':'var(--text3)'}`}}>
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:10}}>
        <span className="mono" style={{fontSize:15,fontWeight:700,color:'var(--text)'}}>{tk.id}</span>
        <span className={`badge ${tk.status==='OPEN'?'b-red':'b-green'}`}>{tk.status}</span>
      </div>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:6,marginBottom:10}}>
        {[['Type',tk.type,'#ff7a8a'],['Port',`:${tk.port}`,'var(--amber)'],['Score',tk.score,'var(--cyan)'],['Src IP',tk.src,'var(--blue)']].map(([l,v,c])=>(
          <div key={l} style={{background:'var(--bg3)',border:'1px solid var(--border2)',padding:'6px 8px',borderRadius:1}}>
            <div style={{fontSize:10,color:'var(--text2)',letterSpacing:1,textTransform:'uppercase',marginBottom:2}}>{l}</div>
            <div className="mono" style={{fontSize:12,color:c}}>{v}</div>
          </div>
        ))}
      </div>
      <div style={{fontSize:10,color:'var(--text3)',marginBottom:10,fontFamily:'Share Tech Mono'}}>{tk.ts}</div>
      {tk.notes.length>0&&(
        <div style={{background:'var(--bg)',border:'1px solid var(--border2)',borderRadius:1,padding:'6px 8px',marginBottom:8,maxHeight:80,overflowY:'auto'}}>
          {tk.notes.map((n,i)=><div key={i} style={{fontSize:11,color:'var(--text2)',marginBottom:2,fontFamily:'Share Tech Mono'}}><span style={{color:'var(--text3)'}}>[{n.ts}]</span> {n.text}</div>)}
        </div>
      )}
      {tk.status==='OPEN'&&<>
        <div style={{display:'flex',gap:6,marginBottom:8}}>
          <input value={note} onChange={e=>setNote(e.target.value)} placeholder="Add investigation note..." onKeyDown={e=>{if(e.key==='Enter'&&note.trim()){onNote(note.trim());setNote('')}}}
            style={{flex:1,background:'var(--bg)',border:'1px solid var(--border)',color:'var(--text)',padding:'5px 8px',fontSize:11,fontFamily:'Share Tech Mono',borderRadius:1,outline:'none'}}/>
          <button onClick={()=>{if(note.trim()){onNote(note.trim());setNote('')}}} style={{background:'rgba(0,229,204,.1)',border:'1px solid var(--cyan)',color:'var(--cyan)',padding:'5px 10px',fontSize:10,fontWeight:700,cursor:'pointer',fontFamily:'Rajdhani,sans-serif',letterSpacing:1,borderRadius:1}}>ADD</button>
        </div>
        <button onClick={onClose} style={{width:'100%',background:'rgba(0,230,118,.08)',border:'1px solid var(--green)',color:'#4dff9b',padding:'7px',fontSize:11,fontWeight:700,cursor:'pointer',textTransform:'uppercase',fontFamily:'Rajdhani,sans-serif',letterSpacing:1,borderRadius:1}}>✓ CLOSE TICKET</button>
      </>}
    </div>
  )
}
function AgentCard({agent:a}){
  return (
    <div style={{background:'var(--bg2)',border:'1px solid var(--border2)',borderRadius:2,padding:14,position:'relative',overflow:'hidden',borderLeft:`3px solid ${a.leftBg}`}}>
      <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:10}}>
        <div style={{width:36,height:36,borderRadius:2,display:'flex',alignItems:'center',justifyContent:'center',fontSize:16,background:`${a.accentColor}1a`,border:`1px solid ${a.accentColor}44`,flexShrink:0,color:a.accentColor}}>{a.icon}</div>
        <div>
          <div style={{fontSize:15,fontWeight:700,color:'var(--text)',letterSpacing:.5}}>{a.name}</div>
          <span style={{fontSize:10,fontWeight:700,letterSpacing:1.5,padding:'2px 8px',borderRadius:1,background:'rgba(0,230,118,.15)',color:'#4dff9b',border:'1px solid rgba(0,230,118,.35)',display:'inline-block',marginTop:3}}>ACTIVE</span>
        </div>
      </div>
      <p style={{fontSize:12,color:'var(--text2)',marginBottom:12,lineHeight:1.65}}>{a.description}</p>
      <div className="ptitle">Live Logs</div>
      <div style={{background:'var(--bg)',border:'1px solid var(--border2)',borderRadius:1,padding:8,height:90,overflowY:'auto',marginBottom:10}}>
        {a.logs.map((l,i)=><div key={i} className="mono" style={{fontSize:11,marginBottom:3,color:LVL_C[l.lvl],lineHeight:1.5}}>[{l.lvl}] {l.t}</div>)}
      </div>
      <div style={{display:'flex',gap:8}}>
        {a.metrics.map(m=>(
          <div key={m.l} style={{background:'var(--bg3)',border:'1px solid var(--border2)',padding:'6px 10px',flex:1,borderRadius:1,textAlign:'center'}}>
            <div className="mono" style={{fontSize:16,fontWeight:700,color:a.accentColor}}>{m.v}</div>
            <div style={{fontSize:10,color:'var(--text2)',letterSpacing:1,textTransform:'uppercase',marginTop:2}}>{m.l}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════  REPORTS  ═══ */
function PageReports({reports}){
  if(reports.length===0)return(
    <div className="panel" style={{display:'flex',alignItems:'center',justifyContent:'center',height:300,border:'1px dashed var(--border2)'}}>
      <div style={{textAlign:'center',color:'var(--text2)'}}>
        <div style={{fontSize:32,marginBottom:10,opacity:.25}}>◈</div>
        <div style={{fontSize:12,letterSpacing:1,marginBottom:4}}>No reports generated yet</div>
        <div style={{fontSize:11,color:'var(--text3)'}}>Use "Generate Report" on the Dashboard to create one</div>
      </div>
    </div>
  )
  return(
    <div style={{display:'flex',flexDirection:'column',gap:14}}>
      <div className="ptitle" style={{marginBottom:0}}>◈ Generated Network Reports ({reports.length})</div>
      {reports.map(r=><ReportCard key={r.id} report={r}/>)}
    </div>
  )
}
function ReportCard({report:r}){
  const [exp,setExp]=useState(true)
  return(
    <div className="panel p-cyan" style={{padding:0,overflow:'hidden'}}>
      <div className="panel-corner" style={{borderColor:'var(--cyan)'}}/>
      <div style={{padding:'12px 16px',display:'flex',alignItems:'center',justifyContent:'space-between',cursor:'pointer',borderBottom:exp?'1px solid var(--border2)':'none'}} onClick={()=>setExp(e=>!e)}>
        <div style={{display:'flex',alignItems:'center',gap:12}}>
          <span className="mono" style={{fontSize:14,fontWeight:700,color:'var(--cyan)'}}>{r.id}</span>
          <span className="badge b-cyan">NETWORK REPORT</span>
          <span style={{fontSize:11,color:'var(--text2)',fontFamily:'Share Tech Mono'}}>{r.ts}</span>
        </div>
        <div style={{display:'flex',alignItems:'center',gap:10}}>
          <span className="badge b-green">{r.status}</span>
          <span style={{color:'var(--text2)',fontSize:11}}>{exp?'▲':'▼'}</span>
        </div>
      </div>
      {exp&&(
        <div style={{padding:'14px 16px'}}>
          <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(110px,1fr))',gap:10,marginBottom:14}}>
            {[['TOTAL FLOWS',r.totalFlows,'var(--blue)'],['THREATS',r.threats,'var(--red)'],['BLOCKED',r.blocked,'var(--amber)'],['BENIGN',r.benign,'var(--green)'],['AVG SCORE',r.avgScore,'var(--cyan)'],['MODEL ACC',`${r.modelAcc}%`,'var(--cyan)']].map(([l,v,c])=>(
              <div key={l} className="mcell"><div className="mc-lbl">{l}</div><div style={{fontSize:20,fontWeight:700,color:c,fontFamily:'Share Tech Mono'}}>{v}</div></div>
            ))}
          </div>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,marginBottom:12}}>
            <div style={{background:'var(--bg3)',border:'1px solid var(--border2)',padding:'10px 14px',borderRadius:1}}>
              <div style={{fontSize:10,color:'var(--text2)',letterSpacing:1.5,marginBottom:6,textTransform:'uppercase'}}>Top Threat Type</div>
              <span className={`badge ${ATTACK_BADGE[r.topThreat]||'b-blue'}`}>{r.topThreat}</span>
            </div>
            <div style={{background:'var(--bg3)',border:'1px solid var(--border2)',padding:'10px 14px',borderRadius:1}}>
              <div style={{fontSize:10,color:'var(--text2)',letterSpacing:1.5,marginBottom:6,textTransform:'uppercase'}}>Top Attack Port</div>
              <span className="mono" style={{color:'var(--amber)',fontSize:14}}>:{r.topPort} <span style={{color:'var(--text3)',fontSize:11}}>({r.topPortFlows} flows)</span></span>
            </div>
          </div>
          <div style={{background:'var(--bg)',border:'1px solid var(--border2)',borderRadius:1,padding:'10px 14px',marginBottom:12}}>
            <div style={{fontSize:10,color:'var(--cyan)',letterSpacing:1.5,marginBottom:8,fontWeight:700,textTransform:'uppercase'}}>ORCHESTRATION PLAN</div>
            {['CLASSIFIER: Continue scanning all incoming flows','ANALYZER: Deep-dive on flagged flow signatures','LOG_ANALYZER: Search historical patterns for recurrence','THREAT_DETECT: Map to MITRE ATT&CK framework','ML_AGENT: Retrain with new threat samples',`RESPONSE: Maintain block on ${r.threats} flagged IPs`].map((s,i)=>(
              <div key={i} style={{fontSize:12,color:'var(--text2)',marginBottom:4,fontFamily:'Share Tech Mono'}}>{i+1}. {s}</div>
            ))}
          </div>
          <div style={{display:'flex',gap:8}}>
            <button onClick={()=>{const blob=new Blob([JSON.stringify(r,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`${r.id}.json`;a.click()}} style={{background:'rgba(0,229,204,.1)',border:'1px solid var(--cyan)',color:'var(--cyan)',padding:'7px 16px',fontSize:11,fontWeight:700,cursor:'pointer',textTransform:'uppercase',fontFamily:'Rajdhani,sans-serif',letterSpacing:1,borderRadius:1}}>↓ DOWNLOAD JSON</button>
            <button onClick={()=>{const txt=`CIPHERNEST NETWORK REPORT\n${r.id} — ${r.ts}\n${'─'.repeat(50)}\nTotal Flows: ${r.totalFlows}\nThreats: ${r.threats}\nBlocked: ${r.blocked}\nBenign: ${r.benign}\nAvg Anomaly Score: ${r.avgScore}\nTop Threat: ${r.topThreat}\nTop Port: :${r.topPort}\nModel Accuracy: ${r.modelAcc}%\nFalse Positive Rate: ${r.fpRate}%`;const blob=new Blob([txt],{type:'text/plain'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`${r.id}.txt`;a.click()}} style={{background:'rgba(74,158,255,.1)',border:'1px solid var(--blue)',color:'#7bc3ff',padding:'7px 16px',fontSize:11,fontWeight:700,cursor:'pointer',textTransform:'uppercase',fontFamily:'Rajdhani,sans-serif',letterSpacing:1,borderRadius:1}}>↓ DOWNLOAD TXT</button>
          </div>
        </div>
      )}
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════  ANOMALY  ═══ */
function PageAnomaly(){
  const [sortKey,setSortKey]=useState('score'),[sortDir,setSortDir]=useState(-1),[filterAtk,setFilterAtk]=useState('ALL')
  const allTypes=useMemo(()=>['ALL',...Array.from(new Set(FLOWS.map(f=>f.atk)))],'')
  const rows=useMemo(()=>{const base=filterAtk==='ALL'?FLOWS:FLOWS.filter(f=>f.atk===filterAtk);return[...base].sort((a,b)=>{const va=a[sortKey]??0,vb=b[sortKey]??0;return sortDir*(vb>va?1:vb<va?-1:0)})},[sortKey,sortDir,filterAtk])
  function toggleSort(k){setSortKey(k);setSortDir(d=>sortKey===k?-d:-1)}
  const stats=useMemo(()=>({threats:FLOWS.filter(f=>f.atk!=='BENIGN').length,blocked:FLOWS.filter(f=>f.status==='BLOCKED').length,benign:FLOWS.filter(f=>f.atk==='BENIGN').length,total:FLOWS.length}),'')
  const SH=({col})=><span style={{fontSize:9,marginLeft:3,color:'var(--text3)'}}>{sortKey===col?(sortDir===-1?'▼':'▲'):'⇅'}</span>
  return (
    <div style={{display:'grid',gridTemplateColumns:'1fr 280px',gap:14}}>
      <div style={{background:'var(--bg2)',border:'1px solid var(--border2)',borderRadius:2,overflow:'hidden'}}>
        <div style={{padding:'10px 14px',background:'var(--bg3)',borderBottom:'1px solid var(--border2)',display:'flex',alignItems:'center',gap:10,flexWrap:'wrap'}}>
          <span className="ptitle" style={{margin:0}}>CICIDS FLOW ANALYSIS</span>
          <div style={{display:'flex',gap:3,flexWrap:'wrap',flex:1}}>
            {allTypes.map(t=><button key={t} onClick={()=>setFilterAtk(t)} style={{background:filterAtk===t?'rgba(0,229,204,.12)':'transparent',border:`1px solid ${filterAtk===t?'var(--cyan)':'var(--border)'}`,color:filterAtk===t?'var(--cyan)':'var(--text2)',padding:'3px 8px',fontSize:10,fontWeight:700,cursor:'pointer',borderRadius:1,fontFamily:'Rajdhani,sans-serif',letterSpacing:.5,textTransform:'uppercase',transition:'all .15s'}}>{t}</button>)}
          </div>
          <span className="pill pill-amber" style={{fontSize:10}}>{rows.length} FLOWS</span>
        </div>
        <div style={{maxHeight:500,overflowY:'auto'}}>
          <table>
            <thead><tr>{[['src','SRC IP'],['dport','PORT'],['atk','ATTACK TYPE'],['conf','CONF'],['bps','BYTES/S'],['pps','PKTS/S'],['score','SCORE'],['status','STATUS']].map(([k,l])=><th key={k} onClick={()=>toggleSort(k)}>{l}<SH col={k}/></th>)}</tr></thead>
            <tbody>
              {rows.map(f=>{const sc=f.score,sc_color=sc>.85?'#ff7a8a':sc>.5?'#ffd24d':'#4dff9b';return(
                <tr key={f.id}>
                  <td style={{color:'var(--text)'}}>{f.src}</td><td style={{color:'var(--text)'}}>{f.dport}</td>
                  <td><span className={`badge ${ATTACK_BADGE[f.atk]||'b-blue'}`}>{f.atk}</span></td>
                  <td style={{color:f.atk==='BENIGN'?'var(--text3)':'var(--text)'}}>{f.atk==='BENIGN'?'—':`${f.conf}%`}</td>
                  <td style={{color:'var(--text)'}}>{f.bps.toLocaleString()}</td><td style={{color:'var(--text)'}}>{f.pps.toLocaleString()}</td>
                  <td><div style={{display:'flex',alignItems:'center',gap:5}}><div style={{width:Math.round(sc*50),height:4,background:sc_color,flexShrink:0}}/><span style={{color:sc_color,fontSize:11}}>{sc.toFixed(3)}</span></div></td>
                  <td><span className={`badge ${f.status==='PASS'?'b-green':f.status==='MONITOR'?'b-amber':'b-red'}`}>{f.status}</span></td>
                </tr>
              )})}
            </tbody>
          </table>
        </div>
      </div>
      <div style={{display:'flex',flexDirection:'column',gap:10}}>
        {[{n:stats.threats,l:'Active Threats',c:'var(--red)'},{n:stats.blocked,l:'IPs Blocked',c:'var(--amber)'},{n:stats.benign,l:'Benign Flows',c:'var(--green)'},{n:stats.total,l:'Total Analyzed',c:'var(--blue)'}].map(s=>(
          <div key={s.l} style={{background:'var(--bg2)',border:'1px solid var(--border2)',padding:'12px 14px',borderRadius:2}}>
            <div className="mono" style={{fontSize:28,fontWeight:700,color:s.c}}>{s.n}</div>
            <div style={{fontSize:11,color:'var(--text2)',letterSpacing:1,textTransform:'uppercase',marginTop:2}}>{s.l}</div>
          </div>
        ))}
        <div style={{background:'var(--bg2)',border:'1px solid var(--border2)',padding:'12px 14px',borderRadius:2}}>
          <div className="ptitle" style={{marginBottom:6}}>Detection Accuracy</div>
          {[{l:'Random Forest',v:97.4},{l:'XGBoost',v:98.1},{l:'Ensemble',v:98.6}].map(m=>(
            <div key={m.l} style={{display:'flex',justifyContent:'space-between',marginBottom:6,fontSize:11}}>
              <span style={{color:'var(--text2)'}}>{m.l}</span><span className="mono" style={{color:'var(--cyan)'}}>{m.v}%</span>
            </div>
          ))}
        </div>
        <div style={{background:'var(--bg2)',border:'1px solid var(--border2)',padding:'12px 14px',borderRadius:2}}>
          <div className="ptitle" style={{marginBottom:8}}>Attack Breakdown</div>
          {['DDoS','Bot','PortScan','Brute Force-Web','Web Attacks-BF'].map(a=>{const count=FLOWS.filter(f=>f.atk===a).length;return(
            <div key={a} style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:7}}>
              <span style={{color:'var(--text2)',fontSize:11}}>{a}</span>
              <span className={`badge ${ATTACK_BADGE[a]||'b-blue'}`}>{count}</span>
            </div>
          )})}
        </div>
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════  LOG FEED  ═══ */
const AGENT_COLORS={MONITOR:'var(--cyan)',ANALYZER:'var(--blue)',THREAT:'var(--red)',ML:'var(--amber)',DECISION:'var(--green)',RESPONSE:'var(--purple)',LEARN:'var(--cyan)',REPORT:'var(--blue)'}
function PageLogs({logs}){
  const [filter,setFilter]=useState('ALL')
  const termRef=useRef(null)
  const filters=['ALL','MONITOR','ANALYZER','THREAT','ML','DECISION','RESPONSE','LEARN','REPORT']
  const visible=useMemo(()=>filter==='ALL'?logs:logs.filter(l=>l.agent===filter),[logs,filter])
  useEffect(()=>{if(termRef.current)termRef.current.scrollTop=0},[visible.length])
  return (
    <div style={{display:'flex',flexDirection:'column',gap:12}}>
      <div style={{display:'flex',gap:6,alignItems:'center',flexWrap:'wrap'}}>
        <span style={{fontSize:11,fontWeight:700,letterSpacing:2,color:'var(--text2)'}}>FILTER:</span>
        {filters.map(f=><button key={f} onClick={()=>setFilter(f)} style={{background:filter===f?'rgba(0,229,204,.12)':'var(--bg2)',border:`1px solid ${filter===f?'var(--cyan)':'var(--border2)'}`,padding:'5px 12px',fontSize:11,fontWeight:700,letterSpacing:1,color:filter===f?'var(--cyan)':'var(--text2)',cursor:'pointer',borderRadius:1,fontFamily:'Rajdhani,sans-serif',textTransform:'uppercase',transition:'all .15s'}}>{f}</button>)}
        <span className="pill pill-green" style={{marginLeft:'auto',fontSize:10}}>{visible.length} ENTRIES</span>
      </div>
      <div ref={termRef} style={{background:'var(--bg)',border:'1px solid var(--border2)',borderRadius:2,padding:14,height:460,overflowY:'auto',fontFamily:'Share Tech Mono,monospace',fontSize:12}}>
        {visible.map(e=>(
          <div key={e.id} style={{display:'flex',gap:10,marginBottom:5,alignItems:'flex-start'}}>
            <span style={{color:'var(--text3)',minWidth:72,flexShrink:0}}>{e.time}</span>
            <span style={{color:AGENT_COLORS[e.agent]||'var(--cyan)',minWidth:90,flexShrink:0,fontWeight:700}}>[{e.agent}]</span>
            <span style={{color:e.lvl==='ERR'?'#ff7a8a':e.lvl==='WARN'?'#ffd24d':e.lvl==='OK'?'#4dff9b':'var(--text)',flex:1}}>{e.t}</span>
          </div>
        ))}
        {visible.length===0&&<div style={{color:'var(--text2)',textAlign:'center',marginTop:80}}>No log entries for filter: {filter}</div>}
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════  ML MODELS  ═══ */
function PageML(){
  const [activeTab,setActiveTab]=useState('overview')
  return (
    <div>
      <div style={{marginBottom:14}}>
        <div style={{fontSize:11,fontWeight:700,letterSpacing:2,color:'var(--text2)',textTransform:'uppercase',marginBottom:4}}>⬡ Machine Learning Ensemble — CICIDS-2018</div>
        <div style={{fontSize:12,color:'var(--text2)',lineHeight:1.6}}>Six complementary models trained on CICIDS-2017/2018 (2.8M labeled flows). The ensemble voter combines supervised, unsupervised, and deep learning signals for maximum accuracy and zero-day coverage.</div>
      </div>
      <div style={{display:'flex',gap:2,marginBottom:14,borderBottom:'1px solid var(--border2)'}}>
        {[['overview','⬡ MODEL OVERVIEW'],['classifier','⚡ LIVE AI CLASSIFIER']].map(([k,l])=>(
          <button key={k} onClick={()=>setActiveTab(k)} style={{background:'none',border:'none',borderBottom:`2px solid ${activeTab===k?'var(--cyan)':'transparent'}`,color:activeTab===k?'var(--cyan)':'var(--text2)',padding:'8px 18px',fontFamily:'Rajdhani,sans-serif',fontSize:12,fontWeight:700,letterSpacing:'1.5px',cursor:'pointer',textTransform:'uppercase',transition:'all .2s',marginBottom:'-1px'}}>{l}</button>
        ))}
      </div>
      {activeTab==='overview'&&<MLOverview/>}
      {activeTab==='classifier'&&<MLClassifier/>}
    </div>
  )
}
function MLOverview(){
  return (
    <div>
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(280px,1fr))',gap:14}}>
        {ML_MODELS.map(m=><MLCard key={m.name} model={m}/>)}
      </div>
      <div className="panel p-cyan" style={{marginTop:14}}>
        <div className="panel-corner" style={{borderColor:'var(--cyan)'}}/>
        <div className="ptitle">⬡ Model Performance Comparison (CICIDS-2018 Test Set)</div>
        <div style={{overflowX:'auto'}}>
          <table>
            <thead><tr><th>MODEL</th><th>TYPE</th><th>ACCURACY</th><th>AUC-ROC</th><th>FPR</th><th>SPEED</th><th>STATUS</th></tr></thead>
            <tbody>
              {[{name:'Random Forest',type:'Supervised',acc:97.4,auc:98.2,fpr:2.1,speed:'Fast',status:'DEPLOYED'},{name:'XGBoost',type:'Supervised',acc:98.1,auc:99.8,fpr:1.8,speed:'Fast',status:'DEPLOYED'},{name:'Isolation Forest',type:'Unsupervised',acc:97.0,auc:96.5,fpr:2.1,speed:'Fast',status:'DEPLOYED'},{name:'LSTM',type:'Deep Learning',acc:96.2,auc:97.1,fpr:2.9,speed:'Medium',status:'DEPLOYED'},{name:'K-Means',type:'Clustering',acc:82.0,auc:85.3,fpr:6.2,speed:'Fast',status:'SUPPORT'},{name:'Ensemble Voter',type:'Meta',acc:98.6,auc:99.4,fpr:1.2,speed:'Fast',status:'PRIMARY'}].map(r=>(
                <tr key={r.name}>
                  <td style={{color:'var(--text)',fontWeight:700}}>{r.name}</td><td style={{color:'var(--text2)'}}>{r.type}</td>
                  <td style={{color:'var(--cyan)'}}>{r.acc}%</td><td style={{color:'#4dff9b'}}>{r.auc}%</td><td style={{color:'#ffd24d'}}>{r.fpr}%</td><td style={{color:'var(--text2)'}}>{r.speed}</td>
                  <td><span className={`badge ${r.status==='PRIMARY'?'b-cyan':r.status==='DEPLOYED'?'b-green':'b-blue'}`}>{r.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
function MLCard({model:m}){
  return (
    <div style={{background:'var(--bg2)',border:'1px solid var(--border2)',borderRadius:2,padding:14,borderTop:`2px solid ${m.color}`}}>
      <div style={{fontSize:14,fontWeight:700,color:'var(--text)',marginBottom:4}}>{m.name}</div>
      <div style={{fontSize:11,color:m.color,letterSpacing:1,textTransform:'uppercase',marginBottom:12}}>{m.type}</div>
      {m.metrics.map(x=>(
        <div key={x.l}>
          <div style={{display:'flex',justifyContent:'space-between',marginBottom:4,fontSize:12}}><span style={{color:'var(--text2)'}}>{x.l}</span><span className="mono" style={{color:m.color}}>{x.v}%</span></div>
          <div style={{height:4,background:'var(--bg4)',marginBottom:8,overflow:'hidden'}}><div style={{height:'100%',width:`${x.v}%`,background:m.color,transition:'width 1s'}}/></div>
        </div>
      ))}
      <div style={{fontSize:11,color:'var(--text2)',marginTop:8,lineHeight:1.65,borderTop:'1px solid var(--border2)',paddingTop:8}}>{m.desc}</div>
    </div>
  )
}
function MLClassifier(){
  const [fields,setFields]=useState(PRESET_FLOWS[0])
  const [result,setResult]=useState(null),[loading,setLoading]=useState(false),[history,setHistory]=useState([]),[modelVotes,setModelVotes]=useState(null)
  function loadPreset(p){setFields(p);setResult(null);setModelVotes(null)}
  function setField(k,v){setFields(f=>({...f,[k]:parseFloat(v)||0}));setResult(null);setModelVotes(null)}
  async function classify(){
    setLoading(true);setResult(null);setModelVotes(null)
    const prompt=`You are a CICIDS-2018 network intrusion detection ML ensemble. Classify this network flow and simulate ensemble model votes.\nFlow Features: Flow Bytes/s: ${fields.flowBytes}, Flow Packets/s: ${fields.flowPkts}, SYN Flag Count: ${fields.synFlags}, RST Flag Count: ${fields.rstFlags}, IAT Mean (s): ${fields.iatMean}, Pkt Length Std: ${fields.pktLenStd}, Active Mean (s): ${fields.activeMean}, Flow Duration (s): ${fields.duration}\nRespond ONLY with valid JSON (no markdown, no extra text):\n{"label":"DDoS|Bot|PortScan|Brute Force-Web|Web Attacks-BF|Infiltration|BENIGN","confidence":<0-100>,"threat_score":<0.000-1.000>,"status":"BLOCKED|MONITOR|PASS","mitre_tactic":"<name>","mitre_id":"<TA####>","explanation":"<2 sentences>","model_votes":{"random_forest":{"label":"...","confidence":<0-100>},"xgboost":{"label":"...","confidence":<0-100>},"isolation_forest":{"label":"...","anomaly_score":<0.0-1.0>},"lstm":{"label":"...","confidence":<0-100>},"ensemble":{"label":"...","confidence":<0-100>}},"top_features":["<feat>: <val> — <impact>","<feat>: <val> — <impact>","<feat>: <val> — <impact>"]}`
    try{
      const res=await fetch('https://api.anthropic.com/v1/messages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({model:'claude-sonnet-4-20250514',max_tokens:1000,messages:[{role:'user',content:prompt}]})})
      const data=await res.json()
      const text=data.content?.find(b=>b.type==='text')?.text||''
      const parsed=JSON.parse(text.replace(/```json|```/g,'').trim())
      setResult(parsed);setModelVotes(parsed.model_votes)
      setHistory(h=>[{...fields,...parsed,ts:new Date().toTimeString().slice(0,8)},...h.slice(0,9)])
    }catch(e){setResult({error:'Classification failed — API error'})}
    setLoading(false)
  }
  const sc=result&&!result.error?result.status==='BLOCKED'?'var(--red)':result.status==='MONITOR'?'var(--amber)':'var(--green)':'var(--text2)'
  return (
    <div style={{display:'grid',gridTemplateColumns:'360px 1fr',gap:14}}>
      <div style={{display:'flex',flexDirection:'column',gap:10}}>
        <div className="panel p-cyan" style={{padding:12}}>
          <div className="panel-corner" style={{borderColor:'var(--cyan)'}}/>
          <div className="ptitle">⬡ Load Traffic Preset</div>
          <div style={{display:'flex',flexDirection:'column',gap:4}}>
            {PRESET_FLOWS.map(p=><button key={p.label} onClick={()=>loadPreset(p)} style={{background:fields.label===p.label?'rgba(0,229,204,.12)':'var(--bg3)',border:`1px solid ${fields.label===p.label?'var(--cyan)':'var(--border)'}`,color:fields.label===p.label?'var(--cyan)':'var(--text2)',padding:'7px 12px',fontFamily:'Rajdhani,sans-serif',fontSize:12,fontWeight:700,letterSpacing:1,cursor:'pointer',textTransform:'uppercase',textAlign:'left',borderRadius:1,transition:'all .15s'}}>{fields.label===p.label?'▶ ':''}{p.label}</button>)}
          </div>
        </div>
        <div className="panel p-blue" style={{padding:12}}>
          <div className="panel-corner" style={{borderColor:'var(--blue)'}}/>
          <div className="ptitle">⬡ CICIDS Flow Features</div>
          {FIELD_DEFS.map(f=>(
            <div key={f.k} style={{marginBottom:10}}>
              <div style={{display:'flex',justifyContent:'space-between',marginBottom:3,fontSize:11}}>
                <span style={{color:'var(--text2)'}}>{f.l}</span>
                <span className="mono" style={{color:'var(--cyan)'}}>{fields[f.k]}{f.unit?` ${f.unit}`:''}</span>
              </div>
              <input type="range" min={f.min} max={f.max} step={f.step} value={fields[f.k]} onChange={e=>setField(f.k,e.target.value)}/>
            </div>
          ))}
          <button onClick={classify} disabled={loading} style={{width:'100%',marginTop:4,background:loading?'var(--bg3)':'rgba(0,229,204,.12)',border:'1px solid var(--cyan)',color:loading?'var(--text2)':'var(--cyan)',padding:'10px',fontFamily:'Rajdhani,sans-serif',fontSize:13,fontWeight:700,letterSpacing:2,cursor:loading?'not-allowed':'pointer',textTransform:'uppercase',borderRadius:1,transition:'all .2s'}}>
            {loading?'⬡ CLASSIFYING...':'⚡ RUN ENSEMBLE CLASSIFIER'}
          </button>
        </div>
      </div>
      <div style={{display:'flex',flexDirection:'column',gap:10}}>
        {!result&&!loading&&<div className="panel" style={{display:'flex',alignItems:'center',justifyContent:'center',height:180,border:'1px dashed var(--border2)'}}>
          <div style={{textAlign:'center',color:'var(--text2)'}}><div style={{fontSize:28,marginBottom:8,opacity:.3}}>⬡</div><div style={{fontSize:12,letterSpacing:1}}>Configure flow features and run classifier</div></div>
        </div>}
        {loading&&<div className="panel p-amber" style={{display:'flex',alignItems:'center',justifyContent:'center',height:180}}>
          <div style={{textAlign:'center'}}><div style={{fontSize:12,color:'#ffd24d',letterSpacing:2,fontWeight:700}}>⬡ ENSEMBLE MODELS PROCESSING...</div><div style={{fontSize:11,color:'var(--text2)',marginTop:8}}>RF → XGBoost → LSTM → Isolation Forest → Voter</div></div>
        </div>}
        {result&&result.error&&<div className="panel p-red"><div style={{color:'#ff7a8a',fontSize:12}}>{result.error}</div></div>}
        {result&&!result.error&&<>
          <div style={{background:'var(--bg2)',border:`1px solid ${sc}`,borderRadius:2,padding:'14px 16px',position:'relative',overflow:'hidden'}}>
            <div style={{position:'absolute',top:0,left:0,right:0,height:2,background:sc}}/>
            <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',flexWrap:'wrap',gap:10}}>
              <div>
                <div style={{fontSize:10,letterSpacing:2,color:'var(--text2)',marginBottom:4,fontWeight:700}}>ENSEMBLE VERDICT</div>
                <div style={{fontSize:22,fontWeight:700,color:sc,letterSpacing:1}}>{result.label}</div>
                <div style={{fontSize:12,color:'var(--text2)',marginTop:2}}>{result.mitre_id} — {result.mitre_tactic}</div>
              </div>
              <div style={{display:'flex',gap:10}}>
                {[['CONFIDENCE',`${result.confidence}%`],['THREAT SCORE',result.threat_score],['DECISION',result.status]].map(([l,v])=>(
                  <div key={l} style={{textAlign:'center',background:'var(--bg3)',border:`1px solid ${l==='DECISION'?sc:'var(--border2)'}`,padding:'10px 18px',borderRadius:1}}>
                    <div className="mono" style={{fontSize:20,fontWeight:700,color:sc}}>{v}</div>
                    <div style={{fontSize:10,color:'var(--text2)',letterSpacing:1}}>{l}</div>
                  </div>
                ))}
              </div>
            </div>
            <div style={{marginTop:12,fontSize:12,color:'var(--text2)',lineHeight:1.65,borderTop:'1px solid var(--border2)',paddingTop:10}}>{result.explanation}</div>
          </div>
          {modelVotes&&<div className="panel p-purple" style={{padding:12}}>
            <div className="panel-corner" style={{borderColor:'var(--purple)'}}/>
            <div className="ptitle">⬡ Individual Model Votes</div>
            <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(140px,1fr))',gap:8}}>
              {[{name:'Random Forest',key:'random_forest',color:'#00e5cc'},{name:'XGBoost',key:'xgboost',color:'#4a9eff'},{name:'Isolation Forest',key:'isolation_forest',color:'#ff3b5e'},{name:'LSTM',key:'lstm',color:'#a855f7'},{name:'Ensemble',key:'ensemble',color:'#00e676'}].map(({name,key,color})=>{
                const v=modelVotes[key]||{};const conf=v.confidence??(v.anomaly_score!=null?Math.round(v.anomaly_score*100):0)
                return <div key={key} style={{background:'var(--bg3)',border:`1px solid ${color}33`,borderTop:`2px solid ${color}`,borderRadius:1,padding:'8px 10px'}}>
                  <div style={{fontSize:10,color:color,fontWeight:700,letterSpacing:1,marginBottom:4,textTransform:'uppercase'}}>{name}</div>
                  <div style={{fontSize:13,fontWeight:700,color:'var(--text)',marginBottom:4}}>{v.label||'—'}</div>
                  <div style={{height:3,background:'var(--bg4)',overflow:'hidden'}}><div style={{height:'100%',width:`${conf}%`,background:color,transition:'width .5s'}}/></div>
                  <div className="mono" style={{fontSize:10,color:color,marginTop:3}}>{conf}%</div>
                </div>
              })}
            </div>
          </div>}
          {result.top_features&&<div className="panel p-red" style={{padding:12}}>
            <div className="panel-corner" style={{borderColor:'var(--red)'}}/>
            <div className="ptitle">⬡ Key Feature Contributions</div>
            {result.top_features.map((f,i)=><div key={i} style={{display:'flex',alignItems:'center',gap:8,marginBottom:7,fontSize:12}}><span className="mono" style={{color:'#ff7a8a',minWidth:14}}>{i+1}.</span><span style={{color:'var(--text2)'}}>{f}</span></div>)}
          </div>}
        </>}
        {history.length>0&&<div className="panel p-cyan" style={{padding:12}}>
          <div className="panel-corner" style={{borderColor:'var(--cyan)'}}/>
          <div className="ptitle">⬡ Classification History</div>
          <div style={{overflowX:'auto'}}>
            <table>
              <thead><tr><th>TIME</th><th>BYTES/S</th><th>LABEL</th><th>CONF</th><th>SCORE</th><th>STATUS</th></tr></thead>
              <tbody>
                {history.map((h,i)=>{const hsc=h.status==='BLOCKED'?'var(--red)':h.status==='MONITOR'?'var(--amber)':'var(--green)';return(
                  <tr key={i}>
                    <td className="mono" style={{color:'var(--text3)',fontSize:10}}>{h.ts}</td>
                    <td style={{color:'var(--text2)',fontSize:10}}>{h.flowBytes?.toLocaleString()}</td>
                    <td><span className={`badge ${ATTACK_BADGE[h.label]||'b-blue'}`}>{h.label}</span></td>
                    <td className="mono" style={{color:'var(--cyan)'}}>{h.confidence}%</td>
                    <td className="mono" style={{color:'#ffd24d'}}>{h.threat_score}</td>
                    <td><span style={{color:hsc,fontWeight:700,fontSize:11}}>{h.status}</span></td>
                  </tr>
                )})}
              </tbody>
            </table>
          </div>
        </div>}
      </div>
    </div>
  )
}
