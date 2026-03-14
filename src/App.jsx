import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react'

/* ═══════════════════════════════════════════════════════════════
   CICIDS-2018 DATA ENGINE
═══════════════════════════════════════════════════════════════ */

const CICIDS_LABELS = [
  { name: 'PortScan',        color: '#ffb800', pct: 0.18 },
  { name: 'BENIGN',          color: '#00e676', pct: 0.32 },
  { name: 'Brute Force-Web', color: '#00e5cc', pct: 0.12 },
  { name: 'DDoS',            color: '#ff3b5e', pct: 0.19 },
  { name: 'Bot',             color: '#a855f7', pct: 0.10 },
  { name: 'Web Attacks-BF',  color: '#4a9eff', pct: 0.09 },
]

const ATTACK_COLORS = {
  BENIGN:           '#00e676',
  DDoS:             '#ff3b5e',
  Bot:              '#a855f7',
  PortScan:         '#ffb800',
  'Brute Force-Web':'#ff3b5e',
  'Web Attacks-BF': '#4a9eff',
  Infiltration:     '#ffb800',
}

const ATTACK_BADGE = {
  BENIGN:           'b-green',
  DDoS:             'b-red',
  Bot:              'b-purple',
  PortScan:         'b-amber',
  'Brute Force-Web':'b-red',
  'Web Attacks-BF': 'b-blue',
  Infiltration:     'b-amber',
}

const ATTACK_TYPES_ALL = ['BENIGN','DDoS','Bot','PortScan','Brute Force-Web','Web Attacks-BF','Infiltration']
const COMMON_PORTS = [80,443,22,3389,8080,6667,25,3306,21,53,8443,3000,110,143,587]

function randIP() { return `${192 + (Math.random() > 0.5 ? 1 : 0)}.168.${Math.floor(Math.random()*20)}.${Math.floor(Math.random()*254)+1}` }
function pick(arr) { return arr[Math.floor(Math.random()*arr.length)] }

function generateFlows(n = 150) {
  return Array.from({ length: n }, (_, i) => {
    const benign = Math.random() < 0.37
    const atk    = benign ? 'BENIGN' : pick(ATTACK_TYPES_ALL.slice(1))
    const bps    = atk === 'DDoS'   ? +(3e6 + Math.random()*2e6).toFixed(0)
                 : atk === 'BENIGN' ? +(800  + Math.random()*6e4).toFixed(0)
                 :                    +(8e3  + Math.random()*9e5).toFixed(0)
    const conf   = benign ? 0 : +(65 + Math.random()*34).toFixed(1)
    const score  = benign ? +(Math.random()*0.14).toFixed(3) : +(0.55 + Math.random()*0.45).toFixed(3)
    const dur    = +(Math.random()*300).toFixed(1)
    return {
      id: i,
      src:  randIP(),
      dst:  randIP(),
      dport: pick(COMMON_PORTS),
      atk,
      conf,
      bps,
      pps:   +(bps / 64).toFixed(1),
      score: parseFloat(score),
      dur,
      synFlags: (atk==='DDoS'||atk==='PortScan') ? 1 : 0,
      rstFlags: atk==='PortScan' ? 1 : 0,
      status: benign ? 'PASS' : parseFloat(score) > 0.85 ? 'BLOCKED' : 'MONITOR',
    }
  })
}

const FLOWS = generateFlows(150)

const ATTACK_PROFILES = {
  ALL: {
    type:'Bot', conf:89, port:8080, dur:'61.7s', bps:'7.12e+5', score:'1.000',
    feats:{ 'Flow bytes/s':'7.12e+5','Packets/s':'29561','SYN flags':'0','RST':'0','IAT Std':'6.30s','Label':'Bot' },
  },
  DDoS: {
    type:'DDoS', conf:97, port:443, dur:'2.1s', bps:'4.55e+6', score:'0.982',
    feats:{ 'Flow bytes/s':'4.55e+6','Packets/s':'98234','SYN flags':'1','RST':'0','IAT Std':'0.01s','Label':'DDoS' },
  },
  PortScan: {
    type:'PortScan', conf:76, port:3389, dur:'120s', bps:'1.2e+3', score:'0.762',
    feats:{ 'Flow bytes/s':'1.2e+3','Packets/s':'45.3','SYN flags':'1','RST':'1','IAT Std':'22.4s','Label':'PortScan' },
  },
  BruteForce: {
    type:'Brute Force', conf:84, port:22, dur:'18.3s', bps:'3.4e+4', score:'0.841',
    feats:{ 'Flow bytes/s':'3.4e+4','Packets/s':'210.9','SYN flags':'1','RST':'0','IAT Std':'0.92s','Label':'BruteForce' },
  },
  Bot: {
    type:'Bot', conf:91, port:6667, dur:'305s', bps:'8.9e+4', score:'0.994',
    feats:{ 'Flow bytes/s':'8.9e+4','Packets/s':'1234.6','SYN flags':'0','RST':'0','IAT Std':'1.22s','Label':'Bot' },
  },
}

const TOP_PORTS = [
  { port:443,  pct:75, flows:20 },
  { port:3389, pct:65, flows:17 },
  { port:138,  pct:67, flows:15 },
  { port:137,  pct:67, flows:12 },
  { port:25,   pct:78, flows:9  },
]

const FEATURE_IMPORTANCE = [
  { label:'Flow Bytes/s',   pct:100, color:'#ff3b5e' },
  { label:'Flow Packets/s', pct:88,  color:'#ff3b5e' },
  { label:'RST Flag Count', pct:86,  color:'#ff3b5e' },
  { label:'SYN Flag Count', pct:75,  color:'#ffb800' },
  { label:'IAT Mean',       pct:62,  color:'#4a9eff' },
  { label:'Pkt Length Std', pct:48,  color:'#ffb800' },
  { label:'Active Mean',    pct:41,  color:'#4a9eff' },
]

/* ═══════════════════════════════════════════════════════════════
   AGENTS DATA
═══════════════════════════════════════════════════════════════ */

const AGENTS = [
  {
    id:'monitor', name:'Monitoring Agent', icon:'◉',
    accentColor:'#00e5cc', iconBg:'rgba(0,229,204,.15)', iconBorder:'1px solid rgba(0,229,204,.3)', leftBg:'#00e5cc',
    description:'Captures and preprocesses raw CICIDS-2018 network flow features. Extracts all 78 features per flow including bytes/s, packets/s, flag counts, IAT statistics, and flow duration. Feeds the real-time analysis pipeline via shared message queue.',
    metrics:[{v:'2847',l:'Flows/s'},{v:'78',l:'Features'},{v:'4ms',l:'Latency'}],
    logs:[
      {lvl:'OK',   t:'Flow ingestion pipeline active — 2847 flows/sec'},
      {lvl:'INFO', t:'CICIDS feature extraction: 78 features per record'},
      {lvl:'OK',   t:'Preprocessing: normalization + standardization complete'},
      {lvl:'INFO', t:'Interfaces: eth0, eth1, eth2 — all sensors nominal'},
      {lvl:'OK',   t:'Forwarding batch to Log Analysis Agent via queue'},
    ],
  },
  {
    id:'log', name:'Log Analysis Agent', icon:'≡',
    accentColor:'#4a9eff', iconBg:'rgba(74,158,255,.15)', iconBorder:'1px solid rgba(74,158,255,.3)', leftBg:'#4a9eff',
    description:'Parses and correlates system logs with CICIDS flow metadata using sliding-window analysis (60s/300s/3600s). Identifies anomalous sequences and temporal patterns. Generates structured event records for downstream processing.',
    metrics:[{v:'14.2K',l:'Logs/min'},{v:'99.1%',l:'Parse Rate'},{v:'12ms',l:'Lag'}],
    logs:[
      {lvl:'OK',   t:'Log correlation engine ready — 8,420 pattern entries loaded'},
      {lvl:'INFO', t:'Sliding window: 60s / 300s / 3600s all active'},
      {lvl:'WARN', t:'Anomalous sequence: 192.168.10.5 — 3 failed auth in 2s'},
      {lvl:'OK',   t:'Temporal pattern DB updated: +47 new patterns indexed'},
      {lvl:'INFO', t:'Forwarding suspicious flows to Threat Detection Agent'},
    ],
  },
  {
    id:'threat', name:'Threat Detection Agent', icon:'⚠',
    accentColor:'#ff3b5e', iconBg:'rgba(255,59,94,.15)', iconBorder:'1px solid rgba(255,59,94,.3)', leftBg:'#ff3b5e',
    description:'Rule-based and signature-driven threat classification against CICIDS-2018 attack signatures. Detects DDoS, PortScan, Brute Force, Web Attacks, Bot and Infiltration patterns using 2,341 active rules and anomaly heuristics.',
    metrics:[{v:'97.4%',l:'Accuracy'},{v:'2.1%',l:'FPR'},{v:'98.8%',l:'Recall'}],
    logs:[
      {lvl:'ERR',  t:'Bot detected — 192.168.10.51:8080 — score 0.994'},
      {lvl:'WARN', t:'PortScan: 172.31.1.20 → /24 subnet sequential probe'},
      {lvl:'ERR',  t:'DDoS: port 443 — 98,234 pkt/sec threshold exceeded'},
      {lvl:'OK',   t:'Signature DB: 2,341 rules active — all up to date'},
      {lvl:'INFO', t:'High-confidence threats forwarded to ML Intelligence Agent'},
    ],
  },
  {
    id:'ml', name:'ML Intelligence Agent', icon:'⬡',
    accentColor:'#ffb800', iconBg:'rgba(255,184,0,.15)', iconBorder:'1px solid rgba(255,184,0,.3)', leftBg:'#ffb800',
    description:'Ensemble ML pipeline: Random Forest + XGBoost + Isolation Forest + LSTM trained on CICIDS-2017/2018. Performs probabilistic threat scoring (AUC 0.998) and zero-day anomaly detection via unsupervised Isolation Forest.',
    metrics:[{v:'97.4%',l:'RF Acc'},{v:'0.998',l:'AUC-ROC'},{v:'512',l:'New Samples'}],
    logs:[
      {lvl:'OK',   t:'Random Forest: 200 trees loaded — 97.4% accuracy'},
      {lvl:'OK',   t:'XGBoost: 500 estimators ready — AUC-ROC 0.998'},
      {lvl:'INFO', t:'Isolation Forest: contamination=0.01 — anomaly detection ON'},
      {lvl:'WARN', t:'Novel pattern detected — IF anomaly score 0.994'},
      {lvl:'OK',   t:'Ensemble vote: Bot — confidence 91% (RF+XGB+LSTM consensus)'},
    ],
  },
  {
    id:'decision', name:'Decision Agent', icon:'▣',
    accentColor:'#00e676', iconBg:'rgba(0,230,118,.15)', iconBorder:'1px solid rgba(0,230,118,.3)', leftBg:'#00e676',
    description:'Orchestrates automated response using MITRE ATT&CK framework. Evaluates threat severity, confidence, and asset criticality. Policy: score>0.85 triggers auto-block; 0.5–0.85 → MONITOR; <0.5 → PASS.',
    metrics:[{v:'1.2s',l:'Resp Time'},{v:'94',l:'Decisions'},{v:'99.8%',l:'Uptime'}],
    logs:[
      {lvl:'OK',   t:'MITRE ATT&CK: 14 tactics, 196 techniques loaded'},
      {lvl:'INFO', t:'Policy: threat_score > 0.85 → auto-block firewall rule'},
      {lvl:'OK',   t:'Decision: BLOCK 192.168.10.51 — Bot, score 0.994'},
      {lvl:'INFO', t:'Decision: MONITOR 172.31.1.20 — PortScan, score 0.762'},
      {lvl:'OK',   t:'Directives dispatched to Response Agent (avg 1.2s)'},
    ],
  },
  {
    id:'response', name:'Response Agent', icon:'⊗',
    accentColor:'#a855f7', iconBg:'rgba(168,85,247,.15)', iconBorder:'1px solid rgba(168,85,247,.3)', leftBg:'#a855f7',
    description:'Executes automated mitigations: IP blocking via firewall API, endpoint isolation, rate limiting, and P1 SOC alert dispatch. Integrates with SIEM for full incident lifecycle tracking. Sub-100ms block SLA.',
    metrics:[{v:'47',l:'IPs Blocked'},{v:'3',l:'Isolated'},{v:'99ms',l:'Block Time'}],
    logs:[
      {lvl:'OK',   t:'Firewall API: connected — iptables + pfSense sync active'},
      {lvl:'OK',   t:'BLOCKED: 192.168.10.51 — Bot, score 0.994 (47ms)'},
      {lvl:'WARN', t:'Rate-limited: 172.31.1.20 — PortScan — 50 req/min cap'},
      {lvl:'OK',   t:'SOC alert dispatched: #INC-2024-8823 — Priority P1'},
      {lvl:'INFO', t:'Incident data forwarded to Learning + Report Agents'},
    ],
  },
  {
    id:'learn', name:'Learning Agent', icon:'↻',
    accentColor:'#00e5cc', iconBg:'rgba(0,229,204,.15)', iconBorder:'1px solid rgba(0,229,204,.3)', leftBg:'#00e5cc',
    description:'Continuously retrains ML models with verified threat samples via active learning and uncertainty sampling. Feedback loops from confirmed incidents improve detection of novel attacks and reduce false positives over 4-hour cycles.',
    metrics:[{v:'512',l:'New Samples'},{v:'+0.3%',l:'Acc Gain'},{v:'4h',l:'Retrain'}],
    logs:[
      {lvl:'OK',   t:'Active learning pipeline: READY — uncertainty sampling ON'},
      {lvl:'INFO', t:'512 verified samples queued for next training cycle (T+4h)'},
      {lvl:'OK',   t:'RF model retrained — accuracy 97.4% → 97.7% (+0.3%)'},
      {lvl:'INFO', t:'FP rate reduced: 2.1% → 1.8% after last cycle'},
      {lvl:'OK',   t:'New model weights deployed to ML Intelligence Agent'},
    ],
  },
  {
    id:'report', name:'Report Agent', icon:'◈',
    accentColor:'#4a9eff', iconBg:'rgba(74,158,255,.15)', iconBorder:'1px solid rgba(74,158,255,.3)', leftBg:'#4a9eff',
    description:'Generates real-time security reports, compliance summaries and executive briefings. Produces CICIDS-formatted incident logs and exports STIX/TAXII threat intel. SIEM connector syncs with Splunk and Elastic.',
    metrics:[{v:'23',l:'Reports/hr'},{v:'8',l:'Alerts Sent'},{v:'SIEM',l:'Connected'}],
    logs:[
      {lvl:'OK',   t:'SIEM connector active — Splunk + Elastic sync running'},
      {lvl:'OK',   t:'Dashboard updated: 150 CICIDS flow records processed'},
      {lvl:'INFO', t:'Incident report #INC-2024-8823 generated — PDF + JSON'},
      {lvl:'OK',   t:'Compliance export: CICIDS CSV + STIX/TAXII formats ready'},
      {lvl:'INFO', t:'Executive summary dispatched: THREAT LEVEL HIGH'},
    ],
  },
]

/* ═══════════════════════════════════════════════════════════════
   LOG MESSAGES POOL
═══════════════════════════════════════════════════════════════ */

const LOG_POOL = [
  {agent:'MONITOR',  lvl:'INFO', t:'Flow ingestion: 2847 flows/sec — CICIDS pipeline active'},
  {agent:'MONITOR',  lvl:'OK',   t:'Feature extraction complete: 78 features/record'},
  {agent:'MONITOR',  lvl:'INFO', t:'Buffer utilization 23% — all network interfaces nominal'},
  {agent:'ANALYZER', lvl:'INFO', t:'Correlation: sliding window 60s — 14,200 events/min'},
  {agent:'ANALYZER', lvl:'WARN', t:'Anomalous sequence: 192.168.10.5 — 3 failed auth in 2s'},
  {agent:'ANALYZER', lvl:'INFO', t:'Temporal pattern matched: T1078.003 (Valid Accounts)'},
  {agent:'THREAT',   lvl:'ERR',  t:'Bot detected: 192.168.10.51 → port 8080 — score 0.994'},
  {agent:'THREAT',   lvl:'WARN', t:'PortScan: 172.31.1.20 — sequential probe 20 ports/sec'},
  {agent:'THREAT',   lvl:'ERR',  t:'DDoS: port 443 — 98,234 pkts/sec — threshold exceeded'},
  {agent:'THREAT',   lvl:'OK',   t:'Signature DB: 2,341 rules — no updates pending'},
  {agent:'ML',       lvl:'INFO', t:'Random Forest: Bot prediction — 97.1% confidence'},
  {agent:'ML',       lvl:'OK',   t:'XGBoost ensemble: DDoS confirmed — AUC-ROC 0.998'},
  {agent:'ML',       lvl:'WARN', t:'Novel pattern — Isolation Forest anomaly score 0.994'},
  {agent:'ML',       lvl:'OK',   t:'Model retrained — accuracy delta +0.3% (97.7%)'},
  {agent:'DECISION', lvl:'OK',   t:'BLOCK: 192.168.10.51 — Bot, score > 0.85 threshold'},
  {agent:'DECISION', lvl:'INFO', t:'MONITOR: 172.31.1.20 — PortScan, score 0.762'},
  {agent:'DECISION', lvl:'INFO', t:'MITRE tactic mapped: TA0011 — Command and Control'},
  {agent:'RESPONSE', lvl:'OK',   t:'Firewall rule added: DROP 192.168.10.51 (99ms)'},
  {agent:'RESPONSE', lvl:'OK',   t:'SOC alert dispatched: #INC-2024-8823 — severity HIGH'},
  {agent:'RESPONSE', lvl:'WARN', t:'Rate limit: 172.31.1.20 capped at 50 req/min'},
  {agent:'LEARN',    lvl:'OK',   t:'512 verified samples queued — active learning pipeline'},
  {agent:'LEARN',    lvl:'INFO', t:'False positive rate: 2.1% → 1.8% (last cycle)'},
  {agent:'REPORT',   lvl:'OK',   t:'Incident #INC-2024-8823 report generated — SIEM synced'},
  {agent:'REPORT',   lvl:'INFO', t:'Dashboard updated: 150 CICIDS flows — THREAT LEVEL HIGH'},
]

const ML_MODELS = [
  {
    name:'Random Forest Classifier', type:'SUPERVISED ENSEMBLE', color:'#00e5cc',
    metrics:[{l:'Accuracy',v:97.4},{l:'Precision',v:96.8},{l:'Recall',v:98.8},{l:'F1-Score',v:97.8}],
    desc:'200 trees, max_depth=20. Trained on CICIDS-2017/2018 (2.8M flows). Primary classifier for 7 attack categories. SMOTE oversampling for class imbalance.',
  },
  {
    name:'XGBoost Threat Scorer', type:'GRADIENT BOOSTING', color:'#4a9eff',
    metrics:[{l:'Accuracy',v:98.1},{l:'AUC-ROC',v:99.8},{l:'Speed',v:92},{l:'Log Loss',v:4}],
    desc:'500 estimators, depth=6, lr=0.1. Best on DDoS + Bot detection. GPU-accelerated inference on 78-feature CICIDS input vector.',
  },
  {
    name:'Isolation Forest', type:'UNSUPERVISED ANOMALY', color:'#ff3b5e',
    metrics:[{l:'Anomaly Det.',v:97},{l:'FPR',v:2.1},{l:'Coverage',v:94},{l:'Contamination',v:1}],
    desc:'100 estimators, contamination=0.01. Zero-day attack detection without labels. Sub-sampling 256 for real-time speed. Runs in parallel with supervised models.',
  },
  {
    name:'LSTM Sequence Model', type:'DEEP LEARNING', color:'#a855f7',
    metrics:[{l:'Accuracy',v:96.2},{l:'Val Acc',v:95.8},{l:'Val Loss',v:76},{l:'Epochs',v:100}],
    desc:'Bidirectional LSTM (128 units). Detects multi-step attack campaigns across 60-step flow sequences. Trained on temporal CICIDS windows.',
  },
  {
    name:'K-Means Clusterer', type:'UNSUPERVISED CLUSTERING', color:'#ffb800',
    metrics:[{l:'Clusters',v:70},{l:'Silhouette',v:82},{l:'Coverage',v:96},{l:'Speed',v:95}],
    desc:'7 clusters → CICIDS attack families. Initial traffic segmentation + feature-space visualization. MiniBatch K-Means for real-time stream processing.',
  },
  {
    name:'Ensemble Voter', type:'META-CLASSIFIER', color:'#00e676',
    metrics:[{l:'Accuracy',v:98.6},{l:'Confidence',v:99.1},{l:'TPR',v:99.4},{l:'FPR',v:1.2}],
    desc:'Weighted soft voting: RF(0.35) + XGB(0.35) + LSTM(0.20) + IF(0.10). Calibrated probability output. Threshold 0.85 triggers auto-block response.',
  },
]

/* ═══════════════════════════════════════════════════════════════
   GLOBAL STYLES (injected once)
═══════════════════════════════════════════════════════════════ */

const GLOBAL_CSS = `
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap');

*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#090c10;--bg2:#0d1117;--bg3:#111820;--bg4:#162030;
  --cyan:#00e5cc;--cyan2:#00b89a;--red:#ff3b5e;--amber:#ffb800;
  --green:#00e676;--blue:#4a9eff;--purple:#a855f7;
  --text:#c8d6e5;--text2:#7a8fa8;--text3:#4a6080;
  --border:#1e3a5a;--border2:#0f2540;
}
html,body,#root{height:100%;background:var(--bg);color:var(--text);font-family:'Rajdhani',sans-serif;font-size:14px;overflow-x:hidden}
.mono{font-family:'Share Tech Mono',monospace!important}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}

/* Panels */
.panel{background:var(--bg2);border:1px solid var(--border2);border-radius:2px;padding:14px;position:relative;overflow:hidden}
.panel::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.p-cyan::before{background:var(--cyan)}
.p-red::before{background:var(--red)}
.p-amber::before{background:var(--amber)}
.p-blue::before{background:var(--blue)}
.p-green::before{background:var(--green)}
.p-purple::before{background:var(--purple)}
.panel-corner{position:absolute;top:0;right:0;width:12px;height:12px;border-top:2px solid;border-right:2px solid;opacity:.3;pointer-events:none}
.panel-corner-bl{position:absolute;bottom:0;left:0;width:12px;height:12px;border-bottom:2px solid;border-left:2px solid;opacity:.3;pointer-events:none}
.ptitle{font-size:11px;font-weight:700;letter-spacing:2px;color:var(--text2);text-transform:uppercase;margin-bottom:12px}

/* Badges */
.badge{padding:2px 8px;border-radius:1px;font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase;display:inline-block;white-space:nowrap}
.b-red   {background:rgba(255,59,94,.15);color:var(--red);border:1px solid rgba(255,59,94,.3)}
.b-amber {background:rgba(255,184,0,.15);color:var(--amber);border:1px solid rgba(255,184,0,.3)}
.b-blue  {background:rgba(74,158,255,.15);color:var(--blue);border:1px solid rgba(74,158,255,.3)}
.b-green {background:rgba(0,230,118,.15);color:var(--green);border:1px solid rgba(0,230,118,.3)}
.b-purple{background:rgba(168,85,247,.15);color:var(--purple);border:1px solid rgba(168,85,247,.3)}
.b-cyan  {background:rgba(0,229,204,.12);color:var(--cyan);border:1px solid rgba(0,229,204,.3)}

/* Pills */
.pill{padding:4px 12px;border-radius:2px;font-weight:700;letter-spacing:1px;text-transform:uppercase;font-size:11px;font-family:'Rajdhani',sans-serif;white-space:nowrap}
.pill-green{background:rgba(0,230,118,.15);color:var(--green);border:1px solid rgba(0,230,118,.3)}
.pill-red  {background:rgba(255,59,94,.15);color:var(--red);border:1px solid rgba(255,59,94,.3)}
.pill-amber{background:rgba(255,184,0,.15);color:var(--amber);border:1px solid rgba(255,184,0,.3)}

/* Metric cells */
.mcell{background:var(--bg3);border:1px solid var(--border2);padding:8px;border-radius:1px}
.mc-lbl{font-size:10px;letter-spacing:1.5px;color:var(--text2);margin-bottom:3px;text-transform:uppercase}
.mc-val{font-size:18px;font-weight:700;color:var(--cyan);font-family:'Share Tech Mono',monospace}

/* Table */
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:var(--bg3);color:var(--text2);padding:8px 10px;text-align:left;font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;border-bottom:1px solid var(--border2);white-space:nowrap;cursor:pointer;user-select:none}
th:hover{color:var(--cyan)}
td{padding:7px 10px;border-bottom:1px solid rgba(30,58,90,.35);font-family:'Share Tech Mono',monospace;color:var(--text);font-size:12px}
tr:hover td{background:rgba(0,229,204,.03)}

/* Live dot */
@keyframes ldot{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(0,230,118,.5)}50%{opacity:.7;box-shadow:0 0 0 6px rgba(0,230,118,0)}}
.live-dot{width:8px;height:8px;border-radius:50%;background:var(--green);animation:ldot 1.5s infinite;flex-shrink:0}

/* Ticker */
@keyframes tick{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}
.ticker-inner{display:inline-block;animation:tick 40s linear infinite}

/* Pulse glow for threat */
@keyframes throb{0%,100%{box-shadow:0 0 0 0 rgba(255,59,94,0)}50%{box-shadow:0 0 8px 2px rgba(255,59,94,.15)}}
`

/* ═══════════════════════════════════════════════════════════════
   TINY CANVAS DONUT
═══════════════════════════════════════════════════════════════ */

function Donut() {
  const ref = useRef(null)
  useEffect(() => {
    const c = ref.current; if (!c) return
    const ctx = c.getContext('2d')
    const cx=90, cy=90, r=70, ir=50
    ctx.clearRect(0,0,180,180)
    let start = -Math.PI/2
    CICIDS_LABELS.forEach(l => {
      const end = start + l.pct*2*Math.PI
      ctx.beginPath(); ctx.moveTo(cx,cy); ctx.arc(cx,cy,r,start,end); ctx.closePath()
      ctx.fillStyle = l.color; ctx.fill()
      start = end
    })
    ctx.beginPath(); ctx.arc(cx,cy,ir,0,Math.PI*2)
    ctx.fillStyle='#0d1117'; ctx.fill()
    ctx.fillStyle='#c8d6e5'; ctx.font='600 13px Rajdhani,sans-serif'; ctx.textAlign='center'
    ctx.fillText('CICIDS',cx,cy-4); ctx.fillText('2018',cx,cy+13)
  }, [])
  return <canvas ref={ref} width={180} height={180} style={{flexShrink:0}}/>
}

/* ═══════════════════════════════════════════════════════════════
   CANVAS LINE CHART
═══════════════════════════════════════════════════════════════ */

function LineChart({ benign, threat }) {
  const ref = useRef(null)
  useEffect(() => {
    const c = ref.current; if (!c) return
    const W=c.width, H=c.height
    const ctx=c.getContext('2d')
    const pad={l:50,r:20,t:15,b:30}
    const inner={w:W-pad.l-pad.r, h:H-pad.t-pad.b}
    ctx.clearRect(0,0,W,H)
    const all=[...benign,...threat]
    const maxV=Math.max(...all)*1.1||1
    function px(i){return pad.l+i*(inner.w/(benign.length-1))}
    function py(v){return pad.t+inner.h*(1-v/maxV)}
    // Grid
    ctx.strokeStyle='rgba(30,58,90,.5)'; ctx.lineWidth=0.5
    for(let i=0;i<=4;i++){
      const y=pad.t+inner.h*(i/4)
      ctx.beginPath(); ctx.moveTo(pad.l,y); ctx.lineTo(pad.l+inner.w,y); ctx.stroke()
      ctx.fillStyle='#7a8fa8'; ctx.font='10px Share Tech Mono,monospace'; ctx.textAlign='right'
      const val=Math.round(maxV*(1-i/4)/1000)
      ctx.fillText(val+'K',pad.l-5,y+4)
    }
    // X labels
    ctx.fillStyle='#7a8fa8'; ctx.font='10px Share Tech Mono,monospace'; ctx.textAlign='center'
    for(let i=0;i<benign.length;i+=4){
      ctx.fillText(`${i*3}m`,px(i),H-8)
    }
    function drawLine(data, color, fill){
      ctx.beginPath()
      data.forEach((v,i)=>{ i===0?ctx.moveTo(px(i),py(v)):ctx.lineTo(px(i),py(v)) })
      if(fill){
        const tmp=new Path2D(); data.forEach((v,i)=>{ i===0?tmp.moveTo(px(i),py(v)):tmp.lineTo(px(i),py(v)) })
        tmp.lineTo(px(data.length-1),pad.t+inner.h); tmp.lineTo(px(0),pad.t+inner.h); tmp.closePath()
        const grad=ctx.createLinearGradient(0,pad.t,0,pad.t+inner.h)
        grad.addColorStop(0,color.replace(')',',0.15)').replace('rgb','rgba'))
        grad.addColorStop(1,color.replace(')',',0)').replace('rgb','rgba'))
        ctx.fillStyle=grad; ctx.fill(tmp)
      }
      ctx.strokeStyle=color; ctx.lineWidth=1.5; ctx.lineJoin='round'; ctx.stroke()
    }
    drawLine(benign,'rgb(74,158,255)',true)
    drawLine(threat,'rgb(255,59,94)',true)
  },[benign,threat])
  return <canvas ref={ref} width={640} height={145} style={{width:'100%',height:'145px'}}/>
}

/* ═══════════════════════════════════════════════════════════════
   MAIN APP
═══════════════════════════════════════════════════════════════ */

export default function App() {
  const [page, setPage] = useState('dashboard')
  const [logs, setLogs] = useState([])
  const [fps, setFps] = useState(2847)
  const [clock, setClock] = useState('')
  const logIdx = useRef(0)
  const styleInjected = useRef(false)

  // Inject CSS once
  if (!styleInjected.current) {
    const el = document.createElement('style')
    el.textContent = GLOBAL_CSS
    document.head.appendChild(el)
    styleInjected.current = true
  }

  // Clock
  useEffect(() => {
    const tick = () => setClock(new Date().toUTCString().slice(17,25)+' UTC')
    tick(); const id=setInterval(tick,1000); return ()=>clearInterval(id)
  },[])

  // Live log feed
  useEffect(() => {
    const seed = Array.from({length:18},(_,i)=>{
      const m=LOG_POOL[i%LOG_POOL.length]
      return {id:i, time:new Date(Date.now()-(18-i)*2800).toTimeString().slice(0,8), ...m}
    }).reverse()
    setLogs(seed)
    logIdx.current = 18
    const id=setInterval(()=>{
      const m=LOG_POOL[logIdx.current%LOG_POOL.length]; logIdx.current++
      setLogs(p=>[{id:logIdx.current,time:new Date().toTimeString().slice(0,8),...m},...p.slice(0,199)])
    },2500)
    return ()=>clearInterval(id)
  },[])

  // FPS jitter
  useEffect(()=>{
    const id=setInterval(()=>setFps(2600+Math.floor(Math.random()*600)),3200)
    return ()=>clearInterval(id)
  },[])

  function handleIR(action) {
    const msgs={
      investigate:`Investigation initiated — forensic agent spawned for 192.168.10.51:8080`,
      lockdown:`FORCE LOCKDOWN — endpoint 192.168.10.51 isolated from network`,
      report:`Incident report #INC-2024-8824 generated — exported to SIEM`,
      escalate:`Escalated to SOC — #INC-2024-8824 P1 assigned`,
    }
    setLogs(p=>[{id:Date.now(),time:new Date().toTimeString().slice(0,8),agent:'DECISION',lvl:'OK',t:msgs[action]},...p.slice(0,199)])
  }

  const PAGES=['dashboard','agents','anomaly','logs','ml']
  const PAGE_LABELS={dashboard:'DASHBOARD',agents:'AGENTS',anomaly:'ANOMALY ANALYSIS',logs:'LOG FEED',ml:'ML MODELS'}

  const tickerItems = [
    `LIVE MODE — CICIDS-2018 — ${fps} flows/sec`,
    'THREAT: Bot detected port 8080 confidence 89%',
    'ML: Ensemble accuracy 98.6%',
    'BLOCKED: IP 192.168.10.51 (Bot score 0.994)',
    'ALERT: DDoS pattern in subnet 172.31.0.0/24',
    'LEARN: Model updated +512 samples',
    'MITRE ATT&CK: TA0011 C2 channel detected',
    'SOC ALERT: #INC-2024-8823 dispatched P1',
  ]

  return (
    <div style={{display:'flex',flexDirection:'column',minHeight:'100vh'}}>
      {/* ── HEADER ── */}
      <header style={{background:'var(--bg2)',borderBottom:'1px solid var(--border2)',padding:'0 20px',display:'flex',alignItems:'center',gap:16,height:54,flexShrink:0,position:'sticky',top:0,zIndex:100}}>
        <div style={{display:'flex',alignItems:'center',gap:10,fontWeight:700,fontSize:20,letterSpacing:2,color:'#fff',whiteSpace:'nowrap'}}>
          <div style={{width:32,height:32,background:'var(--cyan)',clipPath:'polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%)',display:'flex',alignItems:'center',justifyContent:'center',fontSize:14,color:'#000',fontWeight:900,flexShrink:0}}>⬡</div>
          CIPHER<span style={{color:'var(--cyan)'}}>NEST</span>
        </div>

        <nav style={{display:'flex',gap:2,margin:'0 8px',overflowX:'auto',scrollbarWidth:'none'}}>
          {PAGES.map(p=>(
            <button key={p} onClick={()=>setPage(p)} style={{background:'none',border:'none',borderBottom:`2px solid ${page===p?'var(--cyan)':'transparent'}`,color:page===p?'var(--cyan)':'var(--text2)',padding:'6px 14px',fontFamily:'Rajdhani,sans-serif',fontSize:13,fontWeight:600,letterSpacing:'1.5px',cursor:'pointer',textTransform:'uppercase',whiteSpace:'nowrap',height:54,transition:'all .2s'}}>
              {PAGE_LABELS[p]}
            </button>
          ))}
        </nav>

        <div style={{marginLeft:'auto',display:'flex',alignItems:'center',gap:10,flexShrink:0}}>
          <div className="live-dot"/>
          <span className="mono" style={{color:'var(--text2)',fontSize:12}}>{clock}</span>
          <span className="pill pill-green" style={{fontSize:10}}>ALL SYSTEMS NOMINAL</span>
          <span className="pill pill-red" style={{fontSize:10}}>THREAT: HIGH</span>
        </div>
      </header>

      {/* ── TICKER ── */}
      <div style={{background:'#060a0e',borderBottom:'1px solid var(--border2)',padding:'5px 0',overflow:'hidden',whiteSpace:'nowrap',fontFamily:'Share Tech Mono,monospace',fontSize:11,color:'var(--text2)'}}>
        <div className="ticker-inner">
          {[...tickerItems,...tickerItems].join('  •  ')}&nbsp;&nbsp;
        </div>
      </div>

      {/* ── MAIN ── */}
      <main style={{flex:1,padding:16,display:'flex',flexDirection:'column',gap:14}}>
        {page==='dashboard' && <PageDashboard onIR={handleIR}/>}
        {page==='agents'    && <PageAgents/>}
        {page==='anomaly'   && <PageAnomaly/>}
        {page==='logs'      && <PageLogs logs={logs}/>}
        {page==='ml'        && <PageML/>}
      </main>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════
   PAGE: DASHBOARD
═══════════════════════════════════════════════════════════════ */

function PageDashboard({ onIR }) {
  const [filter, setFilter] = useState('ALL')
  const profile = ATTACK_PROFILES[filter] || ATTACK_PROFILES.ALL

  const tlBenign = useMemo(()=>Array.from({length:20},()=>Math.round(800+Math.random()*500)),[])
  const tlThreat = useMemo(()=>Array.from({length:20},(_,i)=>i<12?Math.round(Math.random()*200):Math.round(2000+Math.random()*2500)),[])

  const FILTERS=[
    {k:'ALL',l:'ALL TRAFFIC'},{k:'DDoS',l:'DDoS'},{k:'PortScan',l:'PORT SCAN'},
    {k:'BruteForce',l:'BRUTE FORCE'},{k:'Bot',l:'BOT'},
  ]

  const IR_BTNS=[
    {k:'investigate',icon:'▣',l:'REQUEST INVESTIGATION',danger:false},
    {k:'lockdown',   icon:'⊗',l:'FORCE LOCKDOWN',        danger:true},
    {k:'report',     icon:'◈',l:'GENERATE REPORT',       danger:false},
    {k:'escalate',   icon:'▲',l:'ESCALATE TO SOC',       danger:true},
  ]

  return (
    <div style={{display:'flex',flexDirection:'column',gap:14}}>
      {/* TOP */}
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14}}>
        {/* THREAT ENGINE */}
        <div className="panel p-cyan">
          <div className="panel-corner" style={{borderColor:'var(--cyan)'}}/>
          <div className="panel-corner-bl" style={{borderColor:'var(--cyan)'}}/>
          <div className="ptitle">⬡ AI Threat Engine</div>

          {/* Filter tabs */}
          <div style={{display:'flex',gap:2,marginBottom:12,flexWrap:'wrap'}}>
            {FILTERS.map(f=>(
              <button key={f.k} onClick={()=>setFilter(f.k)} style={{background:filter===f.k?'rgba(0,229,204,.12)':'var(--bg3)',border:`1px solid ${filter===f.k?'var(--cyan)':'var(--border)'}`,color:filter===f.k?'var(--cyan)':'var(--text2)',padding:'5px 12px',fontSize:11,fontWeight:700,letterSpacing:1,cursor:'pointer',borderRadius:1,textTransform:'uppercase',fontFamily:'Rajdhani,sans-serif',transition:'all .15s'}}>
                {f.l}
              </button>
            ))}
          </div>

          {/* Threat detected */}
          <div style={{border:'1px solid var(--red)',background:'rgba(255,59,94,.05)',borderRadius:2,padding:'10px 12px',marginBottom:10}}>
            <div style={{fontSize:10,letterSpacing:2,color:'var(--red)',marginBottom:6,fontWeight:700}}>⚠ THREAT DETECTED</div>
            <div style={{fontSize:14,color:'#fff'}}>Attack Type: <strong style={{color:'var(--red)'}}>{profile.type}</strong></div>
            <div style={{display:'flex',alignItems:'center',gap:10,marginTop:6}}>
              <span style={{fontSize:12,color:'var(--text2)'}}>Confidence:</span>
              <span className="mono" style={{color:'var(--red)',fontWeight:700}}>{profile.conf}%</span>
              <div style={{flex:1,height:6,background:'var(--bg4)',borderRadius:0,overflow:'hidden'}}>
                <div style={{height:'100%',width:`${profile.conf}%`,background:'linear-gradient(90deg,var(--red),var(--amber))',transition:'width .5s'}}/>
              </div>
            </div>
          </div>

          {/* Features */}
          <div style={{border:'1px solid var(--cyan2)',background:'rgba(0,229,204,.04)',borderRadius:2,padding:'8px 12px',marginBottom:10}}>
            <div style={{fontSize:10,letterSpacing:2,color:'var(--cyan2)',marginBottom:5,fontWeight:700}}>CICIDS FEATURE ANALYSIS</div>
            <div className="mono" style={{fontSize:11,color:'var(--text2)',lineHeight:1.9}}>
              {Object.entries(profile.feats).map(([k,v])=>(
                <span key={k}>{k}: <strong style={{color:'var(--cyan)'}}>{v}</strong>{'  '}</span>
              ))}
              <br/>Anomaly pattern matches known threat signature.
            </div>
          </div>

          {/* Metrics */}
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:8,marginBottom:10}}>
            {[['THREAT PORT',profile.port],['FLOW DURATION',profile.dur],['FLOW BYTES/S',profile.bps],['ANOMALY SCORE',profile.score]].map(([l,v])=>(
              <div key={l} className="mcell"><div className="mc-lbl">{l}</div><div className="mc-val">{v}</div></div>
            ))}
          </div>

          {/* IR */}
          <div className="ptitle" style={{marginTop:14}}>⬡ Incident Response</div>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:6}}>
            {IR_BTNS.map(b=>(
              <IRButton key={b.k} icon={b.icon} label={b.l} danger={b.danger} onClick={()=>onIR(b.k)}/>
            ))}
          </div>
        </div>

        {/* RIGHT: DONUT + PORTS */}
        <div className="panel p-blue">
          <div className="panel-corner" style={{borderColor:'var(--blue)'}}/>
          <div className="ptitle">⬡ Label Distribution</div>
          <div style={{display:'flex',gap:20,alignItems:'flex-start'}}>
            <Donut/>
            <div style={{flex:1,minWidth:0}}>
              <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:4,marginBottom:14}}>
                {CICIDS_LABELS.map(l=>(
                  <div key={l.name} style={{display:'flex',alignItems:'center',gap:6,fontSize:11,color:'var(--text2)'}}>
                    <div style={{width:8,height:8,borderRadius:'50%',background:l.color,flexShrink:0}}/>
                    {l.name}
                  </div>
                ))}
              </div>
              <div className="ptitle">⬡ Top Attack Ports</div>
              {TOP_PORTS.map(p=>(
                <div key={p.port} style={{display:'flex',alignItems:'center',gap:8,marginBottom:7,fontSize:12}}>
                  <span className="mono" style={{minWidth:36,color:'var(--text)'}}>{p.port}</span>
                  <div style={{flex:1,height:6,background:'var(--bg4)'}}>
                    <div style={{height:'100%',width:`${p.pct}%`,background:'var(--red)',transition:'width .5s'}}/>
                  </div>
                  <span className="mono" style={{minWidth:32,textAlign:'right',color:'var(--red)',fontSize:11}}>{p.pct}%</span>
                  <span className="mono" style={{color:'var(--text2)',fontSize:11,minWidth:50,textAlign:'right'}}>{p.flows} flows</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* BOTTOM */}
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14}}>
        {/* Timeline */}
        <div className="panel p-green">
          <div className="panel-corner" style={{borderColor:'var(--green)'}}/>
          <div className="ptitle">⬡ Flow Bytes/s Over Time</div>
          <div style={{display:'flex',gap:14,marginBottom:8,fontSize:11,color:'var(--text2)'}}>
            {[['var(--blue)','Flow KB/s (Benign)'],['var(--red)','Flow KB/s (Threat)']].map(([c,l])=>(
              <span key={l} style={{display:'flex',alignItems:'center',gap:5}}>
                <span style={{width:10,height:2,background:c,display:'inline-block'}}/>
                {l}
              </span>
            ))}
          </div>
          <LineChart benign={tlBenign} threat={tlThreat}/>
        </div>

        {/* Feature Importance */}
        <div className="panel p-red">
          <div className="panel-corner" style={{borderColor:'var(--red)'}}/>
          <div className="ptitle">⬡ Anomaly Feature Importance</div>
          {FEATURE_IMPORTANCE.map(f=>(
            <div key={f.label} style={{display:'flex',alignItems:'center',gap:8,marginBottom:9,fontSize:12}}>
              <span style={{minWidth:130,color:'var(--text2)',flexShrink:0}}>{f.label}</span>
              <div style={{flex:1,height:5,background:'var(--bg4)'}}>
                <div style={{height:'100%',width:`${f.pct}%`,background:f.color}}/>
              </div>
              <span className="mono" style={{minWidth:36,textAlign:'right',color:f.color,fontSize:11}}>{f.pct}%</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function IRButton({ icon, label, danger, onClick }) {
  const [hover, setHover] = useState(false)
  const c = hover ? (danger ? 'var(--red)' : 'var(--cyan)') : 'var(--text2)'
  const bg = hover ? (danger ? 'rgba(255,59,94,.06)' : 'rgba(0,229,204,.06)') : 'var(--bg3)'
  const bc = hover ? (danger ? 'var(--red)' : 'var(--cyan)') : 'var(--border)'
  return (
    <button onClick={onClick} onMouseEnter={()=>setHover(true)} onMouseLeave={()=>setHover(false)}
      style={{background:bg,border:`1px solid ${bc}`,padding:'8px 12px',fontSize:11,fontWeight:700,letterSpacing:1,color:c,cursor:'pointer',textTransform:'uppercase',display:'flex',alignItems:'center',gap:6,borderRadius:1,fontFamily:'Rajdhani,sans-serif',transition:'all .2s'}}>
      {icon} {label}
    </button>
  )
}

/* ═══════════════════════════════════════════════════════════════
   PAGE: AGENTS
═══════════════════════════════════════════════════════════════ */

const LOG_LVL_COLOR = { OK:'#00e676', WARN:'#ffb800', ERR:'#ff3b5e', INFO:'#00e5cc' }

function PageAgents() {
  return (
    <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(320px,1fr))',gap:14}}>
      {AGENTS.map(a=><AgentCard key={a.id} agent={a}/>)}
    </div>
  )
}

function AgentCard({ agent: a }) {
  return (
    <div style={{background:'var(--bg2)',border:'1px solid var(--border2)',borderRadius:2,padding:14,position:'relative',overflow:'hidden',borderLeft:`3px solid ${a.leftBg}`}}>
      <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:10}}>
        <div style={{width:36,height:36,borderRadius:2,display:'flex',alignItems:'center',justifyContent:'center',fontSize:16,background:a.iconBg,border:a.iconBorder,flexShrink:0}}>{a.icon}</div>
        <div>
          <div style={{fontSize:15,fontWeight:700,color:'#fff',letterSpacing:.5}}>{a.name}</div>
          <span style={{fontSize:10,fontWeight:700,letterSpacing:1.5,padding:'2px 8px',borderRadius:1,background:'rgba(0,230,118,.15)',color:'var(--green)',border:'1px solid rgba(0,230,118,.3)',display:'inline-block',marginTop:3}}>ACTIVE</span>
        </div>
      </div>
      <p style={{fontSize:12,color:'var(--text2)',marginBottom:12,lineHeight:1.65}}>{a.description}</p>
      <div className="ptitle">Live Logs</div>
      <div style={{background:'var(--bg)',border:'1px solid var(--border2)',borderRadius:1,padding:8,height:95,overflowY:'auto',marginBottom:10}}>
        {a.logs.map((l,i)=>(
          <div key={i} className="mono" style={{fontSize:11,marginBottom:3,opacity:.9,color:LOG_LVL_COLOR[l.lvl],lineHeight:1.5}}>[{l.lvl}] {l.t}</div>
        ))}
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

/* ═══════════════════════════════════════════════════════════════
   PAGE: ANOMALY ANALYSIS
═══════════════════════════════════════════════════════════════ */

function PageAnomaly() {
  const [sortKey, setSortKey] = useState('score')
  const [sortDir, setSortDir] = useState(-1)
  const [filterAtk, setFilterAtk] = useState('ALL')
  const allTypes = useMemo(()=>['ALL',...Array.from(new Set(FLOWS.map(f=>f.atk)))],[])

  const rows = useMemo(()=>{
    const base = filterAtk==='ALL' ? FLOWS : FLOWS.filter(f=>f.atk===filterAtk)
    return [...base].sort((a,b)=>{
      const va=a[sortKey]??0, vb=b[sortKey]??0
      return sortDir*(vb>va?1:vb<va?-1:0)
    })
  },[sortKey,sortDir,filterAtk])

  function toggleSort(k){ setSortKey(k); setSortDir(d=>sortKey===k?-d:-1) }

  const stats = useMemo(()=>({
    threats: FLOWS.filter(f=>f.atk!=='BENIGN').length,
    blocked: FLOWS.filter(f=>f.status==='BLOCKED').length,
    monitor: FLOWS.filter(f=>f.status==='MONITOR').length,
    benign:  FLOWS.filter(f=>f.atk==='BENIGN').length,
    total:   FLOWS.length,
  }),[])

  const SH = ({col}) => <span style={{fontSize:9,marginLeft:3,color:'var(--text3)'}}>{sortKey===col?(sortDir===-1?'▼':'▲'):'⇅'}</span>

  return (
    <div style={{display:'grid',gridTemplateColumns:'1fr 280px',gap:14}}>
      {/* Table */}
      <div style={{background:'var(--bg2)',border:'1px solid var(--border2)',borderRadius:2,overflow:'hidden'}}>
        <div style={{padding:'10px 14px',background:'var(--bg3)',borderBottom:'1px solid var(--border2)',display:'flex',alignItems:'center',gap:10,flexWrap:'wrap'}}>
          <span className="ptitle" style={{margin:0}}>CICIDS FLOW ANALYSIS</span>
          <div style={{display:'flex',gap:3,flexWrap:'wrap',flex:1}}>
            {allTypes.map(t=>(
              <button key={t} onClick={()=>setFilterAtk(t)} style={{background:filterAtk===t?'rgba(0,229,204,.12)':'transparent',border:`1px solid ${filterAtk===t?'var(--cyan)':'var(--border)'}`,color:filterAtk===t?'var(--cyan)':'var(--text2)',padding:'3px 8px',fontSize:10,fontWeight:700,cursor:'pointer',borderRadius:1,fontFamily:'Rajdhani,sans-serif',letterSpacing:.5,textTransform:'uppercase',transition:'all .15s'}}>
                {t}
              </button>
            ))}
          </div>
          <span className="pill pill-amber" style={{fontSize:10}}>{rows.length} FLOWS</span>
        </div>
        <div style={{maxHeight:500,overflowY:'auto'}}>
          <table>
            <thead><tr>
              {[['src','SRC IP'],['dport','PORT'],['atk','ATTACK TYPE'],['conf','CONF'],['bps','BYTES/S'],['pps','PKTS/S'],['score','SCORE'],['status','STATUS']].map(([k,l])=>(
                <th key={k} onClick={()=>toggleSort(k)}>{l}<SH col={k}/></th>
              ))}
            </tr></thead>
            <tbody>
              {rows.map(f=>{
                const sc=f.score
                const sc_color=sc>0.85?'#ff3b5e':sc>0.5?'#ffb800':'#00e676'
                return (
                  <tr key={f.id}>
                    <td>{f.src}</td>
                    <td>{f.dport}</td>
                    <td><span className={`badge ${ATTACK_BADGE[f.atk]||'b-blue'}`}>{f.atk}</span></td>
                    <td style={{color:f.atk==='BENIGN'?'var(--text2)':'var(--text)'}}>{f.atk==='BENIGN'?'—':`${f.conf}%`}</td>
                    <td>{f.bps.toLocaleString()}</td>
                    <td>{f.pps.toLocaleString()}</td>
                    <td>
                      <div style={{display:'flex',alignItems:'center',gap:5}}>
                        <div style={{width:Math.round(sc*50),height:4,background:sc_color,flexShrink:0}}/>
                        <span style={{color:sc_color,fontSize:11}}>{sc.toFixed(3)}</span>
                      </div>
                    </td>
                    <td><span className={`badge ${f.status==='PASS'?'b-green':f.status==='MONITOR'?'b-amber':'b-red'}`}>{f.status}</span></td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Sidebar */}
      <div style={{display:'flex',flexDirection:'column',gap:10}}>
        {[
          {n:stats.threats,l:'Active Threats',   c:'var(--red)'},
          {n:stats.blocked,l:'IPs Blocked',      c:'var(--amber)'},
          {n:stats.benign, l:'Benign Flows',     c:'var(--green)'},
          {n:stats.total,  l:'Total Analyzed',   c:'var(--blue)'},
        ].map(s=>(
          <div key={s.l} style={{background:'var(--bg2)',border:'1px solid var(--border2)',padding:'12px 14px',borderRadius:2}}>
            <div className="mono" style={{fontSize:28,fontWeight:700,color:s.c}}>{s.n}</div>
            <div style={{fontSize:11,color:'var(--text2)',letterSpacing:1,textTransform:'uppercase',marginTop:2}}>{s.l}</div>
          </div>
        ))}

        <div style={{background:'var(--bg2)',border:'1px solid var(--border2)',padding:'12px 14px',borderRadius:2}}>
          <div className="ptitle" style={{marginBottom:6}}>Detection Accuracy</div>
          {[{l:'Random Forest',v:97.4},{l:'XGBoost',v:98.1},{l:'Ensemble',v:98.6}].map(m=>(
            <div key={m.l} style={{display:'flex',justifyContent:'space-between',marginBottom:6,fontSize:11}}>
              <span style={{color:'var(--text2)'}}>{m.l}</span>
              <span className="mono" style={{color:'var(--cyan)'}}>{m.v}%</span>
            </div>
          ))}
        </div>

        <div style={{background:'var(--bg2)',border:'1px solid var(--border2)',padding:'12px 14px',borderRadius:2}}>
          <div className="ptitle" style={{marginBottom:8}}>Attack Breakdown</div>
          {['DDoS','Bot','PortScan','Brute Force-Web','Web Attacks-BF'].map(a=>{
            const count = FLOWS.filter(f=>f.atk===a).length
            return (
              <div key={a} style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:7}}>
                <span style={{color:'var(--text2)',fontSize:11}}>{a}</span>
                <span className={`badge ${ATTACK_BADGE[a]||'b-blue'}`}>{count}</span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════
   PAGE: LOG FEED
═══════════════════════════════════════════════════════════════ */

const AGENT_COLORS = {
  MONITOR:'var(--cyan)', ANALYZER:'var(--blue)', THREAT:'var(--red)',
  ML:'var(--amber)', DECISION:'var(--green)', RESPONSE:'var(--purple)',
  LEARN:'var(--cyan)', REPORT:'var(--blue)',
}

function PageLogs({ logs }) {
  const [filter, setFilter] = useState('ALL')
  const termRef = useRef(null)

  const filters = ['ALL','MONITOR','ANALYZER','THREAT','ML','DECISION','RESPONSE','LEARN','REPORT']

  const visible = useMemo(()=>
    filter==='ALL' ? logs : logs.filter(l=>l.agent===filter),
  [logs, filter])

  useEffect(()=>{
    if(termRef.current) termRef.current.scrollTop = 0
  },[visible.length])

  return (
    <div style={{display:'flex',flexDirection:'column',gap:12}}>
      {/* Filter bar */}
      <div style={{display:'flex',gap:6,alignItems:'center',flexWrap:'wrap'}}>
        <span style={{fontSize:11,fontWeight:700,letterSpacing:2,color:'var(--text2)'}}>FILTER:</span>
        {filters.map(f=>(
          <button key={f} onClick={()=>setFilter(f)} style={{background:filter===f?'rgba(0,229,204,.12)':'var(--bg2)',border:`1px solid ${filter===f?'var(--cyan)':'var(--border2)'}`,padding:'5px 12px',fontSize:11,fontWeight:700,letterSpacing:1,color:filter===f?'var(--cyan)':'var(--text2)',cursor:'pointer',borderRadius:1,fontFamily:'Rajdhani,sans-serif',textTransform:'uppercase',transition:'all .15s'}}>
            {f}
          </button>
        ))}
        <span className="pill pill-green" style={{marginLeft:'auto',fontSize:10}}>{visible.length} ENTRIES</span>
      </div>

      {/* Terminal */}
      <div ref={termRef} style={{background:'var(--bg)',border:'1px solid var(--border2)',borderRadius:2,padding:14,height:460,overflowY:'auto',fontFamily:'Share Tech Mono,monospace',fontSize:12}}>
        {visible.map(e=>(
          <div key={e.id} style={{display:'flex',gap:10,marginBottom:5,alignItems:'flex-start'}}>
            <span style={{color:'var(--text3)',minWidth:72,flexShrink:0}}>{e.time}</span>
            <span style={{color:AGENT_COLORS[e.agent]||'var(--cyan)',minWidth:90,flexShrink:0,fontWeight:700}}>[{e.agent}]</span>
            <span style={{color:e.lvl==='ERR'?'var(--red)':e.lvl==='WARN'?'var(--amber)':e.lvl==='OK'?'var(--green)':'var(--text)',flex:1}}>{e.t}</span>
          </div>
        ))}
        {visible.length===0 && (
          <div style={{color:'var(--text2)',textAlign:'center',marginTop:80}}>No log entries for filter: {filter}</div>
        )}
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════
   PAGE: ML MODELS
═══════════════════════════════════════════════════════════════ */

function PageML() {
  return (
    <div>
      <div style={{marginBottom:14}}>
        <div style={{fontSize:11,fontWeight:700,letterSpacing:2,color:'var(--text2)',textTransform:'uppercase',marginBottom:4}}>⬡ Machine Learning Ensemble — CICIDS-2018</div>
        <div style={{fontSize:12,color:'var(--text2)',lineHeight:1.6}}>
          Six complementary models trained on CICIDS-2017/2018 (2.8M labeled flows). The ensemble voter combines supervised, unsupervised, and deep learning signals for maximum accuracy and zero-day coverage.
        </div>
      </div>

      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(280px,1fr))',gap:14}}>
        {ML_MODELS.map(m=><MLCard key={m.name} model={m}/>)}
      </div>

      {/* Comparison strip */}
      <div className="panel p-cyan" style={{marginTop:14}}>
        <div className="panel-corner" style={{borderColor:'var(--cyan)'}}/>
        <div className="ptitle">⬡ Model Performance Comparison (CICIDS-2018 Test Set)</div>
        <div style={{overflowX:'auto'}}>
          <table>
            <thead><tr>
              <th>MODEL</th><th>TYPE</th><th>ACCURACY</th><th>AUC-ROC</th><th>FPR</th><th>SPEED</th><th>STATUS</th>
            </tr></thead>
            <tbody>
              {[
                {name:'Random Forest',    type:'Supervised',   acc:97.4, auc:98.2, fpr:2.1, speed:'Fast',   status:'DEPLOYED'},
                {name:'XGBoost',          type:'Supervised',   acc:98.1, auc:99.8, fpr:1.8, speed:'Fast',   status:'DEPLOYED'},
                {name:'Isolation Forest', type:'Unsupervised', acc:97.0, auc:96.5, fpr:2.1, speed:'Fast',   status:'DEPLOYED'},
                {name:'LSTM',             type:'Deep Learning',acc:96.2, auc:97.1, fpr:2.9, speed:'Medium', status:'DEPLOYED'},
                {name:'K-Means',          type:'Clustering',   acc:82.0, auc:85.3, fpr:6.2, speed:'Fast',   status:'SUPPORT'},
                {name:'Ensemble Voter',   type:'Meta',         acc:98.6, auc:99.4, fpr:1.2, speed:'Fast',   status:'PRIMARY'},
              ].map(r=>(
                <tr key={r.name}>
                  <td style={{color:'#fff',fontWeight:700}}>{r.name}</td>
                  <td style={{color:'var(--text2)'}}>{r.type}</td>
                  <td style={{color:'var(--cyan)'}}>{r.acc}%</td>
                  <td style={{color:'var(--green)'}}>{r.auc}%</td>
                  <td style={{color:'var(--amber)'}}>{r.fpr}%</td>
                  <td style={{color:'var(--text2)'}}>{r.speed}</td>
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

function MLCard({ model: m }) {
  return (
    <div style={{background:'var(--bg2)',border:'1px solid var(--border2)',borderRadius:2,padding:14,borderTop:`2px solid ${m.color}`}}>
      <div style={{fontSize:14,fontWeight:700,color:'#fff',marginBottom:4}}>{m.name}</div>
      <div style={{fontSize:11,color:m.color,letterSpacing:1,textTransform:'uppercase',marginBottom:12}}>{m.type}</div>
      {m.metrics.map(x=>(
        <div key={x.l}>
          <div style={{display:'flex',justifyContent:'space-between',marginBottom:4,fontSize:12}}>
            <span style={{color:'var(--text2)'}}>{x.l}</span>
            <span className="mono" style={{color:m.color}}>{x.v}%</span>
          </div>
          <div style={{height:4,background:'var(--bg4)',borderRadius:0,marginBottom:8,overflow:'hidden'}}>
            <div style={{height:'100%',width:`${x.v}%`,background:m.color,transition:'width 1s'}}/>
          </div>
        </div>
      ))}
      <div style={{fontSize:11,color:'var(--text2)',marginTop:8,lineHeight:1.65,borderTop:'1px solid var(--border2)',paddingTop:8}}>{m.desc}</div>
    </div>
  )
}
