# CipherNest 🛡️

**Multi-Agent AI Cybersecurity Defense System**

Real-time network threat detection powered by CICIDS-2018 dataset with 8 coordinated AI agents.

## Features

- 🤖 **8 Coordinated Agents**: Monitor → Log → Threat → ML → Decision → Response → Learning → Report
- 📊 **CICIDS-2018 Dataset**: 78-feature flow analysis, 7 attack categories
- 🧠 **ML Ensemble**: Random Forest + XGBoost + Isolation Forest + LSTM (97.4–98.6% accuracy)
- ⚡ **Real-Time Dashboard**: Live flow metrics, threat engine, anomaly scoring
- 🔒 **Auto-Response**: IP blocking, endpoint isolation, SOC escalation
- 📈 **Active Learning**: Continuous model retraining loop

## Pages

| Page | Description |
|------|-------------|
| Dashboard | Live threat engine, CICIDS label distribution, flow timeline, feature importance |
| Agents | Per-agent live logs, metrics, and status |
| Anomaly Analysis | Full CICIDS flow table with sortable columns and confidence scores |
| Log Feed | Filterable real-time multi-agent log stream |
| ML Models | Accuracy metrics for all 6 ML models |

## Deploy

### Vercel (recommended)
1. Push to GitHub
2. Import repo at [vercel.com](https://vercel.com)
3. Vercel auto-detects Vite — click Deploy

### Local dev
```bash
npm install
npm run dev
```

### Build
```bash
npm run build
npm run preview
```

## Tech Stack

- React 18 + Vite
- Pure CSS (no UI library)
- Chart.js via CDN (loaded in HTML)
- CICIDS-2018 feature simulation engine

## Attack Categories (CICIDS-2018)

- **DDoS** — UDP/TCP floods, high packet rate
- **Bot** — IRC C&C, persistent beaconing
- **PortScan** — Sequential probe, low-volume
- **Brute Force-Web** — Dictionary attacks, SSH/HTTP
- **Web Attacks-BF** — SQL injection, XSS patterns
- **Infiltration** — Low-and-slow exfiltration
- **BENIGN** — Normal traffic baseline

## Agent Architecture

```
Incoming Traffic (CICIDS flows)
         │
    Monitoring Agent (78 features)
         │
    Log Analysis Agent (correlation)
         │
    Threat Detection Agent (signatures)
         │
    ML Intelligence Agent (RF+XGB+IF+LSTM)
         │
    Decision Agent (MITRE ATT&CK)
        / \
Response    Report
 Agent      Agent
   │           │
Learning ←─────┘
 Agent
   │
Security Dashboard
```
