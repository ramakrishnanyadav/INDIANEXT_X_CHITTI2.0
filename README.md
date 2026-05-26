<div align="center">
  <img src="https://via.placeholder.com/120x120/1e1b4b/6366f1?text=IQ" alt="SentinelIQ Logo" width="120" height="120" />
  <h1>SentinelIQ</h1>
  <p><b>Explainable Real-Time Browser Threat Intelligence</b></p>
  
  [![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
  [![Node.js 18+](https://img.shields.io/badge/Node.js-18+-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)](https://nodejs.org/)
  [![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
  [![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)](https://reactjs.org/)
  
  <p>
    An advanced, privacy-first threat detection ecosystem featuring a 4-engine ensemble, zero-day threat prevention, and real-time Explainable AI (XAI) insights.
  </p>
</div>

---

## 🌟 Product Overview

**SentinelIQ** is a zero-latency, highly optimized browser extension and backend ecosystem designed to intercept zero-day phishing, malicious URLs, prompt injections, and behavioral anomalies. Unlike traditional blocklists, SentinelIQ leverages a robust 4-Engine Ensemble and state-of-the-art XAI to not just block threats, but **explain why** they were flagged, offering unparalleled transparency and actionable intelligence.

### 🛡️ Core Capabilities

- **Zero-Day Detection**: Catches threats before they appear on blocklists using WHOIS domain age, DOM scraping, and brand spoof rules.
- **4-Engine Ensemble Architecture**: Combines Phishing, URL, Prompt Injection, and Anomaly engines for high-confidence verdicts.
- **Explainable AI (XAI)**: Demystifies AI decisions with SHAP feature attributions and Token highlights.
- **Privacy-First Fast Path**: Local trusted domain checks and caching ensure complete privacy for non-malicious browsing.

---

## 🏗️ System Architecture

Our highly optimized pipeline operates on a lightweight local filtering model before escalating suspicious URLs for deep analysis, guaranteeing zero latency for safe domains.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#1e1b4b', 'primaryTextColor': '#a5b4fc', 'primaryBorderColor': '#6366f1', 'lineColor': '#8b5cf6', 'secondaryColor': '#0f172a', 'tertiaryColor': '#064e3b'}}}%%
flowchart TD
    A["🌐 Browser\n(Chrome Extension)"]:::ext

    subgraph EXT["Extension Layer"]
        direction TB
        C1["content.js\nLink hover scan\nPassword form detect"]
        C2["background.js\nService worker\nScan pipeline"]
        C3["popup.html\nAnalyst briefing UI"]
    end

    subgraph LOCAL["Local Fast-Path (0ms, no API)"]
        L1["✓ Trusted domain check"]
        L2["✓ localhost / private IP"]
        L3["✓ Cache hit (30 min TTL)"]
    end

    subgraph API["FastAPI Backend (4-Engine Ensemble)"]
        direction TB
        R["Router (/api/v1/analyze)"]
        
        E1["🔗 URL Engine\n(BERT, WHOIS, DOM)"]
        E2["📧 Phishing Engine\n(Heuristics, Gemini)"]
        E3["🤖 Injection Engine\n(Pattern matching)"]
        E4["📊 Anomaly Engine\n(Isolation Forest)"]

        ENS["Ensemble Voter\n(Weighted cross-engine vote)"]
        RISK["Risk Scorer (0-100)"]
        XAI["Explainability (SHAP)"]
        NAR["Gemini Narrator\n(Analyst Briefings)"]
    end

    A --> EXT
    C1 -->|"hover/form"| C2
    C2 -->|"check"| LOCAL
    LOCAL -->|"miss → escalate"| API
    R --> E1 & E2 & E3 & E4
    E1 & E2 & E3 & E4 --> ENS
    ENS --> RISK --> XAI --> NAR
    API -->|"JSON response"| C2
    C2 --> C3

    classDef ext fill:#1e1b4b,stroke:#6366f1,color:#a5b4fc,stroke-width:2px
    classDef local fill:#064e3b,stroke:#10b981,color:#6ee7b7,stroke-width:2px
    classDef api fill:#0f172a,stroke:#334155,color:#94a3b8,stroke-width:2px
    
    class A ext
    class L1,L2,L3 local
    class R,E1,E2,E3,E4,ENS,RISK,XAI,NAR api
```

---

## 🚀 Quick Start & Setup Guide

### 1. Prerequisites
- **Python 3.11** (Required for the AI backend ecosystem)
- **Node.js 18+** (Required for the frontend dashboard and extension builds)
- **Git**

### 2. Backend Setup (Run Once)

Initialize the virtual environment and install the required machine learning and server dependencies:

```bash
cd sentineliq/backend
python -m venv venv

# Windows
venv\Scripts\activate
# Mac/Linux
source venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
```

**Obtain a Free Gemini API Key (Highly Recommended)**
1. Visit [Google AI Studio](https://aistudio.google.com/)
2. Click **Get API Key** and copy it.
3. Paste it into your `backend/.env` file: `GEMINI_API_KEY=your_key_here`

*(Note: The system gracefully degrades to heuristics and templates if the Gemini key is omitted.)*

### 3. Running the Ecosystem

You will need two separate terminal windows for the backend and frontend.

**Terminal 1: Start the Backend (FastAPI)**
```bash
cd sentineliq/backend
venv\Scripts\activate      # Windows
# source venv/bin/activate # Mac/Linux
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
*API Documentation available at: [http://localhost:8000/docs](http://localhost:8000/docs)*

**Terminal 2: Start the Frontend (Vite/React)**
```bash
cd sentineliq/frontend
npm install
npm run dev
```
*Dashboard available at: [http://localhost:5173](http://localhost:5173)*

---

## ⚙️ Environment Variables Reference

| Variable | Required | Description |
|---|:---:|---|
| `GEMINI_API_KEY` | ❌ | Enables AI narration and advanced heuristic validation. |
| `FIREBASE_SERVICE_ACCOUNT` | ❌ | Path to Firebase JSON for remote logging (app works 100% locally without it). |
| `MODEL_CACHE_DIR` | ❌ | Directory for HuggingFace model downloads. Default: `./model_cache` |
| `ENVIRONMENT` | ❌ | `development` or `production` |

---

## 🔌 API Reference Highlights

The FastAPI backend exposes a robust suite of REST endpoints, built for low-latency integrations.

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | `GET` | System health check and model status verification. |
| `/api/v1/analyze` | `POST` | Primary analysis endpoint. Evaluates content against the 4-Engine Ensemble. |
| `/api/v1/incidents` | `GET` | Fetch historical security incidents. |
| `/docs` | `GET` | Explore the interactive OpenAPI (Swagger) interface. |

### `/api/v1/analyze` Request Schema (Form Data)

| Field | Type | Required | Description |
|---|---|:---:|---|
| `threat_type` | string | ✅ | Target engine: `phishing`, `url`, `prompt_injection`, or `anomaly`. |
| `content` | string | ✅* | The text, URL, or raw content to analyze. *(Optional if `file` is provided)* |
| `file` | file | ❌ | Direct file upload (PDF, TXT, EML, JSON, CSV). |

---

<div align="center">
  <sub>Built with 🔒 by the SentinelIQ Security Team.</sub>
</div>
