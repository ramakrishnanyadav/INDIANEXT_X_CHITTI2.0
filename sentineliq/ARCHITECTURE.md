# SentinelIQ — System Architecture

> **"Explainable Real-Time Browser Threat Intelligence"**

---

## Full Architecture Diagram

```mermaid
flowchart TD
    A["🌐 Browser\n(Chrome Extension)"]:::ext

    subgraph EXT["Extension Layer"]
        direction TB
        C1["content.js\nLink hover scan\nPassword form detect\nBadge injection"]
        C2["background.js\nService worker\nScan pipeline\nCache · Badge · Stats"]
        C3["popup.html\nAnalyst briefing UI\nRisk score ring\nThreat dashboard"]
    end

    subgraph LOCAL["Local Fast-Path (0ms, no API)"]
        L1["✓ Trusted domain check\n  google.com, github.com…"]
        L2["✓ localhost / private IP\n  skip entirely"]
        L3["✓ Cache hit (30 min TTL)\n  return instantly"]
    end

    subgraph API["FastAPI Backend  /api/v1/analyze"]
        direction TB
        R["Router\nanalyze.py"]

        subgraph ENGINES["4-Engine Ensemble"]
            E1["🔗 URL Engine\nurl_detector.py\n\nWHOIS age · BERT model\n12 structural signals\nDOM zero-day scraping\nBrand spoof detection"]
            E2["📧 Phishing Engine\nphishing.py\n\nHeuristics · BERT · Gemini\nHomoglyph normalization\nAbsence scoring\nExecutive impersonation"]
            E3["🤖 Injection Engine\nprompt_injection.py\n\nDirect override patterns\nRole hijack · Encoded attacks\nUnicode evasion\nGemini cross-validation"]
            E4["📊 Anomaly Engine\nanomaly.py\n\nIsolation Forest\nSession behavioral baseline\nGeo-velocity · Privilege\nLogin velocity"]
        end

        ENS["Ensemble Voter\nensemble.py\n\nWeighted cross-engine vote\nEscalation bonus\nComposite confidence"]
        RISK["Risk Scorer\nrisk_scorer.py\n\n0–100 score\nCRITICAL · HIGH · MEDIUM · LOW"]
        XAI["Explainability\nSHAP features · Token highlights\nFeature attribution weights"]
        NAR["Gemini Narrator\ngemini_narrator.py\n\nTier 1: Gemini 2.0 Flash\nTier 2: Short prompt fallback\nTier 3: Offline template"]
        DB["Firestore\nIncident logging\nHistorical rate tracking"]
    end

    subgraph POPUP["Popup UI"]
        P1["Risk Score Ring\n0–100 animated SVG"]
        P2["AI Analyst Briefing\nExplanation + Action"]
        P3["SHAP Signal Bars\nWhich features fired"]
        P4["Threat Dashboard\nStats · History · Chart"]
    end

    A --> EXT
    C1 -->|"hover/form"| C2
    C2 -->|"check"| LOCAL
    LOCAL -->|"miss → escalate"| API
    R --> E1 & E2 & E3 & E4
    E1 & E2 & E3 & E4 --> ENS
    ENS --> RISK --> XAI --> NAR
    NAR --> DB
    API -->|"JSON response"| C2
    C2 --> C3
    C3 --> POPUP

    classDef ext fill:#1e1b4b,stroke:#6366f1,color:#a5b4fc
    classDef local fill:#064e3b,stroke:#10b981,color:#6ee7b7
    classDef engine fill:#0f172a,stroke:#334155,color:#94a3b8
    classDef api fill:#0d1320,stroke:#6366f1,color:#c7d2fe
    classDef popup fill:#1e1b4b,stroke:#8b5cf6,color:#ddd6fe

    class A ext
    class L1,L2,L3 local
    class E1,E2,E3,E4 engine
    class R,ENS,RISK,XAI,NAR,DB api
    class P1,P2,P3,P4 popup
```

---

## Data Flow — Single URL Scan

```
User visits page
      │
      ▼
content.js detects URL
      │
      ▼
background.js:
  ├─ Trusted domain?     → BENIGN (0ms, no API call)
  ├─ localhost?          → BENIGN (0ms)
  ├─ Cache hit (< 30m)?  → return cached result (0ms)
  └─ None of above       → call FastAPI
                                │
                         ┌──────┴──────┐
                         │  /analyze   │
                         └──────┬──────┘
                                │
                    ┌───────────┼───────────┐
                    ▼           ▼           ▼
               URL Engine   Phishing    Injection
              (WHOIS+BERT)  (BERT+Gem)  (patterns)
                    │           │           │
                    └───────────┼───────────┘
                                ▼
                         Ensemble Vote
                         Weighted confidence
                         Escalation bonus
                                │
                                ▼
                          Risk Score 0–100
                          SHAP features
                                │
                                ▼
                       Gemini Narration
                       Explanation + Action
                                │
                                ▼
                       JSON Response → Extension
                                │
                         ┌──────┴──────┐
                         │   Popup UI  │
                         │  Risk ring  │
                         │  Briefing   │
                         │  Signals    │
                         └─────────────┘
```

---

## Engine Weights (Ensemble Voter)

| Engine | Weight | Detects |
|---|---|---|
| Phishing | 0.30 | Email/text social engineering |
| Prompt Injection | 0.28 | AI chatbot manipulation attacks |
| URL | 0.25 | Malicious/phishing URLs |
| Anomaly | 0.17 | Behavioral session anomalies |

---

## Scanning Priority (Content Script)

| Priority | Trigger | Action |
|---|---|---|
| 0 — Skip | Trusted domain / localhost | No scan, instant BENIGN |
| 1 — Immediate | Page load (current URL) | Full backend scan |
| 1 — Immediate | Password form detected | Escalated scan + banner |
| 2 — On demand | Link hover (250ms debounce) | Scan + tooltip |
| 3 — Manual | Popup URL input | Scan on demand |

---

## Privacy Model

> **SentinelIQ performs lightweight local filtering before escalating suspicious URLs for deep analysis.**

| URL Type | What happens to it |
|---|---|
| Trusted domain (google.com etc.) | Never sent to backend — verdict locally |
| localhost / private IPs | Never sent — local fast-path |
| Cached result (< 30 min old) | Never re-sent — served from local cache |
| Ambiguous/suspicious URL | Sent to backend for deep analysis |

**No URL content is stored permanently.** Scan results are cached locally in Chrome storage with a 30-minute TTL. The backend logs only the incident verdict and metadata to Firestore — not the full URL query parameters.

---

## Competitive Differentiation

| Competitor | Gap | SentinelIQ Advantage |
|---|---|---|
| Chrome Safe Browsing | Blocklist only, no explanation | XAI: explains WHY flagged + analyst action |
| Avast / Bitdefender Extension | Can't detect LLM-generated phishing | Gemini Layer C validates AI-written attacks |
| VirusTotal | Manual submission, no inline | Zero-friction auto scan on every hover |
| GPT / ChatGPT | No browser integration, no WHOIS | Runs inline, live WHOIS, DOM scraping |
| Trend Micro | No prompt injection detection | 4th engine: AI chatbot attack shield |

---

## Zero-Day Detection Capability

SentinelIQ catches threats **before they appear on any blocklist**:

1. **WHOIS domain age** → Flags domains registered < 7 days ago
2. **DOM scraping** → Detects brand logo + password form on wrong domain
3. **Brand spoof rules** → `paypa1.com`, `micros0ft-login.xyz` structural detection
4. **Homoglyph normalization** → Catches Unicode lookalike attacks (`раypal.com`)

> **"We catch what Google Safe Browsing misses — on day zero."**
