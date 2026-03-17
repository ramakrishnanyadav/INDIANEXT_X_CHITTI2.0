# SentinelIQ — Setup Guide

## Prerequisites
- Python 3.11
- Node.js 18+
- Git

---

## Backend Setup (run once)

```bash
cd sentineliq/backend
python -m venv venv
```

```bash
# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate
```

```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env — add your GEMINI_API_KEY
```

---

## Get a Free Gemini API Key
1. Go to https://aistudio.google.com
2. Click **Get API Key**
3. Copy key → paste into `backend/.env` as `GEMINI_API_KEY=...`

---

## Firebase Setup (optional — app works 100% without it)
1. Go to https://console.firebase.google.com
2. Create project → **Project Settings → Service Accounts**
3. **Generate new private key** → download JSON
4. Save as `backend/firebase-service-account.json`

---

## Run Backend

```bash
cd sentineliq/backend

# Windows
venv\Scripts\activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Mac/Linux
source venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Open: http://localhost:8000/docs

---

## Frontend Setup

```bash
cd sentineliq/frontend
npm install
npm run dev
```

Open: http://localhost:5173

---

## VS Code Python Setup
1. Open `sentineliq/` as workspace root
2. `Ctrl+Shift+P` → **Python: Select Interpreter**
3. Choose: `Python 3.11 (venv)` → `backend/venv/Scripts/python.exe`
4. All import errors in the IDE will resolve automatically

---

## Environment Variables Reference

| Variable | Required | Description |
|---|---|---|
| `GEMINI_API_KEY` | No | Enables AI narration. Falls back to templates if missing. |
| `FIREBASE_SERVICE_ACCOUNT` | No | Path to Firebase service account JSON. |
| `MODEL_CACHE_DIR` | No | Directory for HuggingFace model downloads. Default: `./model_cache` |
| `ENVIRONMENT` | No | `development` or `production` |

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Server health + model status |
| `/api/v1/analyze` | POST | Analyze threat (form data) |
| `/api/v1/incidents` | GET | List recent incidents |
| `/docs` | GET | Interactive Swagger UI |

### /api/v1/analyze Form Fields
| Field | Type | Required |
|---|---|---|
| `threat_type` | string | ✅ `phishing`, `url`, `prompt_injection`, or `anomaly` |
| `content` | string | ✅ (or use file) |
| `file` | file | ❌ optional — PDF, TXT, EML, JSON, CSV |
