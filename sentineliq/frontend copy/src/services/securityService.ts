/**
 * securityService.ts
 * ------------------
 * Calls the SentinelIQ FastAPI backend at http://localhost:8000.
 * After every successful analysis, writes the incident directly to Firestore
 * so the Incidents tab reflects it in real-time regardless of backend Firebase state.
 */

import type { Incident } from '@/types/security';
import { db } from '@/lib/firebase';
import { collection, doc, setDoc, serverTimestamp } from 'firebase/firestore';

const API_BASE    = import.meta.env.VITE_API_BASE ?? 'http://localhost:8000';
const ANALYZE_URL = `${API_BASE}/api/v1/analyze`;

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Maps frontend operation names to backend threat_type values */
function toThreatType(operation: string): string {
  switch (operation) {
    case 'url-analysis': return 'url';
    case 'injection':    return 'prompt_injection';
    case 'phishing':     return 'phishing';
    case 'anomaly':      return 'anomaly';
    default:             return 'phishing';
  }
}

/** Maps backend verdict + risk_band to a FE-friendly risk level */
function toRiskLevel(verdict: string, riskBand: string): string {
  const band = (riskBand || '').toUpperCase();
  if (band.includes('CRITICAL') || verdict === 'MALICIOUS')  return 'Critical';
  if (band.includes('HIGH'))     return 'High';
  if (band.includes('MED'))      return 'Medium';
  if (verdict === 'SUSPICIOUS')  return 'Medium';
  return 'Low';
}

/** Human-friendly threat type label */
function toTypeLabel(threatType: string): string {
  switch (threatType) {
    case 'phishing':         return 'Phishing Attack';
    case 'url':              return 'Malicious URL';
    case 'prompt_injection': return 'Prompt Injection';
    case 'anomaly':          return 'Anomaly Detected';
    default:                 return threatType;
  }
}

/** Convert a backend AnalysisResult JSON to the UI shape */
function adaptResult(raw: Record<string, unknown>) {
  const confidence = typeof raw.confidence === 'number' ? raw.confidence : 0;
  const verdict    = typeof raw.verdict    === 'string' ? raw.verdict.toUpperCase() : 'BENIGN';
  const riskScore  = typeof raw.risk_score === 'number' ? raw.risk_score : 0;

  const status =
    verdict === 'MALICIOUS'  ? 'danger'  :
    verdict === 'SUSPICIOUS' ? 'warning' :
    'safe';

  const threats: { name: string; severity: string }[] = [];
  if (Array.isArray(raw.shap_features)) {
    for (const f of raw.shap_features as Array<Record<string, unknown>>) {
      if (parseFloat(String(f.weight ?? 0)) > 0.2) {
        threats.push({
          name:     String(f.feature ?? 'Unknown Signal'),
          severity: parseFloat(String(f.weight ?? 0)) > 0.6 ? 'CRITICAL' : 'HIGH',
        });
      }
    }
  }

  return {
    status,
    score:       Math.round(confidence * 100),
    riskScore,
    verdict,
    details:     typeof raw.explanation === 'string' ? raw.explanation : 'Analysis complete.',
    action:      typeof raw.action      === 'string' ? raw.action      : '',
    threats,
    mode:        raw.detection_mode ?? raw.narration_mode ?? 'heuristic',
    incident_id: typeof raw.incident_id === 'string' ? raw.incident_id : '',
    threat_type: typeof raw.threat_type === 'string' ? raw.threat_type : '',
    risk_band:   typeof raw.risk_band   === 'string' ? raw.risk_band   : '',
    processing_time_ms: typeof raw.processing_time_ms === 'number' ? raw.processing_time_ms : 0,
    timestamp:   typeof raw.timestamp   === 'string' ? raw.timestamp   : new Date().toISOString(),
  };
}

// ── Firestore write ───────────────────────────────────────────────────────────

/**
 * Write an analysis result directly to Firestore `incidents` collection.
 * This runs from the frontend as a reliability guarantee — the backend also
 * writes to Firestore, so one of the two will always succeed.
 *
 * Uses the backend's incident_id as the document key so there are no duplicates.
 */
async function saveToFirestore(
  raw: Record<string, unknown>,
  threatType: string,
): Promise<void> {
  try {
    const confidence = typeof raw.confidence === 'number' ? raw.confidence : 0;
    const verdict    = typeof raw.verdict    === 'string' ? raw.verdict.toUpperCase() : 'BENIGN';
    const riskBand   = typeof raw.risk_band  === 'string' ? raw.risk_band : '';
    const incidentId = typeof raw.incident_id === 'string' ? raw.incident_id : `INC-FE-${Date.now()}`;
    const explanation = typeof raw.explanation === 'string' ? raw.explanation : `Verdict: ${verdict} — Confidence: ${Math.round(confidence * 100)}%`;

    const docRef = doc(collection(db, 'incidents'), incidentId);
    await setDoc(docRef, {
      incident_id:          incidentId,
      threat_type:          threatType,
      verdict,
      confidence,
      risk_score:           raw.risk_score ?? 0,
      risk_band:            riskBand,
      explanation,
      action:               raw.action ?? '',
      detection_mode:       raw.detection_mode ?? 'unknown',
      processing_time_ms:   raw.processing_time_ms ?? 0,
      timestamp:            raw.timestamp ?? new Date().toISOString(),
      shap_features:        Array.isArray(raw.shap_features) ? raw.shap_features : [],
      // Front-end normalised fields (for docToIncident compatibility)
      type:                 toTypeLabel(threatType),
      riskLevel:            toRiskLevel(verdict, riskBand),
      description:          explanation,
    }, { merge: false });

    console.info(`[securityService] Incident ${incidentId} saved to Firestore.`);
  } catch (err) {
    // Non-fatal — backend may have already written it
    console.warn('[securityService] Firestore write failed (non-fatal):', err);
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

/** Analyse a file for security threats. */
async function analyzeFile(file: File, operation = 'anomaly'): Promise<ReturnType<typeof adaptResult>> {
  const threatType = toThreatType(operation);
  try {
    const form = new FormData();
    form.append('threat_type', threatType);
    form.append('content', '');
    form.append('file', file, file.name);

    const res = await fetch(ANALYZE_URL, { method: 'POST', body: form });

    if (!res.ok) {
      const err = await res.text();
      console.error('[securityService.analyzeFile] HTTP error', res.status, err);
      throw new Error(err);
    }

    const json = await res.json() as Record<string, unknown>;
    // Fire-and-forget Firestore write
    void saveToFirestore(json, threatType);
    return adaptResult(json);
  } catch (err) {
    console.warn('[securityService.analyzeFile] backend unavailable:', err);
    return {
      status: 'safe', score: 0, riskScore: 0, verdict: 'BENIGN',
      details: 'Backend unavailable — ensure FastAPI is running on port 8000.',
      action: '', threats: [], mode: 'offline_fallback',
      incident_id: '', threat_type: '', risk_band: '',
      processing_time_ms: 0, timestamp: new Date().toISOString(),
    };
  }
}

/** Analyse arbitrary text for security threats. */
async function analyzeText(content: string, operation: string, _inputType: string): Promise<ReturnType<typeof adaptResult>> {
  const threatType = toThreatType(operation);
  try {
    const form = new FormData();
    form.append('threat_type', threatType);
    form.append('content', content);

    const res = await fetch(ANALYZE_URL, { method: 'POST', body: form });

    if (!res.ok) {
      const err = await res.text();
      console.error('[securityService.analyzeText] HTTP error', res.status, err);
      throw new Error(err);
    }

    const json = await res.json() as Record<string, unknown>;
    // Fire-and-forget Firestore write
    void saveToFirestore(json, threatType);
    return adaptResult(json);
  } catch (err) {
    console.warn('[securityService.analyzeText] backend unavailable:', err);
    return {
      status: 'safe', score: 0, riskScore: 0, verdict: 'BENIGN',
      details: 'Backend unavailable — ensure FastAPI is running on port 8000.',
      action: '', threats: [], mode: 'offline_fallback',
      incident_id: '', threat_type: '', risk_band: '',
      processing_time_ms: 0, timestamp: new Date().toISOString(),
    };
  }
}

/** Fire-and-forget notification for high-risk incidents. */
async function handleNewIncident(incident: Incident): Promise<void> {
  if (incident.riskLevel !== 'Critical' && incident.riskLevel !== 'High') return;
  console.info('[securityService] High-risk incident logged:', incident.id);
}

export const securityService = { analyzeFile, analyzeText, handleNewIncident };