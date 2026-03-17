import { useEffect, useState, useRef } from 'react'
import {
  collection,
  onSnapshot,
  query,
  orderBy,
  limit,
  Timestamp,
  QueryDocumentSnapshot,
  DocumentData,
} from 'firebase/firestore'
import { db, initFirebaseAuth } from '@/lib/firebase'
import type { Incident, RiskLevel } from '@/types/security'

const COLLECTION = 'incidents'
const MAX_ITEMS   = 50

/**
 * Normalise a Firestore document into the app's Incident shape.
 * Handles both server Timestamp objects and plain ISO strings so the
 * collection works whether documents were written by this front-end or
 * by the backend.
 */
/**
 * Convert a backend `risk_band` string (e.g. "HIGH", "CRITICAL") to the
 * frontend RiskLevel type.
 */
function toRiskLevel(raw: unknown): RiskLevel {
  const s = String(raw ?? '').toUpperCase()
  if (s.includes('CRITICAL')) return 'Critical'
  if (s.includes('HIGH'))     return 'High'
  if (s.includes('MED'))      return 'Medium'
  return 'Low'
}

/**
 * Derive a human-friendly incident type label from backend threat_type values.
 */
function toTypeLabel(raw: unknown): string {
  const s = String(raw ?? '').toLowerCase()
  if (s.includes('phish'))     return 'Phishing Attack'
  if (s.includes('url'))       return 'Malicious URL'
  if (s.includes('inject'))    return 'Prompt Injection'
  if (s.includes('anomaly'))   return 'Anomaly Detected'
  if (s.length > 0)            return String(raw)
  return 'Unknown'
}

/**
 * Normalise a Firestore document into the app's Incident shape.
 * Handles BOTH documents written by the FastAPI backend and any
 * documents written directly by the frontend.
 *
 * Backend fields:  threat_type, risk_band, risk_score, explanation, verdict, incident_id
 * Frontend fields: type, riskLevel, description
 */
function docToIncident(doc: QueryDocumentSnapshot<DocumentData>): Incident {
  const d = doc.data()

  // ── Timestamp ──────────────────────────────────────────────────────────────
  let timestamp: string
  if (d.timestamp instanceof Timestamp) {
    timestamp = d.timestamp.toDate().toISOString()
  } else if (typeof d.timestamp === 'string') {
    timestamp = d.timestamp
  } else {
    timestamp = new Date().toISOString()
  }

  // ── Risk Level (backend: risk_band | frontend: riskLevel) ──────────────────
  const riskLevel: RiskLevel = d.riskLevel
    ? (['Critical', 'High', 'Medium', 'Low'].includes(d.riskLevel) ? d.riskLevel as RiskLevel : 'Low')
    : toRiskLevel(d.risk_band ?? d.risk_score ?? '')

  // ── Type (backend: threat_type | frontend: type) ───────────────────────────
  const type = typeof d.type === 'string' && d.type
    ? d.type
    : toTypeLabel(d.threat_type)

  // ── Description (backend: explanation | frontend: description) ─────────────
  const description = typeof d.description === 'string' && d.description
    ? d.description
    : typeof d.explanation === 'string' && d.explanation
      ? d.explanation
      : typeof d.verdict === 'string'
        ? `Verdict: ${d.verdict} — Confidence: ${Math.round((d.confidence ?? 0) * 100)}%`
        : 'Analysis completed.'

  return {
    id: doc.id,
    timestamp,
    type,
    riskLevel,
    description,
  }
}

interface UseFirebaseIncidentsReturn {
  incidents: Incident[]
  loading:   boolean
  error:     string | null
  isLive:    boolean
}

/**
 * Real-time Firestore incidents hook.
 *
 * Reads from the `incidents` collection, ordered by `timestamp` descending.
 * Initialises anonymous auth on first mount so Firestore security rules can
 * scope access.  Gracefully handles missing config / offline state.
 */
export function useFirebaseIncidents(): UseFirebaseIncidentsReturn {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [loading,   setLoading  ] = useState(true)
  const [error,     setError    ] = useState<string | null>(null)
  const [isLive,    setIsLive   ] = useState(false)
  const unsubRef = useRef<(() => void) | null>(null)

  useEffect(() => {
    let cancelled = false

    const bootstrap = async () => {
      // Attempt optional anonymous sign-in — Firestore may still work without it
      // depending on security rules. We never block on auth failure.
      try {
        await initFirebaseAuth()
      } catch {
        // silently ignore — Firestore rules may allow unauthenticated reads
      }
      if (cancelled) return

      try {
        const q = query(
          collection(db, COLLECTION),
          orderBy('timestamp', 'desc'),
          limit(MAX_ITEMS)
        )

        unsubRef.current = onSnapshot(
          q,
          snapshot => {
            if (cancelled) return
            const docs = snapshot.docs.map(docToIncident)
            setIncidents(docs)
            setLoading(false)
            setIsLive(true)
            setError(null)
          },
          err => {
            if (cancelled) return
            console.error('[useFirebaseIncidents]', err)
            // Detect Firestore database not provisioned yet
            const msg = err.message ?? ''
            if (msg.includes('not found') || msg.includes('NOT_FOUND')) {
              setError(
                'Firestore database not provisioned. Go to Firebase Console → Firestore Database → Create database.'
              )
            } else {
              setError(msg || 'Failed to connect to Firebase')
            }
            setLoading(false)
            setIsLive(false)
          }
        )
      } catch (err: any) {
        if (cancelled) return
        const msg = err?.message ?? ''
        if (msg.includes('not found') || msg.includes('NOT_FOUND')) {
          setError('Firestore database not provisioned. Go to Firebase Console → Firestore Database → Create database.')
        } else {
          setError(msg || 'Failed to connect to Firebase')
        }
        setLoading(false)
        setIsLive(false)
      }
    }

    bootstrap()

    return () => {
      cancelled = true
      unsubRef.current?.()
    }
  }, [])

  return { incidents, loading, error, isLive }
}
