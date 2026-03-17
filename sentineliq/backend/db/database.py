import os
import logging
from typing import List

import firebase_admin  # type: ignore[import-untyped]
from firebase_admin import credentials, firestore  # type: ignore[import-untyped]
from fastapi import FastAPI  # type: ignore[import-untyped]

logger = logging.getLogger("sentineliq.db")

_db = None  # Global Firestore client — None when offline


async def init_firebase(app: FastAPI) -> None:  # type: ignore[misc]
    """Initialize Firebase Admin SDK. Stores mode in app.state.firebase_mode."""
    global _db
    sa_path = os.getenv(
        "FIREBASE_SERVICE_ACCOUNT", "./firebase-service-account.json"
    )
    try:
        if os.path.exists(sa_path):
            cred = credentials.Certificate(sa_path)
            firebase_admin.initialize_app(cred)
            _db = firestore.client()
            app.state.firebase_mode = "firestore_connected"
            logger.info("Firebase Firestore connected.")
        else:
            app.state.firebase_mode = "offline_no_service_account"
            logger.warning(
                "firebase-service-account.json not found — running offline."
            )
    except Exception as exc:
        app.state.firebase_mode = ("error:" + str(exc))[:48]  # type: ignore[assignment]
        logger.error("Firebase init failed: %s", exc)


async def save_incident(data: dict) -> bool:
    """Fire-and-forget Firestore write. Returns False silently if offline."""
    if _db is None:
        return False
    try:
        _db.collection("incidents").document(data["incident_id"]).set(data)
        return True
    except Exception as exc:
        logger.warning("save_incident failed (non-fatal): %s", exc)
        return False


async def get_incidents(limit: int = 20, threat_type: str = "") -> List[dict]:
    """Fetch recent incidents from Firestore. Returns [] if offline."""
    if _db is None:
        return []
    try:
        q = _db.collection("incidents").order_by(
            "timestamp", direction=firestore.Query.DESCENDING
        )
        if threat_type:
            q = q.where("threat_type", "==", threat_type)
        q = q.limit(limit)
        return [doc.to_dict() for doc in q.stream()]
    except Exception as exc:
        logger.warning("get_incidents failed (non-fatal): %s", exc)
        return []


async def get_historical_rate(threat_type: str) -> float:
    """Returns fraction of recent incidents that were MALICIOUS for given type."""
    if _db is None:
        return 0.0
    try:
        docs = (
            _db.collection("incidents")
            .where("threat_type", "==", threat_type)
            .order_by("timestamp", direction=firestore.Query.DESCENDING)
            .limit(50)
            .stream()
        )
        records = [doc.to_dict() for doc in docs]
        if not records:
            return 0.0
        malicious: int = sum(1 for r in records if r.get("verdict") == "MALICIOUS")
        ratio: float = malicious / len(records)
        return round(ratio, 4)  # type: ignore[return-value]
    except Exception:
        return 0.0
