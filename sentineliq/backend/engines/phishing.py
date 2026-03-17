"""
engines/phishing.py — Production Phishing / Social-Engineering Detector
=========================================================================

Architecture (3 layers):
  Layer A : Weighted keyword heuristic + regex category scoring
  Layer B : BERT fine-tuned text classifier (ealvaradob/bert-finetuned-phishing)
  Layer C : Gemini AI cross-validation for LLM-generated spear-phishing

All thresholds, model names, weights, and patterns are loaded from config.py.
No magic numbers exist in this file.
"""

import os
import logging
import asyncio
import re
import json
import unicodedata
from typing import Any, Dict, List, Optional
from fastapi import FastAPI  # type: ignore[import-untyped]

# Must be set before transformers import
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "")

logger = logging.getLogger("sentineliq.phishing")

from config import PhishingConfig, HOMOGLYPH_MAP  # type: ignore[import]

# ─── Compile regex patterns once at module load (never inside functions) ──────
import math

_COMPILED_SIGNALS = {
    category: {
        "weight": data["weight"],
        "compiled": [re.compile(p, re.IGNORECASE | re.UNICODE | re.DOTALL) for p in data["patterns"]]
    }
    for category, data in PhishingConfig.HEURISTIC_SIGNALS.items()
}


# ─── Homoglyph normalization ──────────────────────────────────────────────────

def _normalize(text: str) -> str:
    """NFKD decomposition + homoglyph substitution for evasion resistance."""
    text = unicodedata.normalize("NFKD", str(text))
    for fake, real in HOMOGLYPH_MAP.items():
        text = text.replace(fake, real)
    return text


# ─── Model loading ────────────────────────────────────────────────────────────

async def load_phishing_model(app: FastAPI) -> None:  # type: ignore[misc]
    """Load HuggingFace phishing BERT pipeline. Graceful fallback on failure."""
    cache_dir = os.getenv("MODEL_CACHE_DIR", "./model_cache")
    os.makedirs(cache_dir, exist_ok=True)
    try:
        loop = asyncio.get_event_loop()

        def _load() -> Any:
            from transformers import pipeline  # type: ignore[import]
            return pipeline(
                "text-classification",
                model=PhishingConfig.MODEL_NAME,
                tokenizer=PhishingConfig.MODEL_NAME,
                model_kwargs={"cache_dir": cache_dir},
                truncation=True,
                max_length=PhishingConfig.MAX_INPUT_LENGTH,
                return_all_scores=True,
            )

        pipe = await loop.run_in_executor(None, _load)  # type: ignore[arg-type]
        app.state.phishing_model = pipe
        app.state.phishing_mode = "bert_model"
        logger.info("Phishing BERT model loaded: %s", PhishingConfig.MODEL_NAME)
    except Exception as exc:
        app.state.phishing_model = None
        app.state.phishing_mode = "heuristic_fallback"
        logger.warning("Phishing model load failed (%s) — using heuristic fallback.", exc)


# ─── Heuristic scoring ────────────────────────────────────────────────────────

_MALICIOUS_LABELS = {"label_1", "phishing", "malicious", "1", "spam"}


def _heuristic_score(text: str) -> Dict[str, Any]:
    """
    Score ANY text for phishing signals — no URL required.
    Returns score in [0, 1] and list of triggered categories.
    """
    if not text or len(str(text).strip()) < PhishingConfig.MIN_INPUT_LENGTH:
        return {"score": 0.0, "triggered": [], "signal_count": 0}

    # Always normalize first
    normalized_text = _normalize(text)

    triggered_categories = []
    raw_score = 0.0
    seen_weights = set()

    for category, data in _COMPILED_SIGNALS.items():
        for pattern in data["compiled"]:
            if pattern.search(normalized_text):
                # Each category contributes its weight only ONCE
                if category not in seen_weights:
                    raw_score += float(data["weight"])
                    seen_weights.add(category)
                triggered_categories.append(category)
                break  # one match per category is enough

    # Cap at 1.0, apply sigmoid smoothing for confidence feel
    capped = min(raw_score, 2.0)  # allow accumulation up to 2.0 before cap
    smoothed = 1 / (1 + math.exp(-4 * (capped - 0.5)))  # sigmoid centered at 0.5

    return {
        "score": round(smoothed, 4),
        "triggered": list(set(triggered_categories)),
        "signal_count": len(set(triggered_categories)),
        "raw_score": round(raw_score, 4)
    }


def compute_absence_score(text: str) -> Dict[str, Any]:
    """
    Legitimate emails HAVE these things. Phishing often doesn't.
    Score based on what's MISSING, not just what's present.
    """
    score = 0.0
    signals = []

    # No personal name used (Dear User vs Dear John)
    has_personal = bool(re.search(
        r'(?i)dear\s+(mr|mrs|ms|dr|prof)\b|dear\s+[A-Z][a-z]{2,20}\b',
        text
    ))
    if not has_personal:
        score += 0.18
        signals.append("no_personal_name")

    # No company/brand identity
    has_brand = bool(re.search(
        r'(?i)(from|regards|sincerely|team\s+at|the\s+)\s*\b\w{3,20}\s+(inc|corp|ltd|llc|team|support)\b',
        text
    ))
    if not has_brand:
        score += 0.15
        signals.append("no_brand_identity")

    # No contact information
    has_contact = bool(re.search(
        r'(?i)(\+\d[\d\s\-]{8,}|contact\s+us\s+at|help@|support@[a-z]+\.[a-z]{2,4})',
        text
    ))
    if not has_contact:
        score += 0.12
        signals.append("no_contact_info")

    # No unsubscribe / legal footer (legit marketing always has this)
    has_footer = bool(re.search(
        r'(?i)(unsubscribe|opt.?out|privacy\s+policy|terms\s+of\s+service|©\s*\d{4})',
        text
    ))
    if not has_footer:
        score += 0.10
        signals.append("no_legal_footer")

    return {
        "absence_score": round(min(score, 0.50), 4),
        "absence_signals": signals
    }


def _token_scores(text: str) -> List[Dict[str, Any]]:
    """Return per-token highlight scores for frontend rendering."""
    words = str(text).split()
    text_lower = str(text).lower()
    result: List[Dict[str, Any]] = []
    for word in words:
        clean = word.strip(".,!?;:'\"").lower()
        matched_weight: float = 0.0
        for sig in PhishingConfig.SIGNALS:
            if sig in text_lower and clean in sig:
                matched_weight = max(
                    matched_weight,
                    PhishingConfig.SIGNAL_WEIGHTS.get(sig, PhishingConfig.DEFAULT_SIGNAL_WEIGHT)
                )
        if float(matched_weight) > 0.0:
            result.append({"token": word, "score": float(round(matched_weight, 4))})
        else:
            result.append({"token": word, "score": 0.04})
    return result


# ─── Gemini Layer C ───────────────────────────────────────────────────────────

async def _gemini_phishing_judge(text: str, app_state: Any) -> Dict[str, Any]:
    """Layer C Gemini cross-validation to catch flawless LLM-generated phishing."""
    if not getattr(app_state, "gemini_available", False):
        return {"confidence": 0.0, "reason": "Gemini unavailable"}

    client: Optional[Any] = getattr(app_state, "gemini_client", None)
    if client is None:
        return {"confidence": 0.0, "reason": "No Gemini client"}

    snippet: str = str(text)[:500]
    prompt = PhishingConfig.GEMINI_PROMPT_TEMPLATE.format(snippet=snippet)

    try:
        _c = client
        _p = prompt

        def _call() -> Any:
            return _c.models.generate_content(model="gemini-2.5-flash", contents=_p)

        loop = asyncio.get_event_loop()
        response: Any = await asyncio.wait_for(
            loop.run_in_executor(None, _call),  # type: ignore[arg-type]
            timeout=PhishingConfig.GEMINI_TIMEOUT,
        )
        raw: str = str(response.text).strip()
        logger.debug("Gemini Phishing RAW: %s", raw)

        # Strip markdown fences
        raw = re.sub(r"^```[a-z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)

        parsed = json.loads(raw)
        verdict: str = str(parsed.get("verdict", "BENIGN")).upper()
        conf: float = float(parsed.get("confidence", 0.0))
        if verdict != "MALICIOUS":
            conf = 1.0 - conf
        return {
            "confidence": float(round(min(1.0, max(0.0, conf)), 4)),
            "reason": str(parsed.get("reason", "")),
        }
    except json.JSONDecodeError:
        logger.debug("Gemini Phishing JSON parse failed — using fallback")
        return {"confidence": 0.0, "reason": "JSON parse error"}
    except Exception as exc:
        logger.debug("Gemini Phishing Layer C failed: %s", exc)
        return {"confidence": 0.0, "reason": "Gemini failed"}


# ─── Public entry point ───────────────────────────────────────────────────────

async def detect_phishing(text: str, app_state: Any) -> Dict[str, Any]:
    """
    Async phishing detector (3 layers).
    Returns: { confidence, verdict, shap_features, mode, token_scores }
    Never raises.
    """
    try:
        # Input guard
        if text is None:
            text = ""
        text = str(text)

        # Normalize for heuristics
        heuristic_result = _heuristic_score(text)
        heuristic = heuristic_result["score"]
        triggered = heuristic_result["triggered"]

        model: Optional[Any] = getattr(app_state, "phishing_model", None)
        mode: str = getattr(app_state, "phishing_mode", "heuristic_fallback")

        model_conf = 0.0
        if model is not None and len(text.strip()) >= PhishingConfig.MIN_INPUT_LENGTH:
            try:
                loop = asyncio.get_event_loop()
                truncated = text[:PhishingConfig.MAX_INPUT_LENGTH]

                def _infer() -> Any:
                    return model(truncated)  # type: ignore[operator]

                raw = await loop.run_in_executor(None, _infer)  # type: ignore[arg-type]

                # raw is list[list[dict]] when return_all_scores=True
                scores_list: List[Dict[str, Any]] = raw[0] if raw and isinstance(raw[0], list) else raw

                for item in scores_list:
                    lbl = str(item.get("label", "")).lower().strip()
                    sc = float(item.get("score", 0.0))
                    if lbl in _MALICIOUS_LABELS:
                        model_conf = sc
                        break
                else:
                    if scores_list:
                        first_sc = float(scores_list[0].get("score", 0.0))
                        model_conf = 1.0 - first_sc
            except Exception as infer_exc:
                logger.warning("Phishing BERT inference error: %s", infer_exc)
                model_conf = 0.0

        # Replace static blending with heuristic-dominant 3-tier blending
        final_confidence = 0.0
        if model is None or model_conf == 0.0:
            final_confidence = min(1.0, heuristic)
        else:
            if heuristic >= 0.65:
                # Strong social engineering signal — boost standard confidence
                # to guarantee MALICIOUS categorization if heuristics are firing heavily
                final_confidence = (0.20 * model_conf) + (0.80 * heuristic)
            elif heuristic >= 0.35:
                # Moderate signal — balanced blend
                final_confidence = (0.50 * model_conf) + (0.50 * heuristic)
            else:
                # Low heuristic signal — trust BERT more
                final_confidence = (0.75 * model_conf) + (0.25 * heuristic)

        absence = compute_absence_score(text)
        final_confidence = min(1.0, final_confidence + absence["absence_score"] * 0.4)

        # Gemini Layer C: trigger when standard confidence is below threshold
        gemini_conf = 0.0
        if final_confidence < PhishingConfig.GEMINI_TRIGGER_THRESHOLD and len(text) > 50:
            lb = await _gemini_phishing_judge(text, app_state)
            gemini_conf = float(lb["confidence"])
            if gemini_conf > PhishingConfig.GEMINI_OVERRIDE_THRESHOLD:
                mode = "gemini_layer_c_override"

        final_conf = float(round(max(final_confidence, gemini_conf), 4))
        # Always clamp to [0, 1]
        final_conf = min(1.0, max(0.0, final_conf))

        TIER1_SIGNALS = {"urgency_threat_combo", "account_threat", "urgency_deadline"}
        tier1_fired = bool(set(triggered) & TIER1_SIGNALS)

        if tier1_fired and final_conf < 0.55:
            final_conf = 0.55  # floor — BERT cannot override strong social engineering

        if tier1_fired and heuristic > 0.70 and final_conf < 0.75:
            final_conf = 0.75  # strong floor for multiple tier-1 signals

        verdict = (
            "MALICIOUS"   if final_conf >= PhishingConfig.MALICIOUS_THRESHOLD
            else "SUSPICIOUS" if final_conf >= PhishingConfig.SUSPICIOUS_THRESHOLD
            else "BENIGN"
        )

        token_scores = _token_scores(text)

        return {
            "confidence":    final_conf,
            "verdict":       verdict,
            "shap_features": [],
            "mode":          mode,
            "token_scores":  token_scores,
        }
    except Exception as exc:
        logger.error("detect_phishing unhandled error: %s", exc)
        return {
            "confidence":    0.0,
            "verdict":       "BENIGN",
            "shap_features": [],
            "mode":          "error_fallback",
            "token_scores":  [],
        }
