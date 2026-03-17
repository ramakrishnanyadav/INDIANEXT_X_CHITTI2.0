"""
engines/url_detector.py — Production URL/Phishing Link Detector
================================================================

Architecture (3 layers):
  Layer A : Safe-domain fast-path (trusted domain allowlist from config)
  Layer B : Structural rule engine (12 weighted signals, non-linear scoring)
  Layer C : BERT classifier fine-tuned on phishing content
             Model: ealvaradob/bert-finetuned-phishing
             Labels: benign / phishing

All thresholds, model names, weights, and constants are loaded from config.py.
"""

import os
import re
import asyncio
import logging
import math
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "")

logger = logging.getLogger("sentineliq.url")

from config import URLConfig  # type: ignore[import]

# Lazy optional imports (handle gracefully if not installed)
try:
    from bs4 import BeautifulSoup  # type: ignore[import]
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False
    logger.warning("BeautifulSoup (bs4) not installed — DOM scraping disabled.")

try:
    import httpx  # type: ignore[import]
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False
    logger.warning("httpx not installed — DOM scraping disabled.")

# ─── Label mappings ────────────────────────────────────────────────────────────
_MALICIOUS_LABELS = {"label_1", "phishing", "malicious", "unsafe", "1"}
_SAFE_LABELS      = {"label_0", "safe", "benign", "0"}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _is_trusted_domain(hostname: str) -> bool:
    """Returns True if hostname is (or is a subdomain of) a trusted root."""
    h = hostname.lower()
    for td in URLConfig.TRUSTED_DOMAINS:
        if h == td or h.endswith("." + td):
            return True
    return False


def _is_private_host(hostname: str) -> bool:
    """Returns True if hostname is a private/loopback address."""
    return any(hostname.startswith(p) for p in URLConfig.PRIVATE_IP_PREFIXES) or not hostname


def _is_brand_spoof(hostname: str) -> bool:
    """
    Returns True if a known brand appears in hostname but the host
    is NOT the canonical domain for that brand.
    """
    h = hostname.lower()
    for brand in URLConfig.BRAND_NAMES:
        if brand in h:
            canonicals = URLConfig.BRAND_CANONICAL.get(brand, (f"{brand}.com",))
            canonical_match = any(
                h == c.lstrip(".") or h.endswith("." + c.lstrip("."))
                for c in canonicals
            )
            if not canonical_match:
                return True
    return False


# ─── WHOIS domain age (with timeout protection) ───────────────────────────────

def _check_domain_age(hostname: str) -> Dict[str, Any]:
    """
    WHOIS lookup with graceful fallback on any failure.
    Handles: None creation_date, list creation_date, timezone-naive datetime,
             library exceptions, and import errors.
    """
    if not hostname or _is_private_host(hostname):
        return {"age_days": None, "new_domain": False, "very_new_domain": False}
    try:
        import whois  # type: ignore[import]
        from datetime import datetime, timezone
        import signal as _sig

        import threading
        import sys
        import io
        import contextlib

        result_holder: Dict[str, Any] = {}

        def _do_whois() -> None:
            # Trap python-whois' internal print statements safely
            f = io.StringIO()
            with contextlib.redirect_stdout(f), contextlib.redirect_stderr(f):
                try:
                    w = whois.whois(hostname)
                    result_holder["w"] = w
                except Exception as exc:
                    result_holder["err"] = exc

        t = threading.Thread(target=_do_whois, daemon=True)
        t.start()
        t.join(timeout=URLConfig.WHOIS_TIMEOUT_SECONDS)

        if "err" in result_holder or "w" not in result_holder:
            return {"age_days": None, "new_domain": False, "very_new_domain": False}

        w = result_holder["w"]
        creation = w.creation_date

        # Handle list (some WHOIS servers return multiple dates)
        if isinstance(creation, list):
            creation = creation[0] if creation else None
        if creation is None:
            return {"age_days": None, "new_domain": False, "very_new_domain": False}

        # Make timezone-aware
        if hasattr(creation, "tzinfo") and creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        age_days = int((datetime.now(timezone.utc) - creation).days)
        return {
            "age_days":        age_days,
            "new_domain":      bool(age_days < URLConfig.WHOIS_NEW_DOMAIN_DAYS),
            "very_new_domain": bool(age_days < URLConfig.WHOIS_VERY_NEW_DOMAIN_DAYS),
        }
    except ImportError:
        logger.debug("whois library not installed — domain age check skipped.")
        return {"age_days": None, "new_domain": False, "very_new_domain": False}
    except Exception:
        return {"age_days": None, "new_domain": False, "very_new_domain": False}


# ─── Rule engine ──────────────────────────────────────────────────────────────

def _rule_based_features(url: str, domain_age: Dict[str, Any]) -> Dict[str, float]:
    """Run 12 structural checks on the URL. Returns rule → 0.0 or 1.0."""
    url_str = str(url)
    try:
        parsed = urlparse(url_str if "://" in url_str else f"http://{url_str}")
    except ValueError:
        # Malformed URL — treat as clean rather than crashing
        return {k: 0.0 for k in URLConfig.RULE_WEIGHTS}

    hostname = str(parsed.hostname or "").lower()
    path = str(parsed.path).lower()
    query = str(parsed.query).lower()
    full_path_query = path + "?" + query if query else path

    # 1. IP address
    has_ip = float(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname)))

    # 2. Suspicious TLD
    suspicious_tld = float(any(hostname.endswith(tld) for tld in URLConfig.SUSPICIOUS_TLDS))

    # 3. Brand spoof
    brand_spoof = float(_is_brand_spoof(hostname))

    # 4. Suspicious compound keywords
    suspicious_keywords = float(
        any(kw in full_path_query or kw in hostname for kw in URLConfig.SUSPICIOUS_KEYWORDS)
    )

    # 5. No HTTPS for non-private, non-trusted hosts
    is_private = _is_private_host(hostname)
    no_https = float(
        str(parsed.scheme).lower() != "https"
        and not is_private
        and not _is_trusted_domain(hostname)
    )

    # 6. Excessive subdomains (> EXCESSIVE_SUBDOMAIN_DOTS dots)
    excessive_subdomains = float(hostname.count(".") > URLConfig.EXCESSIVE_SUBDOMAIN_DOTS)

    # 7. URL too long
    url_too_long = float(len(url_str) > URLConfig.MAX_URL_LENGTH)

    # 8. @ symbol (@ routing attack)
    has_at_symbol = float("@" in url_str)

    # 9. @ in path (explicit path routing attack)
    at_routing = float("@" in path or ("@" in url_str and "@" not in hostname))

    # 10 & 11. WHOIS domain age
    new_domain      = float(domain_age.get("new_domain", False))
    very_new_domain = float(domain_age.get("very_new_domain", False))

    # 12. Compound keyword stacking
    path_domain_combined = hostname + " " + full_path_query
    pair_hits = sum(
        1 for (w1, w2) in URLConfig.PHISHING_KEYWORD_PAIRS
        if w1 in path_domain_combined and w2 in path_domain_combined
    )
    keyword_stacking = float(min(1.0, pair_hits * 0.3)) if pair_hits >= 2 else 0.0

    return {
        "has_ip":               has_ip,
        "suspicious_tld":       suspicious_tld,
        "brand_spoof":          brand_spoof,
        "suspicious_keywords":  suspicious_keywords,
        "no_https":             no_https,
        "excessive_subdomains": excessive_subdomains,
        "url_too_long":         url_too_long,
        "has_at_symbol":        has_at_symbol,
        "at_routing":           at_routing,
        "new_domain":           new_domain,
        "very_new_domain":      very_new_domain,
        "keyword_stacking":     keyword_stacking,
    }


def _weighted_rule_score(features: Dict[str, float], trusted: bool) -> float:
    """
    Non-linear weighted score in [0, 1].
    Multi-high-weight-signal boost: each additional heavy signal adds BOOST_PER_HIT.
    Trusted domain cap: never exceed TRUSTED_DOMAIN_SCORE_CAP from rules alone.
    """
    fired_items = [(k, v) for k, v in features.items() if v > 0]
    if not fired_items:
        return 0.0

    total_weight = sum(URLConfig.RULE_WEIGHTS.get(k, 0.5) for k in features)
    fired_weight = sum(URLConfig.RULE_WEIGHTS.get(k, 0.5) * v for k, v in features.items())
    raw = fired_weight / total_weight if total_weight > 0 else 0.0

    # Boost for multiple high-weight signals
    heavy_fired = sum(
        1 for k, v in features.items()
        if v > 0 and URLConfig.RULE_WEIGHTS.get(k, 0.0) >= URLConfig.HIGH_WEIGHT_SIGNAL_THRESHOLD
    )
    boost = min(URLConfig.MULTI_SIGNAL_BOOST_CAP, heavy_fired * URLConfig.MULTI_SIGNAL_BOOST_PER_HIT)
    score = min(1.0, raw + boost)

    if trusted:
        score = min(score, URLConfig.TRUSTED_DOMAIN_SCORE_CAP)

    return score


def _features_to_shap(features: Dict[str, float]) -> List[Dict[str, Any]]:
    """Convert fired rule features to SHAP-style explanation list."""
    shap = []
    for name, val in features.items():
        if val > 0:
            w = URLConfig.RULE_WEIGHTS.get(name, 0.5) * val
            shap.append({
                "feature":   name.replace("_", " "),
                "weight":    round(float(w), 4),
                "direction": "positive",
            })
    return sorted(shap, key=lambda x: float(x["weight"]), reverse=True)


# ─── Model inference ──────────────────────────────────────────────────────────

def _model_confidence(model: Any, url_str: str) -> float:
    """Run HuggingFace pipeline, return P(phishing) in [0, 1]."""
    try:
        _url = str(url_str)[:512]
        raw = model(_url)
        result = raw[0] if isinstance(raw, list) else raw
        lbl = str(result.get("label", "")).lower().strip()
        sc = float(result.get("score", 0.5))

        if lbl in _MALICIOUS_LABELS:
            return sc
        elif lbl in _SAFE_LABELS:
            return 1.0 - sc
        else:
            logger.warning("URL model unknown label: %s", lbl)
            return 0.5
    except Exception as infer_exc:
        logger.warning("URL model inference error: %s", infer_exc)
        return 0.0


# ─── DOM scraping (zero-day detection) ────────────────────────────────────────

async def _fetch_and_analyze_dom(url: str, hostname: str) -> Dict[str, Any]:
    """Active DOM scraping for zero-day phishing pages."""
    if not _BS4_AVAILABLE or not _HTTPX_AVAILABLE:
        return {}
    try:
        async with httpx.AsyncClient(  # type: ignore[attr-defined]
            timeout=URLConfig.DOM_FETCH_TIMEOUT,
            verify=False,
            follow_redirects=True,
        ) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return {}

            soup = BeautifulSoup(resp.text, "html.parser")  # type: ignore[misc]
            title_node = soup.title
            title = str(title_node.string).lower() if (title_node and title_node.string) else ""
            has_password = bool(soup.find("input", {"type": "password"}))

            spoofed_brand = None
            for brand in URLConfig.BRAND_NAMES:
                if brand in str(title):
                    spoofed_brand = brand
                    break

            if spoofed_brand and has_password:
                return {
                    "is_zero_day_phishing": True,
                    "reason": f"Page claims to be '{spoofed_brand}' and asks for password on '{hostname}'.",
                }
            return {}
    except Exception as exc:
        logger.debug("DOM fetch failed for %s: %s", url, exc)
        return {}


# ─── Model loading ────────────────────────────────────────────────────────────

async def load_url_model(app: Any) -> None:
    """Load BERT URL phishing classifier. Graceful fallback to rule-based engine."""
    cache_dir = os.getenv("MODEL_CACHE_DIR", "./model_cache")
    os.makedirs(cache_dir, exist_ok=True)
    try:
        loop = asyncio.get_event_loop()

        def _load() -> Any:
            from transformers import pipeline  # type: ignore[import]
            return pipeline(
                "text-classification",
                model=URLConfig.MODEL_NAME,
                tokenizer=URLConfig.MODEL_NAME,
                model_kwargs={"cache_dir": cache_dir},
                truncation=True,
                max_length=512,
                device=-1,
            )

        pipe = await loop.run_in_executor(None, _load)  # type: ignore[arg-type]
        app.state.url_model = pipe
        app.state.url_mode = "distilbert_model"
        logger.info("URL BERT model loaded: %s", URLConfig.MODEL_NAME)
    except Exception as exc:
        app.state.url_model = None
        app.state.url_mode = "rule_based_fallback"
        logger.warning("URL model load failed (%s) — rule-based fallback.", exc)


# ─── Public entry point ───────────────────────────────────────────────────────

async def detect_url(url: str, app_state: Any) -> Dict[str, Any]:
    """
    Production URL threat detector.

    Pipeline:
      1. WHOIS domain age check (async, best-effort, with timeout)
      2. Structural rule engine (12 signals, non-linear weighting)
      3. BERT model inference (if available)
      4. Blend: BERT_WEIGHT * model + RULE_WEIGHT * rules
      5. Verdict thresholding
      6. Zero-day DOM override (if DOM scraping enabled)

    Never raises — all exceptions caught internally.
    """
    try:
        url_str = str(url).strip()

        try:
            parsed = urlparse(url_str if "://" in url_str else f"http://{url_str}")
        except ValueError:
            parsed = urlparse("http://invalid")

        hostname = str(parsed.hostname or "").lower()

        trusted  = _is_trusted_domain(hostname)
        is_priv  = _is_private_host(hostname)

        # Private IP → immediate BENIGN (not a threat)
        if is_priv:
            return {
                "confidence":      0.0,
                "verdict":         "BENIGN",
                "shap_features":   [],
                "mode":            "private_ip_fast_path",
                "domain_age_days": None,
            }

        # WHOIS (run in executor to avoid blocking)
        loop = asyncio.get_event_loop()
        domain_age = await loop.run_in_executor(None, _check_domain_age, hostname)

        # Rule engine
        rule_features = _rule_based_features(url_str, domain_age)
        shap_features = _features_to_shap(rule_features)
        rule_score    = _weighted_rule_score(rule_features, trusted)

        # Model inference
        model: Optional[Any] = getattr(app_state, "url_model", None)
        mode:  str           = getattr(app_state, "url_mode", "rule_based_fallback")

        model_conf = 0.0
        if model is not None and not trusted:
            def _infer() -> float:
                return _model_confidence(model, url_str)

            model_conf = await loop.run_in_executor(None, _infer)  # type: ignore[arg-type]

        # Trusted fast-path (after rule + model computed — log for debugging)
        if trusted:
            return {
                "confidence":      0.0,
                "verdict":         "BENIGN",
                "shap_features":   [],
                "mode":            "trusted_domain_fast_path",
                "domain_age_days": domain_age.get("age_days"),
            }

        # Blend
        if model is None:
            final_conf = float(round(rule_score, 4))
        else:
            final_conf = float(round(
                URLConfig.BERT_WEIGHT * model_conf + URLConfig.RULE_WEIGHT * rule_score, 4
            ))

        # Platt calibration (if calibrator was trained from a prior benchmark run)
        try:
            from xai.calibrator import calibrate_confidence  # type: ignore[import]
            final_conf = float(calibrate_confidence("url", final_conf))
        except Exception:
            pass

        # Clamp
        final_conf = min(1.0, max(0.0, final_conf))

        verdict = (
            "MALICIOUS"   if final_conf >= URLConfig.MALICIOUS_THRESHOLD
            else "SUSPICIOUS" if final_conf >= URLConfig.SUSPICIOUS_THRESHOLD
            else "BENIGN"
        )

        # DOM zero-day override
        dom_analysis: Dict[str, Any] = {}
        dom_analysis = await _fetch_and_analyze_dom(url_str, hostname)

        if dom_analysis.get("is_zero_day_phishing"):
            verdict    = "MALICIOUS"
            final_conf = max(final_conf, 0.99)
            mode       = "dom_scraping_override"
            shap_features.insert(0, {
                "feature":   "zero day dom spoof",
                "weight":    1.0,
                "direction": "positive",
            })

        return {
            "confidence":      final_conf,
            "verdict":         verdict,
            "shap_features":   shap_features,
            "mode":            mode,
            "domain_age_days": domain_age.get("age_days"),
        }

    except Exception as exc:
        logger.error("detect_url unhandled error: %s", exc, exc_info=True)
        return {
            "confidence":      0.0,
            "verdict":         "BENIGN",
            "shap_features":   [],
            "mode":            "error_fallback",
            "domain_age_days": None,
        }
