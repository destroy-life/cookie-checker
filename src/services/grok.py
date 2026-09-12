"""Grok (grok.com) cookie checker — Free / SuperGrok / SuperGrokHeavy / XPremium."""
from __future__ import annotations

import json
import urllib.parse
from pathlib import Path
from typing import Any, Optional

import requests

from ..models import CheckResult, finalize

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


def normalize_plan(raw: Any) -> str:
    if raw is None:
        return "Unknown"
    s = str(raw).strip().lower()
    if not s:
        return "Unknown"
    compact = s.replace(" ", "").replace("_", "").replace("-", "")

    if "heavy" in compact:
        return "SuperGrokHeavy"
    if any(k in compact for k in ("supergrok", "grokpro", "grok.pro", "tiergrokpro")):
        return "SuperGrok"
    if any(k in compact for k in ("xpremium", "premiumplus", "premium+", "premium")):
        return "XPremium"
    if compact in ("free", "basic"):
        return "Free"
    return "Unknown"


def build_session(cookies: dict[str, str]) -> requests.Session:
    s = requests.Session()
    # Un solo dominio raíz para no duplicar cabeceras
    for name, value in cookies.items():
        s.cookies.set(name, value, domain=".grok.com", path="/")
    return s


def headers_for() -> dict[str, str]:
    return {
        "User-Agent": DEFAULT_UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://grok.com/",
        "Origin": "https://grok.com",
    }


def extract_offline(cookies: dict[str, str]) -> dict[str, Any]:
    c_lower = {k.lower(): v for k, v in cookies.items()}
    out: dict[str, Any] = {
        "user_id": c_lower.get("x-userid") or cookies.get("x-userid"),
        "stripe": "__stripe_mid" in c_lower,
        "has_sso": bool(c_lower.get("sso") or c_lower.get("sso-rw")),
    }
    for k, v in cookies.items():
        if "mixpanel" in k.lower():
            try:
                data = json.loads(urllib.parse.unquote(v))
            except Exception:
                data = {}
            if isinstance(data, dict):
                out["user_id"] = out["user_id"] or data.get("$user_id") or data.get("distinct_id")
    return out


def plan_from_subscriptions(data: Any) -> str:
    if not data:
        return "Unknown"
    subs = data.get("subscriptions") if isinstance(data, dict) else None
    if subs is None and isinstance(data, list):
        subs = data
    if not subs:
        return "Free"
    best = "Free"
    rank = {"Free": 0, "XPremium": 1, "Premium": 1, "SuperGrok": 2, "SuperGrokHeavy": 3, "Unknown": -1}
    for item in subs:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "").upper()
        is_active = "ACTIVE" in status and "INACTIVE" not in status
        offer = item.get("activeOffer") if isinstance(item.get("activeOffer"), dict) else {}
        has_live_trial = bool(offer) and "trial" in str(offer.get("type") or "").lower()
        if not is_active and not has_live_trial:
            continue
        candidates = [
            item.get("tier"),
            item.get("product"),
            item.get("productName"),
            item.get("name"),
            item.get("plan"),
            item.get("subscriptionType"),
        ]
        stripe = item.get("stripe") if isinstance(item.get("stripe"), dict) else {}
        candidates.append(stripe.get("productId"))
        google = item.get("google") if isinstance(item.get("google"), dict) else {}
        candidates.append(google.get("productId"))
        product = item.get("product")
        if isinstance(product, dict):
            candidates.append(product.get("name"))
            candidates.append(product.get("id"))
        for c in candidates:
            p = normalize_plan(c)
            if rank.get(p, -1) > rank.get(best, -1):
                best = p
    return best


def check_cookies(
    cookies: dict[str, str],
    source_file: Optional[str] = None,
    *,
    jar=None,
    timeout: int = 20,
) -> CheckResult:
    offline = extract_offline(cookies)
    if not offline.get("has_sso"):
        return finalize(
            service="Grok",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="no_sso_cookie",
            user_id=offline.get("user_id"),
            stripe=bool(offline.get("stripe")),
            source_file=source_file,
        )

    session = build_session(cookies)
    headers = headers_for()

    try:
        r = session.get("https://grok.com/api/auth/session", headers=headers, timeout=timeout)
    except requests.Timeout:
        return finalize(
            service="Grok",
            valid=False,
            category="unknown",
            session_status="timeout",
            reason="connection_timeout",
            user_id=offline.get("user_id"),
            stripe=bool(offline.get("stripe")),
            source_file=source_file,
        )
    except requests.RequestException as e:
        return finalize(
            service="Grok",
            valid=False,
            category="unknown",
            session_status="network_error",
            reason=f"network_error:{type(e).__name__}",
            user_id=offline.get("user_id"),
            stripe=bool(offline.get("stripe")),
            source_file=source_file,
        )

    text = r.text or ""
    # Desafío de Cloudflare -> category="unknown" (nunca valid=True a ciegas)
    if r.status_code in (403, 503) and ("cloudflare" in text.lower() or "just a moment" in text.lower() or "challenge" in text.lower()):
        return finalize(
            service="Grok",
            valid=False,
            category="unknown",
            plan_live="Unknown",
            session_status="challenge",
            reason="cf_challenge",
            user_id=offline.get("user_id"),
            stripe=bool(offline.get("stripe")),
            source_file=source_file,
        )

    # Errores temporales de servidor o rate-limit
    if r.status_code == 429 or r.status_code >= 500:
        return finalize(
            service="Grok",
            valid=False,
            category="unknown",
            session_status=f"http_{r.status_code}",
            reason=f"server_{r.status_code}",
            user_id=offline.get("user_id"),
            stripe=bool(offline.get("stripe")),
            source_file=source_file,
        )

    # Sesión rechazada por el backend
    if r.status_code in (401, 403):
        return finalize(
            service="Grok",
            valid=False,
            category="invalid",
            session_status=f"http_{r.status_code}",
            reason=f"session_http_{r.status_code}",
            user_id=offline.get("user_id"),
            stripe=bool(offline.get("stripe")),
            source_file=source_file,
        )

    if r.status_code != 200:
        return finalize(
            service="Grok",
            valid=False,
            category="unknown",
            session_status=f"http_{r.status_code}",
            reason=f"unexpected_http_{r.status_code}",
            user_id=offline.get("user_id"),
            stripe=bool(offline.get("stripe")),
            source_file=source_file,
        )

    try:
        data = r.json()
    except Exception:
        return finalize(
            service="Grok",
            valid=False,
            category="unknown",
            session_status="error",
            reason="session_not_json",
            user_id=offline.get("user_id"),
            stripe=bool(offline.get("stripe")),
            source_file=source_file,
        )

    status = (data.get("status") or "").lower()
    sess = data.get("session") or {}
    if status != "authenticated" or not sess:
        return finalize(
            service="Grok",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="not_authenticated",
            user_id=offline.get("user_id"),
            stripe=bool(offline.get("stripe")),
            source_file=source_file,
        )

    email = sess.get("email") or sess.get("googleEmail")
    given = (sess.get("givenName") or "").strip()
    family = (sess.get("familyName") or "").strip()
    name = (given + " " + family).strip() or sess.get("name") or sess.get("username") or None
    user_id = offline.get("user_id") or sess.get("userId")

    plan_live = "Unknown"
    xsub = sess.get("xSubscriptionType") or ""
    if xsub:
        plan_live = normalize_plan(xsub)

    # Consultar detalle de suscripciones si está disponible
    try:
        r2 = session.get("https://grok.com/rest/subscriptions", headers=headers, timeout=timeout)
        if r2.status_code == 200:
            try:
                sub_data = r2.json()
                p = plan_from_subscriptions(sub_data)
                if p != "Unknown":
                    plan_live = p
                elif plan_live == "Unknown":
                    plan_live = "Free"
            except Exception:
                pass
    except requests.RequestException:
        pass

    if plan_live == "Unknown":
        plan_live = "Free"

    return finalize(
        service="Grok",
        valid=True,
        category="valid",
        plan_live=plan_live,
        email=email,
        name=name,
        user_id=user_id,
        session_status="ok",
        reason="grok session ok",
        stripe=bool(offline.get("stripe")),
        source_file=source_file,
    )


def check_file(path: Path) -> CheckResult:
    from ..load import load_file, requests_cookie_dict

    jar = load_file(path)
    return check_cookies(requests_cookie_dict(jar), source_file=path.name, jar=jar)