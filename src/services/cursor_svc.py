"""Cursor.com live session check (HTTP).

Module name cursor_svc to avoid clashing with stdlib.
"""
from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import unquote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..load import Jar, requests_cookie_dict
from ..models import CheckResult, finalize

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
ME_URL = "https://cursor.com/api/auth/me"
USAGE_SUMMARY = "https://cursor.com/api/usage-summary"


def _session() -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=2,
        backoff_factor=0.3,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))
    return s


def _waf_challenge(text: str) -> bool:
    low = (text or "").lower()
    return any(
        m in low
        for m in (
            "cf-chl-",
            "just a moment",
            "attention required",
            "verify you are human",
            "checking your browser",
            "cf-challenge",
            "challenge-platform",
        )
    )


def _login_html(text: str) -> bool:
    low = (text or "").lower()
    if not low.strip():
        return False
    return any(
        m in low
        for m in (
            "sign in",
            "sign-in",
            "log in",
            "log-in",
            "/login",
            "authenticator.cursor.sh",
            "workos",
        )
    ) and ("password" in low or "oauth" in low or "sign" in low or "log in" in low)


def _find_session_token(cookies: dict[str, str], jar: Optional[Jar] = None) -> Optional[str]:
    # 1. Buscar en diccionario de cookies
    for k, v in cookies.items():
        if k.lower() == "workoscursorsessiontoken" and v and str(v).strip():
            return unquote(str(v).strip())

    # 2. Buscar en jar si está disponible
    if jar and jar.cookies:
        for c in jar.cookies:
            if (c.name or "").lower() == "workoscursorsessiontoken" and c.value:
                return unquote(str(c.value).strip())
    return None


def _jwt_expired(token: str) -> Optional[bool]:
    """Retorna True si el JWT expiró según su timestamp."""
    try:
        parts = token.split("::", 1)[1].split(".") if "::" in token else token.split(".")
        if len(parts) < 2:
            return None
        segment = parts[1]
        pad = "=" * (-len(segment) % 4)
        raw = base64.urlsafe_b64decode(segment + pad)
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict) or "exp" not in payload:
            return None
        exp = datetime.fromtimestamp(int(payload["exp"]), tz=timezone.utc)
        return exp < datetime.now(timezone.utc)
    except Exception:
        return None


def _map_plan(raw: Any) -> tuple[str, Optional[str]]:
    if raw is None:
        return "Unknown", None
    s = str(raw).strip()
    if not s:
        return "Unknown", None
    low = re.sub(r"[^a-z0-9]+", "", s.lower())

    if "business" in low or "team" in low or "enterprise" in low:
        return "Business", s
    if "pro" in low or "plus" in low:
        return "Pro", s
    if "free" in low or "hobby" in low or low in {"", "none", "null"}:
        return "Free", s
    return "Unknown", s


def check_cookies(
    cookies: dict[str, str],
    source_file: Optional[str] = None,
    *,
    jar: Optional[Jar] = None,
    timeout: int = 25,
) -> CheckResult:
    token = _find_session_token(cookies, jar)
    if not token:
        return finalize(
            service="Cursor",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="missing_WorkosCursorSessionToken",
            source_file=source_file,
        )

    expired = _jwt_expired(token)
    if expired is True:
        return finalize(
            service="Cursor",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="jwt_token_expired",
            source_file=source_file,
            extras={"jwt_expired": True},
        )

    sess = _session()
    # Un solo dominio raíz sin duplicar en la cabecera
    for n, v in cookies.items():
        sess.cookies.set(n, v, domain=".cursor.com", path="/")
    sess.cookies.set("WorkosCursorSessionToken", token, domain=".cursor.com", path="/")

    headers = {
        "User-Agent": UA,
        "Accept": "application/json",
        "Referer": "https://cursor.com/dashboard",
        "Origin": "https://cursor.com",
    }

    try:
        resp = sess.get(ME_URL, headers=headers, timeout=timeout, allow_redirects=True)
    except requests.Timeout:
        return finalize(
            service="Cursor",
            valid=False,
            category="unknown",
            session_status="timeout",
            reason="cursor_timeout",
            source_file=source_file,
        )
    except requests.RequestException as exc:
        return finalize(
            service="Cursor",
            valid=False,
            category="unknown",
            session_status="network_error",
            reason=f"network_error:{type(exc).__name__}",
            source_file=source_file,
        )

    text = (resp.text or "")[:65536]
    low = text.lower()
    final = (resp.url or "").lower()

    if "authenticator.cursor.sh" in final or "/login" in final or _login_html(text):
        return finalize(
            service="Cursor",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="redirected_to_login",
            source_file=source_file,
        )

    if resp.status_code == 401 or "not_authenticated" in low:
        return finalize(
            service="Cursor",
            valid=False,
            category="invalid",
            session_status="unauthorized_401",
            reason="auth_failed_401",
            source_file=source_file,
        )

    if resp.status_code == 403:
        if _waf_challenge(text):
            return finalize(
                service="Cursor",
                valid=False,
                category="unknown",
                session_status="challenge",
                reason="waf_blocked",
                source_file=source_file,
            )
        return finalize(
            service="Cursor",
            valid=False,
            category="invalid",
            session_status="forbidden_403",
            reason="edge_forbidden_403",
            source_file=source_file,
        )

    if resp.status_code == 429 or resp.status_code >= 500:
        return finalize(
            service="Cursor",
            valid=False,
            category="unknown",
            session_status=f"http_{resp.status_code}",
            reason=f"blocked_or_server_{resp.status_code}",
            source_file=source_file,
        )

    if not (200 <= resp.status_code < 300) or not text.strip().startswith("{"):
        return finalize(
            service="Cursor",
            valid=False,
            category="invalid",
            session_status=f"http_{resp.status_code}",
            reason="auth_me_not_json",
            source_file=source_file,
        )

    try:
        payload = resp.json()
    except Exception:
        return finalize(
            service="Cursor",
            valid=False,
            category="unknown",
            session_status="error",
            reason="json_decode_error",
            source_file=source_file,
        )

    if not isinstance(payload, dict):
        return finalize(
            service="Cursor",
            valid=False,
            category="invalid",
            session_status="error",
            reason="invalid_payload_format",
            source_file=source_file,
        )

    email = payload.get("email")
    user_id = payload.get("id") or payload.get("sub")
    name = payload.get("name") or payload.get("given_name")

    if not email and not user_id:
        return finalize(
            service="Cursor",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="no_identity_in_auth_me",
            source_file=source_file,
        )

    # Detección del plan mediante usage-summary
    plan_live = "Free"
    extras: dict[str, Any] = {"backend": "auth/me"}

    try:
        ur = sess.get(USAGE_SUMMARY, headers=headers, timeout=timeout)
        if 200 <= ur.status_code < 300 and (ur.text or "").lstrip().startswith("{"):
            ud = ur.json()
            if isinstance(ud, dict):
                for key in ("membershipType", "membership_type", "plan", "planName", "subscriptionStatus"):
                    if ud.get(key):
                        p, raw = _map_plan(ud.get(key))
                        if p != "Unknown":
                            plan_live = p
                            if raw:
                                extras["plan_raw"] = raw
                            break
                for nest in ("individualMembership", "teamMembership", "subscription"):
                    sub = ud.get(nest)
                    if isinstance(sub, dict):
                        for key in ("membershipType", "type", "plan", "name"):
                            if sub.get(key):
                                p, raw = _map_plan(sub.get(key))
                                if p != "Unknown":
                                    plan_live = p
                                    if raw:
                                        extras["plan_raw"] = raw
                                    break
    except Exception:
        pass

    return finalize(
        service="Cursor",
        valid=True,
        category="valid",
        plan_live=plan_live,
        email=email if isinstance(email, str) else None,
        name=name if isinstance(name, str) else None,
        user_id=str(user_id) if user_id is not None else None,
        session_status="ok",
        reason="cursor session ok",
        source_file=source_file,
        extras=extras,
    )


def check_file(path: Path) -> CheckResult:
    from ..load import load_file

    jar = load_file(path)
    return check_cookies(requests_cookie_dict(jar), source_file=path.name, jar=jar)