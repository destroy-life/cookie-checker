"""Twitter / X live session check (HTTP)."""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any, Optional
from urllib.parse import unquote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..load import Cookie, Jar, requests_cookie_dict
from ..models import CheckResult, finalize

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
VERIFY_URL = "https://api.x.com/1.1/account/verify_credentials.json"
VERIFY_URL_TW = "https://api.twitter.com/1.1/account/verify_credentials.json"
HOME_URL = "https://x.com/home"
BEARER = (
    "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs"
    "%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
)

# Palabras reservadas del sistema que no son nombres de usuario
_BAD_HANDLES = {
    "home", "i", "explore", "search", "settings",
    "login", "logout", "intent", "notifications", "messages",
}


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


def _waf(text: str) -> bool:
    low = (text or "").lower()
    return any(
        m in low
        for m in (
            "cf-chl-",
            "just a moment",
            "attention required",
            "verify you are human",
            "checking your browser",
        )
    )


def _usable_handle(name: Optional[str]) -> Optional[str]:
    if not name or not isinstance(name, str):
        return None
    h = name.strip().lstrip("@")
    if not h or h.lower() in _BAD_HANDLES:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_]{1,30}", h):
        return None
    return h


def _map_plan(user: dict) -> tuple[str, Optional[str]]:
    for key in ("subscription_type", "premium_type", "account_type"):
        v = user.get(key)
        if isinstance(v, str) and v.strip():
            low = v.lower()
            if any(p in low for p in ("premium", "blue", "gold")):
                return "Premium", v
            if "basic" in low:
                return "Basic", v
            clean = re.sub(r"[^A-Za-z0-9]+", "-", v).strip("-")[:40]
            return clean or "Unknown", v

    is_blue = bool(
        user.get("is_blue_verified")
        or user.get("has_gold_checkmark")
        or (user.get("verified") and user.get("verified_type"))
    )
    if is_blue:
        return "Premium", "is_blue_verified"
    return "Free", None


def _parse_home(html: str) -> tuple[Optional[bool], Optional[str], Optional[bool]]:
    """Extrae (is_logged_in, screen_name, is_blue_verified) del HTML de /home."""
    if not html:
        return None, None, None

    m_login = re.search(r'"isLoggedIn"\s*:\s*(true|false)', html)
    logged = (m_login.group(1) == "true") if m_login else None

    handles = re.findall(r'"screen_name"\s*:\s*"([^"]+)"', html)
    handle = None
    for h in handles:
        u = _usable_handle(h)
        if u:
            handle = u
            break

    m_blue = re.search(r'"is_blue_verified"\s*:\s*(true|false)', html)
    is_blue = (m_blue.group(1) == "true") if m_blue else None

    return logged, handle, is_blue


def check_cookies(
    cookies: dict[str, str],
    source_file: Optional[str] = None,
    *,
    jar: Optional[Jar] = None,
    timeout: int = 25,
) -> CheckResult:
    c_lower = {k.lower(): v for k, v in cookies.items()}
    auth_token = c_lower.get("auth_token") or cookies.get("auth_token")

    if not auth_token:
        return finalize(
            service="Twitter",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="missing_auth_token",
            source_file=source_file,
        )

    # Si falta ct0 (token CSRF), generamos uno válido para no descartar la sesión
    ct0 = c_lower.get("ct0") or cookies.get("ct0")
    if not ct0:
        ct0 = uuid.uuid4().hex + uuid.uuid4().hex
        cookies["ct0"] = ct0
        if jar and jar.cookies:
            jar.cookies.append(
                Cookie(name="ct0", value=ct0, domain=".x.com", path="/", secure=True)
            )

    sess = _session()
    # Un solo dominio raíz sin duplicar cabeceras
    for n, v in cookies.items():
        sess.cookies.set(n, v, domain=".x.com", path="/")
        sess.cookies.set(n, v, domain=".twitter.com", path="/")

    headers = {
        "User-Agent": UA,
        "Accept": "application/json",
        "Authorization": f"Bearer {BEARER}",
        "x-csrf-token": ct0,
        "x-twitter-auth-type": "OAuth2Session",
        "x-twitter-active-user": "yes",
        "Referer": "https://x.com/",
        "Origin": "https://x.com",
    }

    saw_404 = False
    last_status = 0
    last_reason = ""

    # 1. Intentar validar por API (verify_credentials)
    for url in (VERIFY_URL, VERIFY_URL_TW):
        try:
            resp = sess.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
                params={"include_email": "true", "skip_status": "true"},
            )
        except requests.Timeout:
            return finalize(
                service="Twitter",
                valid=False,
                category="unknown",
                session_status="timeout",
                reason="twitter_timeout",
                source_file=source_file,
            )
        except requests.RequestException as exc:
            last_reason = f"network:{type(exc).__name__}"
            continue

        last_status = resp.status_code
        text = (resp.text or "")[:65536]
        err_code = None

        try:
            ej = json.loads(text) if text.lstrip().startswith("{") else None
            if isinstance(ej, dict) and isinstance(ej.get("errors"), list) and ej["errors"]:
                e0 = ej["errors"][0]
                if isinstance(e0, dict):
                    err_code = e0.get("code")
        except Exception:
            err_code = None

        if resp.status_code == 401:
            return finalize(
                service="Twitter",
                valid=False,
                category="invalid",
                session_status="unauthorized_401",
                reason=f"auth_failed_401 (code={err_code})",
                source_file=source_file,
            )

        if resp.status_code == 404:
            # En cuentas modernas suele responder 404/code 34 -> Pasamos al fallback de /home
            saw_404 = True
            last_reason = f"verify_404 (code={err_code})"
            continue

        if resp.status_code == 403:
            if _waf(text):
                return finalize(
                    service="Twitter",
                    valid=False,
                    category="unknown",
                    session_status="challenge",
                    reason="waf_blocked",
                    source_file=source_file,
                )
            low = text.lower()
            if err_code == 32 or "could not authenticate" in low or "denied" in low:
                return finalize(
                    service="Twitter",
                    valid=False,
                    category="invalid",
                    session_status="forbidden_403",
                    reason="auth_denied_403",
                    source_file=source_file,
                )
            saw_404 = True
            last_reason = "verify_403"
            continue

        if resp.status_code == 429 or resp.status_code >= 500:
            return finalize(
                service="Twitter",
                valid=False,
                category="unknown",
                session_status=f"http_{resp.status_code}",
                reason=f"server_{resp.status_code}",
                source_file=source_file,
            )

        if not (200 <= resp.status_code < 300):
            last_reason = f"verify_{resp.status_code}"
            continue

        try:
            payload = json.loads(text) if text.lstrip().startswith("{") else None
        except Exception:
            payload = None

        if not isinstance(payload, dict) or payload.get("errors"):
            continue

        screen = payload.get("screen_name") or payload.get("name")
        handle = _usable_handle(screen if isinstance(screen, str) else None)
        uid = payload.get("id_str") or payload.get("id")

        if not handle and not uid:
            continue

        plan_live, _ = _map_plan(payload)
        email = payload.get("email")
        extras: dict[str, Any] = {
            "backend": "verify_credentials",
            "handle": handle,
            "screen_name": handle,
        }

        return finalize(
            service="Twitter",
            valid=True,
            category="valid",
            plan_live=plan_live,
            email=email if isinstance(email, str) else None,
            name=f"@{handle}" if handle else screen,
            user_id=str(uid) if uid else None,
            session_status="ok",
            reason="twitter session ok (api)",
            source_file=source_file,
            extras=extras,
        )

    # 2. Fallback: Verificación en /home (HTML)
    home_headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://x.com/",
    }

    try:
        h_resp = sess.get(HOME_URL, headers=home_headers, timeout=timeout, allow_redirects=True)
    except requests.Timeout:
        return finalize(
            service="Twitter",
            valid=False,
            category="unknown",
            session_status="timeout",
            reason="home_timeout",
            source_file=source_file,
        )
    except requests.RequestException as exc:
        return finalize(
            service="Twitter",
            valid=False,
            category="unknown",
            session_status="network_error",
            reason=f"home_network:{type(exc).__name__}",
            source_file=source_file,
        )

    h_text = h_resp.text or ""
    h_url = (h_resp.url or "").lower()

    if "/login" in h_url or "/i/flow/login" in h_url:
        return finalize(
            service="Twitter",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="redirected_to_login",
            source_file=source_file,
        )

    logged, handle, is_blue = _parse_home(h_text)

    if logged is False:
        return finalize(
            service="Twitter",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="home_logged_out",
            source_file=source_file,
        )

    if logged is True and handle:
        plan_live = "Premium" if is_blue else "Free"
        extras = {
            "backend": "home_html",
            "handle": handle,
            "screen_name": handle,
            "is_blue_verified": bool(is_blue),
        }
        return finalize(
            service="Twitter",
            valid=True,
            category="valid",
            plan_live=plan_live,
            name=f"@{handle}",
            session_status="ok",
            reason="twitter session ok (home)",
            source_file=source_file,
            extras=extras,
        )

    if _waf(h_text) or h_resp.status_code in (403, 429) or h_resp.status_code >= 500:
        return finalize(
            service="Twitter",
            valid=False,
            category="unknown",
            session_status="challenge",
            reason="waf_or_server_blocked",
            source_file=source_file,
        )

    return finalize(
        service="Twitter",
        valid=False,
        category="invalid",
        session_status=f"http_{last_status or h_resp.status_code}",
        reason=last_reason or "session_unusable",
        source_file=source_file,
    )


def check_file(path: Path) -> CheckResult:
    from ..load import load_file

    jar = load_file(path)
    return check_cookies(requests_cookie_dict(jar), source_file=path.name, jar=jar)