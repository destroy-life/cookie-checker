"""Roblox live session check (HTTP)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

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
AUTH_URL = "https://users.roblox.com/v1/users/authenticated"


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


def _security_cookie_name(name: Optional[str]) -> bool:
    if not name:
        return False
    return name.lstrip(".").casefold() == "roblosecurity"


def _find_security_token(cookies: dict[str, str], jar: Optional[Jar] = None) -> Optional[str]:
    for k, v in cookies.items():
        if _security_cookie_name(k) and v and str(v).strip():
            return str(v).strip()
    if jar and jar.cookies:
        for c in jar.cookies:
            if _security_cookie_name(c.name) and c.value and str(c.value).strip():
                return str(c.value).strip()
    return None


def check_cookies(
    cookies: dict[str, str],
    source_file: Optional[str] = None,
    *,
    jar: Optional[Jar] = None,
    timeout: int = 25,
) -> CheckResult:
    token = _find_security_token(cookies, jar)
    if not token:
        return finalize(
            service="Roblox",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="missing_.ROBLOSECURITY",
            source_file=source_file,
        )

    # Asegurar atributos nativos para importación limpia en Cookie-Editor
    if jar and jar.cookies:
        for c in jar.cookies:
            if _security_cookie_name(c.name):
                c.name = ".ROBLOSECURITY"
                c.domain = ".roblox.com"
                c.path = "/"
                c.http_only = True
                c.secure = True

    sess = _session()
    # Asignar a la sesión para evitar cabeceras duplicadas
    sess.cookies.set(".ROBLOSECURITY", token, domain=".roblox.com", path="/")
    for k, v in cookies.items():
        if not _security_cookie_name(k):
            sess.cookies.set(k, v, domain=".roblox.com", path="/")

    headers = {
        "User-Agent": UA,
        "Accept": "application/json",
        "Referer": "https://www.roblox.com/",
        "Origin": "https://www.roblox.com",
    }

    try:
        resp = sess.get(AUTH_URL, headers=headers, timeout=timeout)
    except requests.Timeout:
        return finalize(
            service="Roblox",
            valid=False,
            category="unknown",
            session_status="timeout",
            reason="roblox_timeout",
            source_file=source_file,
        )
    except requests.RequestException as exc:
        return finalize(
            service="Roblox",
            valid=False,
            category="unknown",
            session_status="network_error",
            reason=f"network_error:{type(exc).__name__}",
            source_file=source_file,
        )

    if resp.status_code == 401:
        msg = ""
        try:
            err = resp.json()
            errors = err.get("errors") if isinstance(err, dict) else None
            if isinstance(errors, list) and errors:
                msg = str(errors[0].get("message") or "")
        except Exception:
            pass
        return finalize(
            service="Roblox",
            valid=False,
            category="invalid",
            session_status="unauthorized_401",
            reason=f"auth_failed_401: {msg}" if msg else "auth_failed_401",
            source_file=source_file,
        )

    if resp.status_code == 403:
        return finalize(
            service="Roblox",
            valid=False,
            category="unknown",
            session_status="challenge",
            reason="waf_or_forbidden_403",
            source_file=source_file,
        )

    if resp.status_code == 429 or resp.status_code >= 500:
        return finalize(
            service="Roblox",
            valid=False,
            category="unknown",
            session_status=f"http_{resp.status_code}",
            reason=f"server_{resp.status_code}",
            source_file=source_file,
        )

    if not (200 <= resp.status_code < 300):
        return finalize(
            service="Roblox",
            valid=False,
            category="invalid",
            session_status=f"http_{resp.status_code}",
            reason=f"http_{resp.status_code}",
            source_file=source_file,
        )

    try:
        data = resp.json()
    except Exception:
        return finalize(
            service="Roblox",
            valid=False,
            category="unknown",
            session_status="error",
            reason="auth_200_non_json",
            source_file=source_file,
        )

    if not isinstance(data, dict):
        return finalize(
            service="Roblox",
            valid=False,
            category="invalid",
            session_status="error",
            reason="invalid_payload_format",
            source_file=source_file,
        )

    uid = data.get("id")
    name = data.get("name")
    display_name = data.get("displayName")

    if uid is None or not name:
        return finalize(
            service="Roblox",
            valid=False,
            category="invalid",
            session_status="invalid",
            reason="auth_missing_id_or_name",
            source_file=source_file,
        )

    extras: dict[str, Any] = {
        "id": uid,
        "name": name,
        "displayName": display_name,
        "handle": str(name),
        "username": str(name),
    }

    return finalize(
        service="Roblox",
        valid=True,
        category="valid",
        plan_live="Unknown",
        name=str(name),
        user_id=str(uid),
        session_status="ok",
        reason="roblox session ok",
        source_file=source_file,
        extras=extras,
    )


def check_file(path: Path) -> CheckResult:
    from ..load import load_file

    jar = load_file(path)
    return check_cookies(requests_cookie_dict(jar), source_file=path.name, jar=jar)