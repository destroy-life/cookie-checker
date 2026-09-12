"""Claude.ai live session check (HTTP)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..load import Cookie, Jar, names_present, requests_cookie_dict
from ..models import CheckResult, finalize

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
ORGS_URL = "https://claude.ai/api/organizations"
ACCOUNT_URL = "https://claude.ai/api/account"


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
            "cloudflare",
            "just a moment",
            "cf-chl-",
            "attention required",
            "verify you are human",
            "checking your browser",
        )
    )


def _map_plan(capabilities: list | None, org: dict | None = None) -> tuple[str, Optional[str]]:
    caps = [str(c).lower() for c in (capabilities or [])]
    blob = " ".join(caps)
    raw = ",".join(caps)[:120] if caps else None

    if any("max" in c for c in caps) or "claude_max" in blob:
        return "Max", raw
    if any("pro" in c for c in caps) or "claude_pro" in blob:
        return "Pro", raw
    if any("team" in c for c in caps) or "enterprise" in blob:
        return "Team", raw

    if org and isinstance(org, dict):
        for key in ("name", "display_name", "plan", "plan_type"):
            v = org.get(key)
            if isinstance(v, str) and v.strip():
                low = v.lower()
                if "max" in low:
                    return "Max", v
                if "pro" in low:
                    return "Pro", v
                if "team" in low or "enterprise" in low:
                    return "Team", v

    return "Free", raw


def _find_session_cookie(cookies: dict[str, str]) -> tuple[Optional[str], Optional[str]]:
    """Devuelve (nombre_cookie, valor) buscando sessionKey o sessionKeyV3."""
    for k, v in cookies.items():
        low = k.lower()
        if low in ("sessionkey", "sessionkeyv3") and v and str(v).strip():
            return k, str(v).strip()
    return None, None


def check_cookies(
    cookies: dict[str, str],
    source_file: Optional[str] = None,
    *,
    jar: Optional[Jar] = None,
    timeout: int = 25,
) -> CheckResult:
    c_name, c_val = _find_session_cookie(cookies)
    if not c_name or not c_val:
        return finalize(
            service="Claude",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="missing_sessionKey",
            source_file=source_file,
        )

    # Asegurar que el token tenga atributos compatibles con Cookie-Editor
    if jar and jar.cookies:
        for c in jar.cookies:
            if (c.name or "").lower() in ("sessionkey", "sessionkeyv3"):
                c.http_only = True
                c.secure = True
                if not c.domain:
                    c.domain = ".claude.ai"

    sess = _session()
    # Un solo dominio raíz para no duplicar cabeceras
    for n, v in cookies.items():
        sess.cookies.set(n, v, domain=".claude.ai", path="/")

    headers = {
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://claude.ai/",
        "Origin": "https://claude.ai",
        "anthropic-client-platform": "web_claude_ai",
    }

    # 1. Verificar identidad directa en /api/account
    email: Optional[str] = None
    display_name: Optional[str] = None
    account_id: Optional[str] = None

    try:
        ar = sess.get(ACCOUNT_URL, headers=headers, timeout=timeout, allow_redirects=True)
    except requests.Timeout:
        return finalize(
            service="Claude",
            valid=False,
            category="unknown",
            session_status="timeout",
            reason="account_timeout",
            source_file=source_file,
        )
    except requests.RequestException as e:
        return finalize(
            service="Claude",
            valid=False,
            category="unknown",
            session_status="network_error",
            reason=f"network_error:{type(e).__name__}",
            source_file=source_file,
        )

    ar_text = ar.text or ""
    ar_url = (ar.url or "").lower()

    if "login" in ar_url or "/auth" in ar_url:
        return finalize(
            service="Claude",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="redirected_to_login",
            source_file=source_file,
        )

    if ar.status_code == 401:
        return finalize(
            service="Claude",
            valid=False,
            category="invalid",
            session_status="unauthorized_401",
            reason="auth_failed_401",
            source_file=source_file,
        )

    if ar.status_code == 403:
        if _waf(ar_text):
            return finalize(
                service="Claude",
                valid=False,
                category="unknown",
                session_status="challenge",
                reason="waf_blocked",
                source_file=source_file,
            )
        return finalize(
            service="Claude",
            valid=False,
            category="invalid",
            session_status="forbidden_403",
            reason="session_forbidden_403",
            source_file=source_file,
        )

    if ar.status_code == 429 or ar.status_code >= 500:
        return finalize(
            service="Claude",
            valid=False,
            category="unknown",
            session_status=f"http_{ar.status_code}",
            reason=f"blocked_or_server_{ar.status_code}",
            source_file=source_file,
        )

    if 200 <= ar.status_code < 300:
        try:
            acc_data = ar.json()
            if isinstance(acc_data, dict):
                em = acc_data.get("email_address") or acc_data.get("email")
                if isinstance(em, str) and "@" in em:
                    email = em.strip()
                display_name = (
                    acc_data.get("display_name")
                    or acc_data.get("full_name")
                    or acc_data.get("name")
                )
                account_id = acc_data.get("id") or acc_data.get("uuid")
        except Exception:
            pass

    # 2. Consultar organizaciones y plan
    try:
        resp = sess.get(ORGS_URL, headers=headers, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        resp = None

    plan_live = "Free"
    extras: dict[str, Any] = {"token_cookie": c_name}
    if account_id:
        extras["account_id"] = account_id

    if resp is not None and 200 <= resp.status_code < 300:
        try:
            org_payload = resp.json()
            orgs = (
                org_payload
                if isinstance(org_payload, list)
                else (org_payload.get("organizations") if isinstance(org_payload, dict) else None)
            )
            if isinstance(orgs, list) and orgs:
                org0 = orgs[0] if isinstance(orgs[0], dict) else {}
                caps = org0.get("capabilities") if isinstance(org0.get("capabilities"), list) else []
                plan_live, plan_raw = _map_plan(caps, org0)
                if plan_raw:
                    extras["plan_raw"] = plan_raw
                extras["org_count"] = len(orgs)
                if not email:
                    em0 = org0.get("email_address") or org0.get("email")
                    if isinstance(em0, str) and "@" in em0:
                        email = em0.strip()
        except Exception:
            pass

    # Si ar.status_code fue 200 o se extrajeron organizaciones de forma válida
    if (200 <= ar.status_code < 300) or (resp is not None and 200 <= resp.status_code < 300 and email):
        return finalize(
            service="Claude",
            valid=True,
            category="valid",
            plan_live=plan_live,
            email=email,
            name=display_name,
            user_id=account_id,
            session_status="ok",
            reason="claude session ok",
            source_file=source_file,
            extras=extras,
        )

    return finalize(
        service="Claude",
        valid=False,
        category="invalid",
        session_status=f"http_{ar.status_code}",
        reason=f"session_invalid_http_{ar.status_code}",
        source_file=source_file,
        extras=extras,
    )


def check_file(path: Path) -> CheckResult:
    from ..load import load_file

    jar = load_file(path)
    return check_cookies(requests_cookie_dict(jar), source_file=path.name, jar=jar)