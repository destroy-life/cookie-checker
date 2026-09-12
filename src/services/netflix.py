"""Netflix cookie checker — plan and membership from /account HTML."""
from __future__ import annotations

import html
import re
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

    # Decodificar entidades HTML y escapes unicode
    s = html.unescape(s)
    s = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda m: chr(int(m.group(1), 16)),
        s,
    )

    low = s.lower()
    # Eliminar acentos para comparaciones uniformes
    for a, b in (("á", "a"), ("é", "e"), ("í", "i"), ("ó", "o"), ("ú", "u"), ("ã", "a")):
        low = low.replace(a, b)

    # Con anuncios / Ads (varios idiomas: español, portugués, francés, alemán)
    if any(k in low for k in ("ad", "anuncio", "pub", "werbung")):
        return "Standard With Ads"
    if "premium" in low or "ultra" in low or "4k" in low:
        return "Premium"
    if "standard" in low or "estandar" in low or "padrao" in low:
        return "Standard"
    if "basic" in low or "basico" in low or "essentiel" in low or "basis" in low:
        return "Basic"
    if "mobile" in low or "movil" in low:
        return "Mobile"

    return s.strip()


def _has_netflix_id(cookies: dict) -> bool:
    for k, v in cookies.items():
        if k.lower() in ("netflixid", "securenetflixid") and v and str(v).strip():
            return True
    return False


def check_cookies(
    cookies: dict,
    source_file: Optional[str] = None,
    *,
    jar=None,
    timeout: int = 25,
) -> CheckResult:
    if not _has_netflix_id(cookies):
        return finalize(
            service="Netflix",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="no_netflix_id",
            source_file=source_file,
        )

    s = requests.Session()
    # Un solo dominio raíz para evitar duplicar cookies y saturar el tamaño de cabecera
    for n, v in cookies.items():
        s.cookies.set(n, v, domain=".netflix.com", path="/")

    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
        "Referer": "https://www.netflix.com/",
    }

    try:
        r = s.get(
            "https://www.netflix.com/account",
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
        )
    except requests.Timeout:
        return finalize(
            service="Netflix",
            valid=False,
            category="unknown",
            session_status="timeout",
            reason="connection_timeout",
            source_file=source_file,
        )
    except requests.RequestException as e:
        return finalize(
            service="Netflix",
            valid=False,
            category="unknown",
            session_status="network_error",
            reason=f"network_error:{type(e).__name__}",
            source_file=source_file,
        )

    # Detección de bloqueos de WAF, rate-limit o caídas de servidor
    if r.status_code in (403, 429) or r.status_code >= 500:
        return finalize(
            service="Netflix",
            valid=False,
            category="unknown",
            session_status=f"http_{r.status_code}",
            reason=f"blocked_or_server_{r.status_code}",
            source_file=source_file,
        )

    # Redirección a login o signup = sesión muerta
    curr_url = r.url.lower()
    if "/login" in curr_url or "/signup" in curr_url:
        return finalize(
            service="Netflix",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="login_redirect",
            source_file=source_file,
        )

    html_text = r.text

    # Si no hay indicios de cuenta y el HTML muestra inicio de sesión
    logged_in_markers = (
        "localizedPlanName",
        "currentPlan",
        "YourAccount",
        "memberSince",
        "membershipStatus",
        "account_section",
        "membership-content",
    )
    if not any(marker in html_text for marker in logged_in_markers):
        if "login" in html_text.lower()[:3000]:
            return finalize(
                service="Netflix",
                valid=False,
                category="invalid",
                session_status="expired",
                reason="not_logged_in",
                source_file=source_file,
            )

    extras: dict = {}

    # Detección de estado de suscripción (cuenta cancelada / inactiva)
    m_status = re.search(r'"membershipStatus"\s*:\s*"([^"]+)"', html_text)
    status_str = m_status.group(1).upper() if m_status else ""
    if status_str:
        extras["membership_status"] = status_str

    if status_str in ("FORMER_MEMBER", "NEVER_MEMBER", "ANONYMOUS"):
        return finalize(
            service="Netflix",
            valid=False,
            category="invalid",
            session_status="canceled",
            reason=f"membership_{status_str.lower()}",
            plan_live="Canceled",
            source_file=source_file,
            extras=extras,
        )

    # Retención / Cuenta en pausa
    if re.search(r'"isOnHold"\s*:\s*true|"hasHold"\s*:\s*true', html_text, re.I):
        extras["on_hold"] = True

    # Extracción del plan
    plan_live = "Unknown"
    m_plan = re.search(r'"localizedPlanName"\s*:\s*\{[^}]*"value"\s*:\s*"([^"]+)"', html_text)
    if not m_plan:
        m_plan = re.search(r'"(?:planName|currentPlan|tier)"\s*:\s*"([^"]+)"', html_text)
    if m_plan:
        plan_live = normalize_plan(m_plan.group(1))
    else:
        m_fallback = re.search(
            r'Plan\s+(Premium|Standard|Basic|Mobile|B[aá]sico|Est[aá]ndar)',
            html_text,
            re.I,
        )
        if m_fallback:
            plan_live = normalize_plan(m_fallback.group(1))

    # Extracción de email
    email = None
    m_email = re.search(r'"userEmail"\s*:\s*"([^"]+@[^"]+)"', html_text)
    if not m_email:
        m_email = re.search(r'"email"\s*:\s*\{[^}]*"value"\s*:\s*"([^"]+@[^"]+)"', html_text)
    if not m_email:
        m_email = re.search(r'"email"\s*:\s*"([^"]+@[^"]+)"', html_text)
    if m_email:
        email = m_email.group(1)

    return finalize(
        service="Netflix",
        valid=True,
        category="valid",
        plan_live=plan_live,
        email=email,
        session_status="ok",
        reason="netflix session ok",
        source_file=source_file,
        extras=extras,
    )


def check_file(path: Path) -> CheckResult:
    from ..load import load_file, requests_cookie_dict

    jar = load_file(path)
    return check_cookies(requests_cookie_dict(jar), source_file=path.name, jar=jar)