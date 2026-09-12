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


def _decode_escapes(raw: str) -> str:
    if not raw:
        return ""
    text = html.unescape(str(raw))
    text = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)
    text = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text)
    return text


def normalize_plan(raw: str) -> str:
    """Fallback por texto localizado si faltan las propiedades tecnicas."""
    if not raw:
        return "Unknown"

    decoded = _decode_escapes(raw)
    s = " ".join(decoded.strip().split()).lower()
    if not s:
        return "Unknown"

    # 1. Standard With Ads
    has_ads = (
        re.search(r"\b(ads?|anuncios?|pub|werbung|reklam\w*|iklan)\b", s)
        or any(kw in s for kw in (
            "with ads", "with ad", "con anuncios", "con anuncio",
            "com anúncios", "com anuncios", "avec pub", "avec publicité",
            "mit werbung", "con pubblicità", "con pubblicita",
            "z reklamami", "iklan", "reklam", "광고", "広告", "广告", "廣告",
            "إعلان", "اعلان", "quảng cáo", "quang cao"
        ))
    )
    if has_ads:
        return "Standard With Ads"

    # 2. Premium
    if any(kw in s for kw in (
        "premium", "ultra", "uhd", "4k", "premijum",
        "cao cấp", "cao cap",
        "المميزة", "المميزه", "مميزة", "مميزه",
        "프리미엄", "プレミアム", "高级", "高級"
    )):
        return "Premium"

    # 3. Mobile
    if any(kw in s for kw in (
        "mobile", "móvil", "movil", "celular", "ponsel", "cep",
        "điện thoại", "dien thoai",
        "모바일", "モバイル", "移动", "移動", "جوال", "محمول"
    )):
        return "Mobile"

    # 4. Standard
    if any(kw in s for kw in (
        "standard", "standar", "standart", "estándar", "estandar", "padrão", "padrao",
        "tiêu chuẩn", "tieu chuan",
        "القياسية", "القياسيه", "قياسية", "قياسيه",
        "스탠다드", "スタンダード", "标准", "標準"
    )):
        return "Standard"

    # 5. Basic
    if any(kw in s for kw in (
        "basic", "básico", "basico", "dasar", "minim", "podstawowy", "temel",
        "základní", "zakladni", "cơ bản", "co ban", "essentiel", "basis",
        "الأساسية", "الاساسية", "الأساسيه", "الاساسيه", "أساسية", "اساسية",
        "베이식", "기본", "ベーシック", "基础", "基礎"
    )):
        return "Basic"

    return "Unknown"


def _extract_plan_technicals(
    html_text: str,
) -> tuple[Optional[bool], Optional[int], Optional[str], Optional[int]]:
    """Extrae hasAds, maxStreams, videoQuality y planId del HTML/JSON."""
    block = ""
    m_cp = re.search(r'"currentPlan"\s*:\s*\{([^}]+)\}', html_text)
    if m_cp:
        block = m_cp.group(1)
    else:
        pos = html_text.find('"currentPlan"')
        if pos == -1:
            pos = html_text.find("localizedPlanName")
        if pos != -1:
            block = html_text[max(0, pos - 200):min(len(html_text), pos + 1200)]
        else:
            block = html_text

    has_ads = None
    m_ads = re.search(r'"(?:hasAds|isAdSupported)"\s*:\s*(true|false)', block, re.I)
    if not m_ads and block is not html_text:
        m_ads = re.search(r'"(?:hasAds|isAdSupported)"\s*:\s*(true|false)', html_text, re.I)
    if m_ads:
        has_ads = m_ads.group(1).lower() == "true"

    max_streams = None
    m_streams = re.search(r'"(?:maxStreams|screens)"\s*:\s*"?(\d+)"?', block, re.I)
    if not m_streams and block is not html_text:
        m_streams = re.search(r'"(?:maxStreams|screens)"\s*:\s*"?(\d+)"?', html_text, re.I)
    if m_streams:
        try:
            max_streams = int(m_streams.group(1))
        except ValueError:
            pass

    video_quality = None
    m_quality = re.search(r'"videoQuality"\s*:\s*"([^"]+)"', block, re.I)
    if not m_quality and block is not html_text:
        m_quality = re.search(r'"videoQuality"\s*:\s*"([^"]+)"', html_text, re.I)
    if m_quality:
        video_quality = m_quality.group(1).strip()

    plan_id = None
    m_pid = re.search(r'"planId"\s*:\s*"?(\d+)"?', block, re.I)
    if not m_pid and block is not html_text:
        m_pid = re.search(r'"planId"\s*:\s*"?(\d+)"?', html_text, re.I)
    if m_pid:
        try:
            plan_id = int(m_pid.group(1))
        except ValueError:
            pass

    return has_ads, max_streams, video_quality, plan_id


def _classify_from_technicals(
    has_ads: Optional[bool],
    max_streams: Optional[int],
    video_quality: Optional[str],
    plan_id: Optional[int],
) -> Optional[str]:
    """Clasifica el plan usando indicadores tecnicos numericos y booleanos."""
    # 1. Standard With Ads (hasAds=True o planId 5200)
    if has_ads is True or plan_id == 5200:
        return "Standard With Ads"

    # 2. Premium (4 streams, UHD/4K o planId 3108)
    if max_streams == 4 or plan_id == 3108:
        return "Premium"
    if video_quality and any(uhd in video_quality.upper() for uhd in ("UHD", "4K")):
        return "Premium"

    # 3. Standard (2 streams, HD o planId 3088)
    if max_streams == 2 or plan_id == 3088:
        return "Standard"

    # 4. 1 Pantalla: Discernir entre Basic y Mobile
    if max_streams == 1 or plan_id in (4001, 4120):
        if plan_id == 4120:
            return "Mobile"
        if plan_id == 4001:
            return "Basic"
        if video_quality:
            vq = video_quality.upper()
            if any(sd in vq for sd in ("SD", "480")):
                return "Mobile"
            if any(hd in vq for hd in ("HD", "720", "1080")):
                return "Basic"
        return "Basic"

    # 5. Apoyo general por planId
    PLAN_ID_MAP = {
        5200: "Standard With Ads",
        3108: "Premium",
        3088: "Standard",
        4001: "Basic",
        4120: "Mobile",
    }
    if plan_id in PLAN_ID_MAP:
        return PLAN_ID_MAP[plan_id]

    return None


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

    # Bloqueos de WAF, rate-limit o caidas de servidor
    if r.status_code in (403, 429) or r.status_code >= 500:
        return finalize(
            service="Netflix",
            valid=False,
            category="unknown",
            session_status=f"http_{r.status_code}",
            reason=f"blocked_or_server_{r.status_code}",
            source_file=source_file,
        )

    # Redireccion a login o signup = sesion expirada
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

    # Validar presencia de sesion activa
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

    # Estado de suscripcion (cuenta inactiva o cancelada)
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

    # Retencion / Pausa
    if re.search(r'"isOnHold"\s*:\s*true|"hasHold"\s*:\s*true', html_text, re.I):
        extras["on_hold"] = True

    # 1. Extraccion y clasificacion tecnica principal
    has_ads, max_streams, video_quality, plan_id = _extract_plan_technicals(html_text)

    if has_ads is not None:
        extras["has_ads"] = has_ads
    if max_streams is not None:
        extras["max_streams"] = max_streams
    if video_quality:
        extras["video_quality"] = video_quality
    if plan_id is not None:
        extras["plan_id"] = plan_id

    plan_live = _classify_from_technicals(has_ads, max_streams, video_quality, plan_id)

    # 2. Fallback por nombre localizado si faltan propiedades tecnicas
    if not plan_live or plan_live == "Unknown":
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
            else:
                plan_live = "Unknown"

    # Extraccion de email
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
