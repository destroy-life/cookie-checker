"""Crunchyroll live session check (etp_rt token flow)."""
from __future__ import annotations

import base64
import json
import uuid
from pathlib import Path
from typing import Optional

import requests

from ..models import CheckResult, finalize

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
TOKEN_URL = "https://www.crunchyroll.com/auth/v1/token"
ME_URL = "https://www.crunchyroll.com/accounts/v1/me"
# Public web accountAuthClientId from crunchyroll HTML __APP_CONFIG__
CLIENT_ID = "noaihdevm_6iyg0a8l0q"
BASIC_AUTH = "Basic " + base64.b64encode(f"{CLIENT_ID}:".encode()).decode()


def normalize_plan(raw: str) -> str:
    s = (raw or "").strip().lower()
    if not s:
        return "Unknown"
    if "ultimate" in s:
        return "Ultimate Fan"
    if "mega" in s or "fan_pack" in s or "fan pack" in s:
        return "Mega Fan"
    if "fan" in s:
        return "Fan"
    if "free" in s or "none" in s:
        return "Free"
    if "premium" in s:
        return "Fan"
    return raw.strip()


def _jwt_payload(access_token: str) -> dict:
    try:
        parts = access_token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode()))
    except Exception:
        return {}


def _plan_from_benefits(benefits) -> tuple[str, Optional[str]]:
    """Clasifica Free, Fan, Mega Fan y Ultimate Fan según concurrent_streams."""
    if benefits is None:
        return "Unknown", None
    if not isinstance(benefits, list):
        return "Unknown", str(benefits)

    raw = json.dumps(benefits, separators=(",", ":"))
    if not benefits:
        return "Free", raw

    ben_strs = [str(b).lower() for b in benefits]
    has_premium = any("premium" in b or b == "cr_premium" for b in ben_strs)

    if not has_premium:
        return "Free", raw

    # 1. Ultimate Fan (6 pantallas / catálogo completo)
    if any("concurrent_streams.6" in b or "stream_6" in b or "ultimate" in b for b in ben_strs):
        return "Ultimate Fan", raw

    # 2. Mega Fan (4 pantallas o paquete fan pack)
    if any("concurrent_streams.4" in b or "cr_fan_pack" in b or "mega" in b for b in ben_strs):
        return "Mega Fan", raw

    # 3. Fan (1 pantalla o premium base sin concurrencia extendida)
    return "Fan", raw


def check_cookies(
    cookies: dict,
    source_file: Optional[str] = None,
    *,
    jar=None,
    timeout: int = 25,
) -> CheckResult:
    c_lower = {k.lower(): v for k, v in cookies.items()}
    etp = c_lower.get("etp_rt") or cookies.get("etp_rt")
    device_id = c_lower.get("device_id") or cookies.get("device_id") or c_lower.get("ajs_anonymous_id")
    uid = c_lower.get("ajs_user_id") or cookies.get("ajs_user_id")

    if not etp:
        return finalize(
            service="Crunchyroll",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="no_etp_rt",
            source_file=source_file,
        )

    if not device_id:
        device_id = str(uuid.uuid4())

    sess = requests.Session()
    for n, v in cookies.items():
        sess.cookies.set(n, v, domain=".crunchyroll.com", path="/")

    headers = {
        "User-Agent": UA,
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": BASIC_AUTH,
        "Origin": "https://www.crunchyroll.com",
        "Referer": "https://www.crunchyroll.com/",
    }
    body = {
        "grant_type": "etp_rt_cookie",
        "device_type": "Browser",
        "device_id": device_id,
    }

    try:
        resp = sess.post(
            TOKEN_URL,
            data=body,
            headers=headers,
            timeout=timeout,
        )
    except requests.Timeout:
        return finalize(
            service="Crunchyroll",
            valid=False,
            category="unknown",
            plan_live="Unknown",
            user_id=uid,
            session_status="timeout",
            reason="token_timeout",
            source_file=source_file,
        )
    except requests.RequestException as e:
        return finalize(
            service="Crunchyroll",
            valid=False,
            category="unknown",
            plan_live="Unknown",
            user_id=uid,
            session_status="network_error",
            reason=f"network_error:{type(e).__name__}",
            source_file=source_file,
        )

    text = resp.text or ""
    # Cloudflare Challenge
    if resp.status_code in (403, 503) or "just a moment" in text.lower():
        return finalize(
            service="Crunchyroll",
            valid=False,
            category="unknown",
            plan_live="Unknown",
            user_id=uid,
            session_status="challenge",
            reason="cf_challenge",
            source_file=source_file,
        )

    # Rate-limit o error interno del servidor
    if resp.status_code == 429 or resp.status_code >= 500:
        return finalize(
            service="Crunchyroll",
            valid=False,
            category="unknown",
            plan_live="Unknown",
            user_id=uid,
            session_status=f"http_{resp.status_code}",
            reason=f"server_{resp.status_code}",
            source_file=source_file,
        )

    # Token expirado o rechazado
    if resp.status_code in (400, 401):
        err_code = ""
        try:
            err_j = resp.json() if text.strip().startswith("{") else {}
            if isinstance(err_j, dict):
                err_code = str(err_j.get("error") or err_j.get("code") or "")
        except Exception:
            err_j = {}

        return finalize(
            service="Crunchyroll",
            valid=False,
            category="invalid",
            session_status=f"http_{resp.status_code}",
            reason=f"token_rejected:{err_code or 'session_expired'}",
            user_id=uid,
            source_file=source_file,
            extras={"token_error": err_j if isinstance(err_j, dict) else {}},
        )

    if not (200 <= resp.status_code < 300):
        return finalize(
            service="Crunchyroll",
            valid=False,
            category="unknown",
            plan_live="Unknown",
            user_id=uid,
            session_status=f"http_{resp.status_code}",
            reason=f"token_unexpected_{resp.status_code}",
            source_file=source_file,
        )

    try:
        tok = resp.json()
    except Exception:
        return finalize(
            service="Crunchyroll",
            valid=False,
            category="unknown",
            plan_live="Unknown",
            user_id=uid,
            session_status="error",
            reason="token_not_json",
            source_file=source_file,
        )

    access = tok.get("access_token")
    if not access:
        return finalize(
            service="Crunchyroll",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="no_access_token",
            user_id=uid,
            source_file=source_file,
        )

    claims = _jwt_payload(access)
    plan_live, plan_raw = _plan_from_benefits(claims.get("benefits"))
    account_id = tok.get("account_id")
    email = None
    extras: dict = {
        "account_id": account_id,
        "jwt_status": claims.get("status"),
        "benefits": claims.get("benefits") if isinstance(claims.get("benefits"), list) else None,
    }
    if plan_raw:
        extras["plan_raw"] = plan_raw

    # Obtener perfil y email con el Bearer token
    me_headers = {
        "User-Agent": UA,
        "Accept": "application/json",
        "Authorization": f"Bearer {access}",
    }
    try:
        me = sess.get(ME_URL, headers=me_headers, timeout=timeout)
        extras["me_http"] = me.status_code
        if 200 <= me.status_code < 300:
            try:
                me_j = me.json()
                em = me_j.get("email")
                if isinstance(em, str) and em.strip():
                    email = em.strip()
                uid = uid or me_j.get("external_id") or me_j.get("account_id")
                account_id = account_id or me_j.get("account_id")
                extras["account_id"] = account_id
            except Exception:
                pass
        elif me.status_code in (401, 403):
            return finalize(
                service="Crunchyroll",
                valid=False,
                category="invalid",
                session_status=f"me_{me.status_code}",
                reason=f"me_{me.status_code}_after_token",
                user_id=uid,
                source_file=source_file,
                extras=extras,
            )
    except requests.RequestException as e:
        extras["me_warn"] = type(e).__name__

    reason = "crunchyroll session ok"
    if plan_live and plan_live != "Unknown":
        reason += f" + plan {plan_live}"
    else:
        reason += " + plan unknown"

    return finalize(
        service="Crunchyroll",
        valid=True,
        category="valid",
        plan_live=plan_live,
        email=email,
        user_id=str(uid) if uid is not None else None,
        session_status="ok",
        reason=reason,
        source_file=source_file,
        extras=extras,
    )


def check_file(path: Path) -> CheckResult:
    from ..load import load_file, requests_cookie_dict

    jar = load_file(path)
    return check_cookies(requests_cookie_dict(jar), source_file=path.name, jar=jar)