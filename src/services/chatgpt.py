"""ChatGPT cookie checker — amai session flow.

oai-wm = INFO only (live Plus can include it).
unified_session_manifest / usc_* = Cookie-Editor "no entra" → INVALID for packaging.
Session JSON must include accessToken (and user) to count as valid.
Backend-API verification via Bearer token to prevent ghost/revoked sessions.
"""
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
    """Map plan tokens including chatgptplusplan / entitlement.subscription_plan."""
    if raw is None or isinstance(raw, bool):
        return "Unknown"
    s = str(raw).strip()
    if not s:
        return "Unknown"
    low = s.lower().replace("-", "").replace("_", "").replace(" ", "")
    compact_map = {
        "free": "Free",
        "chatgptfree": "Free",
        "go": "Go",
        "chatgptgo": "Go",
        "plus": "Plus",
        "chatgptplus": "Plus",
        "chatgptplusplan": "Plus",
        "pro": "Pro",
        "chatgptpro": "Pro",
        "chatgptproplan": "Pro",
        "team": "Team",
        "chatgptteam": "Team",
        "enterprise": "Enterprise",
        "business": "Business",
    }
    if low in compact_map:
        return compact_map[low]
    if "plus" in low:
        return "Plus"
    if "pro" in low and "plus" not in low:
        return "Pro"
    if "enterprise" in low:
        return "Enterprise"
    if "business" in low:
        return "Business"
    if "team" in low:
        return "Team"
    if "go" == low or low.endswith("go"):
        return "Go"
    if "free" in low:
        return "Free"
    return "Unknown"


def plan_from_payload(data: Any) -> str:
    """Read accounts.*.account.planType AND entitlement.subscription_plan."""
    if not data or not isinstance(data, dict):
        return "Unknown"

    accounts = data.get("accounts")
    if isinstance(accounts, dict):
        for acc in accounts.values():
            if not isinstance(acc, dict):
                continue
            account = acc.get("account") if isinstance(acc.get("account"), dict) else {}
            for k in ("planType", "plan_type", "plan"):
                if k in account:
                    p = normalize_plan(account[k])
                    if p != "Unknown":
                        return p
            ent = acc.get("entitlement") if isinstance(acc.get("entitlement"), dict) else {}
            for k in ("subscription_plan", "subscriptionPlan", "planType", "plan"):
                if k in ent:
                    p = normalize_plan(ent[k])
                    if p != "Unknown":
                        return p
            aent = account.get("entitlement") if isinstance(account.get("entitlement"), dict) else {}
            for k in ("subscription_plan", "subscriptionPlan", "planType", "plan"):
                if k in aent:
                    p = normalize_plan(aent[k])
                    if p != "Unknown":
                        return p

    for key in ("plan", "planType", "plan_type", "account_plan", "subscription", "subscription_plan"):
        if key in data:
            val = data[key]
            if isinstance(val, dict):
                for sub in ("plan", "planType", "type", "id", "name", "subscription_plan"):
                    if sub in val:
                        p = normalize_plan(val[sub])
                        if p != "Unknown":
                            return p
            else:
                p = normalize_plan(val)
                if p != "Unknown":
                    return p

    for nest in ("account", "user", "account_data", "entitlement"):
        node = data.get(nest)
        if isinstance(node, dict):
            p = plan_from_payload(node)
            if p != "Unknown":
                return p

    return "Unknown"


def info_markers(cookies: dict[str, str]) -> list[str]:
    """Detect jar markers. oai-wm is informational; manifest/usc_* block Cookie-Editor."""
    names = list(cookies.keys())
    lower = {n.lower() for n in names}
    bits: list[str] = []
    if "oai-wm" in cookies or "oai-wm" in lower:
        bits.append("oai-wm")
    if "unified_session_manifest" in cookies or "unified_session_manifest" in lower:
        bits.append("unified_session_manifest")
    if any(n.startswith("usc_") for n in names):
        bits.append("usc_*")
    return bits


def cookie_editor_blockers(cookies: dict[str, str]) -> list[str]:
    """Markers that typically fail Cookie-Editor import."""
    bits = info_markers(cookies)
    return [b for b in bits if b != "oai-wm"]


def extract_identity(cookies: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "email": None,
        "name": None,
        "user_id": None,
        "models": [],
        "stripe": False,
        "oai_wm": False,
    }
    auth_raw = cookies.get("oai-client-auth-info")
    if auth_raw:
        try:
            data = json.loads(urllib.parse.unquote(auth_raw))
            user = data.get("user") or {}
            out["email"] = user.get("email")
            out["name"] = (user.get("name") or "").strip() or None
        except Exception:
            pass
    puid = cookies.get("_puid") or ""
    if puid.startswith("user-"):
        out["user_id"] = puid.split(":")[0]
    for key in ("oai-tpp-model-settings", "oai-last-model-config"):
        raw = cookies.get(key)
        if not raw:
            continue
        try:
            obj = json.loads(urllib.parse.unquote(raw))
            if "model" in obj:
                out["models"].append(str(obj["model"]))
            ms = obj.get("modelSettings") or {}
            if ms.get("lastUsedModelSlug"):
                out["models"].append(str(ms["lastUsedModelSlug"]))
            cfg = obj.get("lastStartedModelConfig") or {}
            if cfg.get("modelSlug"):
                out["models"].append(str(cfg["modelSlug"]))
        except Exception:
            pass
    out["models"] = sorted(set(out["models"]))
    out["stripe"] = "__stripe_mid" in cookies
    out["oai_wm"] = cookies.get("oai-wm") in ("1", "true", "True") or "oai-wm" in cookies
    return out


def build_session(cookies: dict[str, str]) -> requests.Session:
    s = requests.Session()
    # Un solo dominio raíz para evitar duplicar cookies gigantes y saturar cabeceras
    for name, value in cookies.items():
        s.cookies.set(name, value, domain=".chatgpt.com", path="/")
    return s


def headers_for(cookies: dict[str, str]) -> dict[str, str]:
    return {
        "User-Agent": DEFAULT_UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://chatgpt.com/",
        "Origin": "https://chatgpt.com",
        "oai-device-id": cookies.get("oai-did", ""),
        "oai-language": "en-US",
    }


def _get_json(session: requests.Session, url: str, headers: dict, timeout: int = 20):
    try:
        r = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        return 0, None, f"error:{e}"
    if r.status_code == 403 and r.headers.get("cf-mitigated") == "challenge":
        return 403, None, "challenge"
    ct = (r.headers.get("content-type") or "").lower()
    if r.status_code == 200:
        try:
            return 200, r.json(), "ok"
        except Exception:
            if "text/html" in ct or (r.text or "").lstrip().startswith("<!"):
                return 200, None, "challenge" if "cloudflare" in (r.text or "").lower() else "html"
            return 200, None, "html"
    if "text/html" in ct or (r.text or "").lstrip().startswith("<!"):
        return r.status_code, None, "challenge" if "cloudflare" in (r.text or "").lower() else "html"
    return r.status_code, None, f"http_{r.status_code}"


def check_cookies(
    cookies: dict[str, str],
    source_file: Optional[str] = None,
    *,
    jar=None,
    timeout: int = 20,
) -> CheckResult:
    markers = info_markers(cookies)
    extras: dict[str, Any] = {}
    if markers:
        extras["info_markers"] = markers
    blockers = cookie_editor_blockers(cookies)
    if blockers:
        extras["cookie_editor_blockers"] = blockers

    if not cookies:
        return finalize(
            service="ChatGPT",
            valid=False,
            category="invalid",
            session_status="error",
            reason="empty_cookies",
            source_file=source_file,
            extras=extras,
        )

    ident = extract_identity(cookies)
    oai_wm = bool(ident["oai_wm"]) or ("oai-wm" in markers)

    has_session = any(
        k in cookies
        for k in (
            "__Secure-next-auth.session-token.0",
            "__Secure-next-auth.session-token",
            "oai-sc",
            "__Secure-oai-is",
        )
    )
    if not has_session and not ident["email"]:
        return finalize(
            service="ChatGPT",
            valid=False,
            category="invalid",
            session_status="expired",
            reason="no_session_cookies",
            email=ident["email"],
            name=ident["name"],
            user_id=ident["user_id"],
            models_hint=ident["models"],
            stripe=ident["stripe"],
            oai_wm=oai_wm,
            source_file=source_file,
            extras=extras,
        )

    session = build_session(cookies)
    headers = headers_for(cookies)

    # 1. Obtener datos iniciales y el accessToken desde NextAuth
    status, data, note = _get_json(session, "https://chatgpt.com/api/auth/session", headers, timeout)

    if note == "ok" and data is not None:
        if data == {}:
            return finalize(
                service="ChatGPT",
                valid=False,
                category="invalid",
                session_status="expired",
                reason="empty_session",
                plan_live="Unknown",
                email=ident["email"],
                name=ident["name"],
                user_id=ident["user_id"],
                models_hint=ident["models"],
                stripe=ident["stripe"],
                oai_wm=oai_wm,
                source_file=source_file,
                extras=extras,
            )
        user = data.get("user") or {}
        email = ident["email"]
        name = ident["name"]
        access = data.get("accessToken") or data.get("access_token")
        if isinstance(user, dict):
            email = email or user.get("email")
            name = name or (user.get("name") or "").strip() or None
            if not ident["user_id"]:
                ident["user_id"] = user.get("id") or user.get("user_id")

        # Sin accessToken es una sesión parcial/muerta
        if not access:
            return finalize(
                service="ChatGPT",
                valid=False,
                category="invalid",
                session_status="expired",
                reason="session_without_accessToken",
                plan_live="Unknown",
                email=email,
                name=name,
                user_id=ident["user_id"],
                models_hint=ident["models"],
                stripe=ident["stripe"],
                oai_wm=oai_wm,
                source_file=source_file,
                extras=extras,
            )

        # Regla de Cookie-Editor: manifest / usc_* fallan en importación
        if blockers:
            return finalize(
                service="ChatGPT",
                valid=False,
                category="invalid",
                session_status="ok",
                reason="Cookie-Editor no entra (" + ", ".join(blockers) + ")",
                plan_live=plan_from_payload(data),
                email=email,
                name=name,
                user_id=ident["user_id"],
                models_hint=ident["models"],
                stripe=ident["stripe"],
                oai_wm=oai_wm,
                source_file=source_file,
                extras=extras,
            )

        # 2. VALIDACIÓN REAL DE BACKEND (Elimina sesiones fantasma)
        auth_headers = {
            **headers,
            "Authorization": f"Bearer {access}",
        }

        # Consulta al backend real con el Bearer token (exactamente lo que hace la web)
        acc_status, acc, acc_note = _get_json(
            session,
            "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27",
            auth_headers,
            timeout,
        )

        # Si el backend devuelve 401, la sesión está caducada o revocada
        if acc_status == 401:
            return finalize(
                service="ChatGPT",
                valid=False,
                category="invalid",
                session_status="expired",
                reason="session_revoked_401",
                plan_live=plan_from_payload(data),
                email=email,
                name=name,
                user_id=ident["user_id"],
                models_hint=ident["models"],
                stripe=ident["stripe"],
                oai_wm=oai_wm,
                source_file=source_file,
                extras=extras,
            )

        # Si devuelve 403 y no es un captcha (ej. cuenta suspendida/bloqueada)
        if acc_status == 403 and acc_note != "challenge":
            return finalize(
                service="ChatGPT",
                valid=False,
                category="invalid",
                session_status="forbidden",
                reason="account_deactivated_or_forbidden",
                plan_live=plan_from_payload(data),
                email=email,
                name=name,
                user_id=ident["user_id"],
                models_hint=ident["models"],
                stripe=ident["stripe"],
                oai_wm=oai_wm,
                source_file=source_file,
                extras=extras,
            )

        # 3. Detección precisa del plan
        plan = "Unknown"
        if acc_note == "ok" and acc:
            plan = plan_from_payload(acc)
        if plan == "Unknown":
            plan = plan_from_payload(data)
        if plan == "Unknown":
            _, me, me_note = _get_json(session, "https://chatgpt.com/backend-api/me", auth_headers, timeout)
            if me_note == "ok" and me:
                plan = plan_from_payload(me)

        reason = "session ok"
        if "oai-wm" in markers:
            reason += " (info: oai-wm)"

        return finalize(
            service="ChatGPT",
            valid=True,
            category="valid",
            plan_live=plan,
            email=email,
            name=name,
            user_id=ident["user_id"],
            session_status="ok",
            reason=reason,
            models_hint=ident["models"],
            stripe=ident["stripe"],
            oai_wm=oai_wm,
            source_file=source_file,
            extras=extras,
        )

    # Si hay challenge de Cloudflare en la primera petición
    if note in ("challenge", "html") or status == 403:
        if blockers:
            return finalize(
                service="ChatGPT",
                valid=False,
                category="invalid",
                session_status="challenge",
                reason="Cookie-Editor no entra (" + ", ".join(blockers) + ")",
                email=ident["email"],
                name=ident["name"],
                user_id=ident["user_id"],
                models_hint=ident["models"],
                stripe=ident["stripe"],
                oai_wm=oai_wm,
                source_file=source_file,
                extras=extras,
            )
        if has_session and (ident["email"] or ident["user_id"]):
            return finalize(
                service="ChatGPT",
                valid=True,
                category="unknown",
                plan_live="Unknown",
                email=ident["email"],
                name=ident["name"],
                user_id=ident["user_id"],
                session_status="challenge",
                reason="cf_challenge_plan_unavailable",
                models_hint=ident["models"],
                stripe=ident["stripe"],
                oai_wm=oai_wm,
                source_file=source_file,
                extras=extras,
            )
        return finalize(
            service="ChatGPT",
            valid=False,
            category="unknown",
            session_status="challenge",
            reason="cf_challenge_no_identity",
            email=ident["email"],
            name=ident["name"],
            user_id=ident["user_id"],
            models_hint=ident["models"],
            stripe=ident["stripe"],
            oai_wm=oai_wm,
            source_file=source_file,
            extras=extras,
        )

    return finalize(
        service="ChatGPT",
        valid=False,
        category="invalid",
        session_status=note,
        reason=note,
        email=ident["email"],
        name=ident["name"],
        user_id=ident["user_id"],
        models_hint=ident["models"],
        stripe=ident["stripe"],
        oai_wm=oai_wm,
        source_file=source_file,
        extras=extras,
    )


def check_file(path: Path) -> CheckResult:
    from ..load import load_file, requests_cookie_dict

    jar = load_file(path)
    return check_cookies(requests_cookie_dict(jar), source_file=path.name, jar=jar)
