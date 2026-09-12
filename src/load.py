"""Load messy Cookie-Editor JSON / Netscape txt into a simple cookie list."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Cookie:
    name: str
    value: str
    domain: str = ""
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    expiration_date: float | None = None


@dataclass
class Jar:
    cookies: list[Cookie] = field(default_factory=list)
    source: Path | None = None
    service_hint: str = ""   # chatgpt | spotify | ""
    plan_folder: str = "Unknown"  # from cookies/ChatGPT/Plus → Plus


def _finite_expiry(exp) -> float | None:
    """Normalize expiry; handle milliseconds; reject NaN/Inf/overflow."""
    try:
        if exp in (None, "", 0, "0"):
            return None
        val = float(exp)
        if val != val or abs(val) == float("inf"):
            return None
        # Si la fecha viene en milisegundos (timestamp > 100 mil millones), convertir a segundos
        if val > 1e11:
            val /= 1000.0
        if val > 253402300799:  # Año 9999
            return None
        return val
    except (TypeError, ValueError, OverflowError):
        return None


def _as_cookie(obj: dict) -> Cookie | None:
    name = str(obj.get("name") or obj.get("Name") or "").strip()
    if not name:
        return None
    value = obj.get("value")
    if value is None:
        value = obj.get("Value")
    value = "" if value is None else str(value)
    domain = str(obj.get("domain") or obj.get("Domain") or "").strip()
    path = str(obj.get("path") or obj.get("Path") or "/") or "/"
    secure = bool(obj.get("secure") if "secure" in obj else obj.get("Secure", False))
    http_only = bool(obj.get("httpOnly") if "httpOnly" in obj else obj.get("HttpOnly", False))
    exp = obj.get("expirationDate") or obj.get("expires") or obj.get("Expiry")
    expiration_date = _finite_expiry(exp)
    return Cookie(
        name=name,
        value=value,
        domain=domain,
        path=path,
        secure=secure,
        http_only=http_only,
        expiration_date=expiration_date,
    )


def _from_json(text: str) -> list[Cookie]:
    data = json.loads(text)
    if isinstance(data, dict):
        if isinstance(data.get("cookies"), list):
            data = data["cookies"]
        else:
            # single cookie object
            one = _as_cookie(data)
            return [one] if one else []
    if not isinstance(data, list):
        return []
    out: list[Cookie] = []
    for item in data:
        if isinstance(item, dict):
            c = _as_cookie(item)
            if c:
                out.append(c)
    return out


def _from_netscape(text: str) -> list[Cookie]:
    out: list[Cookie] = []
    for line in text.splitlines():
        line = line.rstrip("\r\n")
        if not line or (line.startswith("#") and not line.startswith("#HttpOnly_")):
            continue
        http_only = False
        if line.startswith("#HttpOnly_"):
            http_only = True
            line = line[len("#HttpOnly_"):]
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        domain, _flag, path, secure, expires, name, value = parts[:7]
        exp = _finite_expiry(expires)
        out.append(
            Cookie(
                name=name,
                value=value,
                domain=domain,
                path=path or "/",
                secure=secure.upper() == "TRUE",
                http_only=http_only,
                expiration_date=exp,
            )
        )
    return out


def _from_header(text: str) -> list[Cookie]:
    """name=value; name2=value2 (limpia prefijo 'Cookie:' si existe)."""
    cleaned = text.strip()
    if cleaned.lower().startswith("cookie:"):
        cleaned = cleaned[7:].strip()

    out: list[Cookie] = []
    for part in cleaned.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if name:
            out.append(Cookie(name=name, value=value.strip()))
    return out


def load_file(path: Path) -> Jar:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
        if "\ufffd" in text:
            print(f"[WARN] non-utf8 bytes replaced in {path.name}")
    if text.startswith("\ufeff"):
        text = text.lstrip("\ufeff")
    stripped = text.lstrip()
    cookies: list[Cookie] = []
    looks_json = stripped.startswith("{") or stripped.startswith("[")
    if looks_json:
        try:
            cookies = _from_json(stripped)
        except json.JSONDecodeError as exc:
            print(f"[WARN] invalid JSON in {path.name}: {exc.__class__.__name__}")
            return Jar(cookies=[], source=path)
    if not cookies and "\t" in text:
        cookies = _from_netscape(text)
    if not cookies and not looks_json and "=" in text and "\t" not in text.split("\n", 1)[0]:
        cookies = _from_header(text)
    return Jar(cookies=cookies, source=path)


KNOWN_SERVICES = {
    "chatgpt", "spotify", "grok", "claude", "cursor",
    "twitter", "netflix", "crunchyroll", "roblox",
}


def detect_service(jar: Jar, *, honor_hint: bool = True) -> str:
    """Infer service from folder hint or cookie domains/names. Unknown → \"unknown\"."""
    if honor_hint and getattr(jar, "service_hint", None):
        hint = str(jar.service_hint).strip().lower()
        if hint in ("x", "twitter"):
            return "twitter"
        if hint in KNOWN_SERVICES:
            return hint
    doms = " ".join((c.domain or "").lower() for c in jar.cookies)
    names = " ".join((c.name or "").lower() for c in jar.cookies)
    blob = doms + " " + names
    if "chatgpt.com" in blob or "openai.com" in blob or "__secure-next-auth.session-token" in names:
        return "chatgpt"
    if "spotify.com" in blob or "sp_dc" in names:
        return "spotify"
    if "grok.com" in blob or ("x.ai" in blob and "auth_token" not in names):
        return "grok"
    if "claude.ai" in blob or "anthropic.com" in blob or "sessionkey" in names:
        return "claude"
    if "cursor.com" in blob or "cursor.sh" in blob or "workoscursorsessiontoken" in names:
        return "cursor"
    # Netflix BEFORE Twitter: naive "x.com" is a substring of "netflix.com".
    if (
        "netflix.com" in blob
        or "netflixid" in names
        or "securenetflixid" in names
    ):
        return "netflix"
    if "crunchyroll.com" in blob or "etp_rt" in names:
        return "crunchyroll"
    if "roblox.com" in blob or "roblosecurity" in names:
        return "roblox"
    # Domain tokens: require boundary so netflix.com never matches x.com.
    dom_tokens = set()
    for c in jar.cookies:
        d = (c.domain or "").lower().lstrip(".")
        if d:
            dom_tokens.add(d)
            parts = d.split(".")
            if len(parts) >= 2:
                dom_tokens.add(".".join(parts[-2:]))
    if (
        "twitter.com" in dom_tokens
        or "x.com" in dom_tokens
        or ("auth_token" in names and "ct0" in names)
    ):
        return "twitter"
    # Filename hint for loose jars (netflix1.json etc.) when domains are odd
    stem = jar.source.name.lower() if jar.source else ""
    for key, svc in (
        ("netflix", "netflix"),
        ("spotify", "spotify"),
        ("chatgpt", "chatgpt"),
        ("openai", "chatgpt"),
        ("plusgpt", "chatgpt"),
        ("grok", "grok"),
        ("claude", "claude"),
        ("cursor", "cursor"),
        ("crunchy", "crunchyroll"),
        ("roblox", "roblox"),
        ("twitter", "twitter"),
    ):
        if key in stem:
            return svc
    return "unknown"


def discover_jars(cookies_root: Path) -> list[Jar]:
    """Walk cookies/ (loose files OK) and cookies/<Service>/[Plan]/file."""
    jars: list[Jar] = []
    if not cookies_root.exists():
        return jars
    allowed = {".json", ".txt", ".cookies", ".cookie"}
    for path in sorted(cookies_root.rglob("*")):
        if not path.is_file() or path.name.startswith("."):
            continue
        if path.suffix.lower() not in allowed:
            continue

        rel = path.relative_to(cookies_root)
        parts = [p for p in rel.parts[:-1]]
        service = ""
        plan = "Unknown"
        known_tops = {
            "chatgpt", "spotify", "grok", "claude", "cursor",
            "twitter", "x", "netflix", "crunchyroll", "roblox",
        }
        try:
            jar = load_file(path)
        except OSError as exc:
            print(f"[WARN] skip unreadable {path.name}: {type(exc).__name__}")
            continue
        if not parts:
            if not jar.cookies:
                continue
            detected = detect_service(jar, honor_hint=False)
            if detected == "unknown" or detected not in KNOWN_SERVICES:
                continue
            jar.service_hint = detected
            jar.plan_folder = "Unknown"
            jars.append(jar)
            continue
        top = parts[0].lower()
        if top not in known_tops:
            continue
        if top == "chatgpt":
            service = "chatgpt"
            if len(parts) >= 2:
                plan = parts[1]
        elif top == "spotify":
            service = "spotify"
        elif top == "grok":
            service = "grok"
        elif top == "claude":
            service = "claude"
            if len(parts) >= 2:
                plan = parts[1]
        elif top == "cursor":
            service = "cursor"
            if len(parts) >= 2:
                plan = parts[1]
        elif top in ("twitter", "x"):
            service = "twitter"
            if len(parts) >= 2:
                plan = parts[1]
        elif top == "netflix":
            service = "netflix"
            if len(parts) >= 2:
                plan = parts[1]
        elif top == "crunchyroll":
            service = "crunchyroll"
            if len(parts) >= 2:
                plan = parts[1]
        elif top == "roblox":
            service = "roblox"
        jar.service_hint = service
        jar.plan_folder = plan if plan else "Unknown"
        known = {
            "free": "Free", "plus": "Plus", "go": "Go", "unknown": "Unknown",
            "pro": "Pro", "team": "Team", "enterprise": "Enterprise", "business": "Business",
            "max": "Max", "premium": "Premium", "basic": "Basic", "duo": "Duo",
            "family": "Family", "student": "Student", "standard": "Standard",
            "ads": "Ads", "mobile": "Mobile", "supergrok": "SuperGrok", "fan": "Fan"
        }
        jar.plan_folder = known.get(jar.plan_folder.lower(), jar.plan_folder)
        if jar.cookies:
            jars.append(jar)
    return jars


def requests_cookie_dict(jar: Jar) -> dict[str, str]:
    """Flat name→value (last wins). Prefer apply_jar_cookies for domain-scoped sends."""
    out: dict[str, str] = {}
    for c in jar.cookies:
        if c.name:
            out[c.name] = c.value
    return out


def apply_jar_cookies(sess, jar: Jar) -> None:
    """Load jar into Session preserving domain/path/secure/expiry when possible."""
    for c in jar.cookies:
        if not c.name:
            continue
        kwargs = {
            "name": c.name,
            "value": c.value,
            "path": c.path or "/",
            "secure": bool(c.secure),
        }
        dom = (c.domain or "").strip()
        if dom:
            kwargs["domain"] = dom
        if c.expiration_date is not None:
            try:
                kwargs["expires"] = int(float(c.expiration_date))
            except (TypeError, ValueError, OverflowError):
                pass
        try:
            sess.cookies.set(**kwargs)
        except Exception:
            continue


def cookie_header(jar: Jar) -> str:
    return "; ".join(f"{c.name}={c.value}" for c in jar.cookies if c.name)


def domains_present(jar: Jar) -> set[str]:
    return {(c.domain or "").lower().lstrip(".") for c in jar.cookies if c.domain}


def names_present(jar: Jar) -> set[str]:
    return {(c.name or "").lower() for c in jar.cookies}