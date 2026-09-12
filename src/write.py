"""amai-check file export and write logic."""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from pathlib import Path
from typing import Any

from .load import Cookie, Jar


def safe_stem(name: str) -> str:
    bad = set(r'<>:"/\\|?*')
    out = "".join("_" if (c in bad or ord(c) < 32) else c for c in name).strip(" ._")
    try:
        if hasattr(os.path, "isreserved") and out and os.path.isreserved(out + ".json"):
            out = f"_{out}"
    except Exception:
        pass
    base = out.split(".")[0].upper() if out else ""
    _sup = str.maketrans("¹²³⁴⁵⁶⁷⁸⁹⁰", "1234567890")
    base_ascii = base.translate(_sup)
    reserved = {
        "CON", "PRN", "AUX", "NUL",
        *{f"COM{i}" for i in range(0, 10)},
        *{f"LPT{i}" for i in range(0, 10)},
    }
    if base in reserved or base_ascii in reserved:
        out = f"_{out}" if out else "unnamed"
    out = (out or "unnamed")[:80].rstrip(" .")
    return out or "unnamed"


_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![A-Za-z0-9._%+-])"
)


def is_real_email(value: str | None) -> bool:
    if not value or not str(value).strip():
        return False
    s = str(value).strip()
    low = s.lower()
    if " " in s or "checked by" in low:
        return False
    return bool(_EMAIL_RE.fullmatch(s))


def jar_digest(jar: Jar, src_name: str = "jar") -> str:
    parts: list[str] = []
    if jar.source is not None:
        try:
            parts.append(str(jar.source.resolve()))
        except Exception:
            parts.append(str(jar.source))
    else:
        parts.append(src_name)
    for c in (jar.cookies or [])[:40]:
        parts.append(f"{c.name}={(c.value or '')[:24]}")
    blob = "|".join(parts)
    return hashlib.sha1(blob.encode("utf-8", errors="replace")).hexdigest()[:8]


def label_from_jar(jar: Jar, preferred: str | None = None) -> str:
    if preferred and is_real_email(preferred):
        return safe_stem(preferred.strip())
    if preferred and isinstance(preferred, str):
        pref = preferred.strip()
        junk = {
            "settings", "home", "explore", "notifications", "messages",
            "payments", "premium", "free", "plus", "go", "claude", "cursor",
            "spotify", "chatgpt", "twitter", "netflix", "grok",
        }
        if re.fullmatch(r"@[A-Za-z0-9_]{1,30}", pref):
            if pref[1:].lower() not in junk:
                return safe_stem(pref)
        elif re.fullmatch(r"[A-Za-z0-9_]{1,30}", pref) and pref.lower() not in junk:
            if pref[0].isalpha():
                return safe_stem(f"@{pref}")
    src = jar.source.name if jar.source else "jar"
    src_for_email = Path(src).stem
    m = _EMAIL_RE.search(src_for_email)
    if m and is_real_email(m.group(1)):
        return safe_stem(m.group(1))
    skip = {
        "free", "plus", "go", "pro", "team", "enterprise", "business",
        "unknown", "not-detected", "notdetected",
        "alive", "n_a", "na", "n/a", "dead", "expired", "valid", "invalid",
        "premium", "basic", "standard", "ads", "fan", "mobile", "max", "duo",
        "family", "student", "supergrok", "x-premium", "xpremium",
        "chatgpt", "claude", "cursor", "spotify", "grok", "twitter", "netflix",
        "crunchyroll", "roblox", "openai", "anthropic",
        "0 payments", "0payment", "0_payments", "payments", "payment",
        "settings", "home", "explore", "notifications", "messages",
    }
    for br in re.findall(r"\[([^\]]+)\]", src):
        token = br.strip()
        low = token.lower()
        if not token or low in skip or "checked by" in low or "stylix" in low:
            continue
        if is_real_email(token):
            return safe_stem(token)
        if re.fullmatch(r"@[A-Za-z0-9_]{1,30}", token):
            if token[1:].lower() not in skip:
                return safe_stem(token)
            continue
        if token.startswith("@") or "checked by" in low:
            continue
        if low in skip or "payment" in low:
            continue
        return safe_stem(token)
    stem = Path(src).stem
    num = re.search(r"#(\d+)\s*$", stem)
    suffix = f"_{num.group(1)}" if num else ""
    stem = re.sub(r"\[[^\]]*\]", "", stem).strip(" ._-	")
    stem = re.sub(r"@\w+", "", stem).strip(" ._-	")
    stem = re.sub(r"#\d+\s*$", "", stem).strip(" ._-	")
    base = safe_stem(stem or "jar") or "jar"
    if (
        base.lower() in skip
        or base.lower() in ("jar", "unnamed", "checked")
        or "payment" in base.lower()
        or base.lower().replace("_", " ") in skip
    ):
        return safe_stem(f"jar_{jar_digest(jar, src)}{suffix}")
    return safe_stem(base + suffix)


def atomic_exclusive_write(path: Path, text: str) -> None:
    """Publish a complete file under an exclusive name (temp + link/replace)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = text.encode("utf-8")
    tmp = path.with_name(path.name + f".{uuid.uuid4().hex}.tmp")
    placeholder_owned = False
    published = False
    try:
        with tmp.open("xb") as fh:
            fh.write(data)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        try:
            os.link(tmp, path)
            published = True
        except FileExistsError:
            raise
        except OSError:
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            fd = os.open(path, flags)
            os.close(fd)
            placeholder_owned = True
            try:
                os.replace(tmp, path)
                published = True
                placeholder_owned = False
            except BaseException:
                try:
                    path.unlink()
                except OSError:
                    pass
                placeholder_owned = False
                raise
    except BaseException:
        if placeholder_owned:
            try:
                path.unlink()
            except OSError:
                pass
        raise
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
    if not published:
        raise OSError(f"exclusive write did not publish {path}")


def write_result_json(path: Path, payload: dict[str, Any]) -> None:
    text = json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False)
    atomic_exclusive_write(path, text)


def uniquify_label(
    dest_dir: Path,
    base_label: str,
    digest: str,
    used: set[str],
    *,
    need_cookie: bool = True,
    max_tries: int = 200,
) -> str | None:
    """Return a unique label within dest_dir, or None if exhausted.

    Packaging uses ``{label}.json`` (Cookie-Editor only; reports live in output/reports).
    """
    base = safe_stem(base_label or f"jar_{digest}") or f"jar_{digest}"
    max_base = max(8, 80 - 1 - len(digest))
    if len(base) > max_base:
        base = base[:max_base].rstrip(" ._") or f"jar_{digest[:8]}"
    candidate = base
    n = 0
    while True:
        cookie_path = dest_dir / f"{candidate}.json"
        txt_path = dest_dir / f"{candidate}.txt"
        taken = (
            candidate.lower() in used
            or cookie_path.exists()
            or txt_path.exists()
        )
        if not taken:
            return candidate
        n += 1
        suffix = f"_{digest}" if n == 1 else f"_{digest}_{n}"
        room = max(8, 80 - len(suffix))
        candidate = safe_stem((base[:room].rstrip(" ._") or "jar") + suffix)
        if n > max_tries:
            return None


SESSION_TOKEN_BASE = "__Secure-next-auth.session-token"
MAX_COOKIE_VALUE = 4096


def chunk_session_token_cookies(cookies: list[Cookie]) -> list[Cookie]:
    """Split long ChatGPT session tokens for Cookie-Editor / Netscape import."""
    bare = [c for c in cookies if c.name == SESSION_TOKEN_BASE]
    chunks = [c for c in cookies if c.name.startswith(SESSION_TOKEN_BASE + ".")]
    others = [
        c
        for c in cookies
        if c.name != SESSION_TOKEN_BASE and not c.name.startswith(SESSION_TOKEN_BASE + ".")
    ]
    if chunks:
        return others + chunks
    if not bare:
        return list(cookies)
    out = list(others)
    for c in bare:
        val = c.value or ""
        if len(val) <= MAX_COOKIE_VALUE:
            out.append(c)
            continue
        parts = [val[i : i + MAX_COOKIE_VALUE] for i in range(0, len(val), MAX_COOKIE_VALUE)]
        for idx, part in enumerate(parts):
            out.append(
                Cookie(
                    name=f"{SESSION_TOKEN_BASE}.{idx}",
                    value=part,
                    domain=c.domain,
                    path=c.path,
                    secure=c.secure,
                    http_only=c.http_only,
                    expiration_date=c.expiration_date,
                )
            )
    return out


def cookie_editor_row(c: Cookie) -> dict[str, Any]:
    row: dict[str, Any] = {
        "name": c.name,
        "value": c.value,
        "domain": c.domain or "",
        "path": c.path or "/",
        "secure": bool(c.secure),
        "httpOnly": bool(c.http_only),
        "session": c.expiration_date is None,
        "storeId": None,
    }
    if c.expiration_date is not None:
        row["expirationDate"] = c.expiration_date
    return row


def to_cookie_editor(jar: Jar) -> list[dict[str, Any]]:
    return [cookie_editor_row(c) for c in chunk_session_token_cookies(jar.cookies or [])]


def save_cookie_editor_json(jar: Jar, path: Path) -> None:
    """Write clean Cookie-Editor JSON jar (packaging default)."""
    payload = json.dumps(to_cookie_editor(jar), indent=2, ensure_ascii=False, allow_nan=False)
    atomic_exclusive_write(path, payload)
