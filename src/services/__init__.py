"""Service checker registry (9 services)."""
from __future__ import annotations

from typing import Callable

from ..models import CheckResult
from . import (
    chatgpt,
    claude,
    crunchyroll,
    cursor_svc,
    grok,
    netflix,
    roblox,
    spotify,
    twitter,
)

# key = lowercase service id used in CLI / folders
REGISTRY: dict[str, Callable[..., CheckResult]] = {
    "chatgpt": chatgpt.check_cookies,
    "grok": grok.check_cookies,
    "spotify": spotify.check_cookies,
    "netflix": netflix.check_cookies,
    "crunchyroll": crunchyroll.check_cookies,
    "claude": claude.check_cookies,
    "cursor": cursor_svc.check_cookies,
    "twitter": twitter.check_cookies,
    "roblox": roblox.check_cookies,
}

SERVICE_FOLDER = {
    "chatgpt": "ChatGPT",
    "spotify": "Spotify",
    "grok": "Grok",
    "claude": "Claude",
    "cursor": "Cursor",
    "twitter": "Twitter",
    "netflix": "Netflix",
    "crunchyroll": "Crunchyroll",
    "roblox": "Roblox",
}

ALL_SERVICES = set(REGISTRY.keys())

__all__ = ["REGISTRY", "SERVICE_FOLDER", "ALL_SERVICES"]
