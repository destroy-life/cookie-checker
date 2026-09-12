"""Networkless load format tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.load import detect_service, discover_jars, load_file, requests_cookie_dict


def test_load_cookie_editor_json(tmp_path: Path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps([
        {"name": "sp_dc", "value": "abc", "domain": ".spotify.com"},
        {"name": "sp_key", "value": "xyz", "domain": ".spotify.com"},
    ]), encoding="utf-8")
    jar = load_file(p)
    assert len(jar.cookies) == 2
    d = requests_cookie_dict(jar)
    assert d["sp_dc"] == "abc"
    assert detect_service(jar) == "spotify"


def test_load_netscape(tmp_path: Path):
    p = tmp_path / "b.txt"
    p.write_text(
        "# Netscape HTTP Cookie File\n"
        ".chatgpt.com\tTRUE\t/\tTRUE\t0\t__Secure-next-auth.session-token\ttok123\n"
        ".chatgpt.com\tTRUE\t/\tTRUE\t0\toai-did\tdid456\n",
        encoding="utf-8",
    )
    jar = load_file(p)
    assert any(c.name.startswith("__Secure-next-auth.session-token") for c in jar.cookies)
    assert detect_service(jar) == "chatgpt"


def test_load_bom(tmp_path: Path):
    p = tmp_path / "bom.json"
    payload = json.dumps([{"name": "etp_rt", "value": "1", "domain": ".crunchyroll.com"}])
    p.write_bytes("\ufeff".encode("utf-8") + payload.encode("utf-8"))
    jar = load_file(p)
    assert requests_cookie_dict(jar).get("etp_rt") == "1"
    assert detect_service(jar) == "crunchyroll"


def test_load_header_style(tmp_path: Path):
    p = tmp_path / "h.txt"
    p.write_text("auth_token=aaa; ct0=bbb", encoding="utf-8")
    jar = load_file(p)
    d = requests_cookie_dict(jar)
    assert d["auth_token"] == "aaa"
    assert d["ct0"] == "bbb"


def test_discover_ignores_unknown_folder(tmp_path: Path):
    cookies = tmp_path / "cookies"
    (cookies / "Supercell").mkdir(parents=True)
    (cookies / "Supercell" / "x.json").write_text(
        json.dumps([{"name": "foo", "value": "bar", "domain": ".supercell.com"}]),
        encoding="utf-8",
    )
    (cookies / "Roblox").mkdir(parents=True)
    (cookies / "Roblox" / "ok.json").write_text(
        json.dumps([{"name": ".ROBLOSECURITY", "value": "sec", "domain": ".roblox.com"}]),
        encoding="utf-8",
    )
    jars = discover_jars(cookies)
    assert len(jars) == 1
    assert jars[0].service_hint == "roblox"


def test_discover_loose_admitted_only(tmp_path: Path):
    cookies = tmp_path / "cookies"
    cookies.mkdir()
    (cookies / "known.json").write_text(
        json.dumps([{"name": "sso", "value": "1", "domain": ".grok.com"}]),
        encoding="utf-8",
    )
    (cookies / "noise.json").write_text(
        json.dumps([{"name": "foo", "value": "1", "domain": ".example.com"}]),
        encoding="utf-8",
    )
    jars = discover_jars(cookies)
    assert len(jars) == 1
    assert detect_service(jars[0]) == "grok"


def test_netflix_not_misdetected_as_twitter_via_x_com_substring(tmp_path):
    """"x.com" is a substring of "netflix.com" — must not classify Netflix as Twitter."""
    from src.load import Jar, Cookie, detect_service
    jar = Jar(
        cookies=[Cookie(name="NetflixId", value="abc", domain=".netflix.com")],
        source=tmp_path / "netflix1.json",
    )
    assert detect_service(jar, honor_hint=False) == "netflix"
