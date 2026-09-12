"""Atomic exclusive write collision tests."""
from __future__ import annotations

from pathlib import Path

import pytest

from src.write import atomic_exclusive_write, uniquify_label, write_result_json


def test_atomic_write_creates(tmp_path: Path):
    p = tmp_path / "out.json"
    atomic_exclusive_write(p, '{"ok": true}')
    assert p.read_text(encoding="utf-8") == '{"ok": true}'


def test_atomic_write_collision(tmp_path: Path):
    p = tmp_path / "out.json"
    atomic_exclusive_write(p, "one")
    with pytest.raises(FileExistsError):
        atomic_exclusive_write(p, "two")
    assert p.read_text(encoding="utf-8") == "one"


def test_write_result_json_collision(tmp_path: Path):
    p = tmp_path / "r.json"
    write_result_json(p, {"a": 1})
    with pytest.raises(FileExistsError):
        write_result_json(p, {"a": 2})


def test_uniquify_label(tmp_path: Path):
    used: set[str] = set()
    a = uniquify_label(tmp_path, "same", "abcd1234", used)
    assert a == "same"
    used.add(a.lower())
    (tmp_path / "same.json").write_text("{}", encoding="utf-8")
    b = uniquify_label(tmp_path, "same", "abcd1234", used)
    assert b is not None
    assert b != "same"
    assert "abcd1234" in b


def test_save_cookie_editor_json(tmp_path: Path):
    from src.load import Cookie, Jar
    from src.write import save_cookie_editor_json, to_cookie_editor

    jar = Jar(
        cookies=[
            Cookie(
                name="etp_rt",
                value="abc",
                domain=".crunchyroll.com",
                path="/",
                secure=True,
                http_only=True,
                expiration_date=1893456000.0,
            )
        ]
    )
    path = tmp_path / "x.json"
    save_cookie_editor_json(jar, path)
    data = __import__("json").loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert data[0]["name"] == "etp_rt"
    assert data[0]["httpOnly"] is True
    assert data[0]["domain"] == ".crunchyroll.com"
    assert "expirationDate" in data[0]
