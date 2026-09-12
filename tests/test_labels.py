"""Label preference tests."""
from __future__ import annotations

from pathlib import Path

from src.load import Cookie, Jar
from src.models import finalize
from src.write import is_real_email, label_from_jar, safe_stem


def test_is_real_email():
    assert is_real_email("a@b.co")
    assert not is_real_email("Checked by @Someone")
    assert not is_real_email("@handle")
    assert not is_real_email("")


def test_label_prefers_email():
    jar = Jar(cookies=[Cookie(name="x", value="1")], source=Path("foo.txt"))
    assert label_from_jar(jar, preferred="user@example.com") == safe_stem("user@example.com")


def test_label_twitter_handle():
    jar = Jar(cookies=[], source=Path("x.txt"))
    assert label_from_jar(jar, preferred="@CoolUser").startswith("@")


def test_label_skips_junk_brackets():
    jar = Jar(cookies=[Cookie(name="a", value="bbbbbbbbbbbbbbbbbbbb")], source=Path("[Free] [Checked by @Bot] jar.txt"))
    lab = label_from_jar(jar)
    assert "Checked" not in lab
    assert lab  # digest fallback ok


def test_serial_style_alive_dead():
    # exercised via main helpers conceptually — ensure finalize categories work
    r = finalize(service="Spotify", valid=True, category="valid", email=None)
    assert r.category == "valid"
    r2 = finalize(service="Spotify", valid=False, category="invalid")
    assert r2.category == "invalid"
