"""ChatGPT plan normalize + oai_wm does not invalidate (networkless)."""
from __future__ import annotations

from src.services.chatgpt import info_markers, normalize_plan, plan_from_payload


def test_normalize_chatgptplusplan():
    assert normalize_plan("chatgptplusplan") == "Plus"
    assert normalize_plan("chatgpt_plus") == "Plus"
    assert normalize_plan("Plus") == "Plus"
    assert normalize_plan("free") == "Free"
    assert normalize_plan("pro") == "Pro"
    assert normalize_plan("team") == "Team"


def test_plan_from_accounts_planType():
    payload = {
        "accounts": {
            "acc1": {
                "account": {"planType": "plus"},
            }
        }
    }
    assert plan_from_payload(payload) == "Plus"


def test_plan_from_entitlement_subscription_plan():
    payload = {
        "accounts": {
            "acc1": {
                "account": {},
                "entitlement": {"subscription_plan": "chatgptplusplan"},
            }
        }
    }
    assert plan_from_payload(payload) == "Plus"


def test_plan_from_nested_account_entitlement():
    payload = {
        "accounts": {
            "x": {
                "account": {
                    "entitlement": {"subscription_plan": "chatgptplusplan"},
                }
            }
        }
    }
    assert plan_from_payload(payload) == "Plus"


def test_oai_wm_info_only_markers():
    cookies = {
        "oai-wm": "1",
        "unified_session_manifest": "x",
        "usc_foo": "1",
        "__Secure-next-auth.session-token": "tok",
    }
    bits = info_markers(cookies)
    assert "oai-wm" in bits
    assert "unified_session_manifest" in bits
    assert "usc_*" in bits
    # markers must never be treated as a hard invalidation signal by themselves
    # (check_cookies would still need HTTP; we only assert INFO listing here)
    assert isinstance(bits, list)


def test_oai_wm_does_not_force_invalid_without_http(monkeypatch):
    """With session cookies + identity, CF challenge stays valid; oai_wm is info."""
    from src.services import chatgpt as mod

    def fake_get_json(session, url, headers, timeout=20):
        return 403, None, "challenge"

    monkeypatch.setattr(mod, "_get_json", fake_get_json)
    cookies = {
        "__Secure-next-auth.session-token": "tok",
        "oai-wm": "1",
        "oai-client-auth-info": "%7B%22user%22%3A%7B%22email%22%3A%22a%40b.co%22%2C%22name%22%3A%22A%22%7D%7D",
        "oai-did": "did",
    }
    r = mod.check_cookies(cookies, source_file="t.json")
    assert r.oai_wm is True
    assert r.valid is True
    assert r.category == "unknown"
    assert "info_markers" in (r.extras or {})
