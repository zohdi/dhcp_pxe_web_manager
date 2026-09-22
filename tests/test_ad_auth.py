import sys
import types

from ad_auth import ADAuthenticator


def test_missing_pam_dependency_fails_closed(monkeypatch):
    monkeypatch.setitem(sys.modules, "pam", None)
    result = ADAuthenticator("login").authenticate("alice", "secret")
    assert result.success is False
    assert "PAM" in result.reason


def test_authenticator_uses_configured_service_and_resetcreds_false(monkeypatch):
    calls = {}

    class FakePam:
        reason = "Success"
        def authenticate(self, username, password, service=None, resetcreds=None):
            calls.update(username=username, password=password, service=service, resetcreds=resetcreds)
            return True

    fake_module = types.SimpleNamespace(pam=lambda: FakePam())
    monkeypatch.setitem(sys.modules, "pam", fake_module)
    result = ADAuthenticator("dhcp-manager").authenticate("alice", "secret")
    assert result.success is True
    assert calls == {
        "username": "alice",
        "password": "secret",
        "service": "dhcp-manager",
        "resetcreds": False,
    }


def test_failed_pam_authentication_returns_false(monkeypatch):
    class FakePam:
        reason = "Authentication failure"
        def authenticate(self, *args, **kwargs):
            return False

    monkeypatch.setitem(sys.modules, "pam", types.SimpleNamespace(pam=lambda: FakePam()))
    result = ADAuthenticator().authenticate("alice", "bad")
    assert result.success is False
    assert result.reason == "Authentication failure"
