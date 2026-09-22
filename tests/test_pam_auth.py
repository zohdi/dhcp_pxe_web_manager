import sys
from types import SimpleNamespace

from pam_auth import PAMAuthenticator, is_local_passwd_user


def test_is_local_passwd_user_reads_only_explicit_passwd_entries(tmp_path):
    passwd = tmp_path / "passwd"
    passwd.write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "localuser:x:1000:1000:Local User:/home/localuser:/bin/bash\n",
        encoding="utf-8",
    )

    assert is_local_passwd_user("localuser", passwd) is True
    assert is_local_passwd_user("domainuser", passwd) is False


def test_nonlocal_user_is_rejected_before_pam(monkeypatch, tmp_path):
    passwd = tmp_path / "passwd"
    passwd.write_text("localuser:x:1000:1000::/home/localuser:/bin/bash\n", encoding="utf-8")

    def pam_should_not_be_called():
        raise AssertionError("PAM must not be called for a nonlocal identity")

    monkeypatch.setitem(sys.modules, "pam", SimpleNamespace(pam=pam_should_not_be_called))

    auth = PAMAuthenticator("login", passwd_path=passwd)
    result = auth.authenticate("domainuser", "secret")

    assert result.success is False
    assert "local /etc/passwd account" in result.reason


def test_local_user_can_reach_pam(monkeypatch, tmp_path):
    passwd = tmp_path / "passwd"
    passwd.write_text("localuser:x:1000:1000::/home/localuser:/bin/bash\n", encoding="utf-8")

    calls = {}

    class FakePamClient:
        reason = "Success"

        def authenticate(self, username, password, service, resetcreds):
            calls.update(
                username=username,
                password=password,
                service=service,
                resetcreds=resetcreds,
            )
            return True

    monkeypatch.setitem(sys.modules, "pam", SimpleNamespace(pam=FakePamClient))

    auth = PAMAuthenticator("login", passwd_path=passwd)
    result = auth.authenticate("localuser", "secret")

    assert result.success is True
    assert calls == {
        "username": "localuser",
        "password": "secret",
        "service": "login",
        "resetcreds": False,
    }
