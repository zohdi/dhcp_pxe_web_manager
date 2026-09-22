"""Linux PAM authentication adapter for ACL-approved local users."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PAMAuthResult:
    success: bool
    reason: str


class PAMAuthenticator:
    def __init__(self, service: str = "login"):
        self.service = (service or "login").strip() or "login"

    def authenticate(self, username: str, password: str) -> PAMAuthResult:
        username = (username or "").strip()
        if not username or not password:
            return PAMAuthResult(False, "Linux username and password are required")
        try:
            import pam  # type: ignore
            if pam is None:
                raise ImportError("pam module unavailable")
        except (ImportError, ModuleNotFoundError):
            return PAMAuthResult(False, "PAM support is unavailable; install python-pam on the Linux server")

        try:
            client = pam.pam()
            ok = bool(
                client.authenticate(
                    username,
                    password,
                    service=self.service,
                    resetcreds=False,
                )
            )
            reason = str(getattr(client, "reason", "") or ("Success" if ok else "Authentication failure"))
            return PAMAuthResult(ok, reason)
        except Exception as exc:
            return PAMAuthResult(False, f"PAM authentication error: {exc}")
