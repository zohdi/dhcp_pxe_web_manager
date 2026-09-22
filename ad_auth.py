"""Linux PAM authentication adapter used for AD/VAS-backed login."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ADAuthResult:
    success: bool
    reason: str


class ADAuthenticator:
    def __init__(self, service: str = "login"):
        self.service = (service or "login").strip() or "login"

    def authenticate(self, alias: str, password: str) -> ADAuthResult:
        alias = (alias or "").strip()
        if not alias or not password:
            return ADAuthResult(False, "AD username and password are required")
        try:
            import pam  # type: ignore
            if pam is None:
                raise ImportError("pam module unavailable")
        except (ImportError, ModuleNotFoundError):
            return ADAuthResult(False, "PAM support is unavailable; install python-pam on the Linux server")

        try:
            # A fresh PAM object per login avoids sharing mutable PAM state across requests.
            client = pam.pam()
            ok = bool(
                client.authenticate(
                    alias,
                    password,
                    service=self.service,
                    resetcreds=False,
                )
            )
            reason = str(getattr(client, "reason", "") or ("Success" if ok else "Authentication failure"))
            return ADAuthResult(ok, reason)
        except Exception as exc:
            # Never include the supplied password in errors/logging.
            return ADAuthResult(False, f"PAM authentication error: {exc}")
