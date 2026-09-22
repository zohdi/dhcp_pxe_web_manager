"""Linux PAM authentication adapter for ACL-approved local users.

Only accounts physically present in /etc/passwd are eligible. This deliberately
does not use NSS/getent/pwd.getpwnam(), because those can expose VAS/AD users as
resolvable identities on domain-joined hosts.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

DEFAULT_PASSWD_PATH = Path("/etc/passwd")


@dataclass(frozen=True)
class PAMAuthResult:
    success: bool
    reason: str


def is_local_passwd_user(username: str, passwd_path: Path | str = DEFAULT_PASSWD_PATH) -> bool:
    """Return True only when username is explicitly stored in the passwd file."""
    username = (username or "").strip()
    if not username or ":" in username or "\n" in username or "\r" in username:
        return False

    try:
        with Path(passwd_path).open("r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                line = raw_line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                if line.split(":", 1)[0] == username:
                    return True
    except OSError:
        return False

    return False


class PAMAuthenticator:
    def __init__(
        self,
        service: str = "login",
        passwd_path: Path | str = DEFAULT_PASSWD_PATH,
    ):
        self.service = (service or "login").strip() or "login"
        self.passwd_path = Path(passwd_path)

    def authenticate(self, username: str, password: str) -> PAMAuthResult:
        username = (username or "").strip()
        if not username or not password:
            return PAMAuthResult(False, "Linux username and password are required")

        # Fail closed before PAM. On VAS/SSSD/NIS-enabled hosts, NSS may resolve
        # remote/domain identities, so only an entry physically present in
        # /etc/passwd is considered a local Linux user for this branch.
        if not is_local_passwd_user(username, self.passwd_path):
            return PAMAuthResult(False, "Linux username is not a local /etc/passwd account")

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
