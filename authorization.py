"""Central authorization policy for DHCP Manager web sessions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Optional

from access_control import ACLStore, ROLE_MANAGER, ROLE_VLAN_EDITOR

ROLE_READONLY = "readonly"


@dataclass(frozen=True)
class Identity:
    username: str
    role: str
    auth_source: str


class AuthorizationService:
    def __init__(self, store: ACLStore):
        self.store = store

    def resolve_session(self, session_data: Mapping[str, object]) -> Optional[Identity]:
        username = str(session_data.get("username") or "").strip()
        role = str(session_data.get("role") or "").strip().lower()
        source = str(session_data.get("auth_source") or "").strip().lower()
        if not username:
            return None

        if source == "ad":
            principal = self.store.get_principal(username)
            if not principal or not principal["enabled"]:
                return None
            return Identity(principal["alias"], principal["role"], "ad")

        if source == "local" and role == ROLE_MANAGER:
            return Identity(username, ROLE_MANAGER, "local")

        if source == "readonly" and role == ROLE_READONLY:
            return Identity(username, ROLE_READONLY, "readonly")

        return None

    def can_manage_global(self, identity: Optional[Identity]) -> bool:
        return bool(identity and identity.role == ROLE_MANAGER)

    def can_edit_reservations(self, identity: Optional[Identity]) -> bool:
        return bool(identity and identity.role in (ROLE_MANAGER, ROLE_VLAN_EDITOR))

    def can_view_ip(self, identity: Optional[Identity], ip: str) -> bool:
        if identity is None:
            return False
        if identity.role in (ROLE_MANAGER, ROLE_READONLY):
            return True
        if identity.role == ROLE_VLAN_EDITOR and identity.auth_source == "ad":
            return self.store.can_access_ip(identity.username, ip)
        return False

    def can_edit_ip(self, identity: Optional[Identity], ip: str) -> bool:
        if identity is None:
            return False
        if identity.role == ROLE_MANAGER:
            return True
        if identity.role == ROLE_VLAN_EDITOR and identity.auth_source == "ad":
            return self.store.can_access_ip(identity.username, ip)
        return False

    def filter_entries(self, identity: Optional[Identity], entries: Iterable[dict]) -> list[dict]:
        return [entry for entry in entries if self.can_view_ip(identity, str(entry.get("ip", "")))]
