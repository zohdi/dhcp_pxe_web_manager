"""Application-managed local-user ACL persistence for DHCP Manager.

This database stores authorization metadata only. It never edits ISC DHCP
subnet declarations. VLAN ownership is derived from configured IPv4 CIDRs.
"""
from __future__ import annotations

import ipaddress
import sqlite3
from pathlib import Path
from typing import Iterable, Optional

ROLE_MANAGER = "manager"
ROLE_VLAN_EDITOR = "vlan_editor"
VALID_ROLES = {ROLE_MANAGER, ROLE_VLAN_EDITOR}


class ACLValidationError(ValueError):
    """Raised when ACL metadata is invalid or ambiguous."""


def reservations_outside_new_cidr(entries, old_cidr: str, new_cidr: str) -> list[dict]:
    """Return reservations currently in old_cidr that would fall outside new_cidr."""
    old_network = ipaddress.ip_network(old_cidr, strict=False)
    new_network = ipaddress.ip_network(new_cidr, strict=False)
    affected = []
    for entry in entries or []:
        try:
            address = ipaddress.ip_address(str(entry.get("ip", "")).strip())
        except ValueError:
            continue
        if address.version == 4 and address in old_network and address not in new_network:
            affected.append(entry)
    return affected


class ACLStore:
    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS vlans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    cidr TEXT NOT NULL UNIQUE,
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS principals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alias TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    role TEXT NOT NULL CHECK(role IN ('manager','vlan_editor')),
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS principal_vlans (
                    principal_id INTEGER NOT NULL,
                    vlan_id INTEGER NOT NULL,
                    PRIMARY KEY (principal_id, vlan_id),
                    FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
                    FOREIGN KEY (vlan_id) REFERENCES vlans(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    principal TEXT NOT NULL,
                    auth_source TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT,
                    ip TEXT,
                    result TEXT NOT NULL,
                    details TEXT
                );
                """
            )

    @staticmethod
    def normalize_alias(alias: str) -> str:
        value = (alias or "").strip().lower()
        if not value:
            raise ACLValidationError("Linux username is required")
        if len(value) > 128:
            raise ACLValidationError("Linux username is too long")
        if any(ch.isspace() for ch in value):
            raise ACLValidationError("Linux username cannot contain whitespace")
        return value

    @staticmethod
    def normalize_cidr(cidr: str) -> str:
        try:
            network = ipaddress.ip_network((cidr or "").strip(), strict=False)
        except ValueError as exc:
            raise ACLValidationError(f"Invalid VLAN CIDR: {cidr}") from exc
        if network.version != 4:
            raise ACLValidationError("Only IPv4 VLAN CIDRs are supported")
        return str(network)

    def add_vlan(self, name: str, cidr: str) -> dict:
        name = (name or "").strip()
        if not name:
            raise ACLValidationError("VLAN name is required")
        normalized = self.normalize_cidr(cidr)
        new_network = ipaddress.ip_network(normalized)

        with self._connect() as conn:
            existing = conn.execute("SELECT id, name, cidr FROM vlans").fetchall()
            for row in existing:
                if new_network.overlaps(ipaddress.ip_network(row["cidr"])):
                    raise ACLValidationError(
                        f"VLAN CIDR {normalized} overlaps existing {row['name']} ({row['cidr']})"
                    )
            try:
                cur = conn.execute(
                    "INSERT INTO vlans(name, cidr) VALUES (?, ?)",
                    (name, normalized),
                )
            except sqlite3.IntegrityError as exc:
                raise ACLValidationError("VLAN name or CIDR already exists") from exc
            row = conn.execute("SELECT * FROM vlans WHERE id = ?", (cur.lastrowid,)).fetchone()
            return dict(row)

    def get_vlan(self, vlan_id: int) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, name, cidr, enabled, created_at FROM vlans WHERE id = ?",
                (int(vlan_id),),
            ).fetchone()
        return dict(row) if row else None

    def update_vlan(self, vlan_id: int, name: str, cidr: str) -> dict:
        vlan_id = int(vlan_id)
        name = (name or "").strip()
        if not name:
            raise ACLValidationError("VLAN name is required")
        normalized = self.normalize_cidr(cidr)
        new_network = ipaddress.ip_network(normalized)

        with self._connect() as conn:
            current = conn.execute(
                "SELECT id, name, cidr FROM vlans WHERE id = ?",
                (vlan_id,),
            ).fetchone()
            if current is None:
                raise ACLValidationError("Unknown VLAN mapping")

            existing = conn.execute(
                "SELECT id, name, cidr FROM vlans WHERE id <> ?",
                (vlan_id,),
            ).fetchall()
            for row in existing:
                if new_network.overlaps(ipaddress.ip_network(row["cidr"])):
                    raise ACLValidationError(
                        f"VLAN CIDR {normalized} overlaps existing {row['name']} ({row['cidr']})"
                    )
            try:
                conn.execute(
                    "UPDATE vlans SET name = ?, cidr = ? WHERE id = ?",
                    (name, normalized, vlan_id),
                )
            except sqlite3.IntegrityError as exc:
                raise ACLValidationError("VLAN name or CIDR already exists") from exc
            row = conn.execute(
                "SELECT id, name, cidr, enabled, created_at FROM vlans WHERE id = ?",
                (vlan_id,),
            ).fetchone()
            return dict(row)

    def delete_vlan(self, vlan_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM vlans WHERE id = ?", (int(vlan_id),))

    def list_vlans(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, name, cidr, enabled, created_at FROM vlans ORDER BY name COLLATE NOCASE"
            ).fetchall()
        return [dict(row) for row in rows]

    def _validate_vlan_ids(self, conn: sqlite3.Connection, vlan_ids: Iterable[int]) -> list[int]:
        ids = sorted({int(v) for v in vlan_ids})
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        rows = conn.execute(
            f"SELECT id FROM vlans WHERE enabled = 1 AND id IN ({placeholders})",
            ids,
        ).fetchall()
        found = {row["id"] for row in rows}
        missing = [v for v in ids if v not in found]
        if missing:
            raise ACLValidationError(f"Unknown or disabled VLAN IDs: {missing}")
        return ids

    def upsert_principal(self, alias: str, role: str, vlan_ids: Iterable[int]) -> dict:
        alias = self.normalize_alias(alias)
        role = (role or "").strip().lower()
        if role not in VALID_ROLES:
            raise ACLValidationError(f"Invalid role: {role}")

        with self._connect() as conn:
            ids = self._validate_vlan_ids(conn, vlan_ids)
            if role == ROLE_VLAN_EDITOR and not ids:
                raise ACLValidationError("VLAN Editor requires at least one VLAN")
            if role == ROLE_MANAGER:
                ids = []

            existing = conn.execute(
                "SELECT id FROM principals WHERE alias = ? COLLATE NOCASE", (alias,)
            ).fetchone()
            if existing:
                principal_id = existing["id"]
                conn.execute(
                    "UPDATE principals SET role = ?, enabled = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (role, principal_id),
                )
                conn.execute("DELETE FROM principal_vlans WHERE principal_id = ?", (principal_id,))
            else:
                cur = conn.execute(
                    "INSERT INTO principals(alias, role, enabled) VALUES (?, ?, 1)",
                    (alias, role),
                )
                principal_id = cur.lastrowid

            conn.executemany(
                "INSERT INTO principal_vlans(principal_id, vlan_id) VALUES (?, ?)",
                [(principal_id, vlan_id) for vlan_id in ids],
            )

        principal = self.get_principal(alias)
        assert principal is not None
        return principal

    def set_principal_enabled(self, alias: str, enabled: bool) -> None:
        alias = self.normalize_alias(alias)
        with self._connect() as conn:
            conn.execute(
                "UPDATE principals SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE alias = ? COLLATE NOCASE",
                (1 if enabled else 0, alias),
            )

    def delete_principal(self, alias: str) -> None:
        alias = self.normalize_alias(alias)
        with self._connect() as conn:
            conn.execute("DELETE FROM principals WHERE alias = ? COLLATE NOCASE", (alias,))

    def get_principal(self, alias: str) -> Optional[dict]:
        try:
            alias = self.normalize_alias(alias)
        except ACLValidationError:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, alias, role, enabled, created_at, updated_at FROM principals WHERE alias = ? COLLATE NOCASE",
                (alias,),
            ).fetchone()
            if row is None:
                return None
            principal = dict(row)
            vlans = conn.execute(
                """
                SELECT v.id, v.name, v.cidr, v.enabled
                FROM vlans v
                JOIN principal_vlans pv ON pv.vlan_id = v.id
                WHERE pv.principal_id = ?
                ORDER BY v.name COLLATE NOCASE
                """,
                (row["id"],),
            ).fetchall()
        principal["vlans"] = [dict(v) for v in vlans]
        return principal

    def list_principals(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT alias FROM principals ORDER BY alias COLLATE NOCASE"
            ).fetchall()
        return [self.get_principal(row["alias"]) for row in rows]

    def vlan_for_ip(self, ip: str) -> Optional[dict]:
        try:
            address = ipaddress.ip_address((ip or "").strip())
        except ValueError:
            return None
        if address.version != 4:
            return None
        for vlan in self.list_vlans():
            if vlan["enabled"] and address in ipaddress.ip_network(vlan["cidr"]):
                return vlan
        return None

    def can_access_ip(self, alias: str, ip: str) -> bool:
        principal = self.get_principal(alias)
        if not principal or not principal["enabled"]:
            return False
        if principal["role"] == ROLE_MANAGER:
            return True
        try:
            address = ipaddress.ip_address((ip or "").strip())
        except ValueError:
            return False
        for vlan in principal["vlans"]:
            if vlan["enabled"] and address in ipaddress.ip_network(vlan["cidr"]):
                return True
        return False

    def record_audit(
        self,
        principal: str,
        auth_source: str,
        action: str,
        target: str | None,
        ip: str | None,
        result: str,
        details: str | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_log(principal, auth_source, action, target, ip, result, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    principal or "unknown",
                    auth_source or "unknown",
                    action,
                    target,
                    ip,
                    result,
                    details,
                ),
            )

    def list_audit(self, limit: int = 200) -> list[dict]:
        safe_limit = max(1, min(int(limit), 1000))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, principal, auth_source, action, target, ip, result, details
                FROM audit_log ORDER BY id DESC LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
        return [dict(row) for row in rows]
