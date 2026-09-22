import sqlite3
import pytest

from access_control import ACLStore, ACLValidationError, ROLE_MANAGER, ROLE_VLAN_EDITOR


def store(tmp_path):
    return ACLStore(tmp_path / "acl.db")


def test_new_store_starts_with_empty_acl(tmp_path):
    s = store(tmp_path)
    assert s.list_vlans() == []
    assert s.list_principals() == []


def test_vlan_cidr_is_canonicalized_and_overlap_is_rejected(tmp_path):
    s = store(tmp_path)
    vlan = s.add_vlan("LAB", "10.20.30.44/24")
    assert vlan["cidr"] == "10.20.30.0/24"
    with pytest.raises(ACLValidationError, match="overlaps"):
        s.add_vlan("LAB2", "10.20.30.128/25")


def test_vlan_editor_can_access_only_assigned_vlan(tmp_path):
    s = store(tmp_path)
    lab = s.add_vlan("LAB", "10.20.10.0/24")
    storage = s.add_vlan("STORAGE", "10.20.20.0/24")
    s.upsert_principal("Alice", ROLE_VLAN_EDITOR, [lab["id"]])

    assert s.can_access_ip("alice", "10.20.10.55") is True
    assert s.can_access_ip("ALICE", "10.20.20.55") is False
    assert s.can_access_ip("alice", "192.168.1.1") is False


def test_manager_can_access_any_ip_without_vlan_assignments(tmp_path):
    s = store(tmp_path)
    s.upsert_principal("boss", ROLE_MANAGER, [])
    assert s.can_access_ip("boss", "10.99.99.99") is True
    assert s.can_access_ip("boss", "192.0.2.42") is True


def test_vlan_editor_requires_at_least_one_vlan(tmp_path):
    s = store(tmp_path)
    with pytest.raises(ACLValidationError, match="at least one VLAN"):
        s.upsert_principal("alice", ROLE_VLAN_EDITOR, [])


def test_principal_update_replaces_vlan_scope(tmp_path):
    s = store(tmp_path)
    a = s.add_vlan("A", "10.1.0.0/24")
    b = s.add_vlan("B", "10.2.0.0/24")
    s.upsert_principal("alice", ROLE_VLAN_EDITOR, [a["id"]])
    s.upsert_principal("alice", ROLE_VLAN_EDITOR, [b["id"]])
    p = s.get_principal("ALICE")
    assert [v["name"] for v in p["vlans"]] == ["B"]


def test_deleting_vlan_cascades_scope_and_editor_loses_access(tmp_path):
    s = store(tmp_path)
    vlan = s.add_vlan("LAB", "10.8.0.0/24")
    s.upsert_principal("alice", ROLE_VLAN_EDITOR, [vlan["id"]])
    s.delete_vlan(vlan["id"])
    assert s.can_access_ip("alice", "10.8.0.10") is False


def test_audit_log_records_event_without_schema_seed(tmp_path):
    s = store(tmp_path)
    s.record_audit("Admin", "local", "ACL_VLAN_ADD", "LAB", "10.1.0.0/24", "SUCCESS", "created")
    events = s.list_audit(limit=10)
    assert len(events) == 1
    assert events[0]["principal"] == "Admin"
    assert events[0]["action"] == "ACL_VLAN_ADD"
    assert events[0]["result"] == "SUCCESS"


def test_vlan_update_preserves_id_and_editor_assignment(tmp_path):
    s = store(tmp_path)
    vlan = s.add_vlan("TEAM-X", "10.50.10.0/24")
    s.upsert_principal("alice", ROLE_VLAN_EDITOR, [vlan["id"]])

    updated = s.update_vlan(vlan["id"], "TEAM-RENAMED", "10.50.11.44/24")

    assert updated["id"] == vlan["id"]
    assert updated["name"] == "TEAM-RENAMED"
    assert updated["cidr"] == "10.50.11.0/24"
    principal = s.get_principal("alice")
    assert principal["vlans"] == [
        {"id": vlan["id"], "name": "TEAM-RENAMED", "cidr": "10.50.11.0/24", "enabled": 1}
    ]
    assert s.can_access_ip("alice", "10.50.10.20") is False
    assert s.can_access_ip("alice", "10.50.11.20") is True


def test_vlan_update_rejects_overlap_without_changing_existing_mapping(tmp_path):
    s = store(tmp_path)
    first = s.add_vlan("FIRST", "10.60.10.0/24")
    s.add_vlan("SECOND", "10.60.20.0/24")

    with pytest.raises(ACLValidationError, match="overlaps"):
        s.update_vlan(first["id"], "FIRST", "10.60.20.128/25")

    assert s.get_vlan(first["id"])["cidr"] == "10.60.10.0/24"


def test_reservations_outside_new_cidr_reports_only_old_scope_that_will_be_lost():
    from access_control import reservations_outside_new_cidr

    entries = [
        {"hostname": "keep", "ip": "10.70.10.10"},
        {"hostname": "lost", "ip": "10.70.10.200"},
        {"hostname": "other", "ip": "10.70.20.10"},
        {"hostname": "bad", "ip": "not-an-ip"},
    ]

    affected = reservations_outside_new_cidr(
        entries,
        old_cidr="10.70.10.0/24",
        new_cidr="10.70.10.0/25",
    )

    assert [entry["hostname"] for entry in affected] == ["lost"]
