from access_control import ACLStore, ROLE_MANAGER, ROLE_VLAN_EDITOR
from authorization import AuthorizationService


def make_service(tmp_path):
    store = ACLStore(tmp_path / "acl.db")
    return store, AuthorizationService(store)


def test_local_manager_has_global_view_and_edit(tmp_path):
    _, authz = make_service(tmp_path)
    ident = authz.resolve_session({"role": "manager", "username": "Admin", "auth_source": "local"})
    assert authz.can_view_ip(ident, "203.0.113.10")
    assert authz.can_edit_ip(ident, "203.0.113.10")
    assert authz.can_manage_global(ident)


def test_readonly_keeps_global_view_but_never_edit(tmp_path):
    _, authz = make_service(tmp_path)
    ident = authz.resolve_session({"role": "readonly", "username": "ReadOnly", "auth_source": "readonly"})
    assert authz.can_view_ip(ident, "203.0.113.10")
    assert not authz.can_edit_ip(ident, "203.0.113.10")
    assert not authz.can_manage_global(ident)


def test_vlan_editor_filters_entries_by_assigned_cidr(tmp_path):
    store, authz = make_service(tmp_path)
    v = store.add_vlan("TEAM-X", "10.50.10.0/24")
    store.upsert_principal("alice", ROLE_VLAN_EDITOR, [v["id"]])
    ident = authz.resolve_session({"role": "vlan_editor", "username": "alice", "auth_source": "ad"})
    entries = [
        {"hostname": "x", "ip": "10.50.10.20"},
        {"hostname": "y", "ip": "10.50.20.20"},
    ]
    assert [e["hostname"] for e in authz.filter_entries(ident, entries)] == ["x"]


def test_ad_role_is_reloaded_from_acl_and_revocation_is_immediate(tmp_path):
    store, authz = make_service(tmp_path)
    store.upsert_principal("boss", ROLE_MANAGER, [])
    session = {"role": "manager", "username": "boss", "auth_source": "ad"}
    assert authz.resolve_session(session).role == ROLE_MANAGER
    store.delete_principal("boss")
    assert authz.resolve_session(session) is None
