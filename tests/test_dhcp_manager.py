from pathlib import Path

import pytest

from exceptions import EntryExistsError, EntryNotFoundError
from managers.dhcp_manager import DHCPManager


SAMPLE_CONF = """
default-lease-time 600;
max-lease-time 7200;

host server1 {
    hardware ethernet aa:bb:cc:dd:ee:ff;
    fixed-address 192.168.1.10;
    option host-name "server1";
    ddns-hostname "server1";
}
"""


def manager_for(tmp_path: Path, content: str = SAMPLE_CONF) -> DHCPManager:
    conf = tmp_path / "dhcpd.conf"
    backup = tmp_path / "dhcpd.conf.bak"
    conf.write_text(content)
    backup.write_text(content)
    mgr = DHCPManager(dhcp_conf=conf, backup_conf=backup)
    # Unit tests should not call dhcpd/systemctl on the host.
    mgr.apply_changes = lambda: None
    return mgr


def test_parse_entries(tmp_path: Path):
    mgr = manager_for(tmp_path)
    assert mgr.get_all_entries() == [
        {"hostname": "server1", "mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.10"}
    ]


def test_add_entry_rejects_duplicate_ip(tmp_path: Path):
    mgr = manager_for(tmp_path)
    with pytest.raises(EntryExistsError):
        mgr.add_entry("server2", "00:11:22:33:44:55", "192.168.1.10")


def test_modify_entry_updates_selected_fields(tmp_path: Path):
    mgr = manager_for(tmp_path)
    mgr.modify_entry("server1", new_ip="192.168.1.20")
    entry = mgr.find_entry("server1")
    assert entry is not None
    assert entry["ip"] == "192.168.1.20"


def test_remove_entry_deletes_host_block(tmp_path: Path):
    mgr = manager_for(tmp_path)
    mgr.remove_entry("server1")
    assert mgr.get_all_entries() == []


def test_find_missing_entry_returns_none(tmp_path: Path):
    mgr = manager_for(tmp_path)
    assert mgr.find_entry("missing") is None

def test_add_entry_can_stage_without_restart(tmp_path: Path):
    mgr = manager_for(tmp_path)
    calls = {"apply": 0, "validate_staged": 0}
    mgr.apply_changes = lambda: calls.__setitem__("apply", calls["apply"] + 1)
    mgr.validate_staged_changes = lambda: calls.__setitem__(
        "validate_staged", calls["validate_staged"] + 1
    )

    mgr.add_entry(
        "server2",
        "00:11:22:33:44:55",
        "192.168.1.20",
        apply_immediately=False,
    )

    assert calls == {"apply": 0, "validate_staged": 1}
    assert mgr.find_entry("server2") is not None
