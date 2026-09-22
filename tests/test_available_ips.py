from pathlib import Path
import json
import time

import pytest

from availability_scanner import (
    AvailableIPScanner,
    ScanError,
    filter_available_cache,
    parse_active_leases,
    parse_dhcp_config,
    parse_nmap_xml,
)


DHCP_CONF = r'''
# Entire commented reservation must never count as allocated.
# host dead-old {
#   hardware ethernet aa:bb:cc:dd:ee:00;
#   fixed-address 172.28.103.60;
# }

subnet 172.28.103.0 netmask 255.255.255.0 {
    option routers 172.28.103.1;
    range 172.28.103.101 172.28.103.240;

    host active-one {
        hardware ethernet aa:bb:cc:dd:ee:01;
        fixed-address 172.28.103.50;
    }
}

subnet 172.21.80.0 netmask 255.255.255.0 {
    option routers 172.21.80.1; # inline comments must not affect parsing
    range dynamic-bootp 172.21.80.101 172.21.80.240;
}

subnet 10.99.0.0 netmask 255.255.255.0 {
    option routers 10.99.0.1;
}
'''

LEASES = r'''
lease 172.28.103.70 {
  binding state active;
}
lease 172.28.103.71 {
  binding state active;
}
# A later record is authoritative for the same address.
lease 172.28.103.71 {
  binding state free;
}
lease 172.21.80.77 {
  binding state active;
}
'''


def test_parse_dhcp_config_discovers_subnets_ranges_gateways_and_only_active_reservations():
    parsed = parse_dhcp_config(DHCP_CONF)

    assert [s.cidr for s in parsed.subnets] == [
        "172.28.103.0/24",
        "172.21.80.0/24",
        "10.99.0.0/24",
    ]
    assert parsed.subnets[0].dynamic_ranges == [
        ("172.28.103.101", "172.28.103.240")
    ]
    assert parsed.subnets[1].dynamic_ranges == [
        ("172.21.80.101", "172.21.80.240")
    ]
    assert parsed.subnets[0].gateways == ["172.28.103.1"]
    assert "172.28.103.50" in parsed.fixed_addresses
    assert "172.28.103.60" not in parsed.fixed_addresses


def test_active_lease_parser_uses_latest_binding_state():
    active = parse_active_leases(LEASES)
    assert active == {"172.28.103.70", "172.21.80.77"}


def test_nmap_xml_parser_returns_only_up_ipv4_hosts():
    xml = '''<?xml version="1.0"?>
    <nmaprun>
      <host><status state="up"/><address addr="172.28.103.10" addrtype="ipv4"/></host>
      <host><status state="down"/><address addr="172.28.103.11" addrtype="ipv4"/></host>
      <host><status state="up"/><address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/></host>
    </nmaprun>'''
    assert parse_nmap_xml(xml) == {"172.28.103.10"}


def test_scan_excludes_dynamic_ranges_reservations_gateways_active_leases_and_live_hosts(tmp_path, monkeypatch):
    conf = tmp_path / "dhcpd.conf"
    leases = tmp_path / "dhcpd.leases"
    cache = tmp_path / "available_ips.json"
    conf.write_text(DHCP_CONF, encoding="utf-8")
    leases.write_text(LEASES, encoding="utf-8")

    scanner = AvailableIPScanner(
        dhcp_conf=conf,
        leases_file=leases,
        cache_file=cache,
        nmap_bin="nmap",
        ping_bin="ping",
        ping_verify=True,
        ping_workers=8,
        ping_timeout_seconds=1,
    )

    seen_networks = []

    def fake_nmap(target):
        seen_networks.append(target)
        if target == "172.28.103.0/24":
            return {"172.28.103.10"}
        if target == "172.21.80.0/24":
            return {"172.21.80.10"}
        return set()

    monkeypatch.setattr(scanner, "_discover_nmap_up", fake_nmap)
    monkeypatch.setattr(
        scanner,
        "_parallel_ping_up",
        lambda ips: {"172.28.103.11"} if "172.28.103.11" in ips else set(),
    )

    result = scanner.scan_and_cache(
        managed_cidrs=["172.28.103.0/24", "172.21.80.0/24"]
    )

    assert seen_networks == ["172.28.103.0/24", "172.21.80.0/24"]
    assert result["skipped_unmanaged_subnets"] == ["10.99.0.0/24"]
    subnet_103 = next(s for s in result["subnets"] if s["cidr"] == "172.28.103.0/24")
    available = set(subnet_103["available_ips"])

    assert "172.28.103.1" not in available       # gateway
    assert "172.28.103.50" not in available      # fixed reservation
    assert "172.28.103.70" not in available      # active lease
    assert "172.28.103.101" not in available     # dynamic range
    assert "172.28.103.240" not in available     # dynamic range end inclusive
    assert "172.28.103.10" not in available      # nmap up
    assert "172.28.103.11" not in available      # ping responded
    assert "172.28.103.2" in available
    assert cache.exists()

    loaded = json.loads(cache.read_text(encoding="utf-8"))
    assert loaded["schema_version"] == 1
    assert loaded["subnets"][0]["cidr"] == "172.28.103.0/24"


def test_scan_fails_closed_when_nmap_fails(tmp_path, monkeypatch):
    conf = tmp_path / "dhcpd.conf"
    leases = tmp_path / "dhcpd.leases"
    cache = tmp_path / "available_ips.json"
    conf.write_text(DHCP_CONF, encoding="utf-8")
    leases.write_text("", encoding="utf-8")
    scanner = AvailableIPScanner(conf, leases, cache)

    def fail(_target):
        raise ScanError("nmap failed")

    monkeypatch.setattr(scanner, "_discover_nmap_up", fail)
    with pytest.raises(ScanError):
        scanner.scan_and_cache(managed_cidrs=["172.28.103.0/24"])
    assert not cache.exists()


def test_filter_cache_keeps_only_authorized_ips_and_real_subnet_cidrs():
    cache = {
        "schema_version": 1,
        "generated_at": "2026-09-22T10:00:00+00:00",
        "subnets": [
            {"cidr": "172.28.103.0/24", "available_ips": ["172.28.103.2", "172.28.103.3"]},
            {"cidr": "172.21.80.0/24", "available_ips": ["172.21.80.2"]},
        ],
    }
    filtered = filter_available_cache(cache, lambda ip: ip.startswith("172.28.103."))
    assert [s["cidr"] for s in filtered["subnets"]] == ["172.28.103.0/24"]
    assert filtered["subnets"][0]["available_ips"] == ["172.28.103.2", "172.28.103.3"]


def test_candidate_validation_rechecks_config_leases_and_live_status(tmp_path, monkeypatch):
    conf = tmp_path / "dhcpd.conf"
    leases = tmp_path / "dhcpd.leases"
    cache = tmp_path / "available_ips.json"
    conf.write_text(DHCP_CONF, encoding="utf-8")
    leases.write_text(LEASES, encoding="utf-8")
    scanner = AvailableIPScanner(conf, leases, cache, ping_verify=True)

    monkeypatch.setattr(scanner, "_discover_nmap_up", lambda target: {"172.28.103.20"} if target == "172.28.103.20" else set())
    monkeypatch.setattr(scanner, "_parallel_ping_up", lambda ips: {"172.28.103.21"} if "172.28.103.21" in ips else set())

    ok, reason = scanner.validate_candidate("172.28.103.50")
    assert not ok and "reserved" in reason.lower()

    ok, reason = scanner.validate_candidate("172.28.103.101")
    assert not ok and "dynamic" in reason.lower()

    ok, reason = scanner.validate_candidate("172.28.103.70")
    assert not ok and "lease" in reason.lower()

    ok, reason = scanner.validate_candidate("172.28.103.20")
    assert not ok and "nmap" in reason.lower()

    ok, reason = scanner.validate_candidate("172.28.103.21")
    assert not ok and "ping" in reason.lower()

    ok, reason = scanner.validate_candidate("172.28.103.22")
    assert ok and reason == "available"


def test_scan_never_discovers_unmapped_dhcp_subnets(tmp_path, monkeypatch):
    conf = tmp_path / "dhcpd.conf"
    leases = tmp_path / "dhcpd.leases"
    cache = tmp_path / "available_ips.json"
    conf.write_text(DHCP_CONF, encoding="utf-8")
    leases.write_text("", encoding="utf-8")
    scanner = AvailableIPScanner(conf, leases, cache, ping_verify=False)

    seen = []
    monkeypatch.setattr(scanner, "_discover_nmap_up", lambda target: seen.append(target) or set())

    result = scanner.scan_and_cache(managed_cidrs=["172.28.103.0/24"])

    assert seen == ["172.28.103.0/24"]
    assert [item["cidr"] for item in result["subnets"]] == ["172.28.103.0/24"]
    assert result["managed_vlan_cidrs"] == ["172.28.103.0/24"]
    assert result["skipped_unmanaged_subnets"] == ["172.21.80.0/24", "10.99.0.0/24"]


def test_scan_with_no_managed_vlans_scans_nothing(tmp_path, monkeypatch):
    conf = tmp_path / "dhcpd.conf"
    leases = tmp_path / "dhcpd.leases"
    cache = tmp_path / "available_ips.json"
    conf.write_text(DHCP_CONF, encoding="utf-8")
    leases.write_text("", encoding="utf-8")
    scanner = AvailableIPScanner(conf, leases, cache, ping_verify=False)

    monkeypatch.setattr(
        scanner,
        "_discover_nmap_up",
        lambda target: (_ for _ in ()).throw(AssertionError(f"unexpected scan: {target}")),
    )

    result = scanner.scan_and_cache(managed_cidrs=[])
    assert result["subnets"] == []
    assert result["available_count"] == 0
    assert result["skipped_unmanaged_subnets"] == [
        "172.28.103.0/24",
        "172.21.80.0/24",
        "10.99.0.0/24",
    ]


def test_cache_staleness_and_removal(tmp_path):
    conf = tmp_path / "dhcpd.conf"
    leases = tmp_path / "dhcpd.leases"
    cache_path = tmp_path / "available_ips.json"
    conf.write_text(DHCP_CONF, encoding="utf-8")
    leases.write_text("", encoding="utf-8")
    scanner = AvailableIPScanner(conf, leases, cache_path, cache_max_age_hours=24)

    cache = {
        "schema_version": 1,
        "generated_at_epoch": time.time(),
        "generated_at": "2026-09-22T10:00:00+00:00",
        "subnets": [
            {"cidr": "172.28.103.0/24", "available_ips": ["172.28.103.2", "172.28.103.3"]}
        ],
    }
    scanner.write_cache(cache)
    assert scanner.is_cache_stale(scanner.read_cache()) is False

    scanner.remove_cached_ip("172.28.103.2")
    assert scanner.read_cache()["subnets"][0]["available_ips"] == ["172.28.103.3"]

    old = scanner.read_cache()
    old["generated_at_epoch"] = time.time() - (25 * 3600)
    scanner.write_cache(old)
    assert scanner.is_cache_stale(scanner.read_cache()) is True
