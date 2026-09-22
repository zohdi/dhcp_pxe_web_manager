#!/usr/bin/env python3
"""Refresh the DHCP available-IP JSON cache from live configuration/network state."""
from access_control import ACLStore
from availability_scanner import AvailableIPScanner, ScanError
from config import config


def main() -> int:
    scanner = AvailableIPScanner.from_config(config)
    acl_store = ACLStore(config.ACL_DB_PATH)
    managed_cidrs = [
        vlan["cidr"]
        for vlan in acl_store.list_vlans()
        if vlan.get("enabled")
    ]
    try:
        result = scanner.scan_and_cache(managed_cidrs=managed_cidrs)
    except ScanError as exc:
        print(f"Available IP refresh FAILED: {exc}")
        return 1
    print(
        f"Available IP refresh complete: {result.get('available_count', 0)} candidates "
        f"across {len(result.get('subnets', []))} subnet(s)."
    )
    print(f"Cache: {config.AVAILABLE_IP_CACHE_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
