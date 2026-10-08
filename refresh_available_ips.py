#!/usr/bin/env python3
"""Refresh the DHCP available-IP JSON cache from live configuration/network state."""
import argparse
import fcntl
from datetime import datetime, timezone

from access_control import ACLStore
from availability_scanner import AvailableIPScanner, ScanError
from config import config


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reason", default="scheduled/manual refresh")
    args = parser.parse_args()

    scanner = AvailableIPScanner.from_config(config)
    acl_store = ACLStore(config.ACL_DB_PATH)
    managed_cidrs = [
        vlan["cidr"]
        for vlan in acl_store.list_vlans()
        if vlan.get("enabled")
    ]

    lock_path = config.AVAILABLE_IP_CACHE_PATH.parent / "available_ips_refresh.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    with lock_path.open("a+", encoding="utf-8") as lock_handle:
        print(
            f"[{datetime.now(timezone.utc).isoformat()}] "
            f"Waiting for Available IP scan lock; reason={args.reason}",
            flush=True,
        )
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        print(
            f"[{datetime.now(timezone.utc).isoformat()}] "
            f"Starting Available IP scan; reason={args.reason}",
            flush=True,
        )
        try:
            result = scanner.scan_and_cache(managed_cidrs=managed_cidrs)
        except ScanError as exc:
            print(f"Available IP refresh FAILED: {exc}", flush=True)
            return 1
        except Exception as exc:
            print(f"Available IP refresh FAILED unexpectedly: {exc}", flush=True)
            return 1

        print(
            f"Available IP refresh complete: {result.get('available_count', 0)} candidates "
            f"across {len(result.get('subnets', []))} subnet(s).",
            flush=True,
        )
        print(f"Cache: {config.AVAILABLE_IP_CACHE_PATH}", flush=True)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
