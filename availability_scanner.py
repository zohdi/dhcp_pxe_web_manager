"""Available DHCP reservation IP discovery and cache management.

The scanner treats dhcpd.conf as the source of truth for subnet/range/reservation
configuration, excludes active ISC DHCP leases, performs one Nmap host-discovery
pass per subnet, and optionally verifies remaining candidates with parallel
single-packet pings.
"""
from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional


class ScanError(RuntimeError):
    """Raised when availability scanning cannot be completed safely."""


@dataclass(frozen=True)
class SubnetPlan:
    cidr: str
    dynamic_ranges: list[tuple[str, str]]
    gateways: list[str]


@dataclass(frozen=True)
class ParsedDHCPConfig:
    subnets: list[SubnetPlan]
    fixed_addresses: set[str]


def _strip_comments(text: str) -> str:
    """Strip DHCP-style # comments, including inline comments, outside quotes."""
    cleaned: list[str] = []
    for line in text.splitlines():
        out: list[str] = []
        quoted = False
        escaped = False
        for char in line:
            if escaped:
                out.append(char)
                escaped = False
                continue
            if char == "\\" and quoted:
                out.append(char)
                escaped = True
                continue
            if char == '"':
                quoted = not quoted
                out.append(char)
                continue
            if char == "#" and not quoted:
                break
            out.append(char)
        cleaned.append("".join(out))
    return "\n".join(cleaned)


def _matching_brace(text: str, open_index: int) -> int:
    depth = 0
    quoted = False
    escaped = False
    for idx in range(open_index, len(text)):
        char = text[idx]
        if escaped:
            escaped = False
            continue
        if char == "\\" and quoted:
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
            continue
        if quoted:
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return idx
    raise ScanError("Unbalanced braces in dhcpd.conf")


def _ipv4(value: str) -> Optional[str]:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return str(address) if address.version == 4 else None


def parse_dhcp_config(text: str) -> ParsedDHCPConfig:
    """Parse active IPv4 subnets, ranges, routers, and fixed reservations."""
    cleaned = _strip_comments(text)

    fixed_addresses: set[str] = set()
    for match in re.finditer(r"\bfixed-address\s+([^;]+);", cleaned, flags=re.I):
        for token in re.split(r"[\s,]+", match.group(1).strip()):
            value = _ipv4(token)
            if value:
                fixed_addresses.add(value)

    subnets: list[SubnetPlan] = []
    subnet_re = re.compile(
        r"\bsubnet\s+(\d{1,3}(?:\.\d{1,3}){3})\s+netmask\s+"
        r"(\d{1,3}(?:\.\d{1,3}){3})\s*\{",
        flags=re.I,
    )
    pos = 0
    while True:
        match = subnet_re.search(cleaned, pos)
        if not match:
            break
        open_brace = cleaned.find("{", match.start(), match.end())
        close_brace = _matching_brace(cleaned, open_brace)
        body = cleaned[open_brace + 1 : close_brace]
        pos = close_brace + 1

        try:
            network = ipaddress.ip_network(f"{match.group(1)}/{match.group(2)}", strict=False)
        except ValueError as exc:
            raise ScanError(f"Invalid subnet declaration: {match.group(0)!r}: {exc}") from exc
        if network.version != 4:
            continue

        dynamic_ranges: list[tuple[str, str]] = []
        range_re = re.compile(
            r"\brange(?:\s+dynamic-bootp)?\s+"
            r"(\d{1,3}(?:\.\d{1,3}){3})\s+"
            r"(\d{1,3}(?:\.\d{1,3}){3})\s*;",
            flags=re.I,
        )
        for range_match in range_re.finditer(body):
            start = _ipv4(range_match.group(1))
            end = _ipv4(range_match.group(2))
            if not start or not end:
                continue
            start_ip = ipaddress.ip_address(start)
            end_ip = ipaddress.ip_address(end)
            if start_ip not in network or end_ip not in network or int(start_ip) > int(end_ip):
                raise ScanError(f"Invalid DHCP range {start}-{end} in subnet {network}")
            dynamic_ranges.append((start, end))

        gateways: list[str] = []
        for router_match in re.finditer(r"\boption\s+routers\s+([^;]+);", body, flags=re.I):
            for token in re.split(r"[\s,]+", router_match.group(1).strip()):
                value = _ipv4(token)
                if value and ipaddress.ip_address(value) in network and value not in gateways:
                    gateways.append(value)

        subnets.append(
            SubnetPlan(
                cidr=str(network),
                dynamic_ranges=dynamic_ranges,
                gateways=gateways,
            )
        )

    return ParsedDHCPConfig(subnets=subnets, fixed_addresses=fixed_addresses)


def parse_active_leases(text: str) -> set[str]:
    """Return IPs whose latest lease record has binding state active."""
    cleaned = _strip_comments(text)
    states: dict[str, str] = {}
    lease_re = re.compile(
        r"\blease\s+(\d{1,3}(?:\.\d{1,3}){3})\s*\{(.*?)\}",
        flags=re.I | re.S,
    )
    for match in lease_re.finditer(cleaned):
        ip = _ipv4(match.group(1))
        if not ip:
            continue
        state_match = re.search(r"\bbinding\s+state\s+([A-Za-z-]+)\s*;", match.group(2), flags=re.I)
        if state_match:
            states[ip] = state_match.group(1).lower()
    return {ip for ip, state in states.items() if state == "active"}


def parse_nmap_xml(xml_text: str) -> set[str]:
    """Parse Nmap XML and return IPv4 addresses explicitly reported UP."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ScanError(f"Unable to parse Nmap XML: {exc}") from exc

    up: set[str] = set()
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        for address in host.findall("address"):
            if address.get("addrtype") == "ipv4":
                value = _ipv4(address.get("addr", ""))
                if value:
                    up.add(value)
    return up


def filter_available_cache(cache: dict, predicate: Callable[[str], bool]) -> dict:
    """Copy an availability cache while retaining only IPs allowed by predicate."""
    filtered = copy.deepcopy(cache)
    filtered_subnets = []
    for subnet in cache.get("subnets", []):
        visible = [ip for ip in subnet.get("available_ips", []) if predicate(ip)]
        if not visible:
            continue
        item = copy.deepcopy(subnet)
        item["available_ips"] = visible
        item["available_count_visible"] = len(visible)
        filtered_subnets.append(item)
    filtered["subnets"] = filtered_subnets
    filtered["available_count_visible"] = sum(
        len(item.get("available_ips", [])) for item in filtered_subnets
    )
    return filtered


class AvailableIPScanner:
    def __init__(
        self,
        dhcp_conf: Path,
        leases_file: Path,
        cache_file: Path,
        nmap_bin: str = "nmap",
        ping_bin: str = "ping",
        ping_verify: bool = True,
        ping_workers: int = 32,
        ping_timeout_seconds: int = 1,
        cache_max_age_hours: int = 24,
        nmap_timeout_seconds: int = 180,
        max_hosts_per_subnet: int = 4096,
    ):
        self.dhcp_conf = Path(dhcp_conf)
        self.leases_file = Path(leases_file)
        self.cache_file = Path(cache_file)
        self.nmap_bin = nmap_bin
        self.ping_bin = ping_bin
        self.ping_verify = bool(ping_verify)
        self.ping_workers = max(1, int(ping_workers))
        self.ping_timeout_seconds = max(1, int(ping_timeout_seconds))
        self.cache_max_age_hours = max(1, int(cache_max_age_hours))
        self.nmap_timeout_seconds = max(10, int(nmap_timeout_seconds))
        self.max_hosts_per_subnet = max(2, int(max_hosts_per_subnet))

    @classmethod
    def from_config(cls, config):
        return cls(
            dhcp_conf=config.DHCP_CONF,
            leases_file=config.DHCP_LEASES_FILE,
            cache_file=config.AVAILABLE_IP_CACHE_PATH,
            nmap_bin=config.AVAILABLE_IP_NMAP_BIN,
            ping_bin=config.AVAILABLE_IP_PING_BIN,
            ping_verify=config.AVAILABLE_IP_PING_VERIFY,
            ping_workers=config.AVAILABLE_IP_PING_WORKERS,
            ping_timeout_seconds=config.AVAILABLE_IP_PING_TIMEOUT_SECONDS,
            cache_max_age_hours=config.AVAILABLE_IP_CACHE_MAX_AGE_HOURS,
            nmap_timeout_seconds=config.AVAILABLE_IP_NMAP_TIMEOUT_SECONDS,
            max_hosts_per_subnet=config.AVAILABLE_IP_MAX_HOSTS_PER_SUBNET,
        )

    def _read_dhcp(self) -> str:
        try:
            return self.dhcp_conf.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ScanError(f"Unable to read DHCP config {self.dhcp_conf}: {exc}") from exc

    def _read_leases(self) -> str:
        try:
            return self.leases_file.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return ""
        except OSError as exc:
            raise ScanError(f"Unable to read DHCP leases {self.leases_file}: {exc}") from exc

    def _discover_nmap_up(self, target: str) -> set[str]:
        if shutil.which(self.nmap_bin) is None:
            raise ScanError(f"Nmap executable not found: {self.nmap_bin}")
        command = [
            self.nmap_bin,
            "-sn",
            "-n",
            "--disable-arp-ping",
            "-oX",
            "-",
            target,
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.nmap_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScanError(f"Nmap discovery timed out for {target}") from exc
        except OSError as exc:
            raise ScanError(f"Unable to run Nmap for {target}: {exc}") from exc
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "unknown Nmap error").strip()
            raise ScanError(f"Nmap discovery failed for {target}: {message}")
        return parse_nmap_xml(result.stdout)

    def _ping_one(self, ip: str) -> bool:
        if shutil.which(self.ping_bin) is None:
            raise ScanError(f"ping executable not found: {self.ping_bin}")
        command = [
            self.ping_bin,
            "-4",
            "-c",
            "1",
            "-W",
            str(self.ping_timeout_seconds),
            ip,
        ]
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.ping_timeout_seconds + 2,
                check=False,
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False
        except OSError as exc:
            raise ScanError(f"Unable to run ping: {exc}") from exc

    def _parallel_ping_up(self, ips: Iterable[str]) -> set[str]:
        candidates = list(ips)
        if not candidates or not self.ping_verify:
            return set()
        if shutil.which(self.ping_bin) is None:
            raise ScanError(f"ping executable not found: {self.ping_bin}")

        up: set[str] = set()
        with ThreadPoolExecutor(max_workers=min(self.ping_workers, len(candidates))) as pool:
            future_to_ip = {pool.submit(self._ping_one, ip): ip for ip in candidates}
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    if future.result():
                        up.add(ip)
                except ScanError:
                    raise
                except Exception as exc:
                    raise ScanError(f"Ping verification failed for {ip}: {exc}") from exc
        return up

    @staticmethod
    def _in_ranges(ip: str, ranges: Iterable[tuple[str, str]]) -> bool:
        value = int(ipaddress.ip_address(ip))
        return any(
            int(ipaddress.ip_address(start)) <= value <= int(ipaddress.ip_address(end))
            for start, end in ranges
        )

    def _base_candidates(
        self,
        subnet: SubnetPlan,
        fixed_addresses: set[str],
        active_leases: set[str],
    ) -> tuple[list[str], dict[str, int]]:
        network = ipaddress.ip_network(subnet.cidr)
        if network.num_addresses > self.max_hosts_per_subnet + 2:
            raise ScanError(
                f"Subnet {network} has {network.num_addresses} addresses; "
                f"limit is {self.max_hosts_per_subnet + 2}. Increase "
                "AVAILABLE_IP_MAX_HOSTS_PER_SUBNET only if this scan is intentional."
            )

        gateways = set(subnet.gateways)
        candidates: list[str] = []
        counts = {"gateway": 0, "dynamic_range": 0, "fixed_reservation": 0, "active_lease": 0}
        for address in network.hosts():
            ip = str(address)
            if ip in gateways:
                counts["gateway"] += 1
                continue
            if self._in_ranges(ip, subnet.dynamic_ranges):
                counts["dynamic_range"] += 1
                continue
            if ip in fixed_addresses:
                counts["fixed_reservation"] += 1
                continue
            if ip in active_leases:
                counts["active_lease"] += 1
                continue
            candidates.append(ip)
        return candidates, counts

    @staticmethod
    def _normalize_managed_cidrs(managed_cidrs: Iterable[str]) -> set[str]:
        normalized: set[str] = set()
        for cidr in managed_cidrs:
            try:
                network = ipaddress.ip_network(str(cidr).strip(), strict=False)
            except ValueError as exc:
                raise ScanError(f"Invalid managed VLAN CIDR {cidr!r}: {exc}") from exc
            if network.version != 4:
                raise ScanError(f"Only IPv4 managed VLAN CIDRs are supported: {cidr}")
            normalized.add(str(network))
        return normalized

    def scan(self, managed_cidrs: Iterable[str]) -> dict:
        parsed = parse_dhcp_config(self._read_dhcp())
        if not parsed.subnets:
            raise ScanError("No active IPv4 subnet declarations found in dhcpd.conf")

        managed = self._normalize_managed_cidrs(managed_cidrs)
        selected_subnets = [subnet for subnet in parsed.subnets if subnet.cidr in managed]
        skipped_unmanaged = [subnet.cidr for subnet in parsed.subnets if subnet.cidr not in managed]
        active_leases = parse_active_leases(self._read_leases())

        subnet_results = []
        total_available = 0
        for subnet in selected_subnets:
            candidates, excluded = self._base_candidates(
                subnet,
                parsed.fixed_addresses,
                active_leases,
            )

            nmap_up = self._discover_nmap_up(subnet.cidr)
            after_nmap = [ip for ip in candidates if ip not in nmap_up]
            ping_up = self._parallel_ping_up(after_nmap) if self.ping_verify else set()
            available = [ip for ip in after_nmap if ip not in ping_up]
            available.sort(key=lambda value: int(ipaddress.ip_address(value)))

            excluded["nmap_up"] = len(set(candidates) & nmap_up)
            excluded["ping_up"] = len(set(after_nmap) & ping_up)
            total_available += len(available)
            subnet_results.append(
                {
                    "cidr": subnet.cidr,
                    "dynamic_ranges": [
                        {"start": start, "end": end} for start, end in subnet.dynamic_ranges
                    ],
                    "gateways": list(subnet.gateways),
                    "excluded_counts": excluded,
                    "candidate_count_before_discovery": len(candidates),
                    "available_count": len(available),
                    "available_ips": available,
                }
            )

        now = time.time()
        return {
            "schema_version": 1,
            "generated_at_epoch": now,
            "generated_at": datetime.fromtimestamp(now, timezone.utc).isoformat(),
            "dhcp_conf": str(self.dhcp_conf),
            "leases_file": str(self.leases_file),
            "discovery": {
                "nmap": "-sn -n --disable-arp-ping",
                "parallel_ping_c1": self.ping_verify,
                "ping_workers": self.ping_workers if self.ping_verify else 0,
            },
            "available_count": total_available,
            "managed_vlan_cidrs": sorted(managed, key=lambda value: int(ipaddress.ip_network(value).network_address)),
            "skipped_unmanaged_subnets": skipped_unmanaged,
            "subnets": subnet_results,
        }

    def scan_and_cache(self, managed_cidrs: Iterable[str]) -> dict:
        result = self.scan(managed_cidrs=managed_cidrs)
        self.write_cache(result)
        return result

    def write_cache(self, cache: dict) -> None:
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=self.cache_file.name + ".",
            suffix=".tmp",
            dir=str(self.cache_file.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(cache, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.cache_file)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

    def read_cache(self) -> dict:
        try:
            data = json.loads(self.cache_file.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"schema_version": 1, "generated_at": None, "subnets": [], "available_count": 0}
        except (OSError, json.JSONDecodeError) as exc:
            raise ScanError(f"Unable to read availability cache {self.cache_file}: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("subnets", []), list):
            raise ScanError("Availability cache has an invalid format")
        return data

    def is_cache_stale(self, cache: Optional[dict] = None) -> bool:
        cache = self.read_cache() if cache is None else cache
        try:
            generated = float(cache.get("generated_at_epoch"))
        except (TypeError, ValueError):
            return True
        return (time.time() - generated) > self.cache_max_age_hours * 3600

    def remove_cached_ip(self, ip: str) -> None:
        cache = self.read_cache()
        changed = False
        for subnet in cache.get("subnets", []):
            before = list(subnet.get("available_ips", []))
            after = [candidate for candidate in before if candidate != ip]
            if after != before:
                subnet["available_ips"] = after
                subnet["available_count"] = len(after)
                changed = True
        if changed:
            cache["available_count"] = sum(
                len(subnet.get("available_ips", [])) for subnet in cache.get("subnets", [])
            )
            self.write_cache(cache)

    def validate_candidate(self, ip: str, current_ip: Optional[str] = None) -> tuple[bool, str]:
        value = _ipv4(ip)
        if not value:
            return False, "Invalid IPv4 address"
        if current_ip and value == current_ip:
            return True, "current reservation"

        parsed = parse_dhcp_config(self._read_dhcp())
        address = ipaddress.ip_address(value)
        subnet = next(
            (plan for plan in parsed.subnets if address in ipaddress.ip_network(plan.cidr)),
            None,
        )
        if subnet is None:
            return False, "IP is not inside an active DHCP subnet"

        network = ipaddress.ip_network(subnet.cidr)
        if address == network.network_address or address == network.broadcast_address:
            return False, "Network/broadcast addresses cannot be reserved"
        if value in subnet.gateways:
            return False, "IP is configured as a subnet gateway/router"
        if self._in_ranges(value, subnet.dynamic_ranges):
            return False, "IP is inside an active DHCP dynamic range"
        if value in parsed.fixed_addresses:
            return False, "IP is already reserved in dhcpd.conf"
        if value in parse_active_leases(self._read_leases()):
            return False, "IP has an active DHCP lease"

        nmap_up = self._discover_nmap_up(value)
        if value in nmap_up:
            return False, "IP responded to Nmap discovery"
        if self.ping_verify and value in self._parallel_ping_up([value]):
            return False, "IP responded to ping verification"
        return True, "available"
