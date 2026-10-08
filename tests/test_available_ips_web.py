from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def source(name):
    return (ROOT / name).read_text(encoding="utf-8")


def test_config_has_available_ip_paths_and_scan_defaults():
    text = source("config.py")
    assert "DHCP_LEASES_FILE" in text
    assert "AVAILABLE_IP_CACHE_PATH" in text
    assert "AVAILABLE_IP_CACHE_MAX_AGE_HOURS" in text
    assert "AVAILABLE_IP_NMAP_BIN" in text
    assert "AVAILABLE_IP_PING_VERIFY" in text
    assert "AVAILABLE_IP_PING_WORKERS" in text


def test_web_has_scoped_live_available_ip_page_and_editor_refresh():
    web = source("web.py")
    view = re.search(r'@app\.route\("/available-ips"\)(?P<body>.*?)(?=\n@app\.route\(|\Z)', web, re.S)
    assert view
    assert "@require_editor_or_manager" in view.group("body")
    assert "_available_ip_payload_for_identity" in view.group("body")

    data = re.search(r'@app\.route\("/available-ips/data"\)(?P<body>.*?)(?=\n@app\.route\(|\Z)', web, re.S)
    assert data
    assert "@require_editor_or_manager" in data.group("body")
    assert "jsonify" in data.group("body")

    refresh = re.search(r'@app\.route\("/available-ips/refresh", methods=\["POST"\]\)(?P<body>.*?)(?=\n@app\.route\(|\Z)', web, re.S)
    assert refresh
    assert "@require_editor_or_manager" in refresh.group("body")
    assert "_trigger_available_ip_refresh" in refresh.group("body")
    assert "all_managed_subnets" in refresh.group("body")


def test_add_and_edit_use_cached_options_and_live_revalidation():
    web = source("web.py")
    assert "_available_ip_groups_for_identity" in web
    assert "validate_candidate" in web
    assert "remove_cached_ip" in web
    template = source("templates/add_edit.html")
    assert '<select name="ip"' in template
    assert "available_ip_groups" in template
    assert "group.cidr" in template
    assert "Current IP" in template


def test_index_has_show_available_ips_button_only_for_editors():
    text = source("templates/index.html")
    assert "Show Available IPs" in text
    assert "url_for('available_ips')" in text
    assert "can_edit_entries" in text


def test_available_ip_page_uses_subnet_cidr_not_vlan_id():
    text = source("templates/available_ips.html")
    assert "Available IPs" in text
    assert "subnet.cidr" in text
    assert "VLAN ID" not in text
    assert "Refresh Scan" in text
    assert "generated_at" in text


def test_periodic_refresh_and_dhcp_config_watcher_are_bundled():
    assert (ROOT / "refresh_available_ips.py").exists()
    installer = source("install_available_ip_timer.sh")
    assert "OnUnitActiveSec=15m" in installer
    assert "RandomizedDelaySec=1m" in installer
    assert "dhcp-manager-available-ips.path" in installer
    assert "PathChanged=" in installer
    assert "PathModified=" in installer
    assert "TimeoutStartSec=15min" in installer
    apply_script = source("apply_to_main.sh")
    assert "availability_scanner.py" in apply_script
    assert "refresh_available_ips.py" in apply_script
    assert "templates/available_ips.html" in apply_script
    assert "install_available_ip_timer.sh" in apply_script


def test_cache_is_ignored_by_git():
    text = source("data/.gitignore")
    assert "available_ips.json" in text


def test_scans_are_scoped_to_enabled_acl_vlan_mappings():
    web = source("web.py")
    refresh = source("refresh_available_ips.py")
    scanner = source("availability_scanner.py")

    assert "def _managed_vlan_cidrs" in web
    assert "_trigger_available_ip_refresh" in web
    assert "acl_store.vlan_for_ip(ip) is not None" in web

    assert "ACLStore" in refresh
    assert "list_vlans" in refresh
    assert "managed_cidrs=managed_cidrs" in refresh

    assert "managed_cidrs" in scanner
    assert "skipped_unmanaged_subnets" in scanner

def test_available_ip_page_polls_cache_without_full_page_refresh():
    template = source("templates/available_ips.html")
    assert "available_ips_data" in template
    assert "fetchAvailableIps" in template
    assert "window.setInterval(fetchAvailableIps, 5000)" in template
    assert "X-Requested-With" in template
    assert "Live cache sync" in template


def test_web_crud_stages_config_and_restart_requests_full_rescan():
    web = source("web.py")
    assert web.count("apply_immediately=False") >= 3
    assert "validate_syntax" in web
    restart = re.search(r'@app\.route\("/restart", methods=\["POST"\]\)(?P<body>.*?)(?=\n@app\.route\(|\Z)', web, re.S)
    assert restart
    assert "_trigger_available_ip_refresh" in restart.group("body")

def test_web_refresh_trigger_runs_script_directly_and_logs_output():
    web = source("web.py")
    assert "systemctl" not in web.split("def _trigger_available_ip_refresh", 1)[1].split("# AUTHORIZATION DECORATORS", 1)[0]
    assert "[sys.executable, str(script), \"--reason\", reason]" in web
    assert "available_ips_refresh.log" in web


def test_staged_crud_requests_cache_reconciliation():
    web = source("web.py")
    assert "DHCP reservation added:" in web
    assert "DHCP reservation edited:" in web
    assert "DHCP reservation deleted:" in web


def test_refresh_script_serializes_overlapping_scans():
    refresh = source("refresh_available_ips.py")
    assert "fcntl.flock" in refresh
    assert "LOCK_EX" in refresh
    assert "available_ips_refresh.lock" in refresh
