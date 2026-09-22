#!/usr/bin/env python3
"""
DHCP Manager Web Interface - Flask web application for DHCP management.

Authentication paths:
- Built-in bcrypt Admin (break-glass/full control)
- ACL-approved local Linux users through PAM
- Existing passwordless Read Only access
"""
import traceback
import time
from typing import Tuple, Any
from functools import wraps

import bcrypt
from flask import (
    Flask, render_template, request, redirect, url_for, flash, jsonify,
    session, Response, send_file, abort,
)

from config import config
from managers.dhcp_manager import DHCPManager
from managers.pxe_manager import PXEBootManager
from exceptions import DHCPManagerError, PXEBootError
from utils.logger import get_logger
from access_control import (
    ACLStore,
    ACLValidationError,
    ROLE_MANAGER,
    ROLE_VLAN_EDITOR,
    reservations_outside_new_cidr,
)
from authorization import AuthorizationService, ROLE_READONLY
from pam_auth import PAMAuthenticator
from availability_scanner import (
    AvailableIPScanner,
    ScanError,
    filter_available_cache,
)

app = Flask(__name__)
app.secret_key = config.FLASK_SECRET_KEY

dhcp_mgr = DHCPManager()
pxe_mgr = PXEBootManager()
logger = get_logger("dhcp-web")
acl_store = ACLStore(config.ACL_DB_PATH)
authz = AuthorizationService(acl_store)
pam_authenticator = PAMAuthenticator(config.PAM_SERVICE)
available_ip_scanner = AvailableIPScanner.from_config(config)


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def check_manager_password(plain: str) -> bool:
    try:
        return bcrypt.checkpw(
            plain.encode("utf-8"),
            config.MANAGER_PASSWORD_HASH.encode("utf-8"),
        )
    except Exception:
        return False


def safe_execute(func, *args, **kwargs) -> Tuple[bool, Any]:
    """Safely execute a manager operation and normalize expected failures."""
    try:
        return True, func(*args, **kwargs)
    except DHCPManagerError as e:
        logger.error(f"DHCP Manager error: {e}")
        return False, str(e)
    except PXEBootError as e:
        logger.error(f"PXE Boot error: {e}")
        return False, str(e)
    except Exception as e:
        tb = traceback.format_exc()
        logger.error(f"Unexpected error:\n{tb}")
        return False, str(e)


def current_identity():
    """Resolve the current session, revalidating PAM-user ACL state every request."""
    ident = authz.resolve_session(session)
    if ident is None and session.get("auth_source") == "pam":
        session.clear()
    return ident


@app.before_request
def enforce_session_idle_timeout():
    """Expire authenticated sessions after configured inactivity."""
    if request.endpoint in {
        "login",
        "logout",
        "static",
    }:
        return None

    if not session.get("username"):
        return None

    now = time.time()
    last_activity = session.get("last_activity")

    if last_activity is not None:
        try:
            idle_seconds = now - float(last_activity)
        except (TypeError, ValueError):
            idle_seconds = config.SESSION_IDLE_TIMEOUT_MINUTES * 60 + 1

        if idle_seconds > config.SESSION_IDLE_TIMEOUT_MINUTES * 60:
            session.clear()
            flash(
                "⌛ Session expired due to inactivity. Please sign in again.",
                "warning",
            )
            return redirect(url_for("login"))

    session["last_activity"] = now
    return None


def _audit(action: str, target=None, ip=None, result="SUCCESS", details=None) -> None:
    ident = current_identity()
    principal = ident.username if ident else str(session.get("username") or "anonymous")
    source = ident.auth_source if ident else str(session.get("auth_source") or "unknown")
    try:
        acl_store.record_audit(principal, source, action, target, ip, result, details)
    except Exception as exc:
        logger.error(f"Failed to write ACL audit record: {exc}")


def _forbidden(action: str, target=None, ip=None, details=None):
    _audit(action, target, ip, "DENIED", details)
    abort(403)


def _enforce_view_ip(ip: str, action: str = "VIEW_IP"):
    ident = current_identity()
    if not authz.can_view_ip(ident, ip):
        _forbidden(action, ip, ip, "IP is outside authorized VLAN scope")
    return ident


def _enforce_edit_ip(ip: str, action: str = "EDIT_IP"):
    ident = current_identity()
    if not authz.can_edit_ip(ident, ip):
        _forbidden(action, ip, ip, "IP is outside editable VLAN scope")
    return ident


def _allowed_vlans_for_identity(ident):
    if not ident:
        return []
    if ident.role == ROLE_MANAGER:
        return acl_store.list_vlans()
    if ident.role == ROLE_VLAN_EDITOR and ident.auth_source == "pam":
        principal = acl_store.get_principal(ident.username)
        return principal["vlans"] if principal else []
    return []


def _managed_vlan_cidrs():
    """Return enabled ACL VLAN CIDRs that define the subnets managed by this app."""
    return [vlan["cidr"] for vlan in acl_store.list_vlans() if vlan.get("enabled")]


def _available_ip_visible_to_identity(ident, ip: str) -> bool:
    # Even Managers see availability only for subnets explicitly managed in ACL/VLAN mappings.
    return acl_store.vlan_for_ip(ip) is not None and authz.can_edit_ip(ident, ip)


def _available_ip_cache_for_identity(ident):
    """Return cached candidate IPs filtered through the same server-side ACL policy."""
    cache = available_ip_scanner.read_cache()
    return filter_available_cache(
        cache,
        lambda ip: _available_ip_visible_to_identity(ident, ip),
    )


def _available_ip_groups_for_identity(ident):
    try:
        return _available_ip_cache_for_identity(ident).get("subnets", [])
    except ScanError as exc:
        logger.error(f"Unable to read available-IP cache: {exc}")
        return []


# ============================================================
# AUTHORIZATION DECORATORS
# ============================================================

def require_login(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if current_identity() is None:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapper


def require_manager(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        ident = current_identity()
        if ident is None:
            return redirect(url_for("login"))
        if not authz.can_manage_global(ident):
            _forbidden("MANAGER_ONLY_ROUTE", request.path, None, "Manager privileges required")
        return view_func(*args, **kwargs)
    return wrapper


def require_editor_or_manager(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        ident = current_identity()
        if ident is None:
            return redirect(url_for("login"))
        if not authz.can_edit_reservations(ident):
            _forbidden("DHCP_WRITE_ROUTE", request.path, None, "Reservation edit privileges required")
        return view_func(*args, **kwargs)
    return wrapper


# ============================================================
# LOGIN / LOGOUT
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        mode = (request.form.get("mode") or "login").strip().lower()

        if mode == "readonly":
            session.clear()
            session["role"] = ROLE_READONLY
            session["username"] = "ReadOnly"
            session["auth_source"] = "readonly"
            flash("👀 Logged in with read-only access.", "info")
            return redirect(url_for("index"))

        if mode == "login":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""

            # Built-in break-glass Admin is checked first and does not require an ACL row.
            if username == config.MANAGER_USERNAME and check_manager_password(password):
                session.clear()
                session["role"] = ROLE_MANAGER
                session["username"] = username
                session["auth_source"] = "builtin"
                _audit("BUILTIN_ADMIN_LOGIN", username, None, "SUCCESS")
                flash("✅ Logged in as built-in Admin.", "success")
                return redirect(url_for("index"))

            # Every other login must be both a valid Linux/PAM account and explicitly
            # approved in the app ACL database. Fail closed before PAM if not approved.
            principal = acl_store.get_principal(username)
            if not principal or not principal["enabled"]:
                try:
                    acl_store.record_audit(
                        username or "unknown", "pam", "PAM_LOGIN", username,
                        None, "DENIED", "No enabled ACL principal",
                    )
                except Exception:
                    pass
                flash("❌ Login failed or this Linux account is not authorized.", "danger")
                return render_template("login.html", manager_username=config.MANAGER_USERNAME)

            auth_result = pam_authenticator.authenticate(username, password)
            password = None
            if auth_result.success:
                session.clear()
                session["role"] = principal["role"]
                session["username"] = principal["alias"]
                session["auth_source"] = "pam"
                _audit("PAM_LOGIN", principal["alias"], None, "SUCCESS", f"role={principal['role']}")
                flash(f"✅ Logged in as {principal['alias']}.", "success")
                return redirect(url_for("index"))

            logger.warning(f"PAM login failed for {username!r}: {auth_result.reason}")
            try:
                acl_store.record_audit(
                    username or "unknown", "pam", "PAM_LOGIN", username,
                    None, "DENIED", auth_result.reason,
                )
            except Exception:
                pass
            if "PAM support is unavailable" in auth_result.reason:
                flash(f"❌ {auth_result.reason}", "danger")
            else:
                flash("❌ Login failed or this Linux account is not authorized.", "danger")
            return render_template("login.html", manager_username=config.MANAGER_USERNAME)

        flash("❌ Unsupported login mode.", "danger")

    return render_template("login.html", manager_username=config.MANAGER_USERNAME)


@app.route("/logout")
def logout():
    ident = current_identity()
    if ident:
        _audit("LOGOUT", ident.username, None, "SUCCESS")
    session.clear()
    flash("👋 Logged out.", "info")
    return redirect(url_for("login"))


# ============================================================
# MAIN PAGE / DHCP RESERVATIONS
# ============================================================

@app.route("/")
@require_login
def index():
    ident = current_identity()
    success, result = safe_execute(dhcp_mgr.get_all_entries)
    if not success:
        flash(f"⚠️ Failed to load DHCP entries: {result}", "danger")
        entries = []
    else:
        entries = authz.filter_entries(ident, result)
        for entry in entries:
            vlan = acl_store.vlan_for_ip(entry["ip"])
            entry["acl_vlan"] = vlan["name"] if vlan else "Unmapped"
            try:
                boot_device = pxe_mgr.get_boot_device(entry["ip"])
                entry["boot_device"] = boot_device
                boot_target = pxe_mgr.get_boot_target(entry["ip"])
                entry["boot_target"] = boot_target if boot_target else "No link configured"
                entry["ipxe_url"] = pxe_mgr.get_dynamic_boot_url(entry["ip"])
                entry["ipxe_mac_url"] = ""
                logger.debug(
                    f"Entry {entry['hostname']} ({entry['ip']}): device={boot_device}, target={boot_target}"
                )
            except Exception as e:
                logger.error(f"Failed to get boot device for {entry['ip']}: {e}")
                entry["boot_device"] = "default"
                entry["boot_target"] = "Error reading boot config"
                entry["ipxe_url"] = ""
                entry["ipxe_mac_url"] = ""

    boot_profiles = pxe_mgr.discover_boot_profiles()
    return render_template(
        "index.html",
        entries=entries,
        boot_profiles=boot_profiles,
        role=ident.role,
        username=ident.username,
        auth_source=ident.auth_source,
        can_edit_entries=authz.can_edit_reservations(ident),
        can_manage_global=authz.can_manage_global(ident),
        allowed_vlans=_allowed_vlans_for_identity(ident),
    )


@app.route("/available-ips")
@require_editor_or_manager
def available_ips():
    ident = current_identity()
    try:
        cache = available_ip_scanner.read_cache()
        visible_cache = filter_available_cache(
            cache,
            lambda ip: _available_ip_visible_to_identity(ident, ip),
        )
        stale = available_ip_scanner.is_cache_stale(cache)
        cache_error = None
    except ScanError as exc:
        logger.error(f"Unable to load available-IP cache: {exc}")
        visible_cache = {"generated_at": None, "subnets": [], "available_count_visible": 0}
        stale = True
        cache_error = str(exc)

    return render_template(
        "available_ips.html",
        cache=visible_cache,
        subnets=visible_cache.get("subnets", []),
        generated_at=visible_cache.get("generated_at"),
        stale=stale,
        cache_error=cache_error,
        role=ident.role,
        username=ident.username,
        auth_source=ident.auth_source,
        can_manage_global=authz.can_manage_global(ident),
    )


@app.route("/available-ips/refresh", methods=["POST"])
@require_manager
def available_ips_refresh():
    try:
        result = available_ip_scanner.scan_and_cache(managed_cidrs=_managed_vlan_cidrs())
        _audit(
            "AVAILABLE_IP_SCAN",
            "managed_subnets",
            None,
            "SUCCESS",
            f"subnets={len(result.get('subnets', []))}; available={result.get('available_count', 0)}",
        )
        flash(
            f"✅ Available IP scan completed: {result.get('available_count', 0)} candidates found.",
            "success",
        )
    except Exception as exc:
        logger.error(f"Available IP scan failed: {exc}")
        _audit("AVAILABLE_IP_SCAN", "managed_subnets", None, "FAILED", str(exc))
        flash(f"❌ Available IP scan failed: {exc}", "danger")
    return redirect(url_for("available_ips"))


@app.route("/add", methods=["GET", "POST"])
@require_editor_or_manager
def add_entry():
    ident = current_identity()
    form_entry = None
    if request.method == "POST":
        hostname = request.form.get("hostname", "").strip()
        mac = request.form.get("mac", "").strip()
        ip = request.form.get("ip", "").strip()
        form_entry = {"hostname": hostname, "mac": mac, "ip": ip}
        _enforce_edit_ip(ip, "DHCP_ADD")

        try:
            available, reason = available_ip_scanner.validate_candidate(ip)
        except Exception as exc:
            available, reason = False, f"Availability verification failed: {exc}"

        if not available:
            _audit("DHCP_ADD", hostname, ip, "FAILED", reason)
            flash(f"❌ IP {ip} is not currently available: {reason}", "danger")
        else:
            success, result = safe_execute(dhcp_mgr.add_entry, hostname, mac, ip)
            if success:
                try:
                    available_ip_scanner.remove_cached_ip(ip)
                except Exception as exc:
                    logger.warning(f"Could not remove {ip} from availability cache: {exc}")
                _audit("DHCP_ADD", hostname, ip, "SUCCESS")
                flash(f"✅ Successfully added entry: {hostname}", "success")
                return redirect(url_for("index"))
            _audit("DHCP_ADD", hostname, ip, "FAILED", str(result))
            flash(f"❌ Failed to add entry: {result}", "danger")

    return render_template(
        "add_edit.html",
        action="Add",
        entry=form_entry,
        role=ident.role,
        username=ident.username,
        auth_source=ident.auth_source,
        allowed_vlans=_allowed_vlans_for_identity(ident),
        available_ip_groups=_available_ip_groups_for_identity(ident),
    )


@app.route("/edit/<identifier>", methods=["GET", "POST"])
@require_editor_or_manager
def edit_entry(identifier: str):
    ident = current_identity()
    success, entry = safe_execute(dhcp_mgr.find_entry, identifier)
    if not success or entry is None:
        flash(f"⚠️ Entry not found: {identifier}", "warning")
        return redirect(url_for("index"))

    _enforce_edit_ip(entry["ip"], "DHCP_EDIT_SOURCE")
    original_ip = entry["ip"]

    if request.method == "POST":
        new_hostname = request.form.get("hostname", "").strip() or None
        new_mac = request.form.get("mac", "").strip() or None
        new_ip = request.form.get("ip", "").strip() or None
        target_ip = new_ip or original_ip
        _enforce_edit_ip(target_ip, "DHCP_EDIT_TARGET")

        if target_ip != original_ip:
            try:
                available, reason = available_ip_scanner.validate_candidate(target_ip)
            except Exception as exc:
                available, reason = False, f"Availability verification failed: {exc}"
            if not available:
                entry = {
                    "hostname": new_hostname or entry["hostname"],
                    "mac": new_mac or entry["mac"],
                    "ip": target_ip,
                    "original_ip": original_ip,
                }
                _audit("DHCP_EDIT", identifier, target_ip, "FAILED", reason)
                flash(f"❌ IP {target_ip} is not currently available: {reason}", "danger")
                return render_template(
                    "add_edit.html",
                    action="Edit",
                    entry=entry,
                    current_ip=original_ip,
                    role=ident.role,
                    username=ident.username,
                    auth_source=ident.auth_source,
                    allowed_vlans=_allowed_vlans_for_identity(ident),
                    available_ip_groups=_available_ip_groups_for_identity(ident),
                )

        success, result = safe_execute(
            dhcp_mgr.modify_entry,
            identifier,
            new_hostname=new_hostname,
            new_mac=new_mac,
            new_ip=new_ip,
        )
        if success:
            if target_ip != original_ip:
                try:
                    available_ip_scanner.remove_cached_ip(target_ip)
                except Exception as exc:
                    logger.warning(f"Could not remove {target_ip} from availability cache: {exc}")
            _audit(
                "DHCP_EDIT",
                identifier,
                target_ip,
                "SUCCESS",
                f"old_ip={original_ip}; new_hostname={new_hostname or entry.get('hostname')}; new_mac={new_mac or entry.get('mac')}",
            )
            flash("✅ Entry updated successfully", "success")
            return redirect(url_for("index"))
        _audit("DHCP_EDIT", identifier, target_ip, "FAILED", str(result))
        flash(f"❌ Failed to update entry: {result}", "danger")

    return render_template(
        "add_edit.html",
        action="Edit",
        entry=entry,
        current_ip=original_ip,
        role=ident.role,
        username=ident.username,
        auth_source=ident.auth_source,
        allowed_vlans=_allowed_vlans_for_identity(ident),
        available_ip_groups=_available_ip_groups_for_identity(ident),
    )


@app.route("/delete/<identifier>", methods=["POST"])
@require_editor_or_manager
def delete_entry(identifier: str):
    success, entry = safe_execute(dhcp_mgr.find_entry, identifier)
    if not success or entry is None:
        flash(f"⚠️ Entry not found: {identifier}", "warning")
        return redirect(url_for("index"))
    _enforce_edit_ip(entry["ip"], "DHCP_DELETE")

    success, result = safe_execute(dhcp_mgr.remove_entry, identifier)
    if success:
        _audit("DHCP_DELETE", identifier, entry["ip"], "SUCCESS")
        flash(f"🗑️ Successfully deleted entry: {identifier}", "success")
    else:
        _audit("DHCP_DELETE", identifier, entry["ip"], "FAILED", str(result))
        flash(f"❌ Failed to delete entry: {result}", "danger")
    return redirect(url_for("index"))


# ============================================================
# PXE BOOT - MANAGER OR VLAN-SCOPED EDITOR CHANGES
# ============================================================

@app.route("/bootdevice/<ip>", methods=["POST"])
@require_editor_or_manager
def set_boot_device(ip: str):
    _enforce_edit_ip(ip, "PXE_BOOT_CHANGE")
    boot_device = request.form.get("boot_device", "").strip()
    if not boot_device:
        flash("❌ Boot device not specified", "danger")
        return redirect(url_for("index"))
    if not pxe_mgr.boot_profile_exists(boot_device):
        flash(f"❌ Boot profile does not exist: {boot_device}", "danger")
        return redirect(url_for("index"))

    success, result = safe_execute(pxe_mgr.create_boot_link, ip, boot_device)
    if not success:
        _audit("PXE_BOOT_CHANGE", boot_device, ip, "FAILED", str(result))
        flash(f"❌ Failed to update PXELINUX boot device: {result}", "danger")
        return redirect(url_for("index"))

    script_success, script_result = safe_execute(
        pxe_mgr.write_client_ipxe_scripts,
        boot_device,
        ip=ip,
    )
    if not script_success:
        _audit("PXE_BOOT_CHANGE", boot_device, ip, "FAILED", str(script_result))
        flash(
            f"⚠️ PXELINUX link was updated, but iPXE override creation failed: {script_result}",
            "warning",
        )
        return redirect(url_for("index"))

    _audit("PXE_BOOT_CHANGE", boot_device, ip, "SUCCESS")
    flash(f"✅ Boot profile updated for {ip} → {boot_device}", "success")
    return redirect(url_for("index"))


@app.route("/query/<ip>")
@require_login
def query_boot(ip: str):
    _enforce_view_ip(ip, "PXE_QUERY")
    try:
        target = pxe_mgr.get_boot_target(ip)
        device = pxe_mgr.get_boot_device(ip)
        hex_name = pxe_mgr.ip_to_hex(ip)
        link_path = pxe_mgr.get_link_path(ip)
        ipxe_url = pxe_mgr.get_dynamic_boot_url(ip)
        client_script_path = pxe_mgr.get_client_script_path(ip)
        dispatcher_path = pxe_mgr.get_ipxe_script_path()
        if not target:
            target = "default (no assigned link file)"
        return jsonify({
            "ip": ip,
            "hex_filename": hex_name,
            "link_path": str(link_path),
            "target": target,
            "device": device,
            "ipxe_url": ipxe_url,
            "ipxe_ip_script_path": str(client_script_path),
            "ipxe_ip_script_exists": client_script_path.exists(),
            "ipxe_dispatcher_path": str(dispatcher_path),
            "ipxe_dispatcher_tftp": pxe_mgr.get_ipxe_script_tftp_filename(),
            "link_exists": link_path.exists(),
            "success": True,
        })
    except Exception as e:
        logger.error(f"Failed to query boot config for {ip}: {e}")
        return jsonify({
            "ip": ip,
            "target": "Error retrieving boot configuration",
            "success": False,
            "error": str(e),
        }), 500


# ============================================================
# iPXE DISPATCHER
# ============================================================

@app.route("/ipxe/boot")
def ipxe_boot_auto():
    return Response(pxe_mgr.generate_default_ipxe_script(), mimetype="text/plain")


@app.route("/ipxe/install-default", methods=["POST"])
@require_manager
def ipxe_install_default():
    success, result = safe_execute(pxe_mgr.write_default_ipxe_script)
    if success:
        _audit("IPXE_INSTALL_DEFAULT", str(result), None, "SUCCESS")
        flash(f"✅ Installed iPXE dispatcher: {result}", "success")
    else:
        _audit("IPXE_INSTALL_DEFAULT", None, None, "FAILED", str(result))
        flash(f"❌ Failed to install iPXE dispatcher: {result}", "danger")
    return redirect(url_for("index"))


@app.route("/ipxe/<path:filename>")
def ipxe_static_script(filename: str):
    if not filename.endswith(".ipxe"):
        return Response("Not found\n", mimetype="text/plain", status=404)
    try:
        requested = (pxe_mgr.ipxe_dir / filename).resolve()
        root = pxe_mgr.ipxe_dir.resolve()
        if root not in requested.parents and requested != root:
            return Response("Not found\n", mimetype="text/plain", status=404)
    except Exception:
        return Response("Not found\n", mimetype="text/plain", status=404)
    if not requested.exists() or not requested.is_file():
        return Response("Not found\n", mimetype="text/plain", status=404)
    return send_file(requested, mimetype="text/plain")


@app.route("/ipxe/snippet")
@require_manager
def ipxe_dhcp_snippet():
    return Response(pxe_mgr.generate_isc_dhcp_ipxe_snippet(), mimetype="text/plain")


# ============================================================
# SERVICE MANAGEMENT
# ============================================================

@app.route("/restart", methods=["POST"])
@require_manager
def restart_dhcp_service():
    success, result = safe_execute(dhcp_mgr.restart_service, config.DHCP_SERVICE)
    if success:
        _audit("DHCP_RESTART", config.DHCP_SERVICE, None, "SUCCESS")
        flash("🔄 DHCP service restarted successfully", "success")
    else:
        _audit("DHCP_RESTART", config.DHCP_SERVICE, None, "FAILED", str(result))
        flash(f"❌ Failed to restart DHCP service: {result}", "danger")
    return redirect(url_for("index"))


# ============================================================
# MANAGER-OWNED ACCESS CONTROL
# ============================================================

def _render_access_control_page(
    *,
    edit_vlan=None,
    proposed_name=None,
    proposed_cidr=None,
    affected_entries=None,
):
    ident = current_identity()
    return render_template(
        "access_control.html",
        vlans=acl_store.list_vlans(),
        principals=acl_store.list_principals(),
        audit=acl_store.list_audit(config.ACL_AUDIT_LIMIT),
        role=ident.role if ident else None,
        username=ident.username if ident else None,
        edit_vlan=edit_vlan,
        proposed_name=proposed_name,
        proposed_cidr=proposed_cidr,
        affected_entries=affected_entries or [],
    )


@app.route("/access-control")
@require_manager
def access_control():
    edit_vlan_id = request.args.get("edit_vlan", type=int)
    edit_vlan = acl_store.get_vlan(edit_vlan_id) if edit_vlan_id is not None else None
    if edit_vlan_id is not None and edit_vlan is None:
        flash("❌ VLAN mapping not found.", "danger")
    return _render_access_control_page(edit_vlan=edit_vlan)


@app.route("/access-control/vlans", methods=["POST"])
@require_manager
def access_control_add_vlan():
    name = request.form.get("name", "").strip()
    cidr = request.form.get("cidr", "").strip()
    try:
        vlan = acl_store.add_vlan(name, cidr)
        _audit("ACL_VLAN_ADD", vlan["name"], vlan["cidr"], "SUCCESS")
        flash(f"✅ Added ACL VLAN mapping {vlan['name']} → {vlan['cidr']}", "success")
    except ACLValidationError as exc:
        _audit("ACL_VLAN_ADD", name, cidr, "FAILED", str(exc))
        flash(f"❌ {exc}", "danger")
    return redirect(url_for("access_control"))


@app.route("/access-control/vlans/<int:vlan_id>/edit", methods=["POST"])
@require_manager
def access_control_edit_vlan(vlan_id: int):
    old_vlan = acl_store.get_vlan(vlan_id)
    if old_vlan is None:
        flash("❌ VLAN mapping not found.", "danger")
        return redirect(url_for("access_control"))

    name = request.form.get("name", "").strip()
    cidr = request.form.get("cidr", "").strip()
    confirm_change = request.form.get("confirm_change") == "1"

    try:
        if not name:
            raise ACLValidationError("VLAN name is required")
        normalized_cidr = acl_store.normalize_cidr(cidr)
        affected_entries = []

        if normalized_cidr != old_vlan["cidr"]:
            success, entries = safe_execute(dhcp_mgr.get_all_entries)
            if not success:
                details = f"Could not inspect DHCP reservations before CIDR change: {entries}"
                _audit("ACL_VLAN_UPDATE", old_vlan["name"], normalized_cidr, "FAILED", details)
                flash(f"❌ {details}", "danger")
                return redirect(url_for("access_control", edit_vlan=vlan_id))

            affected_entries = reservations_outside_new_cidr(
                entries,
                old_vlan["cidr"],
                normalized_cidr,
            )
            if affected_entries and not confirm_change:
                return _render_access_control_page(
                    edit_vlan=old_vlan,
                    proposed_name=name,
                    proposed_cidr=normalized_cidr,
                    affected_entries=affected_entries,
                )

        updated = acl_store.update_vlan(vlan_id, name, normalized_cidr)
        details = (
            f"old={old_vlan['name']} {old_vlan['cidr']}; "
            f"new={updated['name']} {updated['cidr']}; "
            f"reservations_outside_new_cidr={len(affected_entries)}"
        )
        _audit("ACL_VLAN_UPDATE", updated["name"], updated["cidr"], "SUCCESS", details)
        flash(
            f"✅ Updated ACL VLAN mapping {old_vlan['name']} → {updated['name']} "
            f"({old_vlan['cidr']} → {updated['cidr']}). Existing user assignments were preserved.",
            "success",
        )
    except (ACLValidationError, ValueError) as exc:
        _audit("ACL_VLAN_UPDATE", old_vlan["name"], cidr, "FAILED", str(exc))
        flash(f"❌ {exc}", "danger")
        return redirect(url_for("access_control", edit_vlan=vlan_id))

    return redirect(url_for("access_control"))


@app.route("/access-control/vlans/<int:vlan_id>/delete", methods=["POST"])
@require_manager
def access_control_delete_vlan(vlan_id: int):
    vlan = next((v for v in acl_store.list_vlans() if v["id"] == vlan_id), None)
    acl_store.delete_vlan(vlan_id)
    _audit("ACL_VLAN_DELETE", vlan["name"] if vlan else str(vlan_id), vlan["cidr"] if vlan else None, "SUCCESS")
    flash("🗑️ ACL VLAN mapping removed. Any attached editor scope was revoked.", "success")
    return redirect(url_for("access_control"))


@app.route("/access-control/principals", methods=["POST"])
@require_manager
def access_control_upsert_principal():
    alias = request.form.get("alias", "").strip()
    role = request.form.get("role", "").strip().lower()
    vlan_ids = request.form.getlist("vlan_ids")
    try:
        principal = acl_store.upsert_principal(alias, role, vlan_ids)
        scopes = ",".join(v["name"] for v in principal["vlans"]) or "ALL"
        _audit("ACL_PRINCIPAL_UPSERT", principal["alias"], None, "SUCCESS", f"role={principal['role']}; scopes={scopes}")
        flash(f"✅ Saved Linux-user ACL for {principal['alias']} ({principal['role']}).", "success")
    except (ACLValidationError, ValueError) as exc:
        _audit("ACL_PRINCIPAL_UPSERT", alias, None, "FAILED", str(exc))
        flash(f"❌ {exc}", "danger")
    return redirect(url_for("access_control"))


@app.route("/access-control/principals/<path:alias>/delete", methods=["POST"])
@require_manager
def access_control_delete_principal(alias: str):
    acl_store.delete_principal(alias)
    _audit("ACL_PRINCIPAL_DELETE", alias, None, "SUCCESS")
    flash(f"🗑️ Removed Linux-user ACL for {alias}. Any active PAM session is revoked on its next request.", "success")
    return redirect(url_for("access_control"))


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(403)
def forbidden_error(error):
    ident = current_identity()
    return render_template(
        "forbidden.html",
        role=ident.role if ident else None,
        username=ident.username if ident else None,
    ), 403


@app.errorhandler(404)
def not_found_error(error):
    flash("⚠️ Page not found", "warning")
    return redirect(url_for("index"))


@app.errorhandler(500)
def internal_error(error):
    tb = traceback.format_exc()
    logger.error(f"Internal server error:\n{tb}")
    flash("❌ A critical server error occurred. Please check the logs.", "danger")
    return redirect(url_for("index"))


# ============================================================
# APPLICATION STARTUP
# ============================================================

def main():
    logger.info(f"Starting DHCP Manager Web Interface on {config.FLASK_HOST}:{config.FLASK_PORT}")
    logger.info(f"PAM service: {config.PAM_SERVICE}; ACL database: {config.ACL_DB_PATH}")
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG)


if __name__ == "__main__":
    main()
