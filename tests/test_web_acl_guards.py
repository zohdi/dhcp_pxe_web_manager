from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def source(name):
    return (ROOT / name).read_text(encoding="utf-8")


def test_web_integrates_ad_login_and_server_side_acl_checks():
    text = source("web.py")
    assert 'mode == "ad"' in text
    assert "ad_authenticator.authenticate" in text
    assert "authz.filter_entries" in text
    assert "_enforce_edit_ip(ip" in text
    assert "_enforce_edit_ip(entry[\"ip\"]" in text
    assert "_enforce_view_ip(ip" in text


def test_global_operations_are_manager_only_and_reservation_crud_allows_editor():
    text = source("web.py")
    assert text.count("@require_editor_or_manager") >= 4
    assert text.count("@require_manager") >= 6
    assert '@app.route("/access-control")' in text


def test_login_is_ad_first_with_readonly_and_local_manager_buttons():
    text = source("templates/login.html")
    assert 'value="ad"' in text
    assert 'value="readonly"' in text
    assert 'value="manager"' not in text
    assert "Local Manager Login" in text
    assert "url_for('local_manager_login')" in text
    assert text.index("Active Directory") < text.index("Read Only Login")


def test_local_manager_has_dedicated_route_and_page():
    web = source("web.py")
    assert '@app.route("/local-manager-login", methods=["GET", "POST"])' in web
    assert '"local_manager_login.html"' in web
    template = source("templates/local_manager_login.html")
    assert "Local Manager Login" in template
    assert 'name="username"' in template
    assert 'name="password"' in template
    assert "Back to AD Login" in template


def test_boot_device_change_allows_editor_or_manager_but_enforces_ip_scope():
    web = source("web.py")
    match = re.search(
        r'@app\.route\("/bootdevice/<ip>", methods=\["POST"\]\)\n(?P<body>.*?)(?=\n@app\.route\(|\Z)',
        web,
        flags=re.S,
    )
    assert match, "boot device route not found"
    body = match.group("body")
    assert "@require_editor_or_manager" in body
    assert "@require_manager" not in body
    assert '_enforce_edit_ip(ip, "PXE_BOOT_CHANGE")' in body


def test_boot_device_controls_are_enabled_for_vlan_editor_and_disabled_for_readonly():
    text = source("templates/index.html")
    assert 'name="boot_device"' in text
    assert '{% if not can_edit_entries %}disabled{% endif %}' in text
    assert '{% if can_edit_entries %}<button class="btn btn-sm btn-primary"' in text
    assert 'title="Manager only">Apply' not in text


def test_vlan_mapping_edit_is_manager_only_and_audited():
    web = source("web.py")
    match = re.search(
        r'@app\.route\("/access-control/vlans/<int:vlan_id>/edit", methods=\["POST"\]\)\n(?P<body>.*?)(?=\n@app\.route\(|\Z)',
        web,
        flags=re.S,
    )
    assert match, "VLAN edit route not found"
    body = match.group("body")
    assert "@require_manager" in body
    assert "acl_store.update_vlan" in body
    assert '"ACL_VLAN_UPDATE"' in body
    assert "confirm_change" in body
    assert "reservations_outside_new_cidr" in body


def test_access_control_page_has_edit_and_save_changes_ui():
    text = source("templates/access_control.html")
    assert "Edit" in text
    assert "Save Changes" in text
    assert "Confirm &amp; Save" in text
    assert "access_control_edit_vlan" in text
    assert "existing DHCP reservation" in text


def test_ad_login_payload_uses_http_compatible_local_rsa_not_plain_password():
    template = source("templates/login.html")
    assert 'id="password"' in template
    assert 'name="password"' not in template
    assert 'name="encrypted_credentials"' in template
    assert "vendor/rsa_oaep_sha256.js" in template
    assert "HttpRsaOaep.encrypt" in template
    assert "window.isSecureContext" not in template
    assert "crypto.subtle" not in template
    assert 'passwordInput.value = ""' in template


def test_http_compatible_crypto_helper_is_bundled_locally():
    vendor = ROOT / "static" / "vendor" / "rsa_oaep_sha256.js"
    assert vendor.exists()
    text = vendor.read_text(encoding="utf-8")
    assert "RSA-OAEP" in text
    assert "SHA-256" in text
    assert "getRandomValues" in text
    assert "Math.random" not in text


def test_web_decrypts_ad_credentials_and_validates_signed_timed_challenge():
    web = source("web.py")
    template = source("templates/login.html")
    assert "decrypt_credentials" in web
    assert "create_login_challenge" in web
    assert "validate_login_challenge" in web
    assert "AD_LOGIN_CHALLENGE_MAX_AGE" in web
    assert 'session["ad_login_nonce"]' not in web
    assert 'session.pop("ad_login_nonce", None)' not in web
    assert "hmac.compare_digest" not in web
    assert 'credentials.get("challenge"' in web
    assert "LOGIN_CHALLENGE" in template
    assert "challenge: LOGIN_CHALLENGE" in template
    assert 'request.form.get("password")' not in web.split('@app.route("/local-manager-login"')[0]


def test_crypto_key_paths_are_configurable_and_not_bundled():
    config_text = source("config.py")
    assert "DHCP_MANAGER_LOGIN_PRIVATE_KEY" in config_text
    assert "DHCP_MANAGER_LOGIN_PUBLIC_KEY" in config_text
    root = ROOT
    assert not (root / "login_private.pem").exists()
    assert not (root / "login_public.pem").exists()


def test_apply_script_copies_http_rsa_helper():
    apply_script = source("apply_to_main.sh")
    assert "static/vendor/rsa_oaep_sha256.js" in apply_script


def test_readme_describes_http_compatible_envelope_without_https_requirement():
    readme = source("README_AD_ACL.md")
    assert "HTTPS is required for the encrypted AD form" not in readme
    assert "ordinary HTTP" in readme
    assert "active man-in-the-middle" in readme
