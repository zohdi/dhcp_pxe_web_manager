from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def source(name):
    return (ROOT / name).read_text(encoding="utf-8")


def test_shared_flash_helper_exists_and_uses_five_second_delay():
    helper = ROOT / "static" / "flash_auto_dismiss.js"
    assert helper.exists()
    text = helper.read_text(encoding="utf-8")
    assert "AUTO_DISMISS_MS = 5000" in text
    assert "FADE_MS = 300" in text
    assert '[data-auto-dismiss="flash"]' in text


def test_all_flask_flash_renderers_are_marked_and_load_shared_helper():
    layout = source("templates/layout.html")
    index = source("templates/index.html")
    add_edit = source("templates/add_edit.html")

    assert 'data-auto-dismiss="flash"' in layout
    assert 'flash_auto_dismiss.js' in layout

    assert 'data-auto-dismiss="flash"' in index
    assert 'flash_auto_dismiss.js' in index
    assert "10000" not in index

    assert 'data-auto-dismiss="flash"' in add_edit
    assert 'flash_auto_dismiss.js' in add_edit


def test_interactive_and_persistent_warning_panels_are_not_auto_dismissed():
    acl = source("templates/access_control.html")
    add_edit = source("templates/add_edit.html")
    login = source("templates/login.html")

    # Static ACL warnings/confirmations must remain until the user acts.
    assert '<div class="alert alert-warning"><strong>Important:' in acl
    assert '<div class="alert alert-warning mb-0">' in acl
    assert 'data-auto-dismiss="flash"' not in acl

    # The VLAN-editor scope info panel is persistent, not a transient flash.
    assert '<div class="alert alert-info py-2">' in add_edit

    # Client-side crypto preparation errors are not Flask flash messages.
    assert 'id="cryptoError"' in login
    assert 'id="cryptoError" data-auto-dismiss="flash"' not in login


def test_installer_copies_shared_flash_helper():
    apply_script = source("apply_to_main.sh")
    assert "static/flash_auto_dismiss.js" in apply_script
