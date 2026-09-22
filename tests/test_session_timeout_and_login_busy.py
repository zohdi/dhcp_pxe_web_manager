from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def source(name):
    return (ROOT / name).read_text(encoding="utf-8")


def test_config_has_30_minute_idle_timeout():
    text = source("config.py")
    assert "SESSION_IDLE_TIMEOUT_MINUTES" in text
    assert "SESSION_IDLE_TIMEOUT_MINUTES: int = 30" in text


def test_web_enforces_idle_timeout_once_per_request():
    text = source("web.py")
    assert "import time" in text
    assert "@app.before_request" in text
    assert "def enforce_session_idle_timeout" in text
    assert 'session.get("last_activity")' in text
    assert "config.SESSION_IDLE_TIMEOUT_MINUTES * 60" in text
    assert "session.clear()" in text
    assert "Session expired due to inactivity" in text
    assert 'session["last_activity"] = now' in text
    assert '"login"' in text
    assert '"local_manager_login"' in text
    assert '"logout"' in text
    assert '"static"' in text


def test_ad_login_has_busy_overlay_and_locks_without_dropping_username():
    text = source("templates/login.html")
    assert 'id="loginBusyOverlay"' in text
    assert "Signing in..." in text
    assert "function setLoginBusy()" in text
    assert "usernameInput.readOnly = true" in text
    assert "passwordInput.readOnly = true" in text
    assert "loginButton.disabled = true" in text
    assert "readonlyButton.disabled = true" in text
    assert 'localManagerLink.setAttribute("aria-disabled", "true")' in text
    assert "let submitInProgress = false" in text
    # Do not disable the username control: disabled controls are omitted from form submission.
    assert "usernameInput.disabled = true" not in text
    # Lock the full UI only after ciphertext is ready.
    assert text.index("setLoginBusy();") > text.index("encryptedInput.value")


def test_local_manager_login_has_busy_state():
    text = source("templates/local_manager_login.html")
    assert 'id="localManagerLoginForm"' in text
    assert 'id="loginBusyOverlay"' in text
    assert "Signing in..." in text
    assert "usernameInput.readOnly = true" in text
    assert "passwordInput.readOnly = true" in text
    assert "loginButton.disabled = true" in text
