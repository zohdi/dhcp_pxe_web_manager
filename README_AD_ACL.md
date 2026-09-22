# AD Authentication + VLAN ACL Overlay V1.4.1 HTTP RSA (main branch)

This package is built for **`zohdi/dhcp_pxe_web_manager` `main` branch only**. It intentionally does not include or modify the default/autodeploy branch.

## What it adds

- AD login is the primary landing-page login.
- Local **Manager** login (full access / break-glass) is available on a separate page.
- Existing passwordless **Read Only** login (global read-only view).
- **AD login through Linux PAM/VAS**.
- AD password is wrapped in a browser-side **RSA-OAEP/SHA-256** envelope before form submission, so plaintext is not present in Network → Payload.
- Each encrypted AD login carries a server-signed, timestamped challenge valid for 120 seconds. The challenge is independent of the Flask session, so refreshing or opening another login page does not invalidate an already-open page.
- Manager-owned SQLite ACL database.
- Roles: **Manager**, **VLAN Editor**, **Read Only**.
- VLAN Editor visibility and DHCP reservation add/edit/delete are restricted by assigned VLAN IPv4 CIDRs.
- VLAN Editors may change **Boot Device** only for IPs inside their assigned VLAN CIDRs.
- iPXE installation/snippet, DHCP restart, ACL administration, and other global PXE settings remain Manager-only.
- Manager can edit existing VLAN → CIDR mappings without deleting/recreating them; AD assignments remain attached by VLAN ID.
- CIDR changes warn before saving if existing DHCP reservations would fall outside the new CIDR.
- Audit log for ACL/security-sensitive changes.
- Normal transient Flask notification banners (login/logout, reservation operations, ACL changes, etc.) automatically fade and disappear after 5 seconds; persistent warnings and confirmation panels remain visible until the user acts.
- Authenticated sessions expire after **30 minutes of inactivity** by default. The timeout is checked on the next request and can be changed in `config.py` with `SESSION_IDLE_TIMEOUT_MINUTES`.
- AD and Local Manager login forms show a **Signing in...** overlay and lock further interaction after submit, preventing accidental double-submits while PAM/VAS or bcrypt authentication is still running.
- **Available IP discovery** parses live DHCP subnet/range/reservation data, active leases, Nmap discovery, and parallel ping verification; candidates are cached and filtered by each user's authorized subnet scope.

## IMPORTANT: ACL ships empty

There is no preconfigured AD user and no VLAN mapping in this package. The first run only creates an empty SQLite schema at `data/access_control.db`.

1. Log in using the local Manager account.
2. Open **Access Control**.
3. Add your VLAN name/CIDR mappings.
4. Add AD aliases and choose `Manager` or `VLAN Editor`.
5. Assign one or more VLANs to each VLAN Editor.

A VLAN mapping here is authorization metadata only. It **does not edit ISC DHCP subnet configuration**. Editing a mapping changes only the ACL name/CIDR boundary; it does not renumber or delete DHCP reservations.

## Install on the VAS-joined work VM

From the existing `main` checkout, back it up first. This V1.4.1 overlay is **cumulative**: it contains the final versions of all files changed by the earlier AD/VLAN ACL overlays, so a clean clone of the original supported `main` branch can go directly to V1.4.1 without applying V1.1/V1.2/V1.3.x first.

Preferred installer:

```bash
git branch --show-current
# MUST print: main

/path/to/this-overlay/apply_to_main.sh /path/to/dhcp_pxe_web_manager
cd /path/to/dhcp_pxe_web_manager
python3 -m pip install -r requirements-auth.txt
```

The installer deliberately refuses to run when the target checkout is not on branch `main`.

## V1.3.4 encrypted AD login prerequisites

The RSA login envelope uses Python `cryptography` on the server and a locally bundled JavaScript RSA-OAEP/SHA-256 helper in the browser. `requirements-auth.txt` installs `cryptography`.

The server keys are **not included in this ZIP**. V1.3 defaults to:

```text
/etc/dhcp-manager/crypto/login_private.pem
/etc/dhcp-manager/crypto/login_public.pem
```

If you have not already created them:

```bash
sudo mkdir -p /etc/dhcp-manager/crypto
sudo chmod 700 /etc/dhcp-manager/crypto

sudo openssl genpkey \
  -algorithm RSA \
  -out /etc/dhcp-manager/crypto/login_private.pem \
  -pkeyopt rsa_keygen_bits:3072

sudo openssl pkey \
  -in /etc/dhcp-manager/crypto/login_private.pem \
  -pubout \
  -out /etc/dhcp-manager/crypto/login_public.pem

sudo chown root:root /etc/dhcp-manager/crypto/login_private.pem
sudo chmod 600 /etc/dhcp-manager/crypto/login_private.pem
sudo chmod 644 /etc/dhcp-manager/crypto/login_public.pem
```

Override the locations if needed:

```bash
export DHCP_MANAGER_LOGIN_PRIVATE_KEY=/path/to/login_private.pem
export DHCP_MANAGER_LOGIN_PUBLIC_KEY=/path/to/login_public.pem
```

**V1.3.4 works on ordinary HTTP.** The login page no longer uses `crypto.subtle`; it uses the bundled `static/vendor/rsa_oaep_sha256.js` helper and `crypto.getRandomValues()` for OAEP randomness. The submitted form contains ciphertext instead of the plaintext AD password. This is defense-in-depth only: on HTTP an active man-in-the-middle attacker can replace the delivered page/JavaScript/public key and capture credentials before encryption. HTTPS remains the correct transport protection when it becomes practical.

The Local Manager credential flow is not part of the AD RSA envelope. Its login page now shares the same post-submit busy/locked UX, but its authentication mechanism remains the existing local bcrypt check.

`python-pam` talks to the host PAM stack. VAS must already be present in the PAM service used by the app. The default service is `login` and can be changed without code:

```bash
export DHCP_MANAGER_AD_PAM_SERVICE=login
```

If your working VAS path is attached to a different PAM service, set that service name instead.

## Quick PAM/VAS test before starting Flask

Run this interactively on the **work VM** (password is read securely and is not stored):

```bash
python3 - <<'PY'
import getpass
import pam
alias = input("AD alias: ").strip()
password = getpass.getpass("AD password: ")
p = pam.pam()
ok = p.authenticate(alias, password, service="login", resetcreds=False)
print("success:", ok)
print("reason:", p.reason)
PY
```

If that works, the web AD authentication path is using the same mechanism.

## Manager password

The current main-branch bcrypt hash remains the default for compatibility. Prefer overriding it through environment variables on the server:

```bash
export DHCP_MANAGER_USERNAME=Admin
export DHCP_MANAGER_PASSWORD_HASH='<bcrypt hash>'
```

Generate a new bcrypt hash locally on the server:

```bash
python3 - <<'PY'
import bcrypt, getpass
pw = getpass.getpass("New manager password: ").encode()
print(bcrypt.hashpw(pw, bcrypt.gensalt()).decode())
PY
```

## Optional paths

```bash
export DHCP_MANAGER_ACL_DB=/opt/dhcp_pxe_web_manager/data/access_control.db
export DHCP_MANAGER_SECRET_KEY='use-a-long-random-secret'
```

## Security behavior

- AD password field has no HTML `name`, so the browser cannot submit it as a plaintext form field.
- AD POST contains `encrypted_credentials` (RSA-OAEP/SHA-256) plus the non-secret alias, not a plaintext password field.
- Encrypted credential payload must contain a valid server-signed login challenge issued within the last 120 seconds. Challenge validation does not depend on Flask session state, so tabs/refreshes do not overwrite each other.
- Private/public RSA key files are server-owned and never copied by the overlay installer.
- AD alias not in ACL: denied.
- Disabled/deleted AD ACL while logged in: session is invalidated on next request.
- Authenticated sessions are invalidated on the first request after the configured inactivity limit; closing the browser also ends the default non-permanent Flask session cookie.
- VLAN Editor manually posts another team's IP: HTTP 403.
- VLAN Editor edits an allowed reservation and tries to move it to another VLAN: HTTP 403.
- VLAN Editor may call the Boot Device change endpoint only for an IP inside an assigned VLAN CIDR; cross-VLAN attempts return HTTP 403.
- VLAN Editor directly calls global iPXE/restart/ACL endpoints: HTTP 403.
- VLAN mapping edits are Manager-only. Renames preserve principal assignments because assignments reference the VLAN database ID, not its display name.
- Read Only remains global view, no writes.


## V1.3.4 HTTP note

The bundled `static/vendor/rsa_oaep_sha256.js` performs RSA-OAEP/SHA-256 without `crypto.subtle`, so the AD form can encrypt its submitted password envelope on ordinary HTTP. V1.3.4 replaces the previous session nonce with a signed 120-second challenge, fixing false `Invalid or expired login challenge` errors caused by another render/refresh overwriting the session nonce. This specifically keeps plaintext out of Network → Payload. It is not a replacement for TLS: on HTTP an active network attacker can replace the delivered JavaScript/public key and capture credentials before encryption. A captured encrypted login payload can also be replayed during its short validity window; the signed challenge provides freshness, not strict one-time replay prevention.

## Available reservation IP discovery (V1.4.1)

The web UI now has **Show Available IPs** for Manager/VLAN Editor sessions and an IP selector on Add/Edit reservation pages. Results are grouped by the actual DHCP subnet CIDR (for example `172.28.103.0/24`), not by an assumed VLAN ID.

The scan is configuration-driven on every refresh. It parses only active (non-commented) `dhcpd.conf` content, discovers `subnet`, `option routers`, all current `range` / `range dynamic-bootp` declarations, and `fixed-address` reservations. This means ranges such as `172.28.103.101-240` or `172.21.80.101-240` are not hard-coded and can change in `dhcpd.conf` without a code change. It also removes addresses with a latest active binding in `/var/lib/dhcp/dhcpd.leases`.

V1.4.1 scopes discovery to the intersection of live DHCP subnets and **enabled VLAN/CIDR mappings in Access Control**. A subnet declared in `dhcpd.conf` but not configured as an enabled VLAN mapping is skipped completely: no Nmap, no ping, no JSON cache entry, and no Manager display. VLAN Editors are then filtered further to only their assigned VLAN mappings. This avoids scanning infrastructure/host-only subnets that exist in `dhcpd.conf` but are not managed by this application.

Network discovery then runs one `nmap -sn -n --disable-arp-ping` pass per subnet. `--disable-arp-ping` is intentional so local proxy-ARP behavior does not simply reproduce an `arping` result. Remaining candidates are checked in parallel with `ping -c1`. The completed result is written atomically to `data/available_ips.json` and the web layer filters that cache again through the logged-in user's server-side ACL scope before displaying any address.

The cache is advisory, so Add/Edit also performs a live re-check immediately before changing `dhcpd.conf`: current reservation/range/router/lease state, single-host Nmap discovery, and the optional ping check. Existing DHCPManager duplicate protection still independently rejects duplicate IP, MAC, and hostname values.

Install Nmap if it is not already available:

```bash
sudo apt-get install -y nmap
```

Create the first cache manually:

```bash
sudo python3 refresh_available_ips.py
```

A Manager can also use **Refresh Scan** in the Available IPs page. VLAN Editors can view only addresses inside their assigned ACL CIDRs; only Managers can initiate a whole-server scan from the GUI.

For an automatic daily refresh, an optional systemd timer installer is included:

```bash
sudo ./install_available_ip_timer.sh "$PWD"
```

The timer uses `OnCalendar=daily`, is persistent across downtime, and adds a small randomized delay. The normal overlay installer does **not** enable network scanning automatically; installing the timer is an explicit administrator action.
