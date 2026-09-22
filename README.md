# DHCP/PXE Web Manager — AD/VAS ACL HTTP Edition

A Flask + CLI DHCP/PXE manager with AD/VAS authentication, VLAN-scoped authorization, and available-IP discovery.

This README describes the **`ad_acl_http`** branch.

## Maintained branches

| Branch | Purpose |
|---|---|
| `main` | Local Linux users + ACL + Available IP scanner |
| `ad_acl_http` | **This branch** — AD/VAS ACL + HTTP-compatible RSA envelope |
| `ad_acl_https` | AD/VAS ACL + HTTPS/Web Crypto |
| `autodeploy_web_dhcp` | Local-auth first-run setup wizard |

## Clone this branch

```bash
cd /opt
sudo git clone -b ad_acl_http https://github.com/zohdi/dhcp_pxe_web_manager.git dhcp_manager
cd /opt/dhcp_manager
```

## Features

- AD login through Linux PAM/VAS
- Explicit ACL approval for every AD alias
- Manager and VLAN Editor roles
- Separate built-in Local Manager login
- Passwordless Read Only mode
- Server-side VLAN/CIDR enforcement
- Audit log and idle session timeout
- Available-IP scanner/list and Add/Edit selector
- PXELINUX/iPXE support
- HTTP-compatible RSA-OAEP/SHA-256 credential envelope

This branch does **not** provide arbitrary local-Linux-user ACL login. Local non-AD access is only the configured built-in Local Manager account.

## Prerequisites

The server must already be joined/configured for AD through VAS, and the selected PAM service must authenticate AD users.

```bash
sudo apt-get update
sudo apt-get install -y isc-dhcp-server bind9 nmap python3 python3-pip openssl
python3 -m pip install -r requirements-auth.txt
```

Default PAM service:

```bash
export DHCP_MANAGER_AD_PAM_SERVICE=login
```

Quick PAM/VAS test:

```bash
python3 - <<'PY'
import getpass, pam
alias = input("AD alias: ").strip()
password = getpass.getpass("AD password: ")
p = pam.pam()
print("success:", p.authenticate(alias, password, service="login", resetcreds=False))
print("reason:", p.reason)
PY
```

## RSA login keys

Keys are not stored in Git.

Default paths:

```text
/etc/dhcp-manager/crypto/login_private.pem
/etc/dhcp-manager/crypto/login_public.pem
```

Create them:

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

Optional overrides:

```bash
export DHCP_MANAGER_LOGIN_PRIVATE_KEY=/path/to/login_private.pem
export DHCP_MANAGER_LOGIN_PUBLIC_KEY=/path/to/login_public.pem
```

The Flask process must be able to read the private key. Do not make it world-readable.

## HTTP credential envelope

This branch uses:

```text
static/vendor/rsa_oaep_sha256.js
```

The AD password is wrapped in RSA-OAEP/SHA-256 before form submission, so it is not sent as a normal plaintext form field.

This is defense in depth, **not a replacement for TLS**. On HTTP, an active network attacker can replace the page, JavaScript or public key. Use `ad_acl_https` whenever HTTPS is practical.

## ACL first run

The ACL starts empty.

1. Sign in using **Local Manager Login**.
2. Open **Access Control**.
3. Add managed VLAN name/CIDR mappings.
4. Add AD aliases.
5. Assign Manager or VLAN Editor.
6. Assign VLANs to VLAN Editors.

An AD account that passes PAM/VAS but is not enabled in the ACL is denied.

## Available IP discovery

The scanner parses live DHCP subnets, dynamic ranges, fixed reservations and active leases; excludes routers/network/broadcast; scans only enabled ACL VLAN mappings; runs Nmap plus optional parallel `ping -c1`; and caches candidates in `data/available_ips.json`.

```bash
sudo python3 refresh_available_ips.py
sudo ./install_available_ip_timer.sh "$PWD"
```

Only Managers can trigger a whole-server refresh from the web UI. VLAN Editors only see candidate IPs in their assigned CIDRs.

## Local Manager configuration

```bash
export DHCP_MANAGER_USERNAME=Admin
export DHCP_MANAGER_PASSWORD_HASH='<bcrypt hash>'
export DHCP_MANAGER_SECRET_KEY='use-a-long-random-secret'
```

## Start the web UI

```bash
sudo python3 web.py
```

Open:

```text
http://<dhcp-manager-ip>:5000
```

## CLI / PXE examples

```bash
sudo ./cli.py list
./cli.py ipxe profiles
./cli.py ipxe snippet
sudo ./cli.py ipxe install-default
sudo ./cli.py boot 192.168.1.10 rocky-9
```

## Runtime state not stored in Git

```text
data/access_control.db
data/available_ips.json
/etc/dhcp-manager/crypto/login_private.pem
/etc/dhcp-manager/crypto/login_public.pem
```

## Testing

```bash
python3 -m pytest -q
```

## Troubleshooting

```bash
sudo dhcpd -t -cf /etc/dhcp/dhcpd.conf
sudo journalctl -u isc-dhcp-server -f
sudo python3 refresh_available_ips.py
journalctl -u dhcp-manager-available-ips.service -n 50
```

See `README_AD_ACL.md` for deeper implementation/security notes.

## Repository

https://github.com/zohdi/dhcp_pxe_web_manager

Original project by Zohdi Mahameed.
