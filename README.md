# DHCP/PXE Web Manager — AD/VAS ACL HTTPS Edition

A Flask + CLI DHCP/PXE manager with AD/VAS authentication, VLAN-scoped authorization, available-IP discovery, and HTTPS-native browser encryption.

This README describes the **`ad_acl_https`** branch.

## Maintained branches

| Branch | Purpose |
|---|---|
| `main` | Local Linux users + ACL + Available IP scanner |
| `ad_acl_http` | AD/VAS ACL + HTTP-compatible RSA envelope |
| `ad_acl_https` | **This branch** — AD/VAS ACL + HTTPS/Web Crypto |
| `autodeploy_web_dhcp` | Local-auth first-run setup wizard |

## Clone this branch

```bash
cd /opt
sudo git clone -b ad_acl_https https://github.com/zohdi/dhcp_pxe_web_manager.git dhcp_manager
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
- Native browser Web Crypto RSA-OAEP/SHA-256 login

This branch does **not** provide arbitrary local-Linux-user ACL login. Local non-AD access is only the configured built-in Local Manager account.

## Prerequisites

The server must already be joined/configured for AD through VAS, and the selected PAM service must authenticate AD users.

```bash
sudo apt-get update
sudo apt-get install -y isc-dhcp-server bind9 nmap python3 python3-pip openssl nginx
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

## HTTPS requirement

The login page uses native browser `crypto.subtle` for RSA-OAEP/SHA-256. AD login is refused in an insecure browser context; it does not fall back to plaintext submission.

Typical deployment:

```text
Browser HTTPS :443
        ↓
nginx / reverse proxy
        ↓
Flask HTTP on 127.0.0.1:5000
```

After nginx changes:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

If Flask is moved to another port, update the nginx `proxy_pass` target too. TLS bytes sent directly to plain Flask will produce malformed/bad-request log messages.

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

## Start Flask

```bash
sudo python3 web.py
```

Access the application through the HTTPS URL configured in your reverse proxy, for example:

```text
https://<dhcp-manager-host>/
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
sudo nginx -t
```

See `README_AD_ACL.md` for deeper implementation/security notes.

## Repository

https://github.com/zohdi/dhcp_pxe_web_manager

Original project by Zohdi Mahameed.
