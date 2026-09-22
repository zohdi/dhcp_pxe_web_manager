# DHCP/PXE Web Manager — Local ACL Edition

A Flask + CLI tool for managing ISC DHCP reservations, PXE/iPXE boot profiles, VLAN-scoped access, and available reservation IPs.

This README describes the **`main`** branch.

## Maintained branches

| Branch | Purpose |
|---|---|
| `main` | **This branch** — built-in Admin + ACL-approved local Linux users + Available IP scanner |
| `ad_acl_http` | AD/VAS ACL edition with HTTP-compatible RSA login envelope |
| `ad_acl_https` | AD/VAS ACL edition with HTTPS/Web Crypto login |
| `autodeploy_web_dhcp` | Local-auth edition with first-run DHCP/TFTP/PXE setup wizard |

## Features

- ISC DHCP reservation add/edit/delete
- PXELINUX and iPXE Boot Device management
- Built-in bcrypt Admin account
- ACL-approved local Linux users with Manager or VLAN Editor roles
- Passwordless Read Only mode
- Server-side VLAN/CIDR authorization
- Audit log and idle session timeout
- Available-IP discovery using live DHCP state, Nmap, and parallel ping
- Available-IP selector on Add/Edit reservation pages
- Optional systemd timer for recurring scans

## Clone this branch

```bash
cd /opt
sudo git clone -b main https://github.com/zohdi/dhcp_pxe_web_manager.git dhcp_manager
cd /opt/dhcp_manager
```

## Prerequisites

Ubuntu/Debian example:

```bash
sudo apt-get update
sudo apt-get install -y isc-dhcp-server bind9 nmap python3 python3-pip
python3 -m pip install -r requirements-auth.txt
```

This branch assumes DHCP/PXE is already configured. For a first-run setup wizard, use `autodeploy_web_dhcp`.

## Authentication

### Built-in Admin

The built-in Admin is independent of PAM and does not require an ACL row.

```bash
export DHCP_MANAGER_USERNAME=Admin
export DHCP_MANAGER_PASSWORD_HASH='<bcrypt hash>'
export DHCP_MANAGER_SECRET_KEY='use-a-long-random-secret'
```

Generate a bcrypt hash:

```bash
python3 - <<'PY'
import bcrypt, getpass
pw = getpass.getpass("New Admin password: ").encode()
print(bcrypt.hashpw(pw, bcrypt.gensalt()).decode())
PY
```

### Local Linux users

Additional users must pass all three checks:

1. username is physically present in `/etc/passwd`
2. username exists and is enabled in the application ACL
3. PAM authentication succeeds

The local-account check intentionally does not rely on NSS/`getent`, so VAS/AD-only identities are rejected on this branch.

The PAM service defaults to `login`:

```bash
export DHCP_MANAGER_PAM_SERVICE=login
```

### Roles

- **Manager** — full application access
- **VLAN Editor** — reservations and Boot Device operations only inside assigned VLAN CIDRs
- **Read Only** — global view, no writes

## First ACL setup

The ACL database starts empty and is not committed to Git.

1. Sign in with the built-in Admin.
2. Open **Access Control**.
3. Add VLAN name/CIDR mappings managed by this application.
4. Add local Linux usernames.
5. Assign Manager or VLAN Editor.
6. Assign VLANs to each VLAN Editor.

Default ACL path:

```text
data/access_control.db
```

## Available IP discovery

The scanner:

1. parses active `dhcpd.conf`
2. scans only DHCP subnets that exactly match enabled VLAN/CIDR mappings
3. excludes network/broadcast, routers, dynamic ranges, fixed reservations and active leases
4. runs `nmap -sn -n --disable-arp-ping`
5. optionally checks remaining candidates in parallel with `ping -c1`
6. writes `data/available_ips.json`

Dynamic DHCP ranges are parsed from the live configuration; they are not hard-coded.

Create the first cache:

```bash
sudo python3 refresh_available_ips.py
```

Install the optional daily timer:

```bash
sudo ./install_available_ip_timer.sh "$PWD"
```

Check it:

```bash
systemctl status dhcp-manager-available-ips.timer
systemctl list-timers dhcp-manager-available-ips.timer
```

The cache is advisory only; Add/Edit performs a live re-check before changing DHCP configuration.

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
sudo ./cli.py add --hostname server1 --mac aa:bb:cc:dd:ee:ff --ip 192.168.1.10
sudo ./cli.py modify server1 --ip 192.168.1.20
./cli.py ipxe profiles
./cli.py ipxe snippet
sudo ./cli.py ipxe install-default
sudo ./cli.py boot 192.168.1.10 rocky-9
```

Set the generated iPXE base URL in `config.py`:

```python
IPXE_HTTP_BASE_URL = "http://<dhcp-manager-ip>:5000"
```

## Runtime state not stored in Git

```text
data/access_control.db
data/available_ips.json
```

## Testing

```bash
python3 -m pytest -q
```

Core tests can also be run with:

```bash
python3 -m unittest tests/test_dhcp_manager.py
```

## Troubleshooting

Validate DHCP:

```bash
sudo dhcpd -t -cf /etc/dhcp/dhcpd.conf
```

Check logs:

```bash
sudo journalctl -u isc-dhcp-server -f
journalctl -u dhcp-manager-available-ips.service -n 50
```

Back up DHCP configuration before major changes:

```bash
sudo cp /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.backup
```

## Repository

https://github.com/zohdi/dhcp_pxe_web_manager

Original project by Zohdi Mahameed.
