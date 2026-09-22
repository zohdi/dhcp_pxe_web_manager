# DHCP/PXE Web Manager — Local ACL build

The `main` branch keeps local authentication while adding the ACL, VLAN-scoping and available-IP features developed in the V1.4.1 line.

## Authentication
- Built-in bcrypt `Admin` remains the break-glass/global Manager and does not require an ACL row.
- Additional **local Linux users** authenticate through PAM (default service: `login`).
- A PAM username is eligible only if it is physically present in `/etc/passwd`.
- NSS/VAS/AD-only identities are rejected before PAM even if the Linux host can resolve them through `getent` or another identity provider.
- Local PAM users must also be explicitly present in Access Control.
- PAM users can be Manager or VLAN Editor.
- Passwordless Read Only mode remains available.
- Authenticated sessions expire after 30 minutes of inactivity on the next request.
- Login UI locks and shows `Signing in...` while authentication is running.

Install the local auth dependencies:

```bash
python3 -m pip install -r requirements-auth.txt
```

## ACL / VLAN behavior
- Manager: global access.
- VLAN Editor: reservations and Boot Device operations only inside assigned IPv4 CIDRs.
- ACL checks are server-side, not only UI filtering.
- VLAN mappings are application authorization metadata; they do not rewrite DHCP subnet declarations.
- The built-in Admin can manage VLAN mappings, local-user ACLs and audit history.

## Available IP discovery
The scanner rereads live state on each refresh:
1. Parse active, non-commented `dhcpd.conf`.
2. Scan only DHCP subnets that exactly match enabled VLAN/CIDR mappings in Access Control.
3. Exclude network/broadcast, routers, dynamic DHCP ranges, fixed reservations and active leases.
4. Run `nmap -sn -n --disable-arp-ping` once per managed subnet.
5. Optionally verify remaining candidates in parallel with `ping -c1`.
6. Cache results in `data/available_ips.json`.

Add/Edit performs a live re-check before changing `dhcpd.conf`; the JSON cache is advisory only.

Install Nmap and create the first cache:

```bash
sudo apt-get install -y nmap
sudo python3 refresh_available_ips.py
```

Optional recurring refresh:

```bash
sudo ./install_available_ip_timer.sh "$PWD"
```

The included timer defaults to daily. Adjust `OnCalendar=` in the systemd timer if another cadence is preferred.

## Runtime state excluded from Git
- `data/access_control.db`
- `data/available_ips.json`

The default `autodeploy_web_dhcp` branch is intentionally separate and remains unchanged.
