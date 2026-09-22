# DHCP/PXE Web Manager — Autodeploy Edition

A Python DHCP/PXE management application with a Flask web UI, CLI, and first-run setup wizard.

This README describes the **`autodeploy_web_dhcp`** branch, which is currently the repository's default branch.

## Maintained branches

| Branch | Purpose |
|---|---|
| `autodeploy_web_dhcp` | **This branch** — first-run DHCP/TFTP/PXE setup wizard |
| `main` | Local Linux users + ACL + Available IP scanner |
| `ad_acl_http` | AD/VAS ACL + HTTP-compatible RSA envelope |
| `ad_acl_https` | AD/VAS ACL + HTTPS/Web Crypto |

## Features

- First-run DHCP/TFTP/PXE setup wizard
- ISC DHCP reservation management
- CLI and Flask web UI
- Built-in local Admin authentication
- Passwordless Read Only mode
- PXELINUX per-client boot links
- iPXE dispatcher and client-specific scripts
- Dynamic Boot Device discovery
- PXELINUX-to-iPXE translation

ACL/Available-IP features from `main` and AD/VAS authentication from the AD branches are intentionally separate from this branch.

## Clone this branch

Explicit branch:

```bash
cd /opt
sudo git clone -b autodeploy_web_dhcp https://github.com/zohdi/dhcp_pxe_web_manager.git dhcp_manager
cd /opt/dhcp_manager
```

Because this is the default branch, this also works:

```bash
cd /opt
sudo git clone https://github.com/zohdi/dhcp_pxe_web_manager.git dhcp_manager
cd /opt/dhcp_manager
```

## System packages

Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y isc-dhcp-server tftpd-hpa syslinux-common pxelinux python3 python3-pip
```

Rocky/RHEL/Fedora:

```bash
sudo dnf install -y dhcp-server tftp-server syslinux-tftpboot python3 python3-pip
```

Python dependencies:

```bash
sudo pip3 install flask bcrypt
```

Make scripts executable:

```bash
sudo chmod +x cli.py web.py
```

## First-run setup wizard

Start the web app:

```bash
sudo python3 web.py
```

Open:

```text
http://<dhcp-manager-ip>:5000
```

On a fresh host, the app redirects to:

```text
/setup/checks
```

The wizard can check/install prerequisites, select the DHCP interface, generate DHCP configuration, configure TFTP, copy PXELINUX/Syslinux files, and build the expected PXE directory structure.

For development without setup redirection:

```bash
DHCP_MANAGER_SKIP_SETUP=1 python3 web.py
```

## Default login

```text
Username: Admin
Password: DHCPManager!
```

Change the default credentials and Flask secret before production use.

## CLI examples

```bash
sudo ./cli.py list
sudo ./cli.py add --hostname server1 --mac aa:bb:cc:dd:ee:ff --ip 192.168.1.10
sudo ./cli.py query server1
sudo ./cli.py modify server1 --ip 192.168.1.20
sudo ./cli.py remove server1
```

## PXELINUX / iPXE

Classic PXELINUX per-client selections are stored under:

```text
/var/lib/tftpboot/pxelinux.cfg/<IP_HEX>
```

Generated iPXE client scripts are stored under:

```text
/var/lib/tftpboot/ipxe/clients/<IP>.ipxe
```

Useful commands:

```bash
./cli.py ipxe profiles
./cli.py ipxe snippet
sudo ./cli.py ipxe install-default
sudo ./cli.py boot 192.168.1.10 rocky-9
sudo ./cli.py ipxe set-client 192.168.1.10 rocky-9
./cli.py ipxe list-clients
```

Set the generated iPXE URL in `config.py`:

```python
IPXE_HTTP_BASE_URL = "http://<dhcp-manager-ip>:5000"
```

## Testing

```bash
python3 -m unittest tests/test_dhcp_manager.py
```

## Security

Before production use:

- change the default Admin password
- change `FLASK_SECRET_KEY`
- disable Flask debug mode
- restrict management access
- prefer HTTPS outside a trusted management network
- back up DHCP configuration

```bash
sudo cp /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.backup
```

## Troubleshooting

Validate DHCP:

```bash
sudo dhcpd -t -cf /etc/dhcp/dhcpd.conf
```

Ubuntu/Debian logs:

```bash
sudo journalctl -u isc-dhcp-server -f
```

Check PXE/TFTP files:

```bash
ls -la /var/lib/tftpboot/
ls -la /var/lib/tftpboot/pxelinux.cfg/
ls -la /var/lib/tftpboot/ipxe/
```

On Rocky/RHEL/Fedora, `syslinux-tftpboot` may install source files under `/tftpboot/`; the wizard can copy the required files into the managed TFTP root.

## Repository

https://github.com/zohdi/dhcp_pxe_web_manager

Original project by Zohdi Mahameed.
