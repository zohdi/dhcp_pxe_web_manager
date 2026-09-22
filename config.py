"""
Centralized configuration for DHCP Manager.
All paths and settings are defined here.
"""
import os
from pathlib import Path
from dataclasses import dataclass

BASE_DIR = Path(__file__).resolve().parent


@dataclass
class DHCPConfig:
    """DHCP server configuration paths and settings."""

    # DHCP Configuration
    DHCP_CONF: Path = Path("/etc/dhcp/dhcpd.conf")
    DHCP_BACKUP: Path = Path("/etc/dhcp/dhcpd.conf.bak")
    DHCP_SERVICE: str = "isc-dhcp-server"
    DHCP_LEASES_FILE: Path = Path("/var/lib/dhcp/dhcpd.leases")

    # Available reservation IP discovery/cache. DHCP ranges are parsed dynamically
    # from dhcpd.conf on every scan; nothing here hard-codes subnet free ranges.
    AVAILABLE_IP_CACHE_PATH: Path = BASE_DIR / "data" / "available_ips.json"
    AVAILABLE_IP_CACHE_MAX_AGE_HOURS: int = 24
    AVAILABLE_IP_NMAP_BIN: str = "nmap"
    AVAILABLE_IP_NMAP_TIMEOUT_SECONDS: int = 180
    AVAILABLE_IP_PING_BIN: str = "ping"
    AVAILABLE_IP_PING_VERIFY: bool = True
    AVAILABLE_IP_PING_WORKERS: int = 32
    AVAILABLE_IP_PING_TIMEOUT_SECONDS: int = 1
    AVAILABLE_IP_MAX_HOSTS_PER_SUBNET: int = 4096

    # DNS/DDNS Configuration
    BIND_SERVICE: str = "bind9"

    # PXE Boot Configuration
    TFTP_BASE_DIR: Path = Path("/var/lib/tftpboot/pxelinux.cfg")
    PXE_DEFAULT_MENU: str = "default"
    PXE_DISK0_MENU: str = "default_local_disk0"
    PXE_DISK1_MENU: str = "default_local_disk1"

    # Dynamic iPXE Configuration
    IPXE_HTTP_BASE_URL: str = "http://127.0.0.1:5000"
    IPXE_DEFAULT_CHAIN_URL: str = ""
    IPXE_DIR: str = "ipxe"
    IPXE_SCRIPT_FILENAME: str = "ipxe/ipxe.ipxe"
    IPXE_CLIENTS_DIR: str = "clients"
    IPXE_MAC_SCRIPT_DIR: str = "ipxe/clients"
    IPXE_BIOS_BOOTLOADER: str = "undionly.kpxe"
    IPXE_UEFI_BOOTLOADER: str = "ipxe.efi"
    PXELINUX_BOOTLOADER: str = "pxelinux.0"
    IPXE_RETRY_SECONDS: int = 10

    # Logging
    LOG_FILE: Path = Path("/var/log/dhcp_manager.log")
    LOG_MAX_BYTES: int = 500000
    LOG_BACKUP_COUNT: int = 2

    # Flask Configuration
    FLASK_SECRET_KEY: str = os.environ.get("DHCP_MANAGER_SECRET_KEY", "supersecretkey")
    FLASK_HOST: str = "0.0.0.0"
    FLASK_PORT: int = 5000
    FLASK_DEBUG: bool = True
    SESSION_IDLE_TIMEOUT_MINUTES: int = 30

    # Local break-glass Manager authentication.
    MANAGER_USERNAME: str = os.environ.get("DHCP_MANAGER_USERNAME", "Admin")
    MANAGER_PASSWORD_HASH: str = os.environ.get(
        "DHCP_MANAGER_PASSWORD_HASH",
        "$2b$12$D3Rhw47KU47/oK6OTreZIu9YL42O4ROVPEEsoHuWpJ4AmYq6bgHLG",
    )

    # Backward-compatible aliases for older local code.
    ADMIN_USERNAME: str = MANAGER_USERNAME
    ADMIN_PASSWORD_HASH: str = MANAGER_PASSWORD_HASH

    # AD/VAS authentication. VAS remains configured in the host PAM stack.
    AD_PAM_SERVICE: str = os.environ.get("DHCP_MANAGER_AD_PAM_SERVICE", "login")

    # Browser-side AD credential envelope (RSA-OAEP/SHA-256).
    # Private key stays server-side; public key is embedded in the login page.
    LOGIN_PRIVATE_KEY_PATH: Path = Path(
        os.environ.get(
            "DHCP_MANAGER_LOGIN_PRIVATE_KEY",
            "/etc/dhcp-manager/crypto/login_private.pem",
        )
    )
    LOGIN_PUBLIC_KEY_PATH: Path = Path(
        os.environ.get(
            "DHCP_MANAGER_LOGIN_PUBLIC_KEY",
            "/etc/dhcp-manager/crypto/login_public.pem",
        )
    )

    # App-owned authorization metadata; does NOT modify dhcpd.conf subnet blocks.
    ACL_DB_PATH: Path = Path(
        os.environ.get("DHCP_MANAGER_ACL_DB", str(BASE_DIR / "data" / "access_control.db"))
    )
    ACL_AUDIT_LIMIT: int = 200


config = DHCPConfig()
