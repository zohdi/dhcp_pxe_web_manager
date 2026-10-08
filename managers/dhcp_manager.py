"""
DHCP Manager - Handles DHCP server configuration management.

Provides CRUD operations for DHCP host entries with automatic
backup, validation, and service management.
"""
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from .pxe_manager import PXEBootManager

from config import config
from exceptions import (
    ValidationError, EntryNotFoundError, EntryExistsError,
    SyntaxValidationError, ServiceError, FileOperationError
)
from utils.validators import validate_dhcp_entry
from utils.logger import get_logger
from utils.colors import green, red, yellow, blue


class DHCPManager:
    """
    Manages DHCP server configuration file with CRUD operations.
    """
    
    # Regex pattern to match DHCP host entries
    HOST_ENTRY_PATTERN = re.compile(
        r'host\s+(\S+)\s*\{[^}]*?'
        r'hardware\s+ethernet\s+(\S+);[^}]*?'
        r'fixed-address\s+(\S+);[^}]*?\}',
        re.MULTILINE
    )
    
    def __init__(
        self,
        dhcp_conf: Optional[Path] = None,
        backup_conf: Optional[Path] = None
    ):
        """
        Initialize DHCP Manager.
        
        Args:
            dhcp_conf: Path to DHCP config file (uses config default if None)
            backup_conf: Path to backup file (uses config default if None)
        """
        self.dhcp_conf = dhcp_conf or config.DHCP_CONF
        self.backup_conf = backup_conf or config.DHCP_BACKUP
        self.logger = get_logger()
    
    # ============================================================
    #                   FILE OPERATIONS
    # ============================================================
    
    def _read_file(self) -> str:
        """
        Read DHCP configuration file.
        
        Returns:
            Configuration file content
            
        Raises:
            FileOperationError: If file cannot be read
        """
        try:
            return self.dhcp_conf.read_text()
        except (OSError, PermissionError) as e:
            raise FileOperationError(f"Failed to read config file: {e}")
    
    def _write_file(self, content: str) -> None:
        """
        Write content to DHCP configuration file.
        
        Args:
            content: Configuration content to write
            
        Raises:
            FileOperationError: If file cannot be written
        """
        try:
            self.dhcp_conf.write_text(content)
            self.logger.info("DHCP configuration updated")
        except (OSError, PermissionError) as e:
            raise FileOperationError(f"Failed to write config file: {e}")
    
    def backup_config(self) -> None:
        """
        Create a backup of the current DHCP configuration.
        
        Raises:
            FileOperationError: If backup fails
        """
        try:
            shutil.copy2(self.dhcp_conf, self.backup_conf)
            self.logger.info(f"Backup created: {self.backup_conf}")
        except (OSError, PermissionError) as e:
            raise FileOperationError(f"Failed to create backup: {e}")
    
    def restore_backup(self) -> None:
        """
        Restore DHCP configuration from backup.
        
        Raises:
            FileOperationError: If restore fails
        """
        try:
            shutil.copy2(self.backup_conf, self.dhcp_conf)
            self.logger.info("Configuration restored from backup")
        except (OSError, PermissionError) as e:
            raise FileOperationError(f"Failed to restore backup: {e}")
    
    # ============================================================
    #                   PARSING & FORMATTING
    # ============================================================
    
    def _strip_comments(self, content: str) -> str:
        """
        Remove comment lines from configuration content.
        
        Args:
            content: Configuration content
            
        Returns:
            Content without comment lines
        """
        lines = []
        for line in content.splitlines():
            if not line.strip().startswith("#"):
                lines.append(line)
        return "\n".join(lines)
    
    def _cleanup_whitespace(self, content: str) -> str:
        """
        Normalize whitespace in configuration content.
        
        - Removes excessive blank lines
        - Maintains single blank lines between blocks
        - Strips leading/trailing whitespace
        
        Args:
            content: Configuration content
            
        Returns:
            Cleaned content
        """
        lines = content.splitlines()
        cleaned = []
        previous_blank = False
        
        for line in lines:
            is_blank = not line.strip()
            
            if is_blank:
                if not previous_blank:
                    cleaned.append("")
                previous_blank = True
            else:
                cleaned.append(line)
                previous_blank = False
        
        # Remove leading/trailing blank lines
        while cleaned and not cleaned[0].strip():
            cleaned.pop(0)
        while cleaned and not cleaned[-1].strip():
            cleaned.pop()
        
        return "\n".join(cleaned) + "\n"
    
    def parse_entries(self, content: Optional[str] = None) -> List[Dict[str, str]]:
        """
        Parse DHCP host entries from configuration content.
        
        Args:
            content: Configuration content (reads from file if None)
            
        Returns:
            List of entry dicts with 'hostname', 'mac', and 'ip' keys
        """
        if content is None:
            content = self._read_file()
        
        # Remove comments for parsing
        cleaned = self._strip_comments(content)
        
        entries = []
        for match in self.HOST_ENTRY_PATTERN.finditer(cleaned):
            entries.append({
                "hostname": match.group(1),
                "mac": match.group(2).lower(),
                "ip": match.group(3),
            })
        
        return entries
    
    def format_entry(self, hostname: str, mac: str, ip: str) -> str:
        """
        Format a DHCP host entry block.
        
        Args:
            hostname: Host name
            mac: MAC address
            ip: IP address
            
        Returns:
            Formatted DHCP entry block
        """
        return (
            f"\nhost {hostname} {{\n"
            f"    hardware ethernet {mac};\n"
            f"    fixed-address {ip};\n"
            f"    option host-name \"{hostname}\";\n"
            f"    ddns-hostname \"{hostname}\";\n"
            f"}}\n"
        )
    
    # ============================================================
    #                   SERVICE MANAGEMENT
    # ============================================================
    
    def _run_command(self, cmd: List[str]) -> Tuple[int, str, str]:
        """
        Execute a system command.
        
        Args:
            cmd: Command and arguments as list
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return 1, "", "Command timed out"
        except Exception as e:
            return 1, "", str(e)
    
    def validate_syntax(self) -> None:
        """
        Validate DHCP configuration syntax.
        
        Raises:
            SyntaxValidationError: If syntax is invalid
        """
        code, stdout, stderr = self._run_command([
            "dhcpd", "-t", "-cf", str(self.dhcp_conf)
        ])
        
        if code != 0:
            error_msg = stderr.strip() or stdout.strip()
            raise SyntaxValidationError(f"Invalid DHCP syntax: {error_msg}")
    
    def restart_service(self, service: str) -> None:
        """
        Restart a systemd service.
        
        Args:
            service: Service name
            
        Raises:
            ServiceError: If restart fails
        """
        code, stdout, stderr = self._run_command([
            "systemctl", "restart", service
        ])
        
        if code != 0:
            error_msg = stderr.strip() or stdout.strip()
            raise ServiceError(f"Failed to restart {service}: {error_msg}")
        
        self.logger.info(f"Service restarted: {service}")
    
    def reload_service(self, service: str) -> None:
        """
        Reload a systemd service.
        
        Args:
            service: Service name
            
        Raises:
            ServiceError: If reload fails (logs warning, doesn't raise)
        """
        code, stdout, stderr = self._run_command([
            "systemctl", "reload", service
        ])
        
        if code != 0:
            error_msg = stderr.strip() or stdout.strip()
            self.logger.warning(f"Failed to reload {service}: {error_msg}")
        else:
            self.logger.info(f"Service reloaded: {service}")
    
    def apply_changes(self) -> None:
        """
        Validate configuration and restart services.
        
        Automatically rolls back to backup if validation or restart fails.
        
        Raises:
            SyntaxValidationError: If syntax validation fails
            ServiceError: If DHCP service restart fails
        """
        print(blue("🔍 Validating DHCP configuration syntax..."))
        
        try:
            self.validate_syntax()
            print(green("✓ Syntax validation passed"))
        except SyntaxValidationError as e:
            print(red(f"✗ Syntax validation failed: {e}"))
            print(yellow("⏪ Restoring from backup..."))
            self.restore_backup()
            raise
        
        print(blue("🔄 Restarting DHCP service..."))
        
        try:
            self.restart_service(config.DHCP_SERVICE)
            print(green("✓ DHCP service restarted successfully"))
        except ServiceError as e:
            print(red(f"✗ DHCP service restart failed: {e}"))
            print(yellow("⏪ Restoring from backup..."))
            self.restore_backup()
            
            # Try to restart with backup config
            try:
                self.restart_service(config.DHCP_SERVICE)
                print(green("✓ DHCP service restored with backup configuration"))
            except ServiceError:
                print(red("✗ CRITICAL: Unable to restore DHCP service!"))
                self.logger.critical("DHCP service failed to start even with backup")
            
            raise
        
        # Reload DNS service (non-critical)
        print(blue("🔄 Reloading DNS service..."))
        try:
            self.reload_service(config.BIND_SERVICE)
            print(green("✓ DNS service reloaded"))
        except ServiceError as e:
            print(yellow(f"⚠ DNS reload failed (non-critical): {e}"))
    
    def validate_staged_changes(self) -> None:
        """Validate a newly written DHCP configuration without restarting services.

        Used by the web UI so multiple reservation changes can be staged safely
        before the operator performs one explicit DHCP restart.
        """
        print(blue("🔍 Validating staged DHCP configuration syntax..."))
        try:
            self.validate_syntax()
            print(green("✓ Staged DHCP syntax validation passed"))
            self.logger.info("DHCP configuration validated; service restart deferred")
        except SyntaxValidationError as e:
            print(red(f"✗ Staged DHCP syntax validation failed: {e}"))
            print(yellow("⏪ Restoring from backup..."))
            self.restore_backup()
            raise

    # ============================================================
    #                   CRUD OPERATIONS
    # ============================================================
    
    def get_all_entries(self) -> List[Dict[str, str]]:
        """
        Get all DHCP entries.
        
        Returns:
            List of entry dicts
        """
        return self.parse_entries()
    
    def find_entry(self, identifier: str) -> Optional[Dict[str, str]]:
        """
        Find an entry by IP, MAC, or hostname.
        
        Args:
            identifier: IP address, MAC address, or hostname
            
        Returns:
            Entry dict or None if not found
        """
        entries = self.get_all_entries()
        identifier_lower = identifier.lower()
        
        for entry in entries:
            if identifier_lower in (
                entry["ip"].lower(),
                entry["mac"].lower(),
                entry["hostname"].lower()
            ):
                return entry
        
        return None
    
    def add_entry(
        self,
        hostname: str,
        mac: str,
        ip: str,
        apply_immediately: bool = True,
    ) -> None:
        """
        Add a new DHCP entry.
        
        Args:
            hostname: Host name
            mac: MAC address
            ip: IP address
            
        Raises:
            ValidationError: If input validation fails
            EntryExistsError: If entry already exists
        """
        # Validate inputs
        hostname, mac, ip = validate_dhcp_entry(hostname, mac, ip)
        
        # Check for duplicates
        entries = self.get_all_entries()
        
        for entry in entries:
            if entry["ip"] == ip:
                raise EntryExistsError(f"IP address already exists: {ip}")
            if entry["mac"].lower() == mac.lower():
                raise EntryExistsError(f"MAC address already exists: {mac}")
            if entry["hostname"].lower() == hostname.lower():
                raise EntryExistsError(f"Hostname already exists: {hostname}")
        
        # Backup current config
        print(blue("💾 Creating backup..."))
        self.backup_config()
        
        # Add new entry
        content = self._read_file()
        new_entry = self.format_entry(hostname, mac, ip)
        
        print(blue("✏️ Adding entry..."))
        self._write_file(content + new_entry)
        
        # Validate now; restart immediately only for callers that request legacy behavior.
        if apply_immediately:
            self.apply_changes()
        else:
            self.validate_staged_changes()
        
        self.logger.info(f"Added DHCP entry: {hostname} ({mac} -> {ip})")
        print(green(f"✓ Successfully added: {hostname}"))
    
    def remove_entry(self, identifier: str, apply_immediately: bool = True) -> None:
        """
        Remove a DHCP entry by IP, MAC, or hostname.
        
        Args:
            identifier: IP address, MAC address, or hostname
            
        Raises:
            EntryNotFoundError: If entry not found
        """
        entry = self.find_entry(identifier)
        
        if not entry:
            raise EntryNotFoundError(f"Entry not found: {identifier}")
        
        # Backup current config
        print(blue("💾 Creating backup..."))
        self.backup_config()
        
        # Remove entry
        content = self._read_file()
        
        # Build pattern to match this specific entry
        pattern = re.compile(
            rf'host\s+{re.escape(entry["hostname"])}\s*\{{[^}}]*?'
            rf'hardware\s+ethernet\s+{re.escape(entry["mac"])};[^}}]*?'
            rf'fixed-address\s+{re.escape(entry["ip"])};[^}}]*?\}}',
            re.MULTILINE
        )
        
        new_content = pattern.sub("", content)
        new_content = self._cleanup_whitespace(new_content)
        
        print(blue("🗑️ Removing entry..."))
        self._write_file(new_content)
        
        # Validate now; restart immediately only for callers that request legacy behavior.
        if apply_immediately:
            self.apply_changes()
        else:
            self.validate_staged_changes()

        try:
            pxe_manager = PXEBootManager()
            pxe_manager.delete_boot_link(entry["ip"])
            pxe_manager.delete_client_ipxe_script(entry["ip"])
        except Exception as e:
            self.logger.warning(f"Failed to remove PXE boot link: {e}")
        
        self.logger.info(f"Removed DHCP entry: {entry['hostname']}")
        print(green(f"✓ Successfully removed: {entry['hostname']}"))
    
    def modify_entry(
        self,
        identifier: str,
        new_hostname: Optional[str] = None,
        new_mac: Optional[str] = None,
        new_ip: Optional[str] = None,
        apply_immediately: bool = True,
    ) -> None:
        """
        Modify an existing DHCP entry.
        
        Args:
            identifier: IP address, MAC address, or hostname to identify entry
            new_hostname: New hostname (optional)
            new_mac: New MAC address (optional)
            new_ip: New IP address (optional)
            
        Raises:
            EntryNotFoundError: If entry not found
            ValidationError: If new values are invalid
            EntryExistsError: If new values conflict with existing entries
        """
        # Find existing entry
        old_entry = self.find_entry(identifier)
        
        if not old_entry:
            raise EntryNotFoundError(f"Entry not found: {identifier}")
        
        # Start with old values
        updated = old_entry.copy()
        
        # Validate and apply new values
        if new_hostname:
            from utils.validators import validate_hostname
            updated["hostname"] = validate_hostname(new_hostname)
        
        if new_mac:
            from utils.validators import validate_mac_address
            updated["mac"] = validate_mac_address(new_mac)
        
        if new_ip:
            from utils.validators import validate_ip_address
            updated["ip"] = validate_ip_address(new_ip)
        
        # Check for conflicts with other entries
        entries = self.get_all_entries()
        
        for entry in entries:
            if entry == old_entry:
                continue
            
            if updated["ip"] == entry["ip"]:
                raise EntryExistsError(f"IP address already exists: {updated['ip']}")
            if updated["mac"].lower() == entry["mac"].lower():
                raise EntryExistsError(f"MAC address already exists: {updated['mac']}")
            if updated["hostname"].lower() == entry["hostname"].lower():
                raise EntryExistsError(f"Hostname already exists: {updated['hostname']}")
        
        # Backup current config
        print(blue("💾 Creating backup..."))
        self.backup_config()
        
        # Remove old entry and add updated one
        content = self._read_file()
        
        # Remove old entry
        pattern = re.compile(
            rf'host\s+{re.escape(old_entry["hostname"])}\s*\{{[^}}]*?'
            rf'hardware\s+ethernet\s+{re.escape(old_entry["mac"])};[^}}]*?'
            rf'fixed-address\s+{re.escape(old_entry["ip"])};[^}}]*?\}}',
            re.MULTILINE
        )
        
        content = pattern.sub("", content)
        
        # Add updated entry
        new_entry = self.format_entry(
            updated["hostname"],
            updated["mac"],
            updated["ip"]
        )
        
        print(blue("✏️ Updating entry..."))
        self._write_file(content + new_entry)
        
        # Validate now; restart immediately only for callers that request legacy behavior.
        if apply_immediately:
            self.apply_changes()
        else:
            self.validate_staged_changes()
        
        self.logger.info(
            f"Modified DHCP entry: {old_entry['hostname']} -> {updated['hostname']}"
        )
        print(green(f"✓ Successfully updated: {updated['hostname']}"))
    
    def query_entry(self, identifier: Optional[str] = None) -> None:
        """
        Query and display DHCP entries.
        
        Args:
            identifier: IP, MAC, or hostname to search for (shows all if None)
        """
        entries = self.get_all_entries()
        
        if identifier is None:
            # Show all entries
            if not entries:
                print(yellow("No DHCP entries found"))
                return
            
            print(f"\n{green('DHCP Entries')} ({len(entries)} total):\n")
            for entry in entries:
                print(f"  {blue(entry['hostname'])}")
                print(f"    MAC: {entry['mac']}")
                print(f"    IP:  {entry['ip']}")
                print()
            return
        
        # Search for specific entry
        entry = self.find_entry(identifier)
        
        if not entry:
            print(red(f"✗ Entry not found: {identifier}"))
            raise EntryNotFoundError(f"Entry not found: {identifier}")
        
        print(f"\n{green('Entry found')}:")
        print(f"  Hostname: {blue(entry['hostname'])}")
        print(f"  MAC:      {entry['mac']}")
        print(f"  IP:       {entry['ip']}")
        print()