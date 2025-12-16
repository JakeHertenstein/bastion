"""YubiKey service - queries 1Password as the source of truth.

This replaces the old YubiKeyCache with a stateless service that:
1. Queries the sync cache (db.accounts) for YubiKey/Token items
2. Scans physical YubiKeys via ykman
3. Compares and reports mismatches
4. Updates 1Password items directly
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from rich.console import Console

if TYPE_CHECKING:
    from .models import Account, Database
    from .db import BastionCacheManager

console = Console()


# Tag for YubiKey device items in 1Password
YUBIKEY_TOKEN_TAG = "YubiKey/Token"


@dataclass
class YubiKeyDevice:
    """YubiKey device info from 1Password."""
    
    uuid: str
    title: str
    serial: str
    vault: str
    oath_slots: list[dict]  # List of {issuer, username, oath_name}
    updated_at: str | None = None
    
    @property
    def slot_count(self) -> int:
        return len(self.oath_slots)
    
    @property
    def slots_remaining(self) -> int:
        return 32 - self.slot_count


@dataclass
class OathAccount:
    """OATH account on a physical YubiKey."""
    
    oath_name: str  # e.g., "GitHub:username"
    
    @property
    def issuer(self) -> str:
        """Extract issuer from OATH name."""
        if ":" in self.oath_name:
            return self.oath_name.split(":")[0]
        return self.oath_name
    
    @property
    def username(self) -> str:
        """Extract username from OATH name."""
        if ":" in self.oath_name:
            return self.oath_name.split(":", 1)[1]
        return ""


@dataclass
class ScanResult:
    """Result of comparing physical YubiKey with 1Password."""
    
    serial: str
    in_sync: bool
    on_device_only: list[str]  # OATH names on device but not in 1P
    in_1p_only: list[str]  # OATH names in 1P but not on device
    matched: list[str]  # OATH names that match


class YubiKeyService:
    """Service for YubiKey operations using 1Password as source of truth."""
    
    def __init__(self, cache_mgr: "BastionCacheManager"):
        """Initialize with cache manager.
        
        Args:
            cache_mgr: BastionCacheManager for accessing sync cache
        """
        self.cache_mgr = cache_mgr
        self._db: "Database | None" = None
    
    @property
    def db(self) -> "Database":
        """Lazy-load database."""
        if self._db is None:
            self._db = self.cache_mgr.load()
        return self._db
    
    def refresh_db(self) -> None:
        """Force refresh database from cache."""
        self._db = self.cache_mgr.load()
    
    # =========================================================================
    # Query methods (read from sync cache)
    # =========================================================================
    
    def get_yubikey_items(self) -> list["Account"]:
        """Get all YubiKey/Token items from sync cache.
        
        Matches items with tags starting with 'YubiKey/Token' (e.g., 'YubiKey/Token/5 NFC').
        
        Returns:
            List of Account objects with YubiKey/Token* tag
        """
        return [
            acc for acc in self.db.accounts.values()
            if any(tag.startswith(YUBIKEY_TOKEN_TAG) for tag in acc.tag_list)
        ]
    
    def get_yubikey_by_serial(self, serial: str) -> "Account | None":
        """Find YubiKey item by serial number.
        
        Args:
            serial: YubiKey serial number
            
        Returns:
            Account if found, None otherwise
        """
        for acc in self.get_yubikey_items():
            # Check fields_cache for SN field
            for field in acc.fields_cache:
                if field.get("label") == "SN" and field.get("value") == serial:
                    return acc
        return None
    
    def get_yubikey_device(self, serial: str) -> YubiKeyDevice | None:
        """Get YubiKey device info by serial.
        
        Args:
            serial: YubiKey serial number
            
        Returns:
            YubiKeyDevice if found, None otherwise
        """
        account = self.get_yubikey_by_serial(serial)
        if not account:
            return None
        
        return self._account_to_device(account)
    
    def get_all_devices(self) -> list[YubiKeyDevice]:
        """Get all YubiKey devices from sync cache.
        
        Returns:
            List of YubiKeyDevice objects, sorted by serial number
        """
        devices = []
        for acc in self.get_yubikey_items():
            device = self._account_to_device(acc)
            if device:
                devices.append(device)
        # Always sort numerically by serial number for consistent display
        return sorted(devices, key=lambda d: int(d.serial) if d.serial.isdigit() else 0)
    
    def _account_to_device(self, account: "Account") -> YubiKeyDevice | None:
        """Convert Account to YubiKeyDevice.
        
        Args:
            account: Account object with YubiKey/Token tag
            
        Returns:
            YubiKeyDevice or None if serial not found
        """
        serial = None
        oath_slots = []
        
        # Extract SN from fields
        for field in account.fields_cache:
            if field.get("label") == "SN":
                serial = field.get("value")
                break
        
        if not serial:
            return None
        
        # Extract OATH slots from sections
        # 1Password stores these as "OATH Slot N" sections
        for field in account.fields_cache:
            section = field.get("section", {})
            section_label = section.get("label", "") if isinstance(section, dict) else ""
            
            if section_label.startswith("OATH Slot"):
                label = field.get("label", "")
                value = field.get("value", "")
                
                # Build oath_name from section fields
                if label == "Issuer":
                    # Find matching username in same section
                    for f2 in account.fields_cache:
                        s2 = f2.get("section", {})
                        s2_label = s2.get("label", "") if isinstance(s2, dict) else ""
                        if s2_label == section_label and f2.get("label") == "Username":
                            username = f2.get("value", "")
                            oath_name = f"{value}:{username}" if username else value
                            oath_slots.append({
                                "issuer": value,
                                "username": username,
                                "oath_name": oath_name,
                            })
                            break
        
        return YubiKeyDevice(
            uuid=account.uuid,
            title=account.title,
            serial=serial,
            vault=account.vault_name,
            oath_slots=oath_slots,
            updated_at=account.last_synced,
        )
    
    def get_login_items_with_yubikey(self, serial: str) -> list["Account"]:
        """Get Login items that have TOTP on a specific YubiKey.
        
        Looks for items with Token N sections where Serial matches.
        
        Args:
            serial: YubiKey serial number
            
        Returns:
            List of Account objects
        """
        results = []
        
        for acc in self.db.accounts.values():
            # Skip YubiKey items themselves
            if YUBIKEY_TOKEN_TAG in acc.tag_list:
                continue
            
            # Check for Token sections with matching serial
            for field in acc.fields_cache:
                section = field.get("section", {})
                section_label = section.get("label", "") if isinstance(section, dict) else ""
                
                if section_label.startswith("Token "):
                    if field.get("label") == "Serial" and field.get("value") == serial:
                        results.append(acc)
                        break
        
        return results
    
    # =========================================================================
    # Hardware scan methods
    # =========================================================================
    
    def list_connected_serials(self) -> list[str]:
        """List serial numbers of connected YubiKeys.
        
        Returns:
            List of serial number strings
        """
        try:
            result = subprocess.run(
                ["ykman", "list", "--serials"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            return [s.strip() for s in result.stdout.strip().split("\n") if s.strip()]
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return []
    
    def scan_oath_accounts(self, serial: str, password: str | None = None) -> list[OathAccount]:
        """Scan OATH accounts on a physical YubiKey.
        
        Args:
            serial: YubiKey serial number
            password: OATH password if required
            
        Returns:
            List of OathAccount objects
        """
        cmd = ["ykman", "--device", serial, "oath", "accounts", "list"]
        
        try:
            if password:
                result = subprocess.run(
                    cmd + ["--password", password],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
            else:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
            
            accounts = []
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line:
                    accounts.append(OathAccount(oath_name=line))
            return accounts
            
        except subprocess.CalledProcessError as e:
            if "password" in e.stderr.lower():
                raise PasswordRequiredError(serial)
            raise
    
    def is_oath_password_required(self, serial: str) -> bool:
        """Check if OATH password is required for a YubiKey.
        
        Args:
            serial: YubiKey serial number
            
        Returns:
            True if password is required
        """
        try:
            result = subprocess.run(
                ["ykman", "--device", serial, "oath", "info"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            return "Password protected" in result.stdout
        except subprocess.CalledProcessError:
            return False
    
    def get_oath_password(self, serial: str) -> str | None:
        """Get OATH password from 1Password for a YubiKey.
        
        Args:
            serial: YubiKey serial number
            
        Returns:
            Password string if found, None otherwise
        """
        account = self.get_yubikey_by_serial(serial)
        if not account:
            return None
        
        # Look for password field
        for field in account.fields_cache:
            if field.get("id") == "password" or field.get("purpose") == "PASSWORD":
                return field.get("value")
            if "password" in field.get("label", "").lower():
                return field.get("value")
        
        return None
    
    # =========================================================================
    # Comparison and sync methods
    # =========================================================================
    
    def compare_device(self, serial: str, password: str | None = None) -> ScanResult:
        """Compare physical YubiKey with 1Password record.
        
        Args:
            serial: YubiKey serial number
            password: OATH password if required
            
        Returns:
            ScanResult with comparison details
        """
        # Get 1Password record
        device = self.get_yubikey_device(serial)
        expected_oath_names = set()
        if device:
            expected_oath_names = {slot["oath_name"] for slot in device.oath_slots}
        
        # Scan physical device
        physical_accounts = self.scan_oath_accounts(serial, password)
        actual_oath_names = {acc.oath_name for acc in physical_accounts}
        
        # Compare
        on_device_only = list(actual_oath_names - expected_oath_names)
        in_1p_only = list(expected_oath_names - actual_oath_names)
        matched = list(actual_oath_names & expected_oath_names)
        
        return ScanResult(
            serial=serial,
            in_sync=len(on_device_only) == 0 and len(in_1p_only) == 0,
            on_device_only=sorted(on_device_only),
            in_1p_only=sorted(in_1p_only),
            matched=sorted(matched),
        )
    
    def update_1p_oath_slots(self, serial: str, oath_accounts: list[OathAccount]) -> bool:
        """Update 1Password YubiKey item with current OATH slots.
        
        Args:
            serial: YubiKey serial number
            oath_accounts: List of OATH accounts from physical scan
            
        Returns:
            True if update succeeded
        """
        account = self.get_yubikey_by_serial(serial)
        if not account:
            console.print(f"[red]No 1Password item found for YubiKey {serial}[/red]")
            return False
        
        # Build field assignments for op item edit
        # First, we need to clear existing OATH Slot sections and add new ones
        assignments = []
        
        for i, oath_acc in enumerate(oath_accounts, 1):
            section_name = f"OATH Slot {i}"
            assignments.append(f'"{section_name}.Issuer[text]={oath_acc.issuer}"')
            assignments.append(f'"{section_name}.Username[text]={oath_acc.username}"')
        
        if not assignments:
            console.print(f"[yellow]No OATH accounts to update for {serial}[/yellow]")
            return True
        
        # Build and execute op item edit command
        cmd = ["op", "item", "edit", account.uuid] + assignments
        
        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            return True
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Failed to update 1Password: {e.stderr}[/red]")
            return False


class PasswordRequiredError(Exception):
    """Raised when OATH password is required but not provided."""
    
    def __init__(self, serial: str):
        self.serial = serial
        super().__init__(f"OATH password required for YubiKey {serial}")


def sync_yubikey_items(cache_mgr: "BastionCacheManager") -> int:
    """Sync only YubiKey/Token items from 1Password.
    
    This is a targeted sync that refreshes just the YubiKey items
    without doing a full vault sync.
    
    Args:
        cache_mgr: BastionCacheManager instance
        
    Returns:
        Number of items synced
    """
    from .op_client import OpClient
    from .planning import RotationPlanner
    
    console.print("[cyan]Syncing YubiKey items from 1Password...[/cyan]")
    
    op_client = OpClient()
    planner = RotationPlanner()
    db = cache_mgr.load()
    
    # Get items with YubiKey/Token tag
    items = op_client.list_items_with_tag(YUBIKEY_TOKEN_TAG)
    
    if not items:
        console.print("[yellow]No YubiKey/Token items found[/yellow]")
        return 0
    
    console.print(f"[dim]Found {len(items)} YubiKey items[/dim]")
    
    # Fetch full details
    full_items = op_client.get_items_batch(items)
    
    synced = 0
    for item in full_items:
        account = planner.process_item(item, db.metadata.compromise_baseline)
        db.accounts[item["id"]] = account
        synced += 1
    
    db.metadata.last_sync = datetime.now(timezone.utc)
    cache_mgr.save(db)
    
    console.print(f"[green]✓ Synced {synced} YubiKey items[/green]")
    return synced
