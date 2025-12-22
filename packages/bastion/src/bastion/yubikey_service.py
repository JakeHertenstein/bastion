"""YubiKey service - queries 1Password as the source of truth.

This replaces the old YubiKeyCache with a stateless service that:
1. Queries the sync cache (db.accounts) for YubiKey/Token items
2. Scans physical YubiKeys via ykman
3. Compares and reports mismatches
4. Updates 1Password items directly
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import quote

from rich.console import Console

if TYPE_CHECKING:
    from .db import BastionCacheManager
    from .models import Account, Database

console = Console()
logger = logging.getLogger(__name__)


def _mask_sensitive(value: str, prefix_len: int = 2) -> str:
    """Mask sensitive values in logs, showing only prefix.

    Args:
        value: Value to mask
        prefix_len: Number of characters to show at start

    Returns:
        Masked value (e.g., 'pa****' for 'password')
    """
    if not value or len(value) <= prefix_len:
        return "***"
    return value[:prefix_len] + "*" * (len(value) - prefix_len)


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

    def __init__(self, cache_mgr: BastionCacheManager):
        """Initialize with cache manager.

        Args:
            cache_mgr: BastionCacheManager for accessing sync cache
        """
        self.cache_mgr = cache_mgr
        self._db: Database | None = None

    @property
    def db(self) -> Database:
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

    def get_yubikey_items(self) -> list[Account]:
        """Get all YubiKey/Token items from sync cache.

        Matches items with tags starting with 'YubiKey/Token' (e.g., 'YubiKey/Token/5 NFC').

        Returns:
            List of Account objects with YubiKey/Token* tag
        """
        return [
            acc for acc in self.db.accounts.values()
            if any(tag.startswith(YUBIKEY_TOKEN_TAG) for tag in acc.tag_list)
        ]

    def get_yubikey_by_serial(self, serial: str) -> Account | None:
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

    def _account_to_device(self, account: Account) -> YubiKeyDevice | None:
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

    def get_login_items_with_yubikey(self, serial: str) -> list[Account]:
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

    def scan_oath_accounts(self, serial: str, password: str | None = None, verbose: int = 0) -> list[OathAccount]:
        """Scan OATH accounts on a physical YubiKey.

        Args:
            serial: YubiKey serial number
            password: OATH password if required
            verbose: Verbosity level (0=silent, 1=info, 2+=debug)

        Returns:
            List of OathAccount objects
        """
        cmd = ["ykman", "--device", serial, "oath", "accounts", "list"]

        if verbose >= 2:
            masked_pwd = _mask_sensitive(password) if password else "<none>"
            logger.debug(f"[YubiKey {serial}] Running: ykman --device {serial} oath accounts list (password: {masked_pwd})")

        try:
            if password:
                if verbose >= 1:
                    logger.info(f"[YubiKey {serial}] Scanning OATH accounts with password...")
                result = subprocess.run(
                    cmd + ["--password", password],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
            else:
                if verbose >= 1:
                    logger.info(f"[YubiKey {serial}] Scanning OATH accounts (no password)...")
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

            if verbose >= 1:
                logger.info(f"[YubiKey {serial}] Found {len(accounts)} OATH accounts")
            if verbose >= 2:
                for acc in accounts:
                    logger.debug(f"  - {acc.oath_name}")

            return accounts

        except subprocess.CalledProcessError as e:
            if verbose >= 1:
                logger.error(f"[YubiKey {serial}] ykman command failed")
            if verbose >= 2:
                logger.debug(f"  stderr: {e.stderr}")
            if "password" in e.stderr.lower():
                if verbose >= 1:
                    logger.warning(f"[YubiKey {serial}] OATH password required but not provided or incorrect")
                raise PasswordRequiredError(serial)
            raise

    def is_oath_password_required(self, serial: str, verbose: int = 0) -> bool:
        """Check if OATH password is required for a YubiKey.

        Args:
            serial: YubiKey serial number
            verbose: Verbosity level (0=silent, 1=info, 2+=debug)

        Returns:
            True if password is required
        """
        try:
            if verbose >= 2:
                logger.debug(f"[YubiKey {serial}] Checking if OATH password required via 'ykman oath info'...")

            result = subprocess.run(
                ["ykman", "--device", serial, "oath", "info"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )

            if verbose >= 2:
                logger.debug(f"[YubiKey {serial}] ykman oath info output:\n{result.stdout}")

            is_protected = "Password protected" in result.stdout or "Password protection: enabled" in result.stdout

            if verbose >= 1:
                if is_protected:
                    logger.info(f"[YubiKey {serial}] OATH password is required")
                else:
                    logger.info(f"[YubiKey {serial}] OATH password NOT required (or check failed)")

            return is_protected

        except subprocess.CalledProcessError as e:
            if verbose >= 2:
                logger.debug(f"[YubiKey {serial}] ykman oath info failed: {e.stderr}")
            return False
        except subprocess.TimeoutExpired:
            if verbose >= 1:
                logger.warning(f"[YubiKey {serial}] ykman oath info timed out (may need password)")
            return False

    def get_oath_password(self, serial: str, verbose: int = 0) -> str | None:
        """Get OATH password from 1Password for a YubiKey.

        Args:
            serial: YubiKey serial number
            verbose: Verbosity level (0=silent, 1=info, 2+=debug)

        Returns:
            Password string if found, None otherwise
        """
        if verbose >= 1:
            logger.info(f"[YubiKey {serial}] Searching for OATH password in 1Password")

        account = self.get_yubikey_by_serial(serial)
        if not account:
            if verbose >= 1:
                logger.warning(f"[YubiKey {serial}] No 1Password item found with serial {serial}")
            return None

        if verbose >= 2:
            logger.debug(f"[YubiKey {serial}] Found item: {account.title} (UUID: {account.uuid})")
            logger.debug(f"[YubiKey {serial}] Scanning {len(account.fields_cache)} fields for password patterns...")
            logger.debug(f"[YubiKey {serial}] All fields in item:")
            for i, field in enumerate(account.fields_cache):
                field_id = field.get("id", "")
                field_purpose = field.get("purpose", "")
                field_label = field.get("label", "")
                field_type = field.get("type", "")
                logger.debug(f"  [{i}] id={field_id!r}, purpose={field_purpose!r}, label={field_label!r}, type={field_type!r}")

        # Look for password field - check multiple naming conventions
        password = None

        # First pass: exact matches (id or purpose)
        for field in account.fields_cache:
            field_id = field.get("id", "")
            field_purpose = field.get("purpose", "")
            field_label = field.get("label", "")

            if field_id == "password" or field_purpose == "PASSWORD":
                password = field.get("value")
                if password:
                    if verbose >= 1:
                        logger.info(f"[YubiKey {serial}] Found password via ID/purpose match (label: {field_label})")
                    return password

        # Second pass: label contains "password"
        for field in account.fields_cache:
            field_label = field.get("label", "")
            if "password" in field_label.lower():
                password = field.get("value")
                if password:
                    if verbose >= 1:
                        logger.info(f"[YubiKey {serial}] Found password via label match (label: {field_label})")
                    return password

        if verbose >= 1:
            logger.warning(f"[YubiKey {serial}] OATH password field not found in 1Password item")
            if verbose >= 2:
                logger.debug(f"[YubiKey {serial}] No fields matched password patterns. Checked {len(account.fields_cache)} fields total.")
                logger.debug(f"[YubiKey {serial}] Password field should have one of: id='password', purpose='PASSWORD', or label containing 'password'")

        return None

    # =========================================================================
    # Comparison and sync methods
    # =========================================================================

    def compare_device(self, serial: str, password: str | None = None, verbose: int = 0) -> ScanResult:
        """Compare physical YubiKey with 1Password record.

        Args:
            serial: YubiKey serial number
            password: OATH password if required
            verbose: Verbosity level (0=silent, 1=info, 2+=debug)

        Returns:
            ScanResult with comparison details
        """
        # Get 1Password record
        device = self.get_yubikey_device(serial)
        expected_oath_names = set()
        if device:
            expected_oath_names = {slot["oath_name"] for slot in device.oath_slots}
            if verbose >= 1:
                logger.info(f"[YubiKey {serial}] 1Password has {len(expected_oath_names)} OATH accounts")
        else:
            if verbose >= 1:
                logger.warning(f"[YubiKey {serial}] Not found in 1Password")

        # Scan physical device
        physical_accounts = self.scan_oath_accounts(serial, password, verbose=verbose)
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

    # =========================================================================
    # Provisioning methods (write to hardware)
    # =========================================================================

    def get_totp_profile(self, serial: str, profile_override: str | None = None) -> str | None:
        """Get TOTP provisioning profile for a YubiKey.

        Args:
            serial: YubiKey serial number
            profile_override: Optional profile name to override

        Returns:
            Profile name or None if not found/configured
        """
        if profile_override:
            return profile_override

        account = self.get_yubikey_by_serial(serial)
        if not account:
            return None

        # Look for "TOTP Configuration.Profile" field
        for field in account.fields_cache:
            section = field.get("section", {})
            section_label = section.get("label", "") if isinstance(section, dict) else ""

            if section_label == "TOTP Configuration" and field.get("label") == "Profile":
                return field.get("value")

        return None

    def get_totp_capacity(self, serial: str) -> int:
        """Get TOTP capacity for a YubiKey.

        Args:
            serial: YubiKey serial number

        Returns:
            Capacity (32 or 64), defaults to 32 if not configured
        """
        account = self.get_yubikey_by_serial(serial)
        if not account:
            return 32

        # Look for "TOTP Configuration.Capacity" field
        for field in account.fields_cache:
            section = field.get("section", {})
            section_label = section.get("label", "") if isinstance(section, dict) else ""

            if section_label == "TOTP Configuration" and field.get("label") == "Capacity":
                try:
                    return int(field.get("value", "32"))
                except (ValueError, TypeError):
                    return 32

        return 32

    def get_accounts_for_profile(self, profile: str) -> list[Account]:
        """Get Login accounts that should be provisioned for a profile.

        Accounts must have:
        - Tag: Bastion/2FA/TOTP/YubiKey/Include/<profile>
        - NOT have: Bastion/2FA/TOTP/YubiKey/Exclude/<profile>

        Args:
            profile: Profile name

        Returns:
            List of Account objects, sorted alphabetically by issuer then username
        """
        include_tag = f"Bastion/2FA/TOTP/YubiKey/Include/{profile}"
        exclude_tag = f"Bastion/2FA/TOTP/YubiKey/Exclude/{profile}"

        matching = []
        for acc in self.db.accounts.values():
            tags = acc.tag_list
            if include_tag in tags and exclude_tag not in tags:
                matching.append(acc)

        # Sort alphabetically by title (which is usually "Issuer: Username")
        # Fall back to username field if title doesn't have useful info
        return sorted(matching, key=lambda a: (a.title.lower(), a.username.lower()))

    def build_provision_plan(
        self,
        serial: str,
        profile_override: str | None = None,
        verbose: int = 0,
    ) -> dict:
        """Build provisioning plan for a YubiKey.

        Args:
            serial: YubiKey serial number
            profile_override: Optional profile name to override
            verbose: Verbosity level

        Returns:
            Dict with provisioning plan:
            - profile: Profile name
            - capacity: Device capacity
            - count: Number of accounts to provision
            - accounts: List of dicts with issuer, username, otpauth
            - ykman_commands: List of ykman commands to execute

        Raises:
            ValueError: If YubiKey not found, profile not set, or no accounts found
        """
        # Get profile
        profile = self.get_totp_profile(serial, profile_override)
        if not profile:
            raise ValueError(
                f"No TOTP profile configured for YubiKey {serial}. "
                "Set 'TOTP Configuration.Profile' field in 1Password or use --profile."
            )

        # Get capacity
        capacity = self.get_totp_capacity(serial)

        # Get matching accounts
        accounts = self.get_accounts_for_profile(profile)
        if not accounts:
            raise ValueError(
                f"No accounts found for profile '{profile}'. "
                f"Tag accounts with 'Bastion/2FA/TOTP/YubiKey/Include/{profile}'."
            )

        # Build account list with TOTP details
        account_list = []
        for acc in accounts:
            # Extract TOTP value from fields (may be a full otpauth URI or a base32 secret)
            totp_value = None
            for field in acc.fields_cache:
                field_type = field.get("type")
                if field_type == "OTP":
                    totp_value = field.get("value")
                    break

            if not totp_value:
                if verbose >= 1:
                    logger.warning(f"No TOTP value found for {acc.title}, skipping")
                continue

            # Parse title or username for issuer/account
            # Common formats: "Issuer: Username", "Issuer (Username)", or just title
            title = acc.title
            username = acc.username or ""

            if ":" in title:
                issuer, account_name = title.split(":", 1)
                issuer = issuer.strip()
                account_name = account_name.strip() or username
            elif "(" in title and ")" in title:
                issuer = title.split("(")[0].strip()
                account_name = username
            else:
                issuer = title
                account_name = username

            # Determine otpauth URI
            if isinstance(totp_value, str) and totp_value.startswith("otpauth://"):
                otpauth_uri = totp_value
            else:
                # Construct a valid otpauth URI from base32 secret
                # Label should be URL-encoded and generally follow "Issuer:Account"
                label = f"{issuer}:{account_name}" if account_name else issuer
                label_enc = quote(label, safe=":@._- ").replace(" ", "%20")
                issuer_enc = quote(issuer, safe="@._- ")
                secret = totp_value
                # Default parameters: digits=6, period=30
                otpauth_uri = f"otpauth://totp/{label_enc}?secret={secret}&issuer={issuer_enc}&digits=6&period=30"

            account_list.append({
                "uuid": acc.uuid,
                "issuer": issuer,
                "username": account_name,
                "otpauth": otpauth_uri,
            })

        if not account_list:
            raise ValueError(f"No accounts with TOTP secrets found for profile '{profile}'")

        # Generate ykman commands (preview only)
        ykman_commands = [f"ykman --device {serial} oath reset --force"]
        for acc in account_list:
            ykman_commands.append(f"ykman --device {serial} oath accounts uri '{acc['otpauth']}' --touch")

        return {
            "serial": serial,
            "profile": profile,
            "capacity": capacity,
            "count": len(account_list),
            "accounts": account_list,
            "ykman_commands": ykman_commands,
        }

    def execute_provision(
        self,
        serial: str,
        plan: dict,
        require_touch: bool = True,
        verbose: int = 0,
    ) -> bool:
        """Execute provisioning plan on YubiKey.

        Args:
            serial: YubiKey serial number
            plan: Provisioning plan from build_provision_plan
            require_touch: Whether to require touch for TOTP
            verbose: Verbosity level

        Returns:
            True if provisioning succeeded
        """
        # Get OATH password if needed
        password = None
        if self.is_oath_password_required(serial):
            password = self.get_oath_password(serial, verbose=verbose)

        # ykman uses --password for OATH operations (not --oath-password)
        password_args = ["--password", password] if password else []

        # Reset OATH application (clears all accounts)
        console.print("[dim]Clearing existing OATH accounts...[/dim]")
        try:
            cmd = ["ykman", "--device", serial, "oath", "reset", "--force"]
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Failed to clear accounts: {e.stderr}[/red]")
            return False

        # Add each account
        for idx, acc in enumerate(plan["accounts"], 1):
            console.print(f"[dim]Adding {idx}/{plan['count']}: {acc['issuer']}:{acc['username']}[/dim]")

            # Use otpauth URI from plan
            otpauth = acc["otpauth"]

            # Build ykman command targeting correct device
            cmd = ["ykman", "--device", serial, "oath", "accounts", "uri", otpauth] + password_args
            if require_touch:
                cmd.append("--touch")

            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)
            except subprocess.CalledProcessError as e:
                console.print(f"[red]Failed to add {acc['issuer']}: {e.stderr}[/red]")
                return False

        return True


class PasswordRequiredError(Exception):
    """Raised when OATH password is required but not provided."""

    def __init__(self, serial: str):
        self.serial = serial
        super().__init__(f"OATH password required for YubiKey {serial}")


def sync_yubikey_items(cache_mgr: BastionCacheManager) -> int:
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

    db.metadata.last_sync = datetime.now(UTC)
    cache_mgr.save(db)

    console.print(f"[green]✓ Synced {synced} YubiKey items[/green]")
    return synced
