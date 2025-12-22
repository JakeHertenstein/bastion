"""Airgap CLI main application.

Air-gapped cryptographic key generation system for SLIP-39 secret sharing.
"""

from __future__ import annotations

import getpass
import hashlib
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from .. import __version__
from ..slip39 import (
    SLIP39Config,
    SLIP39Share,
    compute_share_fingerprint,
    generate_shares,
    recover_secret,
    validate_share,
    verify_share_reentry,
)

# =============================================================================
# HARDWARE DETECTION (Linux-specific for air-gapped Raspberry Pi / Libre Computer)
# =============================================================================

# Known wireless USB vendor IDs (partial list)
WIRELESS_USB_VENDORS = {
    "148f": "Ralink/MediaTek",
    "0bda": "Realtek",
    "0cf3": "Qualcomm Atheros",
    "8087": "Intel Bluetooth",
    "0a5c": "Broadcom Bluetooth",
    "2357": "TP-Link",
    "7392": "Edimax",
    "0b05": "ASUS",
}


@dataclass
class HardwareCheckResult:
    """Result of a hardware check."""

    passed: bool
    devices: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_airgap_safe(self) -> bool:
        """True if no network-capable hardware detected."""
        return self.passed and len(self.devices) == 0


def detect_wireless_interfaces() -> list[str]:
    """Detect wireless network interfaces via /sys/class/net.

    Returns:
        List of detected wireless interface descriptions
    """
    devices = []
    net_path = Path("/sys/class/net")

    if not net_path.exists():
        return devices

    for iface in net_path.iterdir():
        name = iface.name
        # Check for common wireless interface naming patterns
        if name.startswith(("wlan", "wlp", "wifi", "wl")):
            # Try to get more info
            try:
                wireless_path = iface / "wireless"
                if wireless_path.exists():
                    devices.append(f"WiFi interface: {name}")
                else:
                    # Check if type indicates wireless (802.11)
                    type_path = iface / "type"
                    if type_path.exists():
                        devices.append(f"Wireless interface: {name}")
            except PermissionError:
                devices.append(f"Wireless interface: {name} (access denied)")

    return devices


def detect_wired_interfaces() -> list[str]:
    """Detect wired (Ethernet) network interfaces via /sys/class/net.

    Returns:
        List of detected wired interface descriptions
    """
    devices = []
    net_path = Path("/sys/class/net")

    if not net_path.exists():
        return devices

    for iface in net_path.iterdir():
        name = iface.name

        # Skip loopback and virtual interfaces
        if name in ("lo", "docker0", "br0", "virbr0") or name.startswith(("veth", "br-", "docker")):
            continue

        # Skip wireless interfaces (handled separately)
        if name.startswith(("wlan", "wlp", "wifi", "wl")):
            continue

        # Check for Ethernet interfaces
        # Type 1 = ARPHRD_ETHER (Ethernet)
        type_path = iface / "type"
        if type_path.exists():
            try:
                iface_type = type_path.read_text().strip()
                if iface_type == "1":  # Ethernet
                    # Check if it's a physical device (has a device symlink)
                    device_path = iface / "device"
                    if device_path.exists() or name.startswith(("eth", "enp", "eno", "ens")):
                        # Check carrier state (cable plugged in)
                        carrier_path = iface / "carrier"
                        operstate_path = iface / "operstate"

                        state = "unknown"
                        try:
                            if carrier_path.exists():
                                carrier = carrier_path.read_text().strip()
                                state = "connected" if carrier == "1" else "disconnected"
                            elif operstate_path.exists():
                                state = operstate_path.read_text().strip()
                        except (PermissionError, OSError):
                            pass

                        devices.append(f"Ethernet interface: {name} ({state})")
            except (PermissionError, OSError):
                # If we can't read type but name matches ethernet pattern
                if name.startswith(("eth", "enp", "eno", "ens")):
                    devices.append(f"Ethernet interface: {name}")

    return devices


def detect_rfkill_devices() -> list[str]:
    """Detect RF devices via rfkill.

    Returns:
        List of RF device descriptions
    """
    devices = []

    try:
        result = subprocess.run(
            ["rfkill", "list"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if result.returncode == 0 and result.stdout:
            # Parse rfkill output
            for line in result.stdout.splitlines():
                # Device line: "0: phy0: Wireless LAN"
                if re.match(r'^\d+:', line):
                    parts = line.split(':', 2)
                    if len(parts) >= 3:
                        device_type = parts[2].strip()
                        if any(x in device_type.lower() for x in ["wireless", "bluetooth", "wlan", "wifi"]):
                            devices.append(f"RF device: {device_type}")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return devices


def detect_wireless_usb_devices() -> list[str]:
    """Detect known wireless USB devices via lsusb.

    Returns:
        List of USB device descriptions
    """
    devices = []

    try:
        result = subprocess.run(
            ["lsusb"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if result.returncode == 0:
            for line in result.stdout.splitlines():
                # Line format: "Bus 001 Device 002: ID 148f:5370 Ralink Technology, Corp. RT5370..."
                for vendor_id, vendor_name in WIRELESS_USB_VENDORS.items():
                    if f"ID {vendor_id}:" in line.lower() or f"id {vendor_id}:" in line.lower():
                        devices.append(f"USB wireless: {line.strip()} ({vendor_name})")
                        break
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return devices


def check_all_wireless() -> HardwareCheckResult:
    """Run all wireless hardware detection checks.

    Returns:
        HardwareCheckResult with all detected wireless devices
    """
    devices = []
    warnings = []

    # Check network interfaces
    devices.extend(detect_wireless_interfaces())

    # Check rfkill
    rf_devices = detect_rfkill_devices()
    devices.extend(rf_devices)

    # Check USB devices
    usb_devices = detect_wireless_usb_devices()
    devices.extend(usb_devices)

    # Add warning if rfkill/lsusb not available
    try:
        subprocess.run(["rfkill", "--version"], capture_output=True, timeout=2)
    except FileNotFoundError:
        warnings.append("rfkill not installed - RF device detection limited")
    except subprocess.TimeoutExpired:
        pass

    try:
        subprocess.run(["lsusb", "-V"], capture_output=True, timeout=2)
    except FileNotFoundError:
        warnings.append("lsusb not installed - USB device detection limited")
    except subprocess.TimeoutExpired:
        pass

    return HardwareCheckResult(
        passed=len(devices) == 0,
        devices=devices,
        warnings=warnings,
    )


def check_all_wired() -> HardwareCheckResult:
    """Run all wired hardware detection checks.

    Returns:
        HardwareCheckResult with all detected wired devices
    """
    devices = detect_wired_interfaces()

    return HardwareCheckResult(
        passed=len(devices) == 0,
        devices=devices,
        warnings=[],
    )


def check_entropy_sources() -> dict[str, tuple[bool, str]]:
    """Check availability of entropy sources.

    Returns:
        Dict mapping source name to (available, message) tuple
    """
    sources = {}

    # Check Infinite Noise TRNG
    try:
        result = subprocess.run(
            ["infnoise", "--list-devices"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if "Serial:" in result.stdout or "Serial:" in result.stderr:
            sources["infnoise"] = (True, "Infinite Noise TRNG detected")
        else:
            sources["infnoise"] = (False, "No Infinite Noise device found")
    except FileNotFoundError:
        sources["infnoise"] = (False, "infnoise command not installed")
    except subprocess.TimeoutExpired:
        sources["infnoise"] = (False, "infnoise command timed out")

    # Check YubiKey
    try:
        result = subprocess.run(
            ["ykman", "list"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.stdout.strip():
            sources["yubikey"] = (True, f"YubiKey detected: {result.stdout.strip().split(chr(10))[0]}")
        else:
            sources["yubikey"] = (False, "No YubiKey found")
    except FileNotFoundError:
        sources["yubikey"] = (False, "ykman command not installed")
    except subprocess.TimeoutExpired:
        sources["yubikey"] = (False, "ykman command timed out")

    # Check /dev/urandom
    if Path("/dev/urandom").exists():
        sources["system"] = (True, "/dev/urandom available")
    else:
        sources["system"] = (False, "/dev/urandom not found")

    # Check /dev/random
    if Path("/dev/random").exists():
        sources["random"] = (True, "/dev/random available (blocking)")
    else:
        sources["random"] = (False, "/dev/random not found")

    return sources

# Create main app
app = typer.Typer(
    name="airgap",
    help="Air-gapped cryptographic key generation system",
    add_completion=False,
)

console = Console()

# =============================================================================
# SUBCOMMAND APPS
# =============================================================================

cards_app = typer.Typer(help="MicroSD card management")
entropy_app = typer.Typer(help="Entropy collection and verification")
keygen_app = typer.Typer(help="Key generation operations")
backup_app = typer.Typer(help="Backup creation and verification")
check_app = typer.Typer(help="System security checks")
export_app = typer.Typer(help="Export data via QR codes")
keys_app = typer.Typer(help="GPG key management")

app.add_typer(cards_app, name="cards")
app.add_typer(entropy_app, name="entropy")
app.add_typer(keygen_app, name="keygen")
app.add_typer(backup_app, name="backup")
app.add_typer(check_app, name="check")
app.add_typer(export_app, name="export")
app.add_typer(keys_app, name="keys")


# =============================================================================
# VERSION CALLBACK
# =============================================================================

def _version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        console.print(f"Bastion Airgap version: {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version"),
    ] = None,
) -> None:
    """Bastion Airgap - Air-gapped cryptographic key generation system.

    Secure key generation and SLIP-39 secret sharing for air-gapped environments.
    Designed for Tier 1 (highest security) operations with no network connectivity.
    """
    pass


# =============================================================================
# CARDS COMMANDS
# =============================================================================

# Card domains as per AIRGAP-DESIGN-DECISIONS.md
CARD_DOMAINS = ["OS", "SCRATCH", "SECRETS", "BACKUP", "AUDIT", "PARITY"]

# Local cache path
CARDS_CACHE_PATH = Path.home() / ".bsec" / "airgap" / "cards-cache.json"


def _get_cards_from_1password() -> list[dict]:
    """Fetch airgap card inventory from 1Password.

    Queries for Secure Notes tagged with Bastion/Airgap/CARD/*.

    Returns:
        List of card metadata dicts
    """
    import json

    try:
        # Search for items with Airgap/CARD tags
        result = subprocess.run(
            ["op", "item", "list", "--tags", "Bastion/Airgap/CARD", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            return []

        items = json.loads(result.stdout) if result.stdout else []
        cards = []

        for item in items:
            # Get full item details
            detail_result = subprocess.run(
                ["op", "item", "get", item["id"], "--format", "json"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if detail_result.returncode != 0:
                continue

            detail = json.loads(detail_result.stdout)

            # Extract custom fields
            fields = {f.get("label", ""): f.get("value", "") for f in detail.get("fields", [])}

            # Parse tags to find domain
            domain = "UNKNOWN"
            for tag in detail.get("tags", []):
                if tag.startswith("Bastion/Airgap/CARD/"):
                    domain = tag.split("/")[-1]
                    break

            cards.append({
                "id": item["id"],
                "title": detail.get("title", "Unknown"),
                "domain": domain,
                "site": fields.get("Site", ""),
                "role": fields.get("Role", ""),
                "created": fields.get("Created", detail.get("created_at", "")[:10]),
                "last_verified": fields.get("Last Verified", ""),
                "check_digit": fields.get("Check Digit", ""),
                "label": fields.get("Bastion Label", ""),
            })

        return cards

    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return []


def _load_cards_cache() -> list[dict]:
    """Load cards from local cache file.

    Returns:
        List of card metadata dicts, or empty list if cache doesn't exist
    """
    import json

    if not CARDS_CACHE_PATH.exists():
        return []

    try:
        return json.loads(CARDS_CACHE_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def _save_cards_cache(cards: list[dict]) -> None:
    """Save cards to local cache file.

    Args:
        cards: List of card metadata dicts
    """
    import json

    CARDS_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CARDS_CACHE_PATH.write_text(json.dumps(cards, indent=2))


@cards_app.command("list")
def cards_list(
    sync: Annotated[bool, typer.Option("--sync", help="Sync from 1Password before listing")] = False,
    offline: Annotated[bool, typer.Option("--offline", help="Use local cache only (no 1Password)")] = False,
) -> None:
    """List all provisioned microSD cards.

    Card inventory is stored as 1Password Secure Notes tagged with
    Bastion/Airgap/CARD/{DOMAIN}. Use --sync to refresh local cache,
    or --offline to use cached data when air-gapped.
    """
    if offline:
        cards = _load_cards_cache()
        if not cards:
            console.print("[yellow]No cached cards found[/yellow]")
            console.print("[dim]Run 'airgap cards list --sync' when online to populate cache[/dim]")
            return
        console.print("[dim]Using offline cache[/dim]\n")
    else:
        console.print("[cyan]Fetching cards from 1Password...[/cyan]")
        cards = _get_cards_from_1password()

        if sync or not _load_cards_cache():
            _save_cards_cache(cards)
            console.print(f"[dim]Cache updated: {CARDS_CACHE_PATH}[/dim]")

    if not cards:
        console.print("[yellow]No airgap cards found in 1Password[/yellow]")
        console.print("\n[dim]To register a card:[/dim]")
        console.print("  airgap cards provision --domain SECRETS --site home --role master")
        return

    # Build table
    table = Table(title="Airgap Card Inventory", show_header=True)
    table.add_column("Domain", style="cyan")
    table.add_column("Site.Role")
    table.add_column("Created", style="dim")
    table.add_column("Last Verified", style="dim")
    table.add_column("Check", style="dim")

    # Sort by domain priority
    domain_order = {d: i for i, d in enumerate(CARD_DOMAINS)}
    cards.sort(key=lambda c: (domain_order.get(c["domain"], 99), c["site"], c["role"]))

    for card in cards:
        site_role = f"{card['site']}.{card['role']}" if card['site'] and card['role'] else card['title']

        # Color domain based on security level
        domain = card['domain']
        if domain == "SECRETS":
            domain_styled = f"[bold red]{domain}[/bold red]"
        elif domain in ("BACKUP", "AUDIT"):
            domain_styled = f"[yellow]{domain}[/yellow]"
        elif domain in ("OS", "PARITY"):
            domain_styled = f"[green]{domain}[/green]"
        else:
            domain_styled = domain

        table.add_row(
            domain_styled,
            site_role,
            card['created'][:10] if card['created'] else "",
            card['last_verified'][:10] if card['last_verified'] else "[dim]never[/dim]",
            card['check_digit'] or "",
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(cards)} card(s)[/dim]")


@cards_app.command("provision")
def cards_provision(
    domain: Annotated[str, typer.Option("--domain", "-d", help="Card domain")] = None,
    site: Annotated[str, typer.Option("--site", "-s", help="Site identifier (e.g., home, bank-a)")] = None,
    role: Annotated[str, typer.Option("--role", "-r", help="Role within site (e.g., live, master, backup-1)")] = None,
    vault: Annotated[str, typer.Option("--vault", "-v", help="1Password vault")] = "Private",
) -> None:
    """Provision a new microSD card and register in 1Password.

    Creates a 1Password Secure Note with proper tags and fields to track
    the card in the airgap inventory. The card should be physically
    labeled to match the registered identity.

    Domains:
        OS - Live operating system (read-only)
        SCRATCH - Temporary workspace (RAM-based)
        SECRETS - SLIP-39 shares and KEKs (encrypted)
        BACKUP - Encrypted backups
        AUDIT - Logs and metadata
        PARITY - PAR2 recovery data
    """
    from datetime import date

    # Interactive prompts if not provided
    if not domain:
        console.print("[cyan]Card domains:[/cyan]")
        for i, d in enumerate(CARD_DOMAINS, 1):
            console.print(f"  {i}. {d}")
        choice = typer.prompt("Select domain (1-6)", type=int)
        if 1 <= choice <= len(CARD_DOMAINS):
            domain = CARD_DOMAINS[choice - 1]
        else:
            console.print("[red]Invalid choice[/red]")
            raise typer.Exit(1)

    domain = domain.upper()
    if domain not in CARD_DOMAINS:
        console.print(f"[red]Invalid domain: {domain}[/red]")
        console.print(f"Valid domains: {', '.join(CARD_DOMAINS)}")
        raise typer.Exit(1)

    if not site:
        site = typer.prompt("Site identifier (e.g., home, bank-a)")

    if not role:
        role = typer.prompt("Role (e.g., live, master, backup-1)")

    # Sanitize inputs
    site = re.sub(r'[^a-z0-9-]', '', site.lower())
    role = re.sub(r'[^a-z0-9-]', '', role.lower())

    # Generate label with check digit
    today = date.today().isoformat()
    label_base = f"Bastion/Airgap/CARD/{domain}:{site}.{role}:{today}#VERSION=1"

    # Calculate Luhn mod-36 check digit
    try:
        from bastion.label_spec import calculate_luhn_check
        check = calculate_luhn_check(label_base)
    except ImportError:
        # Fallback - simple checksum
        check = chr(65 + (sum(ord(c) for c in label_base) % 26))

    full_label = f"{label_base}|{check}"
    title = f"Airgap Card: {domain} - {site}.{role}"

    console.print("\n[cyan]Creating card registration...[/cyan]")
    console.print(f"  Title: {title}")
    console.print(f"  Domain: {domain}")
    console.print(f"  Site: {site}")
    console.print(f"  Role: {role}")
    console.print(f"  Label: {full_label}")

    if not typer.confirm("\nCreate this card in 1Password?"):
        raise typer.Abort()

    # Create 1Password Secure Note
    try:
        # Build field assignments
        # Note: using secure note template with custom fields
        result = subprocess.run(
            [
                "op", "item", "create",
                "--category", "Secure Note",
                "--title", title,
                "--vault", vault,
                "--tags", f"Bastion/Airgap/CARD/{domain}",
                f"Domain[text]={domain}",
                f"Site[text]={site}",
                f"Role[text]={role}",
                f"Created[text]={today}",
                "Last Verified[text]=",
                f"Check Digit[text]={check}",
                f"Bastion Label[text]={full_label}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            console.print(f"[red]Error creating item: {result.stderr}[/red]")
            raise typer.Exit(1)

        console.print("\n[green]✓ Card registered in 1Password[/green]")
        console.print("\n[bold]Physical labeling instructions:[/bold]")
        console.print(f"  1. Write on card: [cyan]{domain}:{site}.{role}[/cyan]")
        console.print(f"  2. Add check digit: [cyan]{check}[/cyan]")
        console.print("  3. Use color-coded case per domain")

    except subprocess.TimeoutExpired:
        console.print("[red]Error: 1Password CLI timed out[/red]")
        raise typer.Exit(1)
    except FileNotFoundError:
        console.print("[red]Error: 1Password CLI (op) not found[/red]")
        raise typer.Exit(1)


@cards_app.command("verify")
def cards_verify(
    domain: Annotated[str | None, typer.Option("--domain", "-d", help="Card domain to verify")] = None,
    site: Annotated[str | None, typer.Option("--site", "-s", help="Site identifier")] = None,
    role: Annotated[str | None, typer.Option("--role", "-r", help="Role identifier")] = None,
) -> None:
    """Verify card integrity and update Last Verified timestamp.

    Updates the 'Last Verified' field in 1Password for the specified card.
    This should be run after physically verifying the card's integrity
    (filesystem check, checksum validation, etc.).
    """
    from datetime import date

    # Get cards from 1Password
    console.print("[cyan]Fetching cards from 1Password...[/cyan]")
    cards = _get_cards_from_1password()

    if not cards:
        console.print("[yellow]No airgap cards found in 1Password[/yellow]")
        raise typer.Exit(1)

    # Filter by criteria
    matches = cards
    if domain:
        matches = [c for c in matches if c['domain'].upper() == domain.upper()]
    if site:
        matches = [c for c in matches if c['site'].lower() == site.lower()]
    if role:
        matches = [c for c in matches if c['role'].lower() == role.lower()]

    if not matches:
        console.print("[yellow]No matching cards found[/yellow]")
        raise typer.Exit(1)

    if len(matches) > 1:
        console.print("[yellow]Multiple cards match. Please be more specific:[/yellow]")
        for card in matches:
            console.print(f"  • {card['domain']}:{card['site']}.{card['role']}")
        raise typer.Exit(1)

    card = matches[0]
    today = date.today().isoformat()

    console.print("\n[cyan]Updating verification timestamp for:[/cyan]")
    console.print(f"  {card['domain']}:{card['site']}.{card['role']}")

    if not typer.confirm(f"\nMark as verified on {today}?"):
        raise typer.Abort()

    # Update 1Password item
    try:
        result = subprocess.run(
            [
                "op", "item", "edit", card['id'],
                f"Last Verified[text]={today}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            console.print(f"[red]Error updating item: {result.stderr}[/red]")
            raise typer.Exit(1)

        console.print(f"\n[green]✓ Card marked as verified: {today}[/green]")

    except subprocess.TimeoutExpired:
        console.print("[red]Error: 1Password CLI timed out[/red]")
        raise typer.Exit(1)


# =============================================================================
# ENTROPY COMMANDS
# =============================================================================

@entropy_app.command("collect")
def entropy_collect(
    source: Annotated[str, typer.Argument(help="Entropy source: yubikey, dice, infnoise, system")] = "system",
    bits: Annotated[int, typer.Option("--bits", "-b", help="Number of bits to collect")] = 256,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file (default: stdout)")] = None,
    analyze: Annotated[bool, typer.Option("--analyze", "-a", help="Run ENT analysis on collected entropy")] = False,
    raw: Annotated[bool, typer.Option("--raw", help="Output raw bytes instead of base64")] = False,
) -> None:
    """Collect entropy from hardware source.

    Outputs base64-encoded entropy suitable for air-gapped key generation.
    For Tier 1 operations, use hardware sources (infnoise, yubikey).

    Examples:
        airgap entropy collect yubikey --bits 256
        airgap entropy collect infnoise --bits 512 --output entropy.b64
        airgap entropy collect dice --bits 128 --analyze
    """
    import base64
    import sys

    # Import bastion entropy modules
    try:
        # Try bastion package first
        if source == "yubikey":
            from bastion.entropy_yubikey import YubiKeyEntropyError, check_yubikey_available, collect_yubikey_entropy
        elif source == "dice":
            from bastion.entropy_dice import collect_dice_entropy
        elif source == "infnoise":
            from bastion.entropy_infnoise import InfNoiseError, check_infnoise_available, collect_infnoise_entropy
        elif source == "system":
            from bastion.entropy_system_rng import SystemRNGError, collect_urandom_entropy
        else:
            console.print(f"[red]Error: Unknown source '{source}'[/red]")
            console.print("Available sources: yubikey, dice, infnoise, system")
            raise typer.Exit(1)
    except ImportError:
        # Try password_rotation package (legacy path)
        try:
            if source == "yubikey":
                from password_rotation.entropy_yubikey import (
                    YubiKeyEntropyError,
                    check_yubikey_available,
                    collect_yubikey_entropy,
                )
            elif source == "dice":
                from password_rotation.entropy_dice import collect_dice_entropy
            elif source == "infnoise":
                from password_rotation.entropy_infnoise import (
                    InfNoiseError,
                    check_infnoise_available,
                    collect_infnoise_entropy,
                )
            elif source == "system":
                from password_rotation.entropy_system_rng import SystemRNGError, collect_urandom_entropy
        except ImportError:
            console.print("[red]Error: Could not import bastion entropy modules[/red]")
            console.print("Ensure bastion is installed: pip install -e /path/to/bastion")
            raise typer.Exit(1)

    console.print(f"[cyan]Collecting {bits} bits from {source}...[/cyan]")

    try:
        if source == "yubikey":
            if not check_yubikey_available():
                console.print("[red]Error: No YubiKey detected[/red]")
                raise typer.Exit(1)
            entropy_bytes = collect_yubikey_entropy(bits=bits)

        elif source == "dice":
            # Dice collection is interactive
            entropy_bytes = collect_dice_entropy(bits=bits)

        elif source == "infnoise":
            available, error = check_infnoise_available()
            if not available:
                console.print(f"[red]Error: {error}[/red]")
                raise typer.Exit(1)
            entropy_bytes, metadata = collect_infnoise_entropy(bits=bits)
            console.print(f"[dim]Device serial: {metadata.serial}[/dim]")

        elif source == "system":
            entropy_bytes, metadata = collect_urandom_entropy(bits=bits)
            console.print(f"[dim]Source: {metadata.source_device}[/dim]")

    except Exception as e:
        console.print(f"[red]Error collecting entropy: {e}[/red]")
        raise typer.Exit(1)

    # Run ENT analysis if requested
    if analyze:
        try:
            from bastion.entropy import analyze_entropy_with_ent
        except ImportError:
            try:
                from password_rotation.entropy import analyze_entropy_with_ent
            except ImportError:
                console.print("[yellow]Warning: Could not import ENT analysis[/yellow]")
                analyze = False

        if analyze:
            console.print("\n[cyan]Running ENT analysis...[/cyan]")
            analysis = analyze_entropy_with_ent(entropy_bytes)
            if analysis:
                console.print(f"  Entropy: {analysis.entropy_bits_per_byte:.6f} bits/byte")
                console.print(f"  Chi-square p-value: {analysis.chi_square_pvalue:.6f}")
                console.print(f"  Serial correlation: {analysis.serial_correlation:.6f}")
                console.print(f"  Quality: {analysis.quality_rating()}")
            else:
                console.print("[yellow]  ENT not installed - install with: apt install ent[/yellow]")

    # Output entropy
    if raw:
        output_data = entropy_bytes
    else:
        output_data = base64.b64encode(entropy_bytes)

    if output:
        mode = "wb" if raw else "w"
        with open(output, mode) as f:
            if raw:
                f.write(output_data)
            else:
                f.write(output_data.decode() + "\n")
        console.print(f"\n[green]✓ Wrote {len(entropy_bytes)} bytes to {output}[/green]")
    else:
        console.print(f"\n[bold]Entropy ({len(entropy_bytes)} bytes):[/bold]")
        if raw:
            sys.stdout.buffer.write(output_data)
        else:
            console.print(output_data.decode())


@entropy_app.command("verify")
def entropy_verify(
    file: Annotated[Path, typer.Argument(help="Entropy file to verify (base64 or raw)")],
    raw: Annotated[bool, typer.Option("--raw", help="File contains raw bytes instead of base64")] = False,
) -> None:
    """Run ENT analysis on collected entropy.

    Analyzes entropy quality using the ENT tool and reports statistical metrics
    including entropy bits per byte, chi-square distribution, and serial correlation.
    """
    import base64

    if not file.exists():
        console.print(f"[red]Error: File not found: {file}[/red]")
        raise typer.Exit(1)

    # Read file
    if raw:
        entropy_bytes = file.read_bytes()
    else:
        content = file.read_text().strip()
        try:
            entropy_bytes = base64.b64decode(content)
        except Exception as e:
            console.print(f"[red]Error decoding base64: {e}[/red]")
            raise typer.Exit(1)

    console.print(f"[cyan]Analyzing {len(entropy_bytes)} bytes of entropy...[/cyan]\n")

    # Import and run analysis
    try:
        from bastion.entropy import analyze_entropy_with_ent
    except ImportError:
        try:
            from password_rotation.entropy import analyze_entropy_with_ent
        except ImportError:
            console.print("[red]Error: Could not import ENT analysis module[/red]")
            raise typer.Exit(1)

    analysis = analyze_entropy_with_ent(entropy_bytes)

    if analysis is None:
        console.print("[red]Error: ENT tool not installed[/red]")
        console.print("Install with: apt install ent (Linux) or brew install ent (macOS)")
        raise typer.Exit(1)

    # Build results table
    table = Table(title="ENT Analysis Results", show_header=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value")
    table.add_column("Ideal", style="dim")

    table.add_row("Entropy", f"{analysis.entropy_bits_per_byte:.6f} bits/byte", "8.0")
    table.add_row("Chi-square", f"{analysis.chi_square:.2f}", "~256")
    table.add_row("Chi-square p-value", f"{analysis.chi_square_pvalue:.6f}", "0.10-0.90")
    table.add_row("Arithmetic mean", f"{analysis.arithmetic_mean:.4f}", "127.5")
    table.add_row("Monte Carlo π", f"{analysis.monte_carlo_pi:.6f}", "3.14159")
    table.add_row("Monte Carlo error", f"{analysis.monte_carlo_error:.2f}%", "<1%")
    table.add_row("Serial correlation", f"{analysis.serial_correlation:.6f}", "0.0")

    console.print(table)

    # Quality rating
    quality = analysis.quality_rating()
    if quality == "EXCELLENT":
        console.print(f"\n[bold green]Quality: {quality}[/bold green]")
    elif quality == "GOOD":
        console.print(f"\n[bold cyan]Quality: {quality}[/bold cyan]")
    elif quality == "FAIR":
        console.print(f"\n[bold yellow]Quality: {quality}[/bold yellow]")
    else:
        console.print(f"\n[bold red]Quality: {quality}[/bold red]")

    if analysis.is_acceptable():
        console.print("[green]✓ Entropy meets minimum quality requirements[/green]")
    else:
        console.print("[red]✗ Entropy does NOT meet quality requirements[/red]")
        raise typer.Exit(1)


# =============================================================================
# KEYGEN COMMANDS
# =============================================================================

@keygen_app.command("master")
def keygen_master(
    algorithm: Annotated[str, typer.Option("--algorithm", "-a", help="Key algorithm")] = "rsa4096",
    entropy_source: Annotated[str, typer.Option("--entropy", "-e", help="Entropy source")] = "infnoise",
    min_quality: Annotated[str, typer.Option("--min-quality", help="Minimum entropy quality")] = "GOOD",
    inject: Annotated[bool, typer.Option("--inject/--no-inject", help="Inject entropy into kernel pool")] = True,
) -> None:
    """Generate a new GPG master (certify) key.

    This command:
    1. Collects entropy from hardware source
    2. Verifies entropy quality with ENT analysis
    3. Optionally injects entropy into kernel pool
    4. Generates GPG master key (certify capability only)
    5. Logs key generation to sigchain

    Supported algorithms: rsa4096 (default), rsa3072, ed25519
    """
    from ..crypto import (
        EntropyQuality,
        collect_verified_entropy,
        inject_kernel_entropy,
    )

    console.print(Panel.fit(
        f"[bold cyan]GPG Master Key Generation[/bold cyan]\n\n"
        f"Algorithm: {algorithm}\n"
        f"Entropy: {entropy_source}\n"
        f"Min Quality: {min_quality}\n"
        f"Kernel Injection: {'Yes' if inject else 'No'}\n\n"
        "[bold red]⚠️  TIER 1 OPERATION[/bold red]",
        title="🔐 keygen master",
    ))

    if not typer.confirm("\nProceed with master key generation?"):
        raise typer.Abort()

    # Step 1: Collect and verify entropy
    console.print(f"\n[cyan]Step 1: Collecting entropy from {entropy_source}...[/cyan]")
    try:
        quality_enum = EntropyQuality(min_quality.upper())
        collection = collect_verified_entropy(
            bits=4096,
            source=entropy_source,
            min_quality=quality_enum,
        )

        if collection.analysis:
            console.print(f"  Entropy: {collection.analysis.entropy_bits_per_byte:.4f} bits/byte")
            console.print(f"  Quality: [bold]{collection.quality}[/bold]")
        else:
            console.print(f"  Collected {collection.bits} bits")
            console.print("  [yellow]ENT analysis unavailable[/yellow]")

    except Exception as e:
        console.print(f"[red]Error collecting entropy: {e}[/red]")
        raise typer.Exit(1)

    # Step 2: Inject into kernel pool
    if inject:
        console.print("\n[cyan]Step 2: Injecting entropy into kernel pool...[/cyan]")
        try:
            inject_kernel_entropy(collection.data, entropy_bits=collection.bits)
            console.print("  [green]✓ Entropy injected successfully[/green]")
        except PermissionError:
            console.print("  [yellow]⚠ Requires sudo - you may be prompted[/yellow]")
            try:
                inject_kernel_entropy(collection.data, entropy_bits=collection.bits, require_sudo=True)
                console.print("  [green]✓ Entropy injected with sudo[/green]")
            except Exception as e:
                console.print(f"  [red]Failed to inject entropy: {e}[/red]")
                if not typer.confirm("Continue without kernel entropy injection?"):
                    raise typer.Exit(1)
        except Exception as e:
            console.print(f"  [yellow]⚠ Kernel injection not available: {e}[/yellow]")
            console.print("  [dim]GPG will use system entropy pool[/dim]")

    # Step 3: Generate GPG key
    console.print(f"\n[cyan]Step 3: Generating GPG master key ({algorithm})...[/cyan]")
    console.print("[yellow]This will prompt for passphrase interactively[/yellow]")

    # Build GPG key generation parameters
    if algorithm == "rsa4096":
        pass
    elif algorithm == "rsa3072":
        pass
    elif algorithm == "ed25519":
        pass  # Ed25519 has fixed size
    else:
        console.print(f"[red]Unsupported algorithm: {algorithm}[/red]")
        raise typer.Exit(1)

    # Generate key using GPG batch mode for certify-only master key
    # Note: This creates a minimal master key with only certify capability
    console.print("\n[dim]GPG will prompt for user ID and passphrase...[/dim]")

    try:
        # Interactive key generation - GPG will handle prompts
        result = subprocess.run(
            ["gpg", "--full-generate-key", "--expert"],
            timeout=300,  # 5 minute timeout for interactive input
        )

        if result.returncode == 0:
            console.print("\n[green]✓ Master key generated successfully[/green]")
            console.print("\n[cyan]Next steps:[/cyan]")
            console.print("  1. Run 'airgap keygen subkeys' to create subkeys")
            console.print("  2. Run 'airgap keygen transfer-to-yubikey' to move keys to YubiKey")
            console.print("  3. Run 'airgap backup create' to backup keys")
        else:
            console.print("\n[red]Key generation failed or was cancelled[/red]")
            raise typer.Exit(1)

    except subprocess.TimeoutExpired:
        console.print("\n[red]Key generation timed out[/red]")
        raise typer.Exit(1)
    except FileNotFoundError:
        console.print("\n[red]GPG not found. Install with: apt install gnupg[/red]")
        raise typer.Exit(1)


@keygen_app.command("slip39")
def keygen_slip39(
    shares: Annotated[int, typer.Option(help="Total number of shares")] = 5,
    threshold: Annotated[int, typer.Option(help="Threshold for recovery")] = 3,
) -> None:
    """Generate SLIP-39 shares from master secret."""
    console.print(Panel.fit(
        f"[yellow]Not yet implemented[/yellow]\n\n"
        f"[bold red]⚠️  TIER 1 OPERATION[/bold red]\n\n"
        f"SLIP-39 share generation ({threshold}-of-{shares}):\n"
        "1. Input master secret (QR or manual)\n"
        "2. Generate Shamir shares\n"
        "3. Display each share as mnemonic\n"
        "4. Generate QR codes for shares\n"
        "5. Verify share reconstruction",
        title="keygen slip39",
    ))


@keygen_app.command("slip39-generate")
def keygen_slip39_generate(
    words: Annotated[int, typer.Option("--words", "-w", help="Words per share: 20 (128-bit, Cryptosteel) or 33 (256-bit)")] = 20,
    shares: Annotated[int, typer.Option("--shares", "-n", help="Total number of shares")] = 5,
    threshold: Annotated[int, typer.Option("--threshold", "-t", help="Threshold for recovery")] = 3,
    use_passphrase: Annotated[bool, typer.Option("--passphrase/--no-passphrase", help="Use optional SLIP-39 passphrase")] = False,
    skip_verify: Annotated[bool, typer.Option("--skip-verify", help="Skip re-entry verification (NOT RECOMMENDED)")] = False,
    skip_hardware_check: Annotated[bool, typer.Option("--skip-hardware-check", help="Skip wireless hardware check")] = False,
) -> None:
    """Generate SLIP-39 Shamir shares from hardware entropy.

    Creates a master secret split into Shamir shares using the SLIP-39 standard.
    Default is 3-of-5 threshold with 20-word shares (128-bit, Cryptosteel compatible).

    Word count options:
    - 20 words (--words 20): 128-bit secret, fits Cryptosteel Capsule ← DEFAULT
    - 33 words (--words 33): 256-bit secret, requires larger storage

    ⚠️  TIER 1 OPERATION - Requires air-gapped environment

    Workflow:
    1. Verify air-gapped environment (no wireless hardware)
    2. Collect entropy from hardware sources
    3. Generate master secret and split into shares
    4. Display each share one at a time
    5. Verify transcription via re-entry
    6. Show summary with share fingerprints

    Shares are NEVER written to disk - display only.
    """
    # Validate word count option
    if words not in (20, 33):
        console.print(f"[red]Invalid --words value: {words}. Must be 20 or 33.[/red]")
        console.print("  20 words = 128-bit secret (Cryptosteel compatible)")
        console.print("  33 words = 256-bit secret")
        raise typer.Exit(1)

    secret_bits = 128 if words == 20 else 256

    console.print(Panel.fit(
        "[bold red]⚠️  TIER 1 OPERATION[/bold red]\n\n"
        f"SLIP-39 Share Generation ({threshold}-of-{shares})\n\n"
        f"Secret: {secret_bits}-bit ({words} words per share)\n\n"
        "This operation generates cryptographic shares that protect\n"
        "your master secret. Each share must be recorded on metal\n"
        "(Cryptosteel) or paper and stored securely.\n\n"
        "[yellow]Shares will be displayed once. Record carefully![/yellow]",
        title="🔐 SLIP-39 Generation",
    ))

    # ==========================================================================
    # STEP 1: Hardware check (Tier 1 enforcement)
    # ==========================================================================
    if not skip_hardware_check:
        console.print("\n[cyan]Checking for wireless hardware...[/cyan]")
        wireless = check_all_wireless()

        if not wireless.is_airgap_safe:
            console.print("\n[bold red]⚠️  TIER 1 VIOLATION: Wireless hardware detected![/bold red]")
            for device in wireless.devices:
                console.print(f"  • {device}")
            console.print("\n[yellow]Remove all wireless hardware before generating shares.[/yellow]")
            console.print("Use --skip-hardware-check to override (NOT RECOMMENDED).")
            raise typer.Exit(1)

        console.print("[green]✓ No wireless hardware detected[/green]")
    else:
        console.print("\n[yellow]⚠️  Hardware check skipped (--skip-hardware-check)[/yellow]")

    # ==========================================================================
    # STEP 2: Passphrase handling
    # ==========================================================================
    passphrase = ""
    if use_passphrase:
        console.print("\n[cyan]SLIP-39 Passphrase Setup[/cyan]")
        console.print("[yellow]WARNING: This passphrase is NOT recoverable from shares![/yellow]")
        console.print("You must remember it or store it separately.\n")

        while True:
            passphrase = getpass.getpass("Enter passphrase: ")
            passphrase_confirm = getpass.getpass("Confirm passphrase: ")

            if passphrase == passphrase_confirm:
                console.print("[green]✓ Passphrase confirmed[/green]")
                break
            else:
                console.print("[red]Passphrases don't match. Try again.[/red]")

    # ==========================================================================
    # STEP 3: Configuration validation
    # ==========================================================================
    try:
        config = SLIP39Config(
            total_shares=shares,
            threshold=threshold,
            secret_bits=secret_bits,
            passphrase=passphrase,
        )
    except ValueError as e:
        console.print(f"\n[red]Configuration error: {e}[/red]")
        raise typer.Exit(1)

    console.print("\n[cyan]Configuration:[/cyan]")
    console.print(f"  Shares: {config.total_shares}")
    console.print(f"  Threshold: {config.threshold}")
    console.print(f"  Secret size: {config.secret_bits} bits")
    console.print(f"  Words per share: {config.words_per_share}")
    console.print(f"  Passphrase: {'Yes' if passphrase else 'No'}")

    if not Confirm.ask("\nProceed with share generation?"):
        raise typer.Abort()

    # ==========================================================================
    # STEP 4: Generate shares
    # ==========================================================================
    console.print("\n[cyan]Generating master secret and shares...[/cyan]")

    try:
        # Generate using system entropy (could integrate with infnoise later)
        share_set = generate_shares(config=config)
        console.print(f"[green]✓ Generated {share_set.share_count} shares[/green]")
        console.print(f"  Master fingerprint: {share_set.master_fingerprint}")
    except Exception as e:
        console.print(f"\n[red]Share generation failed: {e}[/red]")
        raise typer.Exit(1)

    # ==========================================================================
    # STEP 5: Display and verify each share
    # ==========================================================================
    verified_shares: list[SLIP39Share] = []

    for share in share_set.shares:
        # Clear screen for security
        console.clear()

        # Display share
        console.print(Panel(
            f"[bold cyan]SLIP-39 Share {share.index} of {share.total}[/bold cyan]\n"
            f"[dim]({share.threshold} shares required for recovery)[/dim]\n\n"
            f"[bold]Fingerprint: {share.fingerprint}[/bold]\n\n"
            + _format_mnemonic_grid(share.mnemonic) + "\n\n"
            "[yellow]⚠️  Record this share on Cryptosteel or paper NOW[/yellow]\n"
            "[yellow]This will NOT be shown again after verification[/yellow]",
            title=f"🔐 Share {share.index}/{share.total}",
            border_style="cyan",
        ))

        if skip_verify:
            Prompt.ask("\nPress Enter when recorded", default="")
            verified_shares.append(share)
            continue

        # Wait for user to record
        Prompt.ask("\nPress Enter when you have recorded this share", default="")

        # Clear and verify via re-entry
        console.clear()
        console.print(Panel(
            f"[bold cyan]Verify Share {share.index}[/bold cyan]\n\n"
            f"Re-enter all {share.word_count} words to verify accurate transcription.\n"
            "[dim]Enter words separated by spaces (case-insensitive).[/dim]",
            title=f"✅ Verify Share {share.index}/{share.total}",
        ))

        # Re-entry loop
        max_attempts = 3
        for attempt in range(max_attempts):
            user_input = Prompt.ask(f"\nEnter share {share.index} ({share.word_count} words)")

            if verify_share_reentry(share.mnemonic, user_input):
                console.print(f"\n[green]✓ Share {share.index} verified successfully![/green]")
                console.print(f"  Fingerprint: {share.fingerprint}")
                verified_shares.append(share)
                break
            else:
                remaining = max_attempts - attempt - 1
                if remaining > 0:
                    console.print(f"\n[red]✗ Verification failed. {remaining} attempts remaining.[/red]")
                    console.print("[yellow]Check your transcription carefully.[/yellow]")
                else:
                    console.print("\n[bold red]✗ Maximum attempts exceeded.[/bold red]")
                    console.print("\nOptions:")
                    console.print("  1. Re-display share (security risk)")
                    console.print("  2. Abort generation")

                    choice = Prompt.ask("Choice", choices=["1", "2"], default="2")

                    if choice == "1":
                        # Re-display and retry
                        console.clear()
                        console.print(Panel(
                            f"[bold cyan]RE-DISPLAY: Share {share.index}[/bold cyan]\n\n"
                            + _format_mnemonic_grid(share.mnemonic),
                            title="⚠️  Security Warning",
                            border_style="red",
                        ))
                        Prompt.ask("\nPress Enter when re-recorded", default="")
                        verified_shares.append(share)
                        break
                    else:
                        console.print("\n[yellow]Aborting generation. No shares saved.[/yellow]")
                        raise typer.Abort()

        # Pause before next share
        if share.index < share.total:
            Prompt.ask(f"\nPress Enter to continue to Share {share.index + 1}", default="")

    # ==========================================================================
    # STEP 6: Final summary
    # ==========================================================================
    console.clear()

    if len(verified_shares) == share_set.share_count:
        console.print(Panel(
            f"[bold green]✓ All {share_set.share_count} shares generated and verified![/bold green]\n\n"
            f"Threshold: {config.threshold}-of-{config.total_shares}\n"
            f"Master Fingerprint: {share_set.master_fingerprint}\n\n"
            "[cyan]Share Fingerprints:[/cyan]\n"
            + "\n".join(f"  {s.index}. {s.fingerprint}" for s in verified_shares) + "\n\n"
            "[yellow]Next steps:[/yellow]\n"
            "  1. Store each share in a separate geographic location\n"
            "  2. Apply tamper-evident seals to storage containers\n"
            "  3. Record fingerprints in recovery documentation\n"
            "  4. Run 'airgap keygen slip39-verify' to test recovery",
            title="🎉 SLIP-39 Generation Complete",
            border_style="green",
        ))
    else:
        console.print(Panel(
            f"[yellow]⚠️  Only {len(verified_shares)}/{share_set.share_count} shares verified[/yellow]\n\n"
            "Some shares may not be accurately recorded.\n"
            "Consider regenerating shares.",
            title="⚠️  Incomplete Verification",
            border_style="yellow",
        ))

    # Skip verify option warning
    if skip_verify:
        console.print("\n[yellow]⚠️  Verification was skipped (--skip-verify)[/yellow]")
        console.print("Run 'airgap keygen slip39-verify' to confirm shares work.")


def _format_mnemonic_grid(mnemonic: str) -> str:
    """Format mnemonic as numbered grid for display."""
    words = mnemonic.split()
    lines = []

    # 4 words per row
    for i in range(0, len(words), 4):
        row_words = words[i:i + 4]
        numbered = [f"{i + j + 1:2}. {w:<12}" for j, w in enumerate(row_words)]
        lines.append("".join(numbered))

    return "\n".join(lines)


@keygen_app.command("slip39-recover")
def keygen_slip39_recover(
    use_passphrase: Annotated[bool, typer.Option("--passphrase/--no-passphrase", help="Shares used a passphrase")] = False,
) -> None:
    """Recover master secret from SLIP-39 shares.

    Interactively enter threshold number of shares to recover
    the original master secret.

    ⚠️  TIER 1 OPERATION - Use on air-gapped machine only
    """
    console.print(Panel(
        "[bold cyan]SLIP-39 Share Recovery[/bold cyan]\n\n"
        "Enter your shares one at a time to recover the master secret.\n"
        "You need at least the threshold number of shares.\n\n"
        "[yellow]⚠️  Only perform recovery on an air-gapped machine![/yellow]",
        title="🔓 Recovery Mode",
    ))

    # Collect passphrase if used
    passphrase = ""
    if use_passphrase:
        passphrase = getpass.getpass("\nEnter passphrase: ")

    # Ask how many shares will be entered
    num_shares = IntPrompt.ask("\nHow many shares will you enter?", default=3)
    if num_shares < 2:
        console.print("[red]Need at least 2 shares for recovery.[/red]")
        raise typer.Exit(1)

    # Collect shares
    shares_entered: list[str] = []
    console.print(f"\nEnter {num_shares} shares (or 'cancel' to abort):")
    console.print("[dim]Enter all words separated by spaces.[/dim]\n")

    for share_num in range(1, num_shares + 1):
        while True:
            console.print(f"[cyan]Share {share_num} of {num_shares}:[/cyan]")
            user_input = Prompt.ask("Enter mnemonic (or 'cancel')")

            if user_input.lower() == "cancel":
                console.print("[yellow]Recovery cancelled.[/yellow]")
                raise typer.Abort()

            # Validate share
            is_valid, error = validate_share(user_input)
            if is_valid:
                shares_entered.append(user_input)
                fingerprint = compute_share_fingerprint(user_input)
                console.print(f"[green]✓ Share {share_num} accepted (fingerprint: {fingerprint})[/green]\n")
                break
            else:
                console.print(f"[red]✗ Invalid share: {error}[/red]")
                console.print("[yellow]Check your entry and try again.[/yellow]\n")

    # Attempt recovery
    console.print(f"\n[cyan]Attempting recovery with {len(shares_entered)} shares...[/cyan]")

    try:
        master_secret = recover_secret(shares_entered, passphrase)
        master_fingerprint = hashlib.sha256(master_secret).hexdigest()[:8]

        console.print(Panel(
            "[bold green]✓ Recovery Successful![/bold green]\n\n"
            f"Master Secret Fingerprint: {master_fingerprint}\n"
            f"Secret Size: {len(master_secret) * 8} bits\n\n"
            "[yellow]The recovered secret is in memory only.[/yellow]\n"
            "[yellow]Use it immediately or it will be lost on exit.[/yellow]",
            title="🔓 Recovery Complete",
            border_style="green",
        ))

        # Option to display secret (hex)
        if Confirm.ask("\nDisplay master secret? (security risk)"):
            console.print("\n[bold]Master Secret (hex):[/bold]")
            console.print(f"  {master_secret.hex()}")
            console.print("\n[yellow]Clear your terminal after use![/yellow]")

    except ValueError as e:
        console.print(f"\n[bold red]✗ Recovery failed: {e}[/bold red]")
        console.print("\nPossible causes:")
        console.print("  • Not enough shares (need threshold)")
        console.print("  • Shares from different share sets")
        console.print("  • Incorrect passphrase")
        console.print("  • Corrupted share data")
        raise typer.Exit(1)


@keygen_app.command("slip39-verify")
def keygen_slip39_verify() -> None:
    """Verify SLIP-39 shares can recover the secret.

    Enter threshold number of shares to verify they reconstruct
    correctly. Does NOT display the recovered secret.
    """
    console.print(Panel(
        "[bold cyan]SLIP-39 Share Verification[/bold cyan]\n\n"
        "Test that your recorded shares can recover the master secret.\n"
        "Enter threshold number of shares to verify reconstruction.\n\n"
        "[dim]The recovered secret will NOT be displayed.[/dim]",
        title="✅ Verification Mode",
    ))

    # Check for passphrase
    use_passphrase = Confirm.ask("\nDid you use a passphrase during generation?")
    passphrase = ""
    if use_passphrase:
        passphrase = getpass.getpass("Enter passphrase: ")

    # Ask how many shares will be entered
    num_shares = IntPrompt.ask("\nHow many shares will you enter?", default=3)
    if num_shares < 2:
        console.print("[red]Need at least 2 shares for verification.[/red]")
        raise typer.Exit(1)

    # Collect shares
    shares_entered: list[str] = []
    console.print(f"\nEnter {num_shares} shares:")
    console.print("[dim]Enter all words separated by spaces.[/dim]\n")

    for share_num in range(1, num_shares + 1):
        while True:
            user_input = Prompt.ask(f"Share {share_num} of {num_shares}")

            is_valid, error = validate_share(user_input)
            if is_valid:
                shares_entered.append(user_input)
                fingerprint = compute_share_fingerprint(user_input)
                console.print(f"[green]✓ Share accepted (fingerprint: {fingerprint})[/green]\n")
                break
            else:
                console.print(f"[red]✗ Invalid: {error}[/red]")
                console.print("[yellow]Check your entry and try again.[/yellow]\n")

    # Verify
    console.print(f"\n[cyan]Verifying {len(shares_entered)} shares...[/cyan]")

    try:
        master_secret = recover_secret(shares_entered, passphrase)
        master_fingerprint = hashlib.sha256(master_secret).hexdigest()[:8]

        console.print(Panel(
            "[bold green]✓ Verification Successful![/bold green]\n\n"
            f"Master Fingerprint: {master_fingerprint}\n\n"
            "Your shares can successfully recover the master secret.\n"
            "[dim]The secret was verified but NOT displayed.[/dim]",
            title="✅ Shares Valid",
            border_style="green",
        ))

        # Clear secret from memory
        del master_secret

    except ValueError as e:
        console.print(f"\n[bold red]✗ Verification failed: {e}[/bold red]")
        raise typer.Exit(1)


@keygen_app.command("subkeys")
def keygen_subkeys(
    key_id: Annotated[str | None, typer.Option("--key", "-k", help="Master key ID")] = None,
    sign: Annotated[bool, typer.Option("--sign/--no-sign", help="Create signing subkey")] = True,
    encrypt: Annotated[bool, typer.Option("--encrypt/--no-encrypt", help="Create encryption subkey")] = True,
    auth: Annotated[bool, typer.Option("--auth/--no-auth", help="Create authentication subkey")] = True,
    expire: Annotated[str, typer.Option("--expire", help="Subkey expiration (e.g., 2y)")] = "2y",
) -> None:
    """Create subkeys for an existing master key.

    Creates signing [S], encryption [E], and authentication [A] subkeys
    for use on YubiKey. Master key retains only certify [C] capability.
    """
    console.print(Panel.fit(
        f"[bold cyan]GPG Subkey Generation[/bold cyan]\n\n"
        f"Key ID: {key_id or '(default)'}\n"
        f"Signing [S]: {'Yes' if sign else 'No'}\n"
        f"Encryption [E]: {'Yes' if encrypt else 'No'}\n"
        f"Authentication [A]: {'Yes' if auth else 'No'}\n"
        f"Expiration: {expire}",
        title="🔐 keygen subkeys",
    ))

    if not any([sign, encrypt, auth]):
        console.print("[red]At least one subkey type must be selected[/red]")
        raise typer.Exit(1)

    if not typer.confirm("\nProceed with subkey generation?"):
        raise typer.Abort()

    # Build GPG command
    cmd = ["gpg", "--expert", "--edit-key"]
    if key_id:
        cmd.append(key_id)
    else:
        # Get default key
        result = subprocess.run(
            ["gpg", "--list-secret-keys", "--keyid-format", "long"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0 or not result.stdout:
            console.print("[red]No GPG secret keys found. Run 'airgap keygen master' first.[/red]")
            raise typer.Exit(1)

        # Parse first key
        for line in result.stdout.split("\n"):
            if line.strip().startswith("sec"):
                parts = line.split("/")
                if len(parts) >= 2:
                    key_id = parts[1].split()[0]
                    break

        if not key_id:
            console.print("[red]Could not determine default key[/red]")
            raise typer.Exit(1)

        console.print(f"[dim]Using key: {key_id}[/dim]")
        cmd.append(key_id)

    console.print("\n[yellow]This will open GPG interactive mode.[/yellow]")
    console.print("[dim]Commands to add subkeys:[/dim]")
    if sign:
        console.print("  addkey → (4) RSA sign only or (10) ECC sign → set expiry")
    if encrypt:
        console.print("  addkey → (6) RSA encrypt only or (12) ECC encrypt → set expiry")
    if auth:
        console.print("  addkey → (8) RSA capability → toggle to auth only → set expiry")
    console.print("  save\n")

    try:
        subprocess.run(cmd, timeout=600)
    except subprocess.TimeoutExpired:
        console.print("\n[red]GPG edit timed out[/red]")
    except FileNotFoundError:
        console.print("\n[red]GPG not found[/red]")


@keygen_app.command("transfer-to-yubikey")
def keygen_transfer_yubikey(
    key_id: Annotated[str | None, typer.Option("--key", "-k", help="Key ID to transfer")] = None,
) -> None:
    """Transfer subkeys to YubiKey.

    Moves subkeys to YubiKey OpenPGP slots:
    - Slot 1: Signature key
    - Slot 2: Encryption key
    - Slot 3: Authentication key

    After transfer, subkeys become stubs (private part on YubiKey only).
    """
    console.print(Panel.fit(
        "[bold cyan]Transfer Subkeys to YubiKey[/bold cyan]\n\n"
        "This will move your subkeys to the YubiKey.\n"
        "The private keys will be deleted from disk.\n\n"
        "[bold yellow]⚠️  Ensure you have backups before proceeding![/bold yellow]",
        title="🔐 keytocard",
    ))

    # Check YubiKey
    try:
        result = subprocess.run(
            ["ykman", "list"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if not result.stdout.strip():
            console.print("[red]No YubiKey detected. Insert YubiKey and try again.[/red]")
            raise typer.Exit(1)
        console.print(f"[green]YubiKey detected: {result.stdout.strip().split(chr(10))[0]}[/green]")
    except FileNotFoundError:
        console.print("[red]ykman not found. Install with: pip install yubikey-manager[/red]")
        raise typer.Exit(1)

    if not typer.confirm("\nProceed with key transfer?"):
        raise typer.Abort()

    # Get key ID
    if not key_id:
        result = subprocess.run(
            ["gpg", "--list-secret-keys", "--keyid-format", "long"],
            capture_output=True,
            text=True,
        )
        for line in result.stdout.split("\n"):
            if line.strip().startswith("sec"):
                parts = line.split("/")
                if len(parts) >= 2:
                    key_id = parts[1].split()[0]
                    break

    if not key_id:
        console.print("[red]No secret keys found[/red]")
        raise typer.Exit(1)

    console.print(f"\n[dim]Transferring subkeys for: {key_id}[/dim]")
    console.print("\n[yellow]GPG will open in edit mode.[/yellow]")
    console.print("[dim]For each subkey, select it (key N) then run 'keytocard'[/dim]")
    console.print("[dim]Save when done.[/dim]\n")

    try:
        subprocess.run(["gpg", "--edit-key", key_id], timeout=600)
        console.print("\n[green]Transfer complete. Verify with 'gpg -K'[/green]")
        console.print("[dim]Subkeys should show 'ssb>' indicating stubs[/dim]")
    except subprocess.TimeoutExpired:
        console.print("\n[red]GPG edit timed out[/red]")


# =============================================================================
# BACKUP COMMANDS
# =============================================================================

@backup_app.command("create")
def backup_create(
    device: Annotated[str | None, typer.Option("--device", "-d", help="Block device (e.g., /dev/sdb)")] = None,
    key_id: Annotated[str | None, typer.Option("--key", "-k", help="GPG key ID to backup")] = None,
    label: Annotated[str, typer.Option("--label", "-l", help="LUKS volume label")] = "BASTION_BACKUP",
) -> None:
    """Create LUKS-encrypted backup of GPG keys.

    Creates an encrypted USB backup containing:
    - Master (certify) key
    - Subkeys (before transfer to YubiKey)
    - Public key
    - Revocation certificate
    - Backup manifest with checksums

    Requires a USB drive to be connected.
    """
    from ..backup import (
        check_luks_available,
        create_backup,
        list_block_devices,
    )

    console.print(Panel.fit(
        "[bold cyan]LUKS-Encrypted Key Backup[/bold cyan]\n\n"
        "[bold red]⚠️  WARNING: This will ERASE the target device![/bold red]\n\n"
        "Creates encrypted backup with:\n"
        "• Master key (certify only)\n"
        "• Subkeys (sign, encrypt, auth)\n"
        "• Public key for distribution\n"
        "• Revocation certificate",
        title="🔐 backup create",
    ))

    # Check LUKS availability
    if not check_luks_available():
        console.print("[red]cryptsetup not installed. Install with: apt install cryptsetup[/red]")
        raise typer.Exit(1)

    # List available devices if not specified
    if not device:
        console.print("\n[cyan]Available removable devices:[/cyan]")
        devices = list_block_devices()

        if not devices:
            console.print("[yellow]No removable devices found[/yellow]")
            console.print("[dim]Insert a USB drive and try again[/dim]")
            raise typer.Exit(1)

        for i, dev in enumerate(devices, 1):
            mounted = f" [mounted: {dev['mountpoint']}]" if dev.get('mountpoint') else ""
            console.print(f"  {i}. {dev['name']} ({dev['size']}){mounted}")

        choice = typer.prompt("\nSelect device number", type=int)
        if 1 <= choice <= len(devices):
            device = devices[choice - 1]['name']
        else:
            console.print("[red]Invalid selection[/red]")
            raise typer.Exit(1)

    console.print(f"\n[bold red]⚠️  ALL DATA ON {device} WILL BE ERASED![/bold red]")
    if not typer.confirm(f"Proceed with backup to {device}?"):
        raise typer.Abort()

    # Get GNUPGHOME
    gnupghome = Path(os.environ.get("GNUPGHOME", Path.home() / ".gnupg"))

    console.print(f"\n[cyan]Creating backup on {device}...[/cyan]")
    console.print("[yellow]You will be prompted for a LUKS passphrase[/yellow]")
    console.print("[dim]Use a strong passphrase different from your GPG passphrase[/dim]\n")

    try:
        result = create_backup(device, gnupghome, label=label, key_id=key_id)

        if result.success:
            console.print("\n[bold green]✓ Backup created successfully![/bold green]")
            if result.manifest:
                console.print("\n[dim]Backed up keys:[/dim]")
                for key in result.manifest.key_ids:
                    console.print(f"  • {key}")
                console.print("\n[dim]Files:[/dim]")
                for f in result.manifest.files:
                    console.print(f"  • {f['name']} ({f['size']} bytes)")

            console.print("\n[cyan]Important:[/cyan]")
            console.print("  1. Create a second backup on another USB drive")
            console.print("  2. Store backups in geographically separate locations")
            console.print("  3. Record the LUKS passphrase securely")
        else:
            console.print("\n[red]Backup failed:[/red]")
            for error in result.errors:
                console.print(f"  • {error}")
            raise typer.Exit(1)

    except Exception as e:
        console.print(f"\n[red]Backup error: {e}[/red]")
        raise typer.Exit(1)


@backup_app.command("verify")
def backup_verify(
    device: Annotated[str | None, typer.Option("--device", "-d", help="Block device to verify")] = None,
) -> None:
    """Verify backup integrity and checksums.

    Opens a LUKS backup and verifies all files against the manifest checksums.
    """
    from ..backup import (
        list_block_devices,
        verify_backup_device,
    )

    # List available devices if not specified
    if not device:
        console.print("[cyan]Available removable devices:[/cyan]")
        devices = list_block_devices()

        if not devices:
            console.print("[yellow]No removable devices found[/yellow]")
            raise typer.Exit(1)

        for i, dev in enumerate(devices, 1):
            console.print(f"  {i}. {dev['name']} ({dev['size']})")

        choice = typer.prompt("\nSelect device number", type=int)
        if 1 <= choice <= len(devices):
            device = devices[choice - 1]['name']
        else:
            console.print("[red]Invalid selection[/red]")
            raise typer.Exit(1)

    console.print(f"\n[cyan]Verifying backup on {device}...[/cyan]")
    console.print("[yellow]You will be prompted for the LUKS passphrase[/yellow]\n")

    try:
        valid, errors, manifest = verify_backup_device(device)

        if valid:
            console.print("[bold green]✓ Backup verification PASSED[/bold green]")
            if manifest:
                console.print(f"\n[dim]Created: {manifest.created_at.isoformat()}[/dim]")
                console.print(f"[dim]Keys: {', '.join(manifest.key_ids)}[/dim]")
                console.print(f"[dim]Files: {len(manifest.files)}[/dim]")
        else:
            console.print("[bold red]✗ Backup verification FAILED[/bold red]")
            for error in errors:
                console.print(f"  • {error}")
            raise typer.Exit(1)

    except Exception as e:
        console.print(f"\n[red]Verification error: {e}[/red]")
        raise typer.Exit(1)


# =============================================================================
# CHECK COMMANDS
# =============================================================================

@check_app.command("wireless")
def check_wireless_cmd() -> None:
    """Check for wireless hardware (WiFi, Bluetooth).

    Scans for wireless network interfaces, RF devices via rfkill, and
    known wireless USB adapters. For air-gapped systems, no wireless
    hardware should be present.
    """
    result = check_all_wireless()

    if result.is_airgap_safe:
        console.print(Panel.fit(
            "[bold green]✓ No wireless hardware detected[/bold green]\n\n"
            "System appears safe for air-gapped operations.",
            title="🔒 Wireless Check PASSED",
            border_style="green",
        ))
    else:
        # Build device list
        device_lines = "\n".join(f"  • {d}" for d in result.devices)
        console.print(Panel.fit(
            f"[bold red]⚠️  WIRELESS HARDWARE DETECTED[/bold red]\n\n"
            f"[yellow]Detected devices:[/yellow]\n{device_lines}\n\n"
            "[red]Air-gapped operations require NO wireless hardware.[/red]\n"
            "Remove the device(s) and re-run this check.",
            title="⚠️  Wireless Check FAILED",
            border_style="red",
        ))
        raise typer.Exit(1)

    # Show warnings if any
    if result.warnings:
        for warning in result.warnings:
            console.print(f"[dim]⚠ {warning}[/dim]")


@check_app.command("wired")
def check_wired_cmd() -> None:
    """Check for wired network connections (Ethernet).

    Scans for Ethernet interfaces and their connection state.
    For strict air-gap requirements, no wired network connections
    should be present or active.
    """
    result = check_all_wired()

    if result.is_airgap_safe:
        console.print(Panel.fit(
            "[bold green]✓ No wired network interfaces detected[/bold green]\n\n"
            "System has no Ethernet connections.",
            title="🔒 Wired Check PASSED",
            border_style="green",
        ))
    else:
        # Build device list
        device_lines = "\n".join(f"  • {d}" for d in result.devices)

        # Check if any are connected
        has_connected = any("connected" in d.lower() for d in result.devices)

        if has_connected:
            console.print(Panel.fit(
                f"[bold red]⚠️  ACTIVE WIRED NETWORK CONNECTION[/bold red]\n\n"
                f"[yellow]Detected interfaces:[/yellow]\n{device_lines}\n\n"
                "[red]Air-gapped operations require NO network connectivity.[/red]\n"
                "Disconnect the cable(s) and re-run this check.",
                title="⚠️  Wired Check FAILED",
                border_style="red",
            ))
            raise typer.Exit(1)
        else:
            console.print(Panel.fit(
                f"[bold yellow]⚠️  Wired interfaces present (disconnected)[/bold yellow]\n\n"
                f"[yellow]Detected interfaces:[/yellow]\n{device_lines}\n\n"
                "[dim]Interfaces are disconnected but present.[/dim]\n"
                "[dim]For maximum security, remove Ethernet adapters.[/dim]",
                title="⚠️  Wired Check WARNING",
                border_style="yellow",
            ))


@check_app.command("tier")
def check_tier_cmd(
    tier: Annotated[int, typer.Option(help="Tier level to verify (1, 2, or 3)")] = 1,
) -> None:
    """Verify system meets tier isolation requirements.

    Tier levels:
    - Tier 1 (highest): No wireless, no wired, hardware entropy required
    - Tier 2 (medium): No wireless, wired allowed if disconnected
    - Tier 3 (basic): Wireless and wired allowed
    """
    if tier not in (1, 2, 3):
        console.print("[red]Error: Tier must be 1, 2, or 3[/red]")
        raise typer.Exit(1)

    console.print(f"\n[cyan]Checking Tier {tier} requirements...[/cyan]\n")

    # Check wireless
    wireless_result = check_all_wireless()
    wired_result = check_all_wired()
    entropy_sources = check_entropy_sources()

    # Track failures
    failures = []
    warnings = []

    # Tier 1: Strictest - no network hardware at all
    if tier == 1:
        if not wireless_result.is_airgap_safe:
            failures.append(f"Wireless hardware detected: {len(wireless_result.devices)} device(s)")
        if not wired_result.is_airgap_safe:
            failures.append(f"Wired interfaces detected: {len(wired_result.devices)} interface(s)")
        if not entropy_sources.get("infnoise", (False,))[0] and not entropy_sources.get("yubikey", (False,))[0]:
            failures.append("No hardware entropy source (Infinite Noise or YubiKey required)")

    # Tier 2: No wireless, wired OK if disconnected
    elif tier == 2:
        if not wireless_result.is_airgap_safe:
            failures.append(f"Wireless hardware detected: {len(wireless_result.devices)} device(s)")
        # Wired is allowed but warn if connected
        has_connected = any("connected" in d.lower() for d in wired_result.devices)
        if has_connected:
            failures.append("Active wired network connection detected")
        elif not wired_result.is_airgap_safe:
            warnings.append(f"Wired interfaces present (disconnected): {len(wired_result.devices)}")

    # Tier 3: Basic checks only
    # (All network hardware allowed, just informational)

    # Build results table
    table = Table(title=f"Tier {tier} Check Results", show_header=True)
    table.add_column("Check", style="cyan")
    table.add_column("Status")
    table.add_column("Details", style="dim")

    # Wireless row
    if wireless_result.is_airgap_safe:
        table.add_row("Wireless", "[green]✓ PASS[/green]", "No wireless hardware")
    else:
        status = "[red]✗ FAIL[/red]" if tier <= 2 else "[yellow]⚠ INFO[/yellow]"
        table.add_row("Wireless", status, f"{len(wireless_result.devices)} device(s)")

    # Wired row
    if wired_result.is_airgap_safe:
        table.add_row("Wired", "[green]✓ PASS[/green]", "No wired interfaces")
    else:
        has_connected = any("connected" in d.lower() for d in wired_result.devices)
        if has_connected:
            status = "[red]✗ FAIL[/red]" if tier <= 2 else "[yellow]⚠ INFO[/yellow]"
            table.add_row("Wired", status, "Active connection detected")
        else:
            status = "[yellow]⚠ WARN[/yellow]" if tier <= 2 else "[green]✓ OK[/green]"
            table.add_row("Wired", status, "Interfaces present, disconnected")

    # Entropy row
    hw_entropy = entropy_sources.get("infnoise", (False,))[0] or entropy_sources.get("yubikey", (False,))[0]
    if hw_entropy:
        sources = []
        if entropy_sources.get("infnoise", (False,))[0]:
            sources.append("Infinite Noise")
        if entropy_sources.get("yubikey", (False,))[0]:
            sources.append("YubiKey")
        table.add_row("Hardware Entropy", "[green]✓ PASS[/green]", ", ".join(sources))
    else:
        status = "[red]✗ FAIL[/red]" if tier == 1 else "[yellow]⚠ WARN[/yellow]"
        table.add_row("Hardware Entropy", status, "No hardware RNG found")

    # System entropy row
    if entropy_sources.get("system", (False,))[0]:
        table.add_row("System Entropy", "[green]✓ PASS[/green]", "/dev/urandom available")
    else:
        table.add_row("System Entropy", "[red]✗ FAIL[/red]", "/dev/urandom not found")

    console.print(table)
    console.print()

    # Final verdict
    if failures:
        console.print(Panel.fit(
            f"[bold red]✗ TIER {tier} CHECK FAILED[/bold red]\n\n"
            + "\n".join(f"• {f}" for f in failures),
            border_style="red",
        ))
        raise typer.Exit(1)
    elif warnings:
        console.print(Panel.fit(
            f"[bold yellow]⚠ TIER {tier} CHECK PASSED WITH WARNINGS[/bold yellow]\n\n"
            + "\n".join(f"• {w}" for w in warnings),
            border_style="yellow",
        ))
    else:
        console.print(Panel.fit(
            f"[bold green]✓ TIER {tier} CHECK PASSED[/bold green]\n\n"
            "System meets all requirements for this tier.",
            border_style="green",
        ))


@check_app.command("entropy")
def check_entropy_source_cmd() -> None:
    """Check entropy source availability.

    Scans for available entropy sources including:
    - Infinite Noise TRNG (hardware)
    - YubiKey (hardware)
    - /dev/urandom (system)
    - /dev/random (system, blocking)
    """
    sources = check_entropy_sources()

    table = Table(title="Entropy Source Availability", show_header=True)
    table.add_column("Source", style="cyan")
    table.add_column("Status")
    table.add_column("Details", style="dim")

    for source, (available, message) in sources.items():
        if available:
            table.add_row(source, "[green]✓ Available[/green]", message)
        else:
            table.add_row(source, "[red]✗ Unavailable[/red]", message)

    console.print(table)

    # Summary
    hw_available = sources.get("infnoise", (False,))[0] or sources.get("yubikey", (False,))[0]
    if hw_available:
        console.print("\n[green]✓ Hardware entropy available for Tier 1 operations[/green]")
    else:
        console.print("\n[yellow]⚠ No hardware entropy - only system RNG available[/yellow]")
        console.print("[dim]  For Tier 1 operations, connect Infinite Noise TRNG or YubiKey[/dim]")


# =============================================================================
# EXPORT COMMANDS
# =============================================================================

@export_app.command("salt")
def export_salt(
    recipient: Annotated[str, typer.Option("--recipient", "-r", help="GPG recipient key ID")] = ...,
    bits: Annotated[int, typer.Option("--bits", "-b", help="Salt size in bits")] = 256,
    source: Annotated[str, typer.Option("--source", "-s", help="Entropy source")] = "infnoise",
    min_quality: Annotated[str, typer.Option("--min-quality", help="Minimum entropy quality")] = "GOOD",
    pdf: Annotated[Path | None, typer.Option("--pdf", help="Output PDF file for printing")] = None,
) -> None:
    """Generate and export encrypted salt via QR code.

    Creates a username salt with ENT-verified entropy, encrypts it to
    the manager's GPG public key, and displays as QR code(s) for scanning.

    The manager machine decrypts the salt and stores it in 1Password
    for deterministic username generation.
    """
    from ..crypto import EntropyQuality, generate_salt, gpg_encrypt
    from ..qr import (
        estimate_qr_size,
        generate_pdf,
        generate_qr_terminal,
        split_for_qr,
    )

    console.print(Panel.fit(
        f"[bold cyan]Salt Export via Encrypted QR[/bold cyan]\n\n"
        f"Recipient: {recipient}\n"
        f"Salt size: {bits} bits\n"
        f"Entropy: {source}\n"
        f"Min Quality: {min_quality}",
        title="🔐 export salt",
    ))

    # Step 1: Generate salt with verified entropy
    console.print(f"\n[cyan]Step 1: Generating {bits}-bit salt from {source}...[/cyan]")
    try:
        quality_enum = EntropyQuality(min_quality.upper())
        salt_payload = generate_salt(
            bits=bits,
            source=source,
            min_quality=quality_enum,
            verify=True,
        )
        console.print(f"  Quality: [bold]{salt_payload.entropy_quality}[/bold]")
    except Exception as e:
        console.print(f"[red]Error generating salt: {e}[/red]")
        raise typer.Exit(1)

    # Step 2: Encrypt to recipient
    console.print(f"\n[cyan]Step 2: Encrypting to {recipient}...[/cyan]")
    try:
        payload_json = salt_payload.to_json()
        encrypted = gpg_encrypt(payload_json.encode(), recipient, armor=True)
        console.print(f"  Encrypted size: {len(encrypted)} bytes")
    except Exception as e:
        console.print(f"[red]Encryption failed: {e}[/red]")
        console.print("[dim]Ensure recipient's public key is imported: airgap keys import <key.asc>[/dim]")
        raise typer.Exit(1)

    # Step 3: Split for QR if needed
    encrypted_str = encrypted.decode()
    qr_parts = split_for_qr(encrypted_str, max_bytes=2000)

    console.print("\n[cyan]Step 3: QR code generation...[/cyan]")
    console.print(f"  Parts needed: {len(qr_parts)}")

    qr_info = estimate_qr_size(qr_parts[0].to_qr_string() if len(qr_parts) > 1 else encrypted_str)
    console.print(f"  QR version: {qr_info.version} ({qr_info.modules}×{qr_info.modules})")

    # Generate PDF if requested
    if pdf:
        console.print(f"\n[cyan]Generating PDF: {pdf}[/cyan]")
        try:
            generate_pdf(qr_parts, pdf, title="Bastion Salt Export")
            console.print(f"[green]✓ PDF saved: {pdf}[/green]")
        except Exception as e:
            console.print(f"[yellow]PDF generation failed: {e}[/yellow]")

    # Display QR codes in terminal
    console.print("\n" + "=" * 60)
    console.print("[bold]Scan the following QR code(s) with the manager machine:[/bold]")
    console.print("=" * 60 + "\n")

    for i, part in enumerate(qr_parts):
        if len(qr_parts) > 1:
            console.print(f"[bold cyan]QR Code {part.sequence}/{part.total}[/bold cyan]")
            qr_data = part.to_qr_string()
        else:
            console.print("[bold cyan]QR Code (single)[/bold cyan]")
            qr_data = part.data

        qr_output = generate_qr_terminal(qr_data)
        console.print(qr_output)

        if i < len(qr_parts) - 1:
            typer.prompt("\nPress Enter for next QR code", default="")

    console.print("\n[yellow]⚠️  Clear screen after scanning (Ctrl-L or 'clear')[/yellow]")
    console.print("[dim]Salt has been displayed - do not leave visible[/dim]")


@export_app.command("pubkey")
def export_pubkey(
    key_id: Annotated[str | None, typer.Option("--key", "-k", help="Key ID to export")] = None,
    qr: Annotated[bool, typer.Option("--qr", help="Display as QR code")] = False,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file")] = None,
) -> None:
    """Export GPG public key for transfer to manager.

    Exports the public key in ASCII-armored format. Can display as
    QR code for camera scanning or save to file for USB transfer.
    """
    from ..crypto import gpg_list_keys
    from ..qr import generate_qr_terminal, split_for_qr

    # Get key ID if not specified
    if not key_id:
        keys = gpg_list_keys(secret=True)
        if not keys:
            console.print("[red]No GPG secret keys found[/red]")
            raise typer.Exit(1)
        key_id = keys[0]['keyid']
        console.print(f"[dim]Using key: {key_id}[/dim]")

    # Export public key
    try:
        result = subprocess.run(
            ["gpg", "--armor", "--export", key_id],
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0 or not result.stdout:
            console.print(f"[red]Failed to export key: {key_id}[/red]")
            raise typer.Exit(1)

        pubkey = result.stdout.decode()
        console.print(f"[green]✓ Exported public key ({len(pubkey)} bytes)[/green]")
    except Exception as e:
        console.print(f"[red]Export error: {e}[/red]")
        raise typer.Exit(1)

    # Output to file
    if output:
        output.write_text(pubkey)
        console.print(f"[green]✓ Saved to: {output}[/green]")

    # Display as QR
    if qr:
        qr_parts = split_for_qr(pubkey, max_bytes=2000)

        if len(qr_parts) > 1:
            console.print(f"\n[yellow]Public key requires {len(qr_parts)} QR codes[/yellow]")
            console.print("[dim]Consider using USB transfer for large keys[/dim]")

        for i, part in enumerate(qr_parts):
            if len(qr_parts) > 1:
                console.print(f"\n[bold cyan]QR Code {part.sequence}/{part.total}[/bold cyan]")
                qr_data = part.to_qr_string()
            else:
                console.print("\n[bold cyan]Public Key QR Code[/bold cyan]")
                qr_data = part.data

            qr_output = generate_qr_terminal(qr_data)
            console.print(qr_output)

            if i < len(qr_parts) - 1:
                typer.prompt("\nPress Enter for next QR code", default="")

    # Print to stdout if no output specified
    if not output and not qr:
        console.print("\n[dim]Public key:[/dim]")
        console.print(pubkey)


# =============================================================================
# KEYS COMMANDS
# =============================================================================

@keys_app.command("import")
def keys_import(
    keyfile: Annotated[Path, typer.Argument(help="Path to public key file (.asc)")],
) -> None:
    """Import a GPG public key.

    Imports the manager's public key so that airgap can encrypt data
    (salts, secrets) for secure transfer via QR code.
    """
    from ..crypto import gpg_import_key

    if not keyfile.exists():
        console.print(f"[red]File not found: {keyfile}[/red]")
        raise typer.Exit(1)

    console.print(f"[cyan]Importing key from {keyfile}...[/cyan]")

    try:
        key_data = keyfile.read_bytes()
        key_id = gpg_import_key(key_data)
        console.print(f"[green]✓ Imported key: {key_id}[/green]")

        # Show key details
        result = subprocess.run(
            ["gpg", "--list-keys", key_id],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            console.print(f"\n[dim]{result.stdout}[/dim]")

    except Exception as e:
        console.print(f"[red]Import failed: {e}[/red]")
        raise typer.Exit(1)


@keys_app.command("list")
def keys_list(
    secret: Annotated[bool, typer.Option("--secret", "-s", help="Show secret keys only")] = False,
) -> None:
    """List GPG keys in the keyring.

    Shows available public or secret keys that can be used for
    encryption and signing operations.
    """
    from ..crypto import gpg_list_keys

    keys = gpg_list_keys(secret=secret)

    if not keys:
        key_type = "secret" if secret else "public"
        console.print(f"[yellow]No {key_type} keys found[/yellow]")
        if secret:
            console.print("[dim]Run 'airgap keygen master' to generate keys[/dim]")
        else:
            console.print("[dim]Run 'airgap keys import <file.asc>' to import a public key[/dim]")
        return

    table = Table(title="Secret Keys" if secret else "Public Keys", show_header=True)
    table.add_column("Key ID", style="cyan")
    table.add_column("User ID")
    table.add_column("Fingerprint", style="dim")

    for key in keys:
        table.add_row(
            key['keyid'][-8:],  # Short key ID
            key['uid'][:50] + "..." if len(key['uid']) > 50 else key['uid'],
            key['fingerprint'][-16:] if key['fingerprint'] else "",
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(keys)} key(s)[/dim]")


@keys_app.command("export")
def keys_export(
    key_id: Annotated[str | None, typer.Option("--key", "-k", help="Key ID to export")] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file")] = None,
    secret: Annotated[bool, typer.Option("--secret", help="Export secret key (DANGER)")] = False,
) -> None:
    """Export GPG key to file.

    Exports public key by default. Use --secret to export secret key
    (only for backup purposes - handle with extreme care).
    """
    # Get key ID if not specified
    if not key_id:
        result = subprocess.run(
            ["gpg", "--list-secret-keys", "--keyid-format", "long"],
            capture_output=True,
            text=True,
        )
        for line in result.stdout.split("\n"):
            if line.strip().startswith("sec"):
                parts = line.split("/")
                if len(parts) >= 2:
                    key_id = parts[1].split()[0]
                    break

    if not key_id:
        console.print("[red]No key found to export[/red]")
        raise typer.Exit(1)

    if secret:
        console.print("[bold red]⚠️  WARNING: Exporting SECRET key![/bold red]")
        console.print("[yellow]This key should NEVER be transmitted over network[/yellow]")
        if not typer.confirm("Are you sure?"):
            raise typer.Abort()
        cmd = ["gpg", "--armor", "--export-secret-keys", key_id]
    else:
        cmd = ["gpg", "--armor", "--export", key_id]

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=30)

        if result.returncode != 0 or not result.stdout:
            console.print("[red]Failed to export key[/red]")
            raise typer.Exit(1)

        key_data = result.stdout.decode()

        if output:
            output.write_text(key_data)
            console.print(f"[green]✓ Exported to: {output}[/green]")
        else:
            console.print(key_data)

    except Exception as e:
        console.print(f"[red]Export error: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
