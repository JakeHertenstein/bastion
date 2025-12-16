"""YubiKey commands using 1Password as source of truth.

Commands:
- yubikey scan: Scan connected YubiKeys and compare with 1Password
- yubikey list: List all YubiKey items from sync cache
- yubikey status: Show status of all known YubiKeys
- update yubikey: Update 1Password with physical scan results
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from ..helpers import get_encrypted_db_manager, get_yubikey_service
from ...yubikey_service import YubiKeyService, sync_yubikey_items, PasswordRequiredError
from .update import update_metadata, update_metadata_show

console = Console()

# Type alias for common db option
DbPathOption = Annotated[
    Optional[Path],
    typer.Option(
        "--db",
        help="Database file path",
        envvar="PASSWORD_ROTATION_DB",
    ),
]


def register_commands(app: typer.Typer) -> None:
    """Register yubikey-related commands with the app."""
    
    @app.command("yubikey")
    def yubikey_command(
        action: Annotated[str, typer.Argument(help="Action: 'scan', 'list', or 'status'")],
        serial: Annotated[str | None, typer.Option("--serial", "-s", help="Specific YubiKey serial")] = None,
        update: Annotated[bool, typer.Option("--update", "-u", help="Update 1Password with scan results")] = False,
        force_sync: Annotated[bool, typer.Option("--force-sync", help="Force sync YubiKey items before operation")] = False,
    ) -> None:
        """
        YubiKey management commands.
        
        Actions:
          scan    - Scan connected YubiKeys to compare with 1Password
          list    - List all YubiKey items from sync cache
          status  - Show sync status of all known YubiKeys
        
        Examples:
          bsec 1p yubikey list                    # List all YubiKeys from 1Password
          bsec 1p yubikey scan                    # Scan connected YubiKeys
          bsec 1p yubikey scan --update           # Scan and update 1Password
          bsec 1p yubikey scan --serial 12345678  # Scan specific YubiKey
          bsec 1p yubikey status                  # Show status overview
        """
        cache_mgr = get_encrypted_db_manager()
        
        # Auto-sync YubiKey items if forced or cache seems stale
        if force_sync:
            sync_yubikey_items(cache_mgr)
        
        service = YubiKeyService(cache_mgr)
        
        if action == "list":
            _yubikey_list(service)
        elif action == "scan":
            _yubikey_scan(service, serial, update)
        elif action == "status":
            _yubikey_status(service)
        # Legacy aliases
        elif action in ("cache-slots", "sync"):
            console.print("[yellow]Note:[/yellow] 'cache-slots' is deprecated. Use 'scan --update' instead.")
            _yubikey_scan(service, serial, update=True)
        else:
            console.print(f"[red]Error:[/red] Unknown action '{action}'")
            console.print("Valid actions: scan, list, status")
            raise typer.Exit(1)

    @app.command("update")
    def update_command(
        noun: Annotated[str, typer.Argument(help="Resource type: yubikey or metadata")],
        uuid: Annotated[str | None, typer.Argument(help="[metadata] Item UUID to update")] = None,
        serial: Annotated[str | None, typer.Option(help="[yubikey] YubiKey serial to update")] = None,
        all_yubikeys: Annotated[bool, typer.Option("--all", help="[yubikey] Update all connected YubiKeys")] = False,
        # Bastion Metadata date fields
        password_changed: Annotated[str | None, typer.Option(help="[metadata] Password change date YYYY-MM-DD")] = None,
        password_expires: Annotated[str | None, typer.Option(help="[metadata] Password expiry date YYYY-MM-DD")] = None,
        totp_issued: Annotated[str | None, typer.Option(help="[metadata] TOTP seed issue date YYYY-MM-DD")] = None,
        last_review: Annotated[str | None, typer.Option(help="[metadata] Last security review date YYYY-MM-DD")] = None,
        next_review: Annotated[str | None, typer.Option(help="[metadata] Next review due date YYYY-MM-DD")] = None,
        breach_detected: Annotated[str | None, typer.Option(help="[metadata] Breach detection date YYYY-MM-DD")] = None,
        risk_level: Annotated[str | None, typer.Option(help="[metadata] Risk level: CRITICAL/HIGH/MEDIUM/LOW")] = None,
        bastion_notes: Annotated[str | None, typer.Option(help="[metadata] Security notes")] = None,
        show: Annotated[bool, typer.Option("--show", help="[metadata] Show current metadata")] = False,
    ) -> None:
        """Update YubiKey items or Bastion Metadata section in login items.
        
        YubiKey examples:
          bsec 1p update yubikey --serial 12345678    # Update specific YubiKey from scan
          bsec 1p update yubikey --all                # Update all connected YubiKeys
        
        Metadata examples:
          bsec 1p update metadata <UUID> --show       # Show current metadata
          bsec 1p update metadata <UUID> --password-changed 2025-11-27
        """
        if noun in ("yubikey", "yubikeys"):
            service = get_yubikey_service()
            
            if all_yubikeys:
                serials = service.list_connected_serials()
                if not serials:
                    console.print("[yellow]No YubiKeys connected[/yellow]")
                    raise typer.Exit(1)
            elif serial:
                serials = [serial]
            else:
                console.print("[red]Must specify --serial or --all[/red]")
                raise typer.Exit(1)
            
            _update_yubikeys(service, serials)
        
        elif noun == "metadata":
            if not uuid:
                console.print("[red]Error: UUID required for metadata operations[/red]")
                console.print("Usage: bsec 1p update metadata <UUID> [OPTIONS]")
                raise typer.Exit(1)
            
            if show:
                update_metadata_show(uuid)
            else:
                update_metadata(
                    uuid, password_changed, password_expires, totp_issued,
                    last_review, next_review, breach_detected, risk_level, bastion_notes
                )
        
        else:
            console.print(f"[red]Unknown resource type: {noun}[/red]")
            console.print("Valid types: yubikey, metadata")
            raise typer.Exit(1)


def _yubikey_list(service: YubiKeyService) -> None:
    """List all YubiKey items from sync cache."""
    devices = service.get_all_devices()
    
    if not devices:
        console.print("[yellow]No YubiKey/Token items found in sync cache[/yellow]")
        console.print("[dim]Run 'bsec 1p sync vault' to sync from 1Password[/dim]")
        return
    
    table = Table(title="YubiKey Devices (from 1Password)")
    table.add_column("Serial", style="cyan")
    table.add_column("Title", style="white")
    table.add_column("Vault", style="dim")
    table.add_column("OATH Slots", justify="right")
    table.add_column("Last Synced", style="dim")
    
    for device in devices:
        table.add_row(
            device.serial,
            device.title,
            device.vault,
            f"{device.slot_count}/32",
            device.updated_at[:10] if device.updated_at else "Never",
        )
    
    console.print(table)
    console.print(f"\n[dim]Total: {len(devices)} YubiKey(s)[/dim]")


def _yubikey_scan(service: YubiKeyService, serial: str | None, update: bool) -> None:
    """Scan connected YubiKeys and compare with 1Password."""
    connected = sorted(service.list_connected_serials(), key=lambda s: int(s) if s.isdigit() else 0)  # Sort numerically
    
    if not connected:
        console.print("[yellow]No YubiKeys connected[/yellow]")
        console.print("Connect a YubiKey and try again.")
        return
    
    # Filter to specific serial if provided
    if serial:
        if serial not in connected:
            console.print(f"[red]YubiKey {serial} not connected[/red]")
            console.print(f"Connected: {', '.join(connected)}")
            raise typer.Exit(1)
        connected = [serial]
    
    console.print(f"[cyan]Scanning {len(connected)} YubiKey(s)...[/cyan]\n")
    
    results = []
    for sn in connected:
        console.print(f"[bold]{sn}[/bold]")
        
        # Check if in 1Password
        device = service.get_yubikey_device(sn)
        if not device:
            console.print(f"  [yellow]⚠ Not found in 1Password (no YubiKey/Token item with SN={sn})[/yellow]")
            continue
        
        console.print(f"  Title: {device.title}")
        
        # Get password if needed
        password = None
        if service.is_oath_password_required(sn):
            password = service.get_oath_password(sn)
            if not password:
                console.print(f"  [yellow]⚠ OATH password required but not found in 1Password[/yellow]")
                continue
        
        # Scan and compare
        try:
            result = service.compare_device(sn, password)
            results.append(result)
            
            if result.in_sync:
                console.print(f"  [green]✓ In sync ({len(result.matched)} accounts)[/green]")
            else:
                if result.on_device_only:
                    console.print(f"  [yellow]⚠ On device but not in 1P ({len(result.on_device_only)}):[/yellow]")
                    for name in result.on_device_only[:5]:
                        console.print(f"    + {name}")
                    if len(result.on_device_only) > 5:
                        console.print(f"    ... and {len(result.on_device_only) - 5} more")
                
                if result.in_1p_only:
                    console.print(f"  [red]✗ In 1P but not on device ({len(result.in_1p_only)}):[/red]")
                    for name in result.in_1p_only[:5]:
                        console.print(f"    - {name}")
                    if len(result.in_1p_only) > 5:
                        console.print(f"    ... and {len(result.in_1p_only) - 5} more")
                
                if update:
                    console.print(f"  [cyan]Updating 1Password...[/cyan]")
                    # Get full account list from device
                    accounts = service.scan_oath_accounts(sn, password)
                    if service.update_1p_oath_slots(sn, accounts):
                        console.print(f"  [green]✓ Updated 1Password with {len(accounts)} slots[/green]")
                    else:
                        console.print(f"  [red]✗ Failed to update 1Password[/red]")
                else:
                    console.print(f"  [dim]Run with --update to sync to 1Password[/dim]")
        
        except PasswordRequiredError:
            console.print(f"  [yellow]⚠ OATH password required[/yellow]")
        except Exception as e:
            console.print(f"  [red]✗ Error: {e}[/red]")
        
        console.print()
    
    # Summary
    if results:
        in_sync = sum(1 for r in results if r.in_sync)
        out_of_sync = len(results) - in_sync
        console.print(f"[bold]Summary:[/bold] {in_sync} in sync, {out_of_sync} need attention")


def _yubikey_status(service: YubiKeyService) -> None:
    """Show status overview of all YubiKeys."""
    devices = service.get_all_devices()
    connected = service.list_connected_serials()
    
    if not devices:
        console.print("[yellow]No YubiKey/Token items found[/yellow]")
        console.print("[dim]Run 'bsec 1p sync vault' to sync from 1Password[/dim]")
        return
    
    table = Table(title="YubiKey Status")
    table.add_column("Serial", style="cyan")
    table.add_column("Title")
    table.add_column("Connected", justify="center")
    table.add_column("Slots (1P)")
    table.add_column("Status")
    
    for device in devices:
        is_connected = device.serial in connected
        
        status = "[dim]Unknown[/dim]"
        if is_connected:
            try:
                password = service.get_oath_password(device.serial) if service.is_oath_password_required(device.serial) else None
                result = service.compare_device(device.serial, password)
                if result.in_sync:
                    status = "[green]✓ In sync[/green]"
                else:
                    issues = []
                    if result.on_device_only:
                        issues.append(f"+{len(result.on_device_only)}")
                    if result.in_1p_only:
                        issues.append(f"-{len(result.in_1p_only)}")
                    status = f"[yellow]⚠ {', '.join(issues)}[/yellow]"
            except Exception:
                status = "[yellow]⚠ Scan failed[/yellow]"
        
        table.add_row(
            device.serial,
            device.title,
            "[green]✓[/green]" if is_connected else "[dim]✗[/dim]",
            f"{device.slot_count}/32",
            status,
        )
    
    console.print(table)
    
    # Show connected but unknown YubiKeys
    known_serials = {d.serial for d in devices}
    unknown = [s for s in connected if s not in known_serials]
    if unknown:
        console.print(f"\n[yellow]⚠ Connected but not in 1Password: {', '.join(unknown)}[/yellow]")
        console.print("[dim]Create a YubiKey/Token item with SN field to track these[/dim]")


def _update_yubikeys(service: YubiKeyService, serials: list[str]) -> None:
    """Update 1Password with current OATH slots from physical YubiKeys."""
    console.print(f"[cyan]Updating {len(serials)} YubiKey(s) in 1Password...[/cyan]\n")
    
    success = 0
    failed = 0
    
    for sn in serials:
        console.print(f"[bold]{sn}[/bold]")
        
        # Check if connected
        connected = service.list_connected_serials()
        if sn not in connected:
            console.print(f"  [red]✗ Not connected[/red]")
            failed += 1
            continue
        
        # Get password if needed
        password = None
        if service.is_oath_password_required(sn):
            password = service.get_oath_password(sn)
            if not password:
                console.print(f"  [yellow]⚠ OATH password required but not found[/yellow]")
                failed += 1
                continue
        
        try:
            accounts = service.scan_oath_accounts(sn, password)
            console.print(f"  Scanned {len(accounts)} OATH accounts")
            
            if service.update_1p_oath_slots(sn, accounts):
                console.print(f"  [green]✓ Updated 1Password[/green]")
                success += 1
            else:
                console.print(f"  [red]✗ Failed to update[/red]")
                failed += 1
        except Exception as e:
            console.print(f"  [red]✗ Error: {e}[/red]")
            failed += 1
    
    console.print(f"\n[bold]Summary:[/bold] {success} updated, {failed} failed")
