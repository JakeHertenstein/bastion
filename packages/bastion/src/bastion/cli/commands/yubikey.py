"""YubiKey management operations.

Functions for YubiKey cache management, password retrieval, and slot auditing.
Note: The main _yubikey_migrate function remains in cli_legacy.py due to its
complexity and tight integration with the CLI flow.
"""

from __future__ import annotations

import json
import subprocess
from typing import TYPE_CHECKING

import typer

from ..console import console
from ..helpers import get_yubikey_cache

if TYPE_CHECKING:
    from bastion.db import DatabaseManager
    from bastion.op_client import OpClient
    from bastion.yubikey_cache import YubiKeyCache


def get_yubikey_password_from_1password(op_uuid: str, op_client: "OpClient") -> str | None:
    """Get YubiKey OATH password from 1Password crypto wallet item.
    
    Args:
        op_uuid: 1Password UUID of the YubiKey crypto wallet item
        op_client: OpClient instance for fetching items
        
    Returns:
        The password string if found, None otherwise
    """
    try:
        item_data = op_client.get_item(op_uuid)
        if not item_data:
            console.print("[yellow]⚠ Could not fetch YubiKey item from 1Password[/yellow]")
            return None
        
        # Look for password field in the item
        fields = item_data.get("fields", [])
        
        for field in fields:
            # Check for standard password field
            if field.get("id") == "password" or field.get("purpose") == "PASSWORD":
                password = field.get("value")
                if password:
                    return password
            # Also check for field labeled "OATH Password" or similar
            field_label = field.get("label", "").lower()
            if "oath" in field_label and "password" in field_label:
                password = field.get("value")
                if password:
                    return password
            # Check for any field with "password" in the label (case-insensitive)
            if "password" in field_label:
                password = field.get("value")
                if password:
                    return password
        
        console.print(f"[yellow]⚠ No password/OATH password field found in YubiKey item {op_uuid}[/yellow]")
        return None
    except Exception as e:
        # Handle any errors gracefully
        console.print(f"[yellow]⚠ Error fetching password from 1Password: {e}[/yellow]")
        return None


def yubikey_refresh_cache(
    cache: "YubiKeyCache",
    op_client: "OpClient | None" = None,
    get_password_fn=None,
) -> None:
    """Refresh YubiKey slot cache for connected devices.
    
    Args:
        cache: YubiKeyCache instance
        op_client: Optional OpClient for fetching passwords from 1Password
        get_password_fn: Optional function to get password (for testing/DI)
    """
    console.print("[cyan]Refreshing YubiKey cache...[/cyan]\n")
    
    connected = cache.list_connected_yubikeys()
    
    if not connected:
        console.print("[yellow]No YubiKeys connected[/yellow]")
        console.print("Connect YubiKeys and try again.")
        return
    
    console.print(f"Found {len(connected)} YubiKey(s):\n")
    
    # Get password function - use provided or default
    if get_password_fn is None:
        get_password_fn = get_yubikey_password_from_1password
    
    # Try to get password from 1Password once for all YubiKeys
    # Search for any YubiKey Note item with OATH Password field
    oath_password = None
    if op_client:
        try:
            # First try cached UUIDs
            for serial in connected:
                if serial in cache.serials and cache.serials[serial].op_uuid:
                    oath_password = get_password_fn(cache.serials[serial].op_uuid, op_client)
                    if oath_password:
                        console.print("[dim]Using password from 1Password[/dim]\n")
                        break
            
            # If not found, search for YK-{serial} Note items
            if not oath_password:
                result = subprocess.run(
                    ["op", "item", "list", "--categories", "Secure Note", "--format", "json"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
                all_items = json.loads(result.stdout)
                
                for serial in connected:
                    yk_title = f"YK-{serial}"
                    yk_item = next((item for item in all_items if item.get('title') == yk_title), None)
                    if yk_item:
                        oath_password = get_password_fn(yk_item['id'], op_client)
                        if oath_password:
                            console.print("[dim]Using password from 1Password[/dim]\n")
                            break
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass  # Will prompt for password if needed
    
    for serial in connected:
        console.print(f"[cyan]Refreshing {serial}...[/cyan]")
        
        # Use existing role or default to empty (optional field)
        role = cache.serials[serial].role if serial in cache.serials else ""
        
        success, message = cache.refresh_serial(serial, role, oath_password)
        
        if success:
            info = cache.serials[serial]
            console.print(f"[green]✓ {serial}: {info.slot_count}/32 slots - {message}[/green]\n")
        else:
            console.print(f"[red]✗ {serial}: {message}[/red]\n")
    
    cache.save()
    console.print("[green]Cache refresh complete[/green]")


def yubikey_audit_slots(db_manager: "DatabaseManager", cache: "YubiKeyCache") -> None:
    """Audit YubiKey slot usage and identify gaps.
    
    Args:
        db_manager: DatabaseManager instance
        cache: YubiKeyCache instance
    """
    from rich.table import Table
    
    # Load database
    db = db_manager.load()
    
    console.print("[cyan]YubiKey Slot Audit[/cyan]\n")
    
    # Overall slot usage table
    if cache.serials:
        table = Table(title="YubiKey Slot Usage")
        table.add_column("Serial", style="cyan")
        table.add_column("Role", style="yellow")
        table.add_column("Slots Used", justify="right")
        table.add_column("Remaining", justify="right")
        table.add_column("Cache Age", justify="right")
        table.add_column("Status", style="green")
        
        # Sort numerically by serial number for consistent display
        for serial, info in sorted(cache.serials.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0):
            status = "⚠ Stale" if info.is_stale else "✓ Fresh"
            status_color = "yellow" if info.is_stale else "green"
            
            table.add_row(
                serial,
                info.role or "Unknown",
                f"{info.slot_count}/32",
                str(info.slots_remaining),
                f"{info.cache_age_days}d",
                f"[{status_color}]{status}[/{status_color}]",
            )
        
        console.print(table)
        console.print()
    else:
        console.print("[yellow]No YubiKeys in cache. Run 'bastion refresh yubikey' first.[/yellow]\n")
    
    # Find accounts with TOTP but missing documentation
    missing_docs = []
    for acc in db.accounts.values():
        has_yubikey_totp = "Bastion/2FA/TOTP/YubiKey" in acc.tag_list
        # Check for yubikey_totp custom field (would need to fetch from 1Password)
        # For now, just check tag
        if has_yubikey_totp:
            # Simplified check - in production would verify custom field exists
            pass
    
    # Find accounts with redundancy gaps
    redundancy_gaps = []
    for acc in db.accounts.values():
        if "Bastion/Redundancy/Multi-YubiKey" in acc.tag_list:
            # Check how many YubiKeys have this account
            # Would need to parse custom fields or check cache
            # For now, list as potential gap
            redundancy_gaps.append(acc)
    
    if redundancy_gaps:
        console.print("[yellow]Accounts Tagged for Multi-YubiKey Redundancy:[/yellow]")
        for acc in redundancy_gaps:
            console.print(f"  • {acc.title}")
        console.print("\n[dim]Verify these accounts have TOTP on multiple YubiKeys[/dim]\n")
    
    # Show partial migrations
    partial = cache.get_partial_migrations()
    if partial:
        console.print("[yellow]Partial Migrations Requiring Attention:[/yellow]")
        for tx in partial:
            console.print(f"  • {tx.account_name}")
            console.print(f"    Completed: {', '.join(tx.completed_serials)}")
            console.print(f"    Failed: {', '.join(tx.failed_serials)}")
        console.print()


def yubikey_clean_cache(
    cache: "YubiKeyCache",
    serial: str | None = None,
    dry_run: bool = False,
    op_client: "OpClient | None" = None,
) -> None:
    """Clean YubiKey cache by syncing with hardware.
    
    Compares cached OATH accounts against actual hardware and removes
    stale entries that no longer exist on the YubiKey.
    
    Args:
        cache: YubiKeyCache instance
        serial: Optional specific serial to clean (default: all)
        dry_run: If True, show what would be done without making changes
        op_client: Optional OpClient for fetching passwords from 1Password
    """
    import getpass
    import subprocess
    
    action = "Would clean" if dry_run else "Cleaning"
    console.print(f"[cyan]{action} YubiKey cache by syncing with hardware...[/cyan]\n")
    
    # Determine which serials to clean
    if serial:
        if serial not in cache.serials:
            console.print(f"[red]Error:[/red] YubiKey {serial} not found in cache")
            import typer
            raise typer.Exit(1)
        serials_to_clean = [serial]
    else:
        serials_to_clean = list(cache.serials.keys())
    
    if not serials_to_clean:
        console.print("[yellow]No YubiKeys in cache to clean[/yellow]")
        return
    
    # Try to get password from 1Password first
    oath_password = None
    if op_client:
        for s in serials_to_clean:
            if s in cache.serials and cache.serials[s].op_uuid:
                oath_password = get_yubikey_password_from_1password(cache.serials[s].op_uuid, op_client)
                if oath_password:
                    console.print("[dim]Using password from 1Password[/dim]")
                    break
    
    # Fall back to checking if password needed and prompting
    if not oath_password:
        needs_password = False
        for s in serials_to_clean:
            try:
                result = subprocess.run(
                    ["ykman", "--device", s, "oath", "info"],
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                if b"password" in result.stdout.lower() or b"password" in result.stderr.lower():
                    needs_password = True
                    break
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        if needs_password:
            oath_password = getpass.getpass("YubiKey OATH password: ")
    
    total_removed = 0
    
    for s in serials_to_clean:
        console.print(f"[cyan]YubiKey {s}:[/cyan]")
        
        # Get actual OATH accounts from hardware
        try:
            result = subprocess.run(
                ["ykman", "--device", s, "oath", "accounts", "list"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                input=f"{oath_password}\n".encode() if oath_password else b"",
                timeout=30,
                check=True,
            )
            hardware_accounts = {line.strip() for line in result.stdout.decode().strip().split('\n') if line.strip()}
        except subprocess.CalledProcessError as e:
            console.print(f"  [red]✗ Could not read from device: {e.stderr.decode().strip()}[/red]")
            continue
        except subprocess.TimeoutExpired:
            console.print("  [red]✗ Timeout reading from device[/red]")
            continue
        
        # Get cached accounts
        cached_accounts = {acc["oath_name"] for acc in cache.serials[s].accounts if isinstance(acc, dict)}
        
        # Find accounts in cache but not on hardware
        to_remove = cached_accounts - hardware_accounts
        
        if not to_remove:
            console.print(f"  [green]✓ Cache is clean ({len(cached_accounts)} accounts match hardware)[/green]")
        else:
            console.print(f"  Found {len(to_remove)} stale entries to remove:")
            for oath_name in sorted(to_remove):
                if dry_run:
                    console.print(f"    [yellow]Would remove:[/yellow] {oath_name}")
                else:
                    cache.serials[s].remove_account_by_oath_name(oath_name)
                    console.print(f"    [red]Removed:[/red] {oath_name}")
                    total_removed += 1
            
            if not dry_run:
                console.print(f"  [green]✓ Cleaned {len(to_remove)} entries[/green]")
        
        # Show what remains
        remaining = len(cache.serials[s].accounts)
        console.print(f"  Cache now has {remaining} accounts\n")
    
    if not dry_run and total_removed > 0:
        cache.save()
        console.print(f"[green]✓ Cleaned {total_removed} total stale entries from cache[/green]")
    elif dry_run and total_removed > 0:
        console.print(f"[yellow]Dry run: Would remove {total_removed} total stale entries[/yellow]")


def update_yubikey_items(serials: list[str], cache: "YubiKeyCache") -> None:
    """Update YubiKey Note items in 1Password with OATH slot sections.
    
    Syncs the OATH accounts from the cache to 1Password by creating
    structured OATH Slot sections in the YubiKey Note item.
    
    Args:
        serials: List of YubiKey serial numbers to update
        cache: YubiKeyCache instance
    """
    import json
    import subprocess
    
    console.print("[cyan]Updating YubiKey Note items with OATH slot sections...[/cyan]\n")
    
    for serial in serials:
        console.print(f"[dim]Checking YubiKey {serial}...[/dim]")
        if serial not in cache.serials:
            console.print(f"[yellow]  YubiKey {serial} not found in cache[/yellow]")
            continue
        
        if not cache.serials[serial].op_uuid:
            console.print(f"[yellow]  YubiKey {serial} not linked to 1Password (no op_uuid)[/yellow]")
            console.print("[dim]    Run 'bastion link yubikey --all' to link YubiKeys to 1Password Note items[/dim]")
            continue
        
        yubikey_op_uuid = cache.serials[serial].op_uuid
        oath_accounts = [acc for acc in cache.serials[serial].accounts if isinstance(acc, dict)]
        console.print(f"[dim]  Found {len(oath_accounts)} OATH accounts in cache[/dim]")
        
        if not oath_accounts:
            console.print(f"[yellow]  No OATH accounts found in cache for YubiKey {serial}[/yellow]")
            continue
        
        # Sort by OATH name, then assign sequential slot numbers
        sorted_accounts = sorted(oath_accounts, key=lambda a: a.get("oath_name", ""))
        
        try:
            result = subprocess.run(
                ["op", "item", "get", yubikey_op_uuid, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            item_data = json.loads(result.stdout)
            
            # Remove old oath_accounts field and OATH Slot sections with their fields
            item_data["fields"] = [f for f in item_data.get("fields", []) 
                                  if f.get("label") != "oath_accounts" and 
                                  not f.get("section", {}).get("label", "").startswith("OATH Slot ")]
            item_data["sections"] = [s for s in item_data.get("sections", [])
                                    if not s.get("label", "").startswith("OATH Slot ")]
            
            # Build new sections and fields lists to ensure proper ordering
            new_sections = []
            new_fields = []
            
            for i, acc in enumerate(sorted_accounts, start=1):
                # Use padded slot number to ensure proper sorting in 1Password
                section_id = f"oath_slot_{i:02d}"
                section_label = f"OATH Slot {i}"
                
                # Parse oath_name to split issuer and account
                oath_name = acc.get("oath_name", "")
                if ":" in oath_name:
                    issuer, account_name = oath_name.split(":", 1)
                else:
                    issuer = oath_name
                    account_name = ""
                
                new_sections.append({
                    "id": section_id,
                    "label": section_label
                })
                
                new_fields.extend([
                    {
                        "section": {"id": section_id, "label": section_label},
                        "type": "STRING",
                        "label": "Issuer",
                        "value": issuer
                    },
                    {
                        "section": {"id": section_id, "label": section_label},
                        "type": "STRING",
                        "label": "Username",
                        "value": account_name
                    }
                ])
            
            # Add all sections and fields at once
            if "sections" not in item_data:
                item_data["sections"] = []
            if "fields" not in item_data:
                item_data["fields"] = []
            
            item_data["sections"].extend(new_sections)
            item_data["fields"].extend(new_fields)
            
            # Update item with JSON stdin
            subprocess.run(
                ["op", "item", "edit", yubikey_op_uuid, "-"],
                input=json.dumps(item_data),
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            console.print(f"[green]✓ Updated YubiKey {serial} with {len(sorted_accounts)} OATH slot sections[/green]")
            
        except subprocess.CalledProcessError as e:
            error_detail = e.stderr.strip() if e.stderr else str(e)
            console.print(f"[yellow]⚠ Could not update YubiKey {serial}: {error_detail[:200]}[/yellow]")
        except json.JSONDecodeError as e:
            console.print(f"[yellow]⚠ JSON parse error for YubiKey {serial}: {e}[/yellow]")


def yubikey_discover(cache: "YubiKeyCache") -> dict[str, int]:
    """Discover YubiKeys from 1Password and add them to cache.
    
    Searches for 1Password items with tag 'YubiKey/Token', extracts the SN field,
    and creates cache entries for YubiKeys not yet in the cache. This allows
    tracking YubiKeys without requiring physical connection.
    
    Args:
        cache: YubiKeyCache instance
        
    Returns:
        Dict with counts: 'discovered', 'already_known', 'no_sn'
    """
    from datetime import datetime, timezone
    from bastion.yubikey_cache import YubiKeySerialInfo
    
    console.print("[cyan]Discovering YubiKeys from 1Password...[/cyan]\n")
    
    # Get all items with YubiKey/Token tag
    try:
        result = subprocess.run(
            ["op", "item", "list", "--tags", "YubiKey/Token", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        all_items = json.loads(result.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        console.print(f"[red]Error fetching 1Password items: {e}[/red]")
        raise typer.Exit(1)
    
    if not all_items:
        console.print("[yellow]No items found with tag 'YubiKey/Token'[/yellow]")
        return {'discovered': 0, 'already_known': 0, 'no_sn': 0}
    
    console.print(f"Found {len(all_items)} YubiKey/Token item(s) in 1Password\n")
    
    discovered_count = 0
    already_known_count = 0
    no_sn_count = 0
    
    for item in all_items:
        item_title = item.get('title', item['id'])
        vault_name = item.get('vault', {}).get('name', 'Private')
        
        try:
            # Fetch full item to get SN field
            item_result = subprocess.run(
                ["op", "item", "get", item['id'], "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            full_item = json.loads(item_result.stdout)
            
            # Find SN field
            serial = None
            role = ""
            for field in full_item.get('fields', []):
                if field.get('label') == 'SN' and field.get('value'):
                    serial = field['value']
                elif field.get('label') == 'Role' and field.get('value'):
                    role = field['value']
            
            if not serial:
                console.print(f"[yellow]⚠ {item_title}: No SN field found[/yellow]")
                no_sn_count += 1
                continue
            
            # Check if already in cache
            if serial in cache.serials:
                # Update op_uuid if not set
                if not cache.serials[serial].op_uuid:
                    cache.serials[serial].op_uuid = item['id']
                    console.print(f"[green]✓ {serial}: Linked existing entry to '{item_title}'[/green]")
                else:
                    console.print(f"[dim]  {serial}: Already known ('{item_title}')[/dim]")
                already_known_count += 1
            else:
                # Create new cache entry
                cache.serials[serial] = YubiKeySerialInfo(
                    serial=serial,
                    role=role,
                    accounts=[],  # Empty until physical scan
                    last_updated=datetime.now(timezone.utc),
                    op_uuid=item['id'],
                )
                console.print(f"[green]✓ {serial}: Discovered from '{item_title}' (vault: {vault_name})[/green]")
                discovered_count += 1
                
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            console.print(f"[yellow]⚠ {item_title}: Error fetching details - {e}[/yellow]")
            continue
    
    cache.save()
    
    console.print(f"\n[cyan]Summary:[/cyan]")
    console.print(f"  Discovered: {discovered_count}")
    console.print(f"  Already known: {already_known_count}")
    console.print(f"  No SN field: {no_sn_count}")
    
    return {
        'discovered': discovered_count,
        'already_known': already_known_count,
        'no_sn': no_sn_count,
    }


def yubikey_link_single(
    serial: str,
    cache: "YubiKeyCache",
    db_manager: "DatabaseManager",
) -> None:
    """Link a single YubiKey serial to its 1Password Note item.
    
    Searches for 1Password items with tag 'YubiKey/Token' and matches
    the SN field to the serial number.
    
    Args:
        serial: YubiKey serial number
        cache: YubiKeyCache instance
        db_manager: DatabaseManager instance
        
    Raises:
        RuntimeError: If no matching 1Password item is found
    """
    # Search for items with YubiKey/Token tag
    try:
        result = subprocess.run(
            ["op", "item", "list", "--tags", "YubiKey/Token", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        all_items = json.loads(result.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        raise RuntimeError(f"Error fetching 1Password items: {e}")
    
    # Find matching item by SN field
    for item in all_items:
        try:
            # Fetch full item to get fields
            item_result = subprocess.run(
                ["op", "item", "get", item['id'], "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            full_item = json.loads(item_result.stdout)
            
            # Check SN field
            for field in full_item.get('fields', []):
                if field.get('label') == 'SN' and field.get('value') == serial:
                    op_uuid = item['id']
                    vault_name = item.get('vault', {}).get('name', 'Private')
                    item_title = item.get('title', op_uuid)
                    
                    # Update cache
                    if serial in cache.serials:
                        cache.serials[serial].op_uuid = op_uuid
                    else:
                        from datetime import datetime, timezone
                        from bastion.yubikey_cache import YubiKeySerialInfo
                        cache.serials[serial] = YubiKeySerialInfo(
                            serial=serial,
                            role="Unknown",
                            accounts=[],
                            last_updated=datetime.now(timezone.utc),
                            op_uuid=op_uuid,
                        )
                    
                    cache.save()
                    console.print(f"[green]✓ {serial}: Linked to '{item_title}' (vault: {vault_name})[/green]")
                    return
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            continue
    
    raise RuntimeError(f"No 1Password item found with tag 'YubiKey/Token' and SN='{serial}'")


def yubikey_link_all(cache: "YubiKeyCache") -> dict[str, int]:
    """Link all YubiKeys in cache to 1Password Note items.
    
    Searches for 1Password items with tag 'YubiKey/Token' and matches
    the SN field to link them to cache entries.
    
    Args:
        cache: YubiKeyCache instance
        
    Returns:
        Dict with counts: 'linked', 'already_linked', 'not_found'
    """
    console.print("[cyan]Linking all YubiKeys in cache to 1Password items...[/cyan]\n")
    
    if not cache.serials:
        console.print("[yellow]No YubiKeys found in cache[/yellow]")
        return {'linked': 0, 'already_linked': 0, 'not_found': 0}
    
    # Get all items with YubiKey/Token tag
    try:
        result = subprocess.run(
            ["op", "item", "list", "--tags", "YubiKey/Token", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        all_items = json.loads(result.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        console.print(f"[red]Error fetching 1Password items: {e}[/red]")
        raise typer.Exit(1)
    
    # Build a map of serial -> UUID by fetching each item's SN field
    sn_to_uuid = {}
    console.print("[cyan]Scanning 1Password for YubiKey/Token items...[/cyan]")
    for item in all_items:
        try:
            # Fetch full item to get SN field
            item_result = subprocess.run(
                ["op", "item", "get", item['id'], "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            full_item = json.loads(item_result.stdout)
            
            # Find SN field
            for field in full_item.get('fields', []):
                if field.get('label') == 'SN' and field.get('value'):
                    serial = field['value']
                    sn_to_uuid[serial] = {
                        'uuid': item['id'],
                        'title': item.get('title', item['id']),
                        'vault': item.get('vault', {}).get('name', 'Private')
                    }
                    break
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            continue
    
    # Link each YubiKey in cache (sorted numerically by serial for consistent output)
    linked_count = 0
    already_linked_count = 0
    not_found_count = 0
    
    for serial_num in sorted(cache.serials.keys(), key=lambda s: int(s) if s.isdigit() else 0):
        if cache.serials[serial_num].op_uuid:
            console.print(f"[dim]  {serial_num}: Already linked to {cache.serials[serial_num].op_uuid}[/dim]")
            already_linked_count += 1
        elif serial_num in sn_to_uuid:
            item_info = sn_to_uuid[serial_num]
            cache.serials[serial_num].op_uuid = item_info["uuid"]
            console.print(f"[green]✓ {serial_num}: Linked to '{item_info['title']}' (vault: {item_info['vault']})[/green]")
            linked_count += 1
        else:
            console.print(f"[yellow]⚠ {serial_num}: No matching 1Password item found (tag: YubiKey/Token, SN: {serial_num})[/yellow]")
            not_found_count += 1
    
    cache.save()
    
    return {
        'linked': linked_count,
        'already_linked': already_linked_count,
        'not_found': not_found_count,
    }


def yubikey_rebuild_mappings(cache: "YubiKeyCache", db_manager: "DatabaseManager") -> None:
    """Rebuild UUID mappings from 1Password custom fields.
    
    Scans all 1Password items for yubikey_oath_name fields and rebuilds
    the cache mappings between OATH accounts and 1Password items.
    
    Args:
        cache: YubiKeyCache instance
        db_manager: DatabaseManager instance
    """
    import json
    import subprocess
    
    from bastion.cli.yubikey_helpers import get_yubikey_field
    
    console.print("[cyan]Rebuilding UUID mappings from 1Password custom fields...[/cyan]\n")
    
    # First, do normal refresh to get current OATH accounts
    yubikey_refresh_cache(cache)
    
    # Load database to get all accounts
    db = db_manager.load()
    
    # For each YubiKey serial
    updated_count = 0
    for serial, info in cache.serials.items():
        console.print(f"Processing YubiKey {serial}...")
        
        # For each OATH account on this YubiKey
        for oath_name in info.get_oath_names():
            # Search 1Password items for matching yubikey_oath_name custom field
            found = False
            for account in db.accounts.values():
                try:
                    result = subprocess.run(
                        ["op", "item", "get", account.uuid, "--format", "json"],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=30,
                    )
                    item_data = json.loads(result.stdout)
                    
                    # Check yubikey_oath_name field (try both old and new formats)
                    stored_oath_name = get_yubikey_field(item_data, "oath_name", "YubiKey TOTP")
                    
                    if stored_oath_name == oath_name:
                        # Found matching 1Password item
                        info.add_or_update_mapping(
                            oath_name=oath_name,
                            op_uuid=account.uuid,
                            op_title=account.title,
                        )
                        console.print(f"  ✓ Mapped '{oath_name}' → {account.title} ({account.uuid})")
                        updated_count += 1
                        found = True
                    
                    if found:
                        break
                        
                except (subprocess.CalledProcessError, json.JSONDecodeError):
                    continue
            
            if not found:
                console.print(f"  [yellow]⚠ No 1Password mapping found for '{oath_name}'[/yellow]")
    
    cache.save()
    console.print(f"\n[green]✓ Rebuilt {updated_count} UUID mappings[/green]")


def yubikey_rollback(account_name: str, db_manager: "DatabaseManager", cache: YubiKeyCache) -> None:
    """Rollback partial or failed YubiKey migration."""
    import subprocess
    
    # Load database
    db = db_manager.load()
    
    # Find account
    account = None
    for acc in db.accounts.values():
        if acc.title.lower() == account_name.lower():
            account = acc
            break
    
    if not account:
        console.print(f"[red]Error: Account '{account_name}' not found[/red]")
        raise typer.Exit(1)
    
    # Get transaction
    transaction = cache.get_transaction_for_account(account.uuid)
    
    if not transaction:
        console.print(f"[yellow]No migration transaction found for '{account_name}'[/yellow]")
        return
    
    console.print(f"[cyan]Migration Status for: {account.title}[/cyan]\n")
    console.print(f"  Status: {transaction.status}")
    console.print(f"  Completed YubiKeys: {', '.join(transaction.completed_serials) if transaction.completed_serials else 'None'}")
    console.print(f"  Failed YubiKeys: {', '.join(transaction.failed_serials) if transaction.failed_serials else 'None'}")
    console.print(f"  Date: {transaction.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    
    if transaction.status == "complete":
        console.print("\n[green]Migration completed successfully, no rollback needed[/green]")
        return
    
    if transaction.status == "partial":
        keep = typer.confirm("\nKeep partial migration?", default=True)
        
        if keep:
            console.print("\n[yellow]Partial migration kept. To complete manually:[/yellow]")
            console.print(f"  1. Connect remaining YubiKeys: {', '.join(transaction.failed_serials)}")
            console.print(f"  2. Run: ykman --device SERIAL oath accounts uri \"{transaction.issuer}:...\" \"otpauth://...\" --touch")
            console.print("  3. Update 1Password custom field 'yubikey_totp' with additional serials")
            return
    
    # Remove TOTP from completed YubiKeys
    if transaction.completed_serials:
        console.print(f"\n[yellow]Removing TOTP from YubiKeys: {', '.join(transaction.completed_serials)}[/yellow]\n")
        
        # Check which YubiKeys are currently connected
        currently_connected = cache.list_connected_yubikeys()
        
        for serial in transaction.completed_serials:
            # Check if YubiKey is connected
            if serial not in currently_connected:
                console.print(f"[dim]⊘ Skipping YubiKey {serial} (not currently connected)[/dim]")
                continue
            
            console.print(f"[cyan]→ YubiKey {serial}...[/cyan]", end=" ")
            
            try:
                result = subprocess.run(
                    [
                        "ykman",
                        "--device", serial,
                        "oath", "accounts", "delete",
                        f"{transaction.issuer}:{account.title}",
                        "--force",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=True,
                )
                console.print("[green]✓ Removed[/green]")
            except subprocess.CalledProcessError as e:
                error_msg = e.stderr.strip() if e.stderr else str(e)
                console.print(f"[red]✗ Failed: {error_msg[:80]}[/red]")
    
    # Update transaction status
    transaction.status = "rolled_back"
    cache.save()
    
    console.print("\n[green]Rollback complete. TOTP remains in 1Password.[/green]")


def migrate_yubikey_fields(uuid, all_items, non_interactive, dry_run, status) -> None:
    """Helper function to migrate YubiKey TOTP traceability fields."""
    from bastion.migration_yubikey_fields import YubiKeyFieldMigration
    from pathlib import Path
    
    migrator = YubiKeyFieldMigration(dry_run=dry_run)
    
    if status:
        migrator.show_status_table()
        return
    
    if uuid:
        migrator.migrate_item(uuid, interactive=not non_interactive)
        log_path = Path.cwd() / "yubikey_migration.log.json"
        migrator.save_migration_log(log_path)
        return
    
    if all_items:
        stats = migrator.migrate_all(interactive=not non_interactive)
        console.print("\n[cyan]Migration Summary:[/cyan]")
        console.print(f"  Total items: {stats['total']}")
        console.print(f"  Migrated: {stats['migrated']}")
        console.print(f"  Skipped: {stats['skipped']}")
        console.print(f"  Failed: {stats['failed']}")
        log_path = Path.cwd() / "yubikey_migration.log.json"
        migrator.save_migration_log(log_path)
        return
    
    console.print("[yellow]No action specified. Use --status, --uuid, or --all[/yellow]")
    console.print("\nRun: bastion migrate fields yubikey --help")
    raise typer.Exit(1)


def add_totp_bulk(tag: str, target_serials: list[str], db_manager: "DatabaseManager", cache: "YubiKeyCache") -> None:
    """Add all accounts with specified tag to target YubiKey(s)."""
    from bastion.op_client import OpClient
    import getpass
    
    console.print(f"[cyan]Finding accounts with tag: {tag}[/cyan]\n")
    
    # Load database
    db = db_manager.load()
    op_client = OpClient()
    
    # Find accounts with the tag
    accounts_to_add = []
    for account in db.accounts.values():
        if tag in account.tag_list:
            accounts_to_add.append(account)
    
    if not accounts_to_add:
        console.print(f"[yellow]No accounts found with tag '{tag}'[/yellow]")
        return
    
    console.print(f"[cyan]Found {len(accounts_to_add)} account(s) with tag '{tag}'[/cyan]\n")
    
    # Pre-load OATH passwords from 1Password once for all accounts
    console.print("[cyan]Loading OATH passwords from 1Password...[/cyan]")
    passwords_by_serial = {}
    for serial in target_serials:
        if serial in cache.serials and cache.serials[serial].op_uuid:
            op_uuid = cache.serials[serial].op_uuid
            password = get_yubikey_password_from_1password(op_uuid, op_client)
            if password:
                passwords_by_serial[serial] = password
    
    if passwords_by_serial:
        console.print(f"[green]✓ Loaded OATH passwords for {len(passwords_by_serial)} YubiKey(s)[/green]")
        unique_passwords = set(passwords_by_serial.values())
        if len(unique_passwords) == 1:
            oath_password = list(unique_passwords)[0]
            console.print("[dim]  All YubiKeys use the same OATH password[/dim]")
        else:
            console.print("[yellow]  Target YubiKeys have different OATH passwords[/yellow]")
            oath_password = getpass.getpass("Enter YubiKey OATH password: ")
    else:
        console.print("[yellow]  No OATH passwords found in 1Password[/yellow]")
        oath_password = getpass.getpass("Enter YubiKey OATH password (or press Enter if none): ")
    
    # Pre-scan all target YubiKeys for existing OATH accounts once
    console.print("\n[cyan]Scanning YubiKeys for existing accounts...[/cyan]")
    all_existing_by_serial = {}
    for serial in target_serials:
        try:
            check_result = subprocess.run(
                ["ykman", "--device", serial, "oath", "accounts", "list"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                input=f"{oath_password}\n".encode(),
                timeout=30,
                check=False,
            )
            if check_result.returncode == 0:
                accounts = [line.strip() for line in check_result.stdout.decode().strip().split('\n') if line.strip()]
                all_existing_by_serial[serial] = accounts
        except (subprocess.TimeoutExpired, Exception):
            all_existing_by_serial[serial] = []
    
    # Combine all existing accounts for conflict detection
    all_existing_accounts = []
    for accounts in all_existing_by_serial.values():
        all_existing_accounts.extend(accounts)
    all_existing_accounts = list(set(all_existing_accounts))
    console.print(f"[green]✓ Found {len(all_existing_accounts)} existing OATH accounts across {len(all_existing_by_serial)} YubiKey(s)[/green]\n")
    
    # Pre-build potential conflicts list from database (accounts with same title)
    console.print("[cyan]Analyzing potential title conflicts...[/cyan]")
    conflicting_titles = {}
    for account in accounts_to_add:
        title_conflicts = []
        for acc_id, acc in db.accounts.items():
            if acc.title == account.title and acc.uuid != account.uuid:
                title_conflicts.append(acc)
        if title_conflicts:
            conflicting_titles[account.uuid] = title_conflicts
    
    if conflicting_titles:
        console.print(f"[yellow]⚠ Found {len(conflicting_titles)} account(s) with title conflicts[/yellow]")
    else:
        console.print("[green]✓ No title conflicts detected[/green]")
    console.print()
    
    # Add each account to all target YubiKeys
    success_count = 0
    skip_count = 0
    error_count = 0
    
    for i, account in enumerate(accounts_to_add, 1):
        console.print(f"\n[cyan]═══ Account {i}/{len(accounts_to_add)}: {account.title} ═══[/cyan]")
        try:
            yubikey_migrate(
                account.uuid, 
                db_manager, 
                cache, 
                target_serials, 
                by_uuid=True,
                passwords_by_serial=passwords_by_serial,
                oath_password=oath_password,
                existing_by_serial=all_existing_by_serial,
                conflicting_titles=conflicting_titles.get(account.uuid, [])
            )
            success_count += 1
        except KeyboardInterrupt:
            console.print("\n[yellow]⚠ Interrupted by user[/yellow]")
            break
        except Exception as e:
            error_str = str(e)[:150]
            if "No target YubiKeys are currently connected" in error_str:
                console.print("[dim]⊘ Skipped (no connected YubiKeys)[/dim]")
                skip_count += 1
            else:
                console.print(f"[red]✗ Error: {error_str}[/red]")
                error_count += 1
    
    console.print("\n[cyan]═══ Summary ═══[/cyan]")
    console.print(f"[green]✓ Completed: {success_count}[/green]")
    if skip_count > 0:
        console.print(f"[dim]⊘ Skipped: {skip_count} (no connected YubiKeys)[/dim]")
    if error_count > 0:
        console.print(f"[red]✗ Errors: {error_count}[/red]")
    
    # Update all YubiKey Note items once with OATH slot sections
    if success_count > 0:
        console.print()
        update_yubikey_items(target_serials, cache)


def yubikey_migrate(
    account_identifier: str, 
    db_manager: "DatabaseManager", 
    cache: "YubiKeyCache", 
    target_serials: list[str] | None = None,
    by_uuid: bool = False,
    passwords_by_serial: dict[str, str] | None = None,
    oath_password: str | None = None,
    existing_by_serial: dict[str, list[str]] | None = None,
    conflicting_titles: list | None = None
) -> None:
    """Migrate TOTP from 1Password to YubiKey.
    
    Args:
        account_identifier: Name or UUID of the account to migrate
        db_manager: Database manager instance
        cache: YubiKey cache instance
        target_serials: Optional list of target YubiKey serials (skips prompt)
        by_uuid: If True, treat account_identifier as UUID and skip account selection
        passwords_by_serial: Optional dict of passwords keyed by serial number
        oath_password: Optional OATH password to use for all YubiKeys
        existing_by_serial: Optional pre-scanned dict of existing OATH accounts by serial
        conflicting_titles: Optional list of accounts with same title for disambiguation
    """
    import urllib.parse
    import getpass
    from bastion.op_client import OpClient
    from bastion.tag_operations import TagOperations
    from ..yubikey_helpers import generate_unique_oath_name, get_yubikey_field, get_all_oath_names_from_tokens
    
    # Load database
    db = db_manager.load()
    op_client = OpClient()
    
    # Find all matching accounts
    matches = []
    if by_uuid:
        # Direct UUID lookup - no ambiguity
        for acc in db.accounts.values():
            if acc.uuid == account_identifier:
                matches.append(acc)
                break
    else:
        # Name lookup - titles may not be unique
        for acc in db.accounts.values():
            if acc.title.lower() == account_identifier.lower():
                matches.append(acc)
    
    if not matches:
        identifier_type = "UUID" if by_uuid else "name"
        console.print(f"[red]Error: Account {identifier_type} '{account_identifier}' not found[/red]")
        raise typer.Exit(1)
    
    # Handle multiple matches - show details for selection (skip if by_uuid since that's unique)
    if len(matches) > 1 and not by_uuid:
        console.print(f"[yellow]Found {len(matches)} accounts with title '{account_identifier}':[/yellow]\n")
        
        # Display matches with details
        for i, acc in enumerate(matches, 1):
            # Get full item details for vault and fields
            try:
                result = subprocess.run(
                    ["op", "item", "get", acc.uuid, "--format", "json"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
                item_data = json.loads(result.stdout)
                vault = item_data.get("vault", {}).get("name", "Unknown")
                
                # Extract username, email, and website
                username = None
                email = None
                website = None
                for field in item_data.get("fields", []):
                    if field.get("id") == "username":
                        username = field.get("value")
                    elif field.get("type") == "EMAIL" or field.get("id") == "email":
                        email = field.get("value")
                
                # Get primary URL
                urls = item_data.get("urls", [])
                if urls:
                    website = urls[0].get("href", "")
                
                console.print(f"  [cyan]{i}.[/cyan] {acc.title}")
                console.print(f"      Vault: {vault}")
                if website:
                    console.print(f"      Website: {website}")
                if username:
                    console.print(f"      Username: {username}")
                if email:
                    console.print(f"      Email: {email}")
                console.print(f"      UUID: [dim]{acc.uuid}[/dim]\n")
                
            except (subprocess.CalledProcessError, json.JSONDecodeError):
                # Fallback if item fetch fails
                console.print(f"  [cyan]{i}.[/cyan] {acc.title}")
                console.print(f"      UUID: [dim]{acc.uuid}[/dim]\n")
        
        # Prompt for selection
        selection_input = typer.prompt("Select account number (or 'all' or comma-separated like '1,2,3')", default="all")
        
        # Parse selection
        selected_indices = []
        if selection_input.lower() == "all":
            selected_indices = list(range(len(matches)))
        else:
            try:
                # Parse comma-separated or single number
                parts = [p.strip() for p in selection_input.split(",")]
                for part in parts:
                    num = int(part)
                    if num < 1 or num > len(matches):
                        console.print(f"[red]Error: Invalid selection {num}[/red]")
                        raise typer.Exit(1)
                    selected_indices.append(num - 1)
            except ValueError:
                console.print("[red]Error: Invalid input. Use 'all' or numbers like '1' or '1,2,3'[/red]")
                raise typer.Exit(1)
        
        accounts_to_migrate = [matches[i] for i in selected_indices]
    else:
        accounts_to_migrate = [matches[0]]
    
    # Prompt for target YubiKeys (once for all accounts) unless already provided
    if target_serials is None:
        console.print("\n[cyan]Available YubiKeys:[/cyan]")
        connected = cache.list_connected_yubikeys()
        if not connected:
            console.print("[yellow]No YubiKeys currently connected[/yellow]")
            console.print("Connect YubiKeys and try again, or enter serial numbers manually.")
        else:
            for serial in connected:
                role = cache.serials[serial].role if serial in cache.serials else "Unknown"
                console.print(f"  {serial} ({role})")
        
        target_input = typer.prompt(
            "\nMigrate to which YubiKeys? (comma-separated serials or 'all')",
            default="all",
        )
        
        if target_input.lower() == "all":
            if not connected:
                console.print("[red]Error: No YubiKeys connected for 'all' option[/red]")
                raise typer.Exit(1)
            target_serials = connected
        else:
            target_serials = [s.strip() for s in target_input.split(",")]
    
    # Pre-load OATH passwords from 1Password (if not already loaded from bulk operation)
    if not passwords_by_serial:
        passwords_by_serial = {}
        for serial in target_serials:
            if serial in cache.serials and cache.serials[serial].op_uuid:
                op_uuid = cache.serials[serial].op_uuid
                password = get_yubikey_password_from_1password(op_uuid, op_client)
                if password:
                    passwords_by_serial[serial] = password
    
    # If no password provided, try to load from 1Password or prompt
    if oath_password is None:
        if passwords_by_serial:
            unique_passwords = set(passwords_by_serial.values())
            if len(unique_passwords) == 1:
                oath_password = list(unique_passwords)[0]
                console.print("[dim]✓ Loaded OATH password from 1Password[/dim]")
            else:
                console.print("[yellow]Target YubiKeys have different OATH passwords[/yellow]")
                oath_password = getpass.getpass("Enter YubiKey OATH password: ")
        else:
            oath_password = getpass.getpass("Enter YubiKey OATH password (or press Enter if none): ")
    
    # Process each selected account
    for account in accounts_to_migrate:
        console.print(f"\n[cyan]Migrating TOTP for: {account.title}[/cyan]\n")
        
        # Get full item details with TOTP
        try:
            result = subprocess.run(
                ["op", "item", "get", account.uuid, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            item_data = json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Error getting item from 1Password: {e.stderr}[/red]")
            continue  # Skip to next account
        except json.JSONDecodeError:
            console.print("[red]Error parsing 1Password response[/red]")
            continue  # Skip to next account
        
        # Extract TOTP secret, username, vault, and website for disambiguation
        totp_field = item_data.get("fields", [])
        totp_secret = None
        username = None
        vault_name = item_data.get("vault", {}).get("name", "")
        website = None
        
        for field in totp_field:
            if field.get("type") == "OTP":  # 1Password uses "OTP" type for TOTP fields
                totp_secret = field.get("value")  # The base32 secret
            elif field.get("id") == "username":
                username = field.get("value")
        
        # Get primary URL
        urls = item_data.get("urls", [])
        if urls:
            website = urls[0].get("href", "")
        
        if not totp_secret:
            console.print("[red]Error: No TOTP field found in 1Password item[/red]")
            console.print("[yellow]Hint: This account may not have TOTP configured[/yellow]")
            continue  # Skip to next account
        
        # Check if TOTP secret is actually a full otpauth:// URI (some services store it this way)
        if totp_secret.startswith("otpauth://"):
            try:
                from urllib.parse import parse_qs, urlparse
                parsed = urlparse(totp_secret)
                params = parse_qs(parsed.query)
                if 'secret' in params:
                    totp_secret = params['secret'][0]
                    console.print("[dim]  Extracted secret from otpauth:// URI[/dim]")
                else:
                    console.print("[red]Error: Could not extract secret from TOTP URI[/red]")
                    continue
            except Exception as e:
                console.print(f"[red]Error parsing TOTP URI: {e}[/red]")
                continue
        
        # Validate TOTP secret is valid base32
        import re
        totp_secret_clean = totp_secret.strip().replace(" ", "").replace("-", "").upper()
        if not re.match(r'^[A-Z2-7]+=*$', totp_secret_clean):
            console.print("[red]Error: Invalid TOTP secret format (not valid base32)[/red]")
            console.print(f"[dim]  Secret starts with: {totp_secret[:20]}...[/dim]")
            continue
        
        # Use cleaned secret
        totp_secret = totp_secret_clean
        
        # Use pre-provided title conflicts or find them now
        if conflicting_titles is None:
            title_conflicts = []
            for acc_id, acc in db.accounts.items():
                if acc.title == account.title and acc.uuid != account.uuid:
                    title_conflicts.append(acc)
        else:
            title_conflicts = conflicting_titles
        
        if title_conflicts:
            console.print(f"[yellow]⚠ Found {len(title_conflicts)} other account(s) with same title '{account.title}'[/yellow]")
        
        # Construct TOTP URI from secret
        # Format: otpauth://totp/Issuer:Account?secret=SECRET&issuer=Issuer
        issuer = account.title
        totp_account = username if username else "user"  # Use username or fallback to "user"
        totp_uri = f"otpauth://totp/{issuer}:{totp_account}?secret={totp_secret}&issuer={issuer}"
        
        # Check for existing redundancy tag
        has_multi_yubikey = "Bastion/Redundancy/Multi-YubiKey" in account.tag_list
        
        if has_multi_yubikey:
            console.print("[yellow]⚠ Account tagged for multi-YubiKey redundancy[/yellow]")
        
        # Migrate to each YubiKey sequentially
        completed_serials = []
        failed_serials = []
        
        # Use pre-scanned OATH accounts or scan now
        if existing_by_serial is not None:
            all_existing_accounts = []
            for accounts in existing_by_serial.values():
                all_existing_accounts.extend(accounts)
            all_existing_accounts = list(set(all_existing_accounts))
        else:
            # Fallback: scan now (for non-bulk operations)
            console.print("\n[cyan]Scanning YubiKeys for existing accounts...[/cyan]")
            all_existing_accounts = []
            for serial in target_serials:
                try:
                    check_result = subprocess.run(
                        ["ykman", "--device", serial, "oath", "accounts", "list"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        input=f"{oath_password}\n".encode(),
                        timeout=30,
                        check=False,
                    )
                    if check_result.returncode == 0:
                        accounts = [line.strip() for line in check_result.stdout.decode().strip().split('\n') if line.strip()]
                        all_existing_accounts.extend(accounts)
                except (subprocess.TimeoutExpired, Exception):
                    pass  # Skip if can't read this YubiKey
            all_existing_accounts = list(set(all_existing_accounts))
        
        # Exclude any existing account that belongs to this UUID (from cache)
        # This ensures idempotent migrations - we don't conflict with ourselves
        accounts_to_exclude = set()
        for serial in target_serials:
            if serial in cache.serials:
                for acc in cache.serials[serial].accounts:
                    if isinstance(acc, dict) and acc.get("op_uuid") == account.uuid:
                        accounts_to_exclude.add(acc.get("oath_name"))
        
        all_existing_accounts = [name for name in all_existing_accounts if name not in accounts_to_exclude]
        
        # Build potential conflicts list from title conflicts
        potential_conflicts = set(all_existing_accounts)
        
        if title_conflicts:
            console.print(f"[cyan]Fetching usernames from {len(title_conflicts)} conflicting account(s)...[/cyan]")
            for conflict_acc in title_conflicts:
                try:
                    conflict_result = subprocess.run(
                        ["op", "item", "get", conflict_acc.uuid, "--format", "json"],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=30,
                    )
                    conflict_data = json.loads(conflict_result.stdout)
                    conflict_username = None
                    for field in conflict_data.get("fields", []):
                        if field.get("id") == "username":
                            conflict_username = field.get("value")
                            break
                    
                    # Generate simple OATH name for this conflict
                    conflict_oath_name = f"{conflict_acc.title}:{conflict_username if conflict_username else 'user'}"
                    potential_conflicts.add(conflict_oath_name)
                    
                except (subprocess.CalledProcessError, json.JSONDecodeError):
                    # Skip conflicts that can't be fetched
                    console.print(f"[dim]  Could not fetch details for conflicting account {conflict_acc.uuid}[/dim]")
        
        # Convert to list for name generation
        all_potential_names = list(potential_conflicts)
        
        # Generate unique OATH name with progressive disambiguation (same for all YubiKeys)
        issuer_unique, account_unique = generate_unique_oath_name(
            title=account.title,
            username=username,
            vault=vault_name,
            website=website,
            uuid=account.uuid,
            existing_names=all_potential_names,
        )
        new_oath_name = f"{issuer_unique}:{account_unique}"
        
        # Build TOTP URI with unique name
        totp_uri = f"otpauth://totp/{urllib.parse.quote(issuer_unique)}:{urllib.parse.quote(account_unique)}?secret={totp_secret}&issuer={urllib.parse.quote(issuer_unique)}"
        
        console.print(f"\n[cyan]Migrating TOTP: {new_oath_name}[/cyan]\n")
        
        # Check which YubiKeys are currently connected
        connected_yubikeys = cache.list_connected_yubikeys()
        
        # Filter to only connected YubiKeys
        available_serials = [s for s in target_serials if s in connected_yubikeys]
        skipped_serials = [s for s in target_serials if s not in connected_yubikeys]
        
        if skipped_serials:
            console.print(f"[dim]⊘ Skipping {len(skipped_serials)} YubiKey(s) not currently connected: {', '.join(skipped_serials)}[/dim]")
        
        if not available_serials:
            console.print(f"[yellow]⚠ No target YubiKeys are currently connected. Skipping '{account.title}'.[/yellow]")
            return
        
        console.print(f"[green]✓ Processing {len(available_serials)} connected YubiKey(s): {', '.join(available_serials)}[/green]\n")
        
        for serial in available_serials:
            console.print(f"[cyan]→ YubiKey {serial}...[/cyan]", end=" ")
            
            try:
                # Get existing OATH accounts on this YubiKey
                existing_accounts = []
                check_result = subprocess.run(
                    ["ykman", "--device", serial, "oath", "accounts", "list"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    input=f"{oath_password}\n".encode(),
                    timeout=30,
                    check=False,
                )
                if check_result.returncode == 0:
                    existing_accounts = [line.strip() for line in check_result.stdout.decode().strip().split('\n') if line.strip()]
                
                # Single source of truth: Get all OATH names from 1Password Token sections
                old_oath_names = []
                try:
                    field_result = subprocess.run(
                        ["op", "item", "get", account.uuid, "--format", "json"],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=30,
                    )
                    field_data = json.loads(field_result.stdout)
                    old_oath_names = get_all_oath_names_from_tokens(field_data)
                    
                    if old_oath_names:
                        if len(old_oath_names) > 1:
                            console.print(f"[yellow]⚠ Found {len(old_oath_names)} existing OATH entries in 1Password[/yellow]")
                        if new_oath_name not in old_oath_names:
                            console.print(f"[yellow]Updating OATH name: {old_oath_names[0]} → {new_oath_name}[/yellow]")
                except (subprocess.CalledProcessError, json.JSONDecodeError):
                    pass  # No Token sections or fetch failed
                
                # Delete all old OATH accounts from YubiKey
                password_to_use = passwords_by_serial.get(serial) if passwords_by_serial else oath_password
                for old_name in old_oath_names:
                    if old_name in existing_accounts:  # Verify it actually exists on YubiKey
                        console.print(f"[dim]  Removing existing: {old_name}[/dim]")
                        subprocess.run(
                            ["ykman", "--device", serial, "oath", "accounts", "delete", old_name, "--force"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            input=f"{password_to_use}\n".encode(),
                            timeout=30,
                            check=True,
                        )
                
                # Add TOTP account to YubiKey with touch policy
                # ykman oath accounts uri expects just the URI with --touch option
                # Use per-serial password or fallback to shared password
                password_to_use = passwords_by_serial.get(serial) if passwords_by_serial else oath_password
                result = subprocess.run(
                    [
                        "ykman",
                        "--device", serial,
                        "oath", "accounts", "uri",
                        totp_uri,
                        "--touch",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    input=f"{password_to_use}\n".encode(),
                    timeout=30,
                    check=True,
                )
                
                console.print("[green]✓ Added[/green]")
                completed_serials.append(serial)
                
            except subprocess.CalledProcessError as e:
                error_msg = e.stderr.decode() if isinstance(e.stderr, bytes) else str(e.stderr)
                console.print(f"[red]✗ Failed: {error_msg.strip()[:80]}[/red]")
                failed_serials.append(serial)
            except subprocess.TimeoutExpired:
                console.print("[red]✗ Timeout[/red]")
                failed_serials.append(serial)
        
        # Determine migration status
        if failed_serials and completed_serials:
            status = "partial"
        elif failed_serials:
            status = "failed"
        else:
            status = "complete"
        
        # Update 1Password custom fields if any succeeded
        if completed_serials:
            console.print("\n[cyan]Updating 1Password custom fields...[/cyan]")
            
            # Get existing item data to check for existing serials
            existing_serials = []
            try:
                field_result = subprocess.run(
                    ["op", "item", "get", account.uuid, "--format", "json"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
                field_data = json.loads(field_result.stdout)
                
                # Try to read existing serials from either format
                existing_value = get_yubikey_field(field_data, "serials", "YubiKey TOTP")
                if existing_value:
                    existing_serials = [s.strip() for s in existing_value.split(",")]
            except (subprocess.CalledProcessError, json.JSONDecodeError):
                pass  # Field doesn't exist or fetch failed
            
            # Merge existing with new completed serials (deduplicate)
            all_serials = list(set(existing_serials + completed_serials))
            
            # Build edit fields for new Token section format (individual sections per token)
            edit_fields = []
            
            # Get account vault for cross-vault check
            account_vault_id = None
            try:
                account_details = subprocess.run(
                    ["op", "item", "get", account.uuid, "--format", "json"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
                account_data = json.loads(account_details.stdout)
                account_vault_id = account_data.get("vault", {}).get("id")
            except (subprocess.CalledProcessError, json.JSONDecodeError):
                pass  # Will skip REFERENCE fields if can't determine vault
            
            # Add individual Token sections (Token 1, Token 2, ...)
            # All tokens are YubiKey type with shared OATH Name
            for i, serial in enumerate(sorted(all_serials), start=1):
                section_name = f"Token {i}"
                edit_fields.extend([
                    f"{section_name}.Serial[text]={serial}",
                    f"{section_name}.Type[text]=YubiKey",
                    f"{section_name}.OATH Name[text]={new_oath_name}",
                    f"{section_name}.TOTP Enabled[text]=yes",
                    f"{section_name}.PassKey Enabled[text]=",
                ])
                
                # Note: Reference fields cannot be created via CLI, must be added manually in 1Password UI
                # if serial in cache.serials and cache.serials[serial].op_uuid:
                #     yubikey_uuid = cache.serials[serial].op_uuid
                #     console.print(f"[dim]  Tip: Add YubiKey Item reference manually in 1Password UI: {yubikey_uuid}[/dim]")
            
            try:
                result = subprocess.run(
                    ["op", "item", "edit", account.uuid] + edit_fields,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
                console.print(f"[green]✓ Saved OATH Name: {new_oath_name}[/green]")
                console.print(f"[green]✓ Created {len(all_serials)} token sections (Type: YubiKey)[/green]")
                
                # Create bidirectional links to YubiKey items
                from bastion.linking import ItemLinker
                linker = ItemLinker()
                for serial in all_serials:
                    if serial in cache.serials and cache.serials[serial].op_uuid:
                        yubikey_uuid = cache.serials[serial].op_uuid
                        try:
                            linker.create_link(account.uuid, yubikey_uuid, bidirectional=True)
                            console.print(f"[green]✓ Linked to YubiKey {serial}[/green]")
                        except ValueError as e:
                            # Cross-vault or other validation error
                            console.print(f"[yellow]⚠ Could not link to YubiKey {serial}: {e}[/yellow]")
                        except Exception as e:
                            console.print(f"[yellow]⚠ Unexpected error linking to YubiKey {serial}: {e}[/yellow]")
            except subprocess.CalledProcessError as e:
                stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else str(e.stderr)
                console.print("[red]✗ Failed to save Token sections:[/red]")
                console.print(f"[dim]{stderr.strip()}[/dim]")
                console.print(f"[yellow]Edit fields attempted: {edit_fields[:3]}...[/yellow]")
        
        # Prompt to remove TOTP from 1Password if full migration
        if status == "complete":
            console.print("\n[cyan]TOTP successfully migrated to YubiKey(s)[/cyan]")
            
            # Update tags
            tag_ops = TagOperations(op_client)
            
            # Remove Phone-App tag if exists
            if "Bastion/2FA/TOTP/Phone-App" in account.tag_list:
                tag_ops.remove_tag(account, "Bastion/2FA/TOTP/Phone-App")
            
            # Add YubiKey tag
            if "Bastion/2FA/TOTP/YubiKey" not in account.tag_list:
                tag_ops.add_tag(account, "Bastion/2FA/TOTP/YubiKey")
            
            console.print("[green]✓ Updated tags[/green]")
    
    # Clear password from memory
    if 'oath_password' in locals():
        del oath_password


def yubikey_sync_workflow(
    db_manager: "DatabaseManager",
    cache: "YubiKeyCache",
    force_refresh: bool = False,
) -> None:
    """Run the complete YubiKey sync workflow.
    
    Steps:
      1. Checks cache staleness (refreshes if > 1 day old or force_refresh)
      2. Links all connected YubiKeys to 1Password
      3. Updates YubiKey Note items with OATH slot sections
    
    Args:
        db_manager: Database manager instance
        cache: YubiKey cache instance
        force_refresh: Force cache refresh even if recent
    """
    from datetime import datetime, timedelta, timezone
    from bastion.op_client import OpClient
    
    console.print("[bold cyan]YubiKey Sync Workflow[/bold cyan]")
    console.print("=" * 50)
    
    # Step 1: Check cache staleness and refresh if needed
    should_refresh = force_refresh
    
    # Check staleness based on metadata (works for both encrypted and file storage)
    if not should_refresh:
        updated_at = cache.metadata.get("updated_at")
        if updated_at:
            try:
                # Parse ISO format with timezone awareness
                if updated_at.endswith("Z"):
                    updated_at = updated_at[:-1] + "+00:00"
                cache_time = datetime.fromisoformat(updated_at)
                if cache_time.tzinfo is None:
                    cache_time = cache_time.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                cache_age = now - cache_time
                if cache_age > timedelta(days=1):
                    console.print(f"[yellow]Cache is {cache_age.days} day(s) old, refreshing...[/yellow]")
                    should_refresh = True
                else:
                    console.print(f"[green]✓ Cache is recent ({cache_age.seconds // 3600} hours old)[/green]")
            except (ValueError, TypeError):
                console.print("[yellow]Could not parse cache age, refreshing...[/yellow]")
                should_refresh = True
        else:
            console.print("[yellow]Cache metadata missing, refreshing...[/yellow]")
            should_refresh = True
    
    if should_refresh:
        console.print("\n[cyan]Step 1/4: Refreshing YubiKey cache...[/cyan]")
        op_client = OpClient()
        yubikey_refresh_cache(cache, op_client)
    else:
        console.print("\n[dim]Step 1/4: Skipping refresh (use --force-refresh to override)[/dim]")
    
    # Step 2: Link all YubiKeys to 1Password
    console.print("\n[cyan]Step 2/4: Linking YubiKeys to 1Password...[/cyan]")
    unlinked_serials = [s for s in cache.serials.keys() if not cache.serials[s].op_uuid]
    if unlinked_serials:
        for serial in unlinked_serials:
            try:
                yubikey_link_single(serial, cache, db_manager)
            except Exception as e:
                console.print(f"[yellow]⚠ Could not link YubiKey {serial}: {e}[/yellow]")
    else:
        console.print("[green]✓ All YubiKeys already linked[/green]")
    
    # Step 3: Update YubiKey Note items
    console.print("\n[cyan]Step 3/4: Updating YubiKey Note items...[/cyan]")
    serials = list(cache.serials.keys())
    if serials:
        update_yubikey_items(serials, cache)
    else:
        console.print("[yellow]No YubiKeys found in cache[/yellow]")
    
    # Step 4: Inform about TOTP migration
    console.print("\n[cyan]Step 4/4: Processing TOTP migrations...[/cyan]")
    console.print("[dim]To complete TOTP migration, run:[/dim]")
    console.print("[bold]  bastion add totp bulk --all[/bold]")
    
    console.print("\n[bold green]✓ YubiKey sync workflow complete![/bold green]")
    console.print("=" * 50)


def sync_yubikey_accounts(
    source: str | None,
    target: str | None,
    db_manager: "DatabaseManager",
) -> None:
    """Sync OATH accounts from one YubiKey to others.
    
    Args:
        source: Source YubiKey serial number
        target: Target YubiKey serial(s) or 'all'
        db_manager: Database manager instance
    """
    import getpass
    from bastion.op_client import OpClient
    
    if not source:
        console.print("[red]Error:[/red] --from SERIAL is required")
        raise typer.Exit(1)
    
    cache = get_yubikey_cache()
    
    # Verify source YubiKey exists in cache
    if source not in cache.serials:
        console.print(f"[red]Error:[/red] Source YubiKey {source} not found in cache")
        console.print("Run 'bastion refresh yubikey' to update cache")
        raise typer.Exit(1)
    
    # Get all accounts from source YubiKey
    source_accounts = cache.serials[source].accounts
    if not source_accounts:
        console.print(f"[yellow]No accounts found on source YubiKey {source}[/yellow]")
        raise typer.Exit(0)
    
    # Extract 1Password UUIDs from source accounts
    account_uuids = []
    for acc in source_accounts:
        if isinstance(acc, dict) and acc.get("op_uuid"):
            account_uuids.append(acc.get("op_uuid"))
    
    if not account_uuids:
        console.print(f"[yellow]No 1Password linked accounts found on YubiKey {source}[/yellow]")
        console.print("Accounts must be migrated with this tool to have 1Password links")
        raise typer.Exit(1)
    
    console.print(f"[cyan]Found {len(account_uuids)} accounts on source YubiKey {source}[/cyan]")
    
    # Determine target YubiKeys
    if not target:
        available = [s for s in cache.serials.keys() if s != source]
        if not available:
            console.print("[yellow]No other YubiKeys found in cache[/yellow]")
            raise typer.Exit(1)
        console.print("\nAvailable target YubiKeys:")
        for s in available:
            role = cache.serials[s].role
            count = len(cache.serials[s].accounts)
            console.print(f"  {s} ({role}) - {count} accounts")
        target_input = typer.prompt("\nSync to which YubiKeys? (comma-separated serials or 'all')", default="all")
        if target_input == "all":
            target_serials = available
        else:
            target_serials = [s.strip() for s in target_input.split(",")]
    elif target == "all":
        target_serials = [s for s in cache.serials.keys() if s != source]
        if not target_serials:
            console.print("[yellow]No other YubiKeys found in cache besides source[/yellow]")
            raise typer.Exit(1)
    else:
        target_serials = [target]
    
    if not target_serials:
        console.print("[yellow]No target YubiKeys specified[/yellow]")
        raise typer.Exit(1)
    
    console.print(f"\n[cyan]Will sync {len(account_uuids)} accounts to {len(target_serials)} YubiKey(s)[/cyan]")
    for s in target_serials:
        role = cache.serials.get(s, type('obj', (), {'role': 'Unknown'})).role
        console.print(f"  → {s} ({role})")
    
    proceed = typer.confirm("\nProceed with sync?", default=True)
    if not proceed:
        raise typer.Exit(0)
    
    db = db_manager.load()
    
    console.print("\n[cyan]Starting sync...[/cyan]\n")
    success_count = 0
    seen_uuids = set()
    
    accounts_to_migrate = []
    for uuid in account_uuids:
        if uuid in seen_uuids:
            continue
        seen_uuids.add(uuid)
        
        account = None
        for acc in db.accounts.values():
            if acc.uuid == uuid:
                account = acc
                break
        
        if account:
            accounts_to_migrate.append(account)
        else:
            console.print(f"[yellow]⚠ Account UUID {uuid[:8]}... not found in database, skipping[/yellow]")
    
    console.print(f"Will migrate {len(accounts_to_migrate)} unique accounts\n")
    
    op_client = OpClient()
    passwords_by_serial = {}
    unlinked_serials = []
    
    for serial in target_serials:
        console.print(f"[dim]Checking YubiKey {serial} for password in 1Password...[/dim]")
        if serial in cache.serials and cache.serials[serial].op_uuid:
            op_uuid = cache.serials[serial].op_uuid
            console.print(f"[dim]  Found 1Password UUID: {op_uuid}[/dim]")
            password = get_yubikey_password_from_1password(op_uuid, op_client)
            if password:
                passwords_by_serial[serial] = password
                console.print(f"[green]✓ Loaded OATH password from 1Password for YubiKey {serial}[/green]")
            else:
                console.print(f"[yellow]⚠ No password found in 1Password for YubiKey {serial}[/yellow]")
        else:
            unlinked_serials.append(serial)
            console.print(f"[yellow]⚠ YubiKey {serial} not linked to 1Password vault[/yellow]")
    
    if unlinked_serials:
        console.print(f"\n[yellow]Warning: {len(unlinked_serials)} YubiKey(s) not linked to 1Password:[/yellow]")
        for serial in unlinked_serials:
            console.print(f"  • {serial}")
        console.print("\n[cyan]To link these YubiKeys and store passwords in 1Password:[/cyan]")
        console.print("  1. Run: [bold]bastion link yubikey --serial <SERIAL>[/bold]")
        console.print("  2. Or run: [bold]bastion link yubikey --all[/bold] to link all connected YubiKeys")
        console.print("\n[dim]Linking allows automatic password retrieval for future migrations.[/dim]\n")
        
        should_link = typer.confirm("Would you like to continue with manual password entry?", default=True)
        if not should_link:
            console.print("[yellow]Aborting sync. Run 'bastion link yubikey --all' first to link YubiKeys.[/yellow]")
            raise typer.Exit(1)
        console.print()
    
    oath_password = None
    if passwords_by_serial:
        unique_passwords = set(passwords_by_serial.values())
        if len(unique_passwords) == 1:
            oath_password = list(unique_passwords)[0]
            console.print("[green]✓ All target YubiKeys use the same OATH password (auto-loaded from 1Password)[/green]\n")
        else:
            console.print("[yellow]Target YubiKeys have different OATH passwords stored in 1Password[/yellow]")
            console.print("[yellow]Will use stored passwords per YubiKey[/yellow]\n")
    else:
        console.print("[yellow]No OATH passwords found in 1Password for target YubiKeys[/yellow]")
        oath_password = getpass.getpass("Enter YubiKey OATH password (or press Enter if none): ")
        print()
    
    for account in accounts_to_migrate:
        console.print(f"[cyan]Syncing: {account.title}[/cyan]")
        try:
            yubikey_migrate(account.uuid, db_manager, cache, target_serials, by_uuid=True, 
                           passwords_by_serial=passwords_by_serial, oath_password=oath_password)
            console.print(f"[green]✓ {account.title}[/green]")
            success_count += 1
        except Exception as e:
            console.print(f"[red]✗ {account.title}: {str(e)[:100]}[/red]")
    
    console.print(f"\n[green]Sync complete: {success_count}/{len(account_uuids)} accounts synced[/green]")
    
    # Update YubiKey Note items
    console.print("\n[cyan]Updating YubiKey Note items with OATH slot sections...[/cyan]")
    db = db_manager.load()
    
    for serial in target_serials:
        console.print(f"[dim]  Checking YubiKey {serial}...[/dim]")
        
        yubikey_item = None
        for acc in db.accounts.values():
            if acc.category == "SECURE_NOTE" and f"YK-{serial}" in acc.title:
                yubikey_item = acc
                break
        
        if not yubikey_item:
            console.print(f"[yellow]  YubiKey Note item not found for serial {serial}[/yellow]")
            continue
        
        try:
            password = passwords_by_serial.get(serial, oath_password) if passwords_by_serial else oath_password
            list_result = subprocess.run(
                ["ykman", "--device", serial, "oath", "accounts", "list"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                input=f"{password}\n".encode() if password else b"",
                timeout=30,
                check=False,
            )
            
            if list_result.returncode != 0:
                console.print(f"[yellow]  Could not list OATH accounts on YubiKey {serial}[/yellow]")
                continue
            
            oath_names = [line.strip() for line in list_result.stdout.decode().strip().split('\n') if line.strip()]
            console.print(f"[dim]    Found {len(oath_names)} OATH accounts on hardware[/dim]")
            
            if not oath_names:
                console.print(f"[dim]  No OATH accounts on YubiKey {serial}[/dim]")
                continue
            
            oath_to_title = {}
            for acc in db.accounts.values():
                if acc.category == "LOGIN":
                    acc_data = subprocess.run(
                        ["op", "item", "get", acc.uuid, "--format", "json"],
                        capture_output=True, text=True, check=False, timeout=10,
                    )
                    if acc_data.returncode == 0:
                        try:
                            item_data = json.loads(acc_data.stdout)
                            for field in item_data.get("fields", []):
                                section = field.get("section", {})
                                section_label = section.get("label", "")
                                if section_label.startswith("Token "):
                                    for f2 in item_data.get("fields", []):
                                        if (f2.get("section", {}).get("label") == section_label and
                                            f2.get("label") == "Serial" and f2.get("value") == serial):
                                            for f3 in item_data.get("fields", []):
                                                if (f3.get("section", {}).get("label") == section_label and
                                                    f3.get("label") == "OATH Name"):
                                                    oath_name = f3.get("value", "")
                                                    if oath_name:
                                                        oath_to_title[oath_name] = acc.title
                                            break
                        except json.JSONDecodeError:
                            pass
            
            try:
                result = subprocess.run(
                    ["op", "item", "get", yubikey_item.uuid, "--format", "json"],
                    capture_output=True, text=True, check=True, timeout=30,
                )
                item_data = json.loads(result.stdout)
                
                item_data["fields"] = [f for f in item_data.get("fields", []) 
                                      if f.get("label") != "oath_accounts"]
                item_data["sections"] = [s for s in item_data.get("sections", [])
                                        if not s.get("label", "").startswith("OATH Slot ")]
                
                if "sections" not in item_data:
                    item_data["sections"] = []
                
                sorted_oath_names = sorted(oath_names)
                
                for i, oath_name in enumerate(sorted_oath_names, start=1):
                    section_id = f"oath_slot_{i}"
                    section_label = f"OATH Slot {i}"
                    
                    item_data["sections"].append({"id": section_id, "label": section_label})
                    item_data["fields"].extend([
                        {"section": {"id": section_id, "label": section_label},
                         "type": "STRING", "label": "OATH Name", "value": oath_name},
                        {"section": {"id": section_id, "label": section_label},
                         "type": "STRING", "label": "Account Title", "value": oath_to_title.get(oath_name, "Unknown")}
                    ])
                
                subprocess.run(
                    ["op", "item", "edit", yubikey_item.uuid, "-"],
                    input=json.dumps(item_data), capture_output=True, text=True, check=True, timeout=30,
                )
                console.print(f"[green]✓ Updated YubiKey {serial} with {len(sorted_oath_names)} OATH slot sections[/green]")
                
            except subprocess.CalledProcessError as e:
                error_detail = e.stderr if e.stderr else "Unknown error"
                console.print(f"[yellow]⚠ Could not update YubiKey {serial}: {error_detail.strip()[:100]}[/yellow]")
            except json.JSONDecodeError as e:
                console.print(f"[yellow]⚠ JSON parse error for YubiKey {serial}: {e}[/yellow]")
                
        except subprocess.TimeoutExpired:
            console.print(f"[yellow]  Timeout querying YubiKey {serial}[/yellow]")
        except Exception as e:
            console.print(f"[yellow]  Error with YubiKey {serial}: {e}[/yellow]")


def link_yubikey_with_uuid(
    serial: str,
    op_uuid: str | None,
    cache: "YubiKeyCache",
) -> None:
    """Link a YubiKey serial to a 1Password UUID.
    
    If op_uuid is not provided, checks if serial already has a UUID in cache
    and reports status.
    
    Args:
        serial: YubiKey serial number
        op_uuid: 1Password item UUID (optional)
        cache: YubiKeyCache instance
    """
    import typer
    from datetime import datetime, timezone
    from bastion.yubikey_cache import YubiKeySerialInfo
    
    # If no UUID provided, check if serial already has op_uuid in cache
    if not op_uuid and serial in cache.serials and cache.serials[serial].op_uuid:
        op_uuid = cache.serials[serial].op_uuid
        console.print(f"[green]✓ Found existing link in cache: {op_uuid}[/green]")
    
    # If still no UUID, report what we found
    if not op_uuid:
        console.print(f"[cyan]Searching cache for YubiKey serial '{serial}'...[/cyan]")
        if serial in cache.serials:
            console.print(f"[yellow]YubiKey {serial} found in cache but not linked to 1Password item[/yellow]")
            console.print("[yellow]Please provide the 1Password UUID to establish the link:[/yellow]")
            console.print("  bastion link yubikey SERIAL UUID")
            raise typer.Exit(1)
        else:
            console.print(f"[yellow]YubiKey {serial} not found in cache[/yellow]")
            console.print("[yellow]Please provide the 1Password UUID:[/yellow]")
            console.print("  bastion link yubikey SERIAL UUID")
            raise typer.Exit(1)
    
    # Ensure serial exists in cache, create if not
    if serial not in cache.serials:
        console.print(f"[yellow]YubiKey {serial} not in cache, adding...[/yellow]")
        cache.serials[serial] = YubiKeySerialInfo(
            serial=serial,
            role="Unknown",
            accounts=[],
            last_updated=datetime.now(timezone.utc),
            op_uuid=op_uuid,
        )
    else:
        # Update existing entry
        cache.serials[serial].op_uuid = op_uuid
    
    cache.save()
    
    console.print(f"[green]✓ Linked YubiKey {serial} to 1Password UUID {op_uuid}[/green]")
    console.print("[cyan]OATH passwords will now be auto-loaded from 1Password during migration[/cyan]")
