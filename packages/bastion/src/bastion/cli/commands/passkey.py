"""Passkey health CLI commands.

Utilities for detecting and managing orphaned passkeys caused by the
1Password CLI bug where JSON editing deletes passkey private keys.

See: bastion/support/1PASSWORD-CLI-PASSKEY-BUG.md
"""

from __future__ import annotations

import json
import time
from typing import Annotated

import typer

from ..console import console
from ...op_client import OpClient
from ...passkey_health import (
    get_clipboard_json,
    get_item_info_from_export,
    get_passkey_status,
)


# Tag applied to items with orphaned passkeys
ORPHANED_PASSKEY_TAG = "Bastion/Problem/Passkey/Orphaned"

# Tag for items verified as healthy (skip in future audits)
VERIFIED_PASSKEY_TAG = "Bastion/Verified/Passkey/Healthy"

# Tag that identifies items with software passkeys (at risk of CLI bug)
SOFTWARE_PASSKEY_TAG = "Bastion/2FA/Passkey/Software"


app = typer.Typer(
    name="passkey",
    help="Passkey health detection and cleanup utilities",
)


@app.command("check")
def check_clipboard(
    tag_if_orphaned: Annotated[
        bool,
        typer.Option("--tag", help=f"Apply '{ORPHANED_PASSKEY_TAG}' tag if orphaned"),
    ] = False,
    mark_verified: Annotated[
        bool,
        typer.Option("--verify", help=f"Apply '{VERIFIED_PASSKEY_TAG}' tag if healthy"),
    ] = False,
) -> None:
    """Check passkey health from clipboard JSON.

    Copy an item's JSON from 1Password desktop app (right-click → Copy as JSON),
    then run this command to check if the passkey is healthy or orphaned.

    Use --tag to automatically apply the orphaned tag for tracking.
    Use --verify to mark healthy passkeys (skipped in future audits).
    """
    export_json = get_clipboard_json()

    if not export_json:
        console.print("[red]✗ No valid JSON found in clipboard[/red]")
        console.print()
        console.print("[dim]To check a passkey:[/dim]")
        console.print("  1. Open 1Password desktop app")
        console.print("  2. Select the item with the passkey")
        console.print("  3. Right-click → Copy as JSON")
        console.print("  4. Run this command again")
        raise typer.Exit(1)

    info = get_item_info_from_export(export_json)
    status = get_passkey_status(export_json)

    console.print(f"[bold]{info['title']}[/bold]", end="")
    if info["url"]:
        console.print(f" [dim]({info['url']})[/dim]")
    else:
        console.print()

    if info["uuid"]:
        console.print(f"[dim]UUID: {info['uuid']}[/dim]")

    console.print()

    if status == "healthy":
        console.print("[green]✓ Passkey is healthy[/green]")
        console.print("[dim]  Both public metadata and private key are present[/dim]")
        
        # Mark as verified if requested
        if mark_verified and info["uuid"]:
            _apply_tag(info["uuid"], info["title"], VERIFIED_PASSKEY_TAG)
            
    elif status == "orphaned":
        console.print("[red]✗ Passkey is ORPHANED[/red]")
        console.print("[yellow]  Public metadata exists but private key was deleted[/yellow]")
        
        # Apply tag if requested
        if tag_if_orphaned and info["uuid"]:
            _apply_tag(info["uuid"], info["title"], ORPHANED_PASSKEY_TAG)
        
        console.print()
        console.print("[dim]This passkey cannot be used for authentication.[/dim]")
        console.print("[dim]You'll need to delete it and re-register with the service.[/dim]")
        raise typer.Exit(1)
    else:
        console.print("[dim]○ No passkey on this item[/dim]")


@app.command("audit")
def audit_passkeys(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show what would be done without making changes"),
    ] = False,
    include_verified: Annotated[
        bool,
        typer.Option("--include-verified", help="Include items already marked as verified"),
    ] = False,
    auto_open: Annotated[
        bool,
        typer.Option("--auto", help="Auto-open items in 1Password (macOS only)"),
    ] = False,
) -> None:
    """Audit all software passkeys via clipboard workflow.

    Lists items tagged with 'Bastion/2FA/Passkey/Software' and guides you
    through checking each one by copying JSON from the 1Password UI.

    For each item:
    1. Prompts you to copy the item's JSON from 1Password
    2. Reads clipboard and checks passkey health
    3. If orphaned, applies 'Bastion/Problem/Passkey/Orphaned' tag
    4. If healthy, applies 'Bastion/Verified/Passkey/Healthy' tag

    Items already tagged as verified are skipped unless --include-verified is used.
    Use --dry-run to preview without applying tags.
    Use --auto to automatically open each item in 1Password (macOS only).
    """
    # Check for macOS automation if --auto requested
    if auto_open:
        from ...macos_automation import is_macos, is_1password_running
        
        if not is_macos():
            console.print("[red]Error:[/red] --auto flag requires macOS")
            raise typer.Exit(1)
        
        if not is_1password_running():
            console.print("[red]Error:[/red] 1Password is not running. Please open 1Password first.")
            raise typer.Exit(1)
        
        console.print("[cyan]Auto-open mode enabled - items will open in 1Password automatically[/cyan]")
        console.print()

    try:
        op = OpClient()
    except RuntimeError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    # Get items with software passkey tag
    items = op.list_items_by_tag(SOFTWARE_PASSKEY_TAG)
    
    if not items:
        console.print(f"[dim]No items found with tag '{SOFTWARE_PASSKEY_TAG}'[/dim]")
        return

    # Filter out already verified items unless requested
    if not include_verified:
        original_count = len(items)
        items = [
            item for item in items
            if VERIFIED_PASSKEY_TAG not in item.get("tags", [])
            and ORPHANED_PASSKEY_TAG not in item.get("tags", [])
        ]
        skipped_verified = original_count - len(items)
        if skipped_verified > 0:
            console.print(f"[dim]Skipping {skipped_verified} already verified/tagged item(s)[/dim]")
            console.print()

    if not items:
        console.print("[green]✓ All software passkey items have been audited[/green]")
        return

    console.print(f"[cyan]Found {len(items)} item(s) to audit[/cyan]")
    console.print()

    # Track results
    healthy: list[str] = []
    orphaned: list[str] = []
    skipped: list[str] = []
    no_passkey: list[str] = []

    for i, item in enumerate(items, 1):
        title = item.get("title", "Unknown")
        uuid = item.get("id", "")
        vault_id = item.get("vault", {}).get("id")
        
        console.print(f"[bold][{i}/{len(items)}] {title}[/bold]")
        console.print(f"[dim]UUID: {uuid}[/dim]")
        console.print()
        
        # Auto-open in 1Password if requested
        if auto_open:
            from ...macos_automation import (
                open_item_and_prompt,
                ring_bell,
                get_clipboard_content,
                wait_for_clipboard_change,
                activate_terminal,
            )
            
            # Get current clipboard before opening item
            original_clipboard = get_clipboard_content()
            
            console.print("[yellow]→ Opening in 1Password...[/yellow]")
            if not open_item_and_prompt(uuid, vault_id):
                console.print("[yellow]→ Could not auto-open. Please find the item manually.[/yellow]")
            
            console.print("[cyan]→ Waiting for JSON copy (right-click → Copy as JSON)...[/cyan]")
            
            # Keep waiting until we get valid JSON with matching UUID
            export_json = None
            last_clipboard = original_clipboard
            
            while export_json is None:
                # Wait for clipboard to change
                new_content = wait_for_clipboard_change(last_clipboard, timeout=120.0, check_interval=0.3)
                
                if new_content is None:
                    console.print("[red]✗ Timeout waiting for clipboard[/red]")
                    skipped.append(title)
                    break
                
                last_clipboard = new_content
                
                # Try to parse as JSON
                try:
                    parsed = json.loads(new_content)
                except json.JSONDecodeError:
                    console.print("[dim]  (not JSON, still waiting...)[/dim]")
                    continue
                
                # Verify UUID matches
                clipboard_uuid = parsed.get("uuid", "")
                if clipboard_uuid and clipboard_uuid != uuid:
                    console.print(f"[yellow]  Wrong item ({clipboard_uuid[:8]}...), waiting for {uuid[:8]}...[/yellow]")
                    continue
                
                # Success!
                export_json = parsed
            
            if export_json is None:
                # Timed out - already added to skipped
                console.print()
                continue
            
            # Success! Bring focus back to terminal
            ring_bell()
            activate_terminal()
            console.print("[green]✓ JSON captured[/green]")
            
        else:
            # Manual mode - prompt user
            console.print("[yellow]→ Copy this item's JSON from 1Password UI[/yellow]")
            console.print("[dim]  (Right-click item → Copy as JSON)[/dim]")
            console.print()
            
            proceed = typer.confirm("Ready? (JSON copied to clipboard)", default=True)
            
            if not proceed:
                console.print("[dim]Skipped[/dim]")
                skipped.append(title)
                console.print()
                continue
            
            # Read clipboard
            export_json = get_clipboard_json()
            
            if not export_json:
                console.print("[red]✗ No valid JSON in clipboard[/red]")
                skipped.append(title)
                console.print()
                continue
            
            # Verify UUID matches (safety check)
            clipboard_uuid = export_json.get("uuid", "")
            if clipboard_uuid and clipboard_uuid != uuid:
                console.print(f"[red]✗ UUID mismatch! Expected {uuid}, got {clipboard_uuid}[/red]")
                console.print("[dim]Make sure you copied the correct item[/dim]")
                skipped.append(title)
                console.print()
                continue
        
        # Check passkey status
        status = get_passkey_status(export_json)
        
        if status == "healthy":
            console.print("[green]✓ Passkey is healthy[/green]")
            healthy.append(title)
            
            if not dry_run:
                _apply_tag(uuid, title, VERIFIED_PASSKEY_TAG)
            else:
                console.print(f"[dim]Would apply tag: {VERIFIED_PASSKEY_TAG}[/dim]")
                
        elif status == "orphaned":
            console.print("[red]✗ Passkey is ORPHANED[/red]")
            orphaned.append(title)
            
            if not dry_run:
                _apply_tag(uuid, title, ORPHANED_PASSKEY_TAG)
            else:
                console.print(f"[dim]Would apply tag: {ORPHANED_PASSKEY_TAG}[/dim]")
        else:
            console.print("[dim]○ No passkey found (tag may be incorrect)[/dim]")
            no_passkey.append(title)
        
        console.print()
        
        # Show next item message and delay (only in auto mode)
        if auto_open and i < len(items):
            next_title = items[i].get("title", "Unknown")
            console.print(f"[cyan]→ Next: {next_title} (2 seconds...)[/cyan]")
            time.sleep(2)
            console.print()

    # Summary
    console.print("[bold]═══ Audit Summary ═══[/bold]")
    console.print(f"[green]Healthy:[/green] {len(healthy)}")
    console.print(f"[red]Orphaned:[/red] {len(orphaned)}")
    console.print(f"[dim]Skipped:[/dim] {len(skipped)}")
    console.print(f"[dim]No passkey:[/dim] {len(no_passkey)}")
    
    if orphaned:
        console.print()
        console.print("[red]Orphaned items:[/red]")
        for title in orphaned:
            console.print(f"  • {title}")
        
    if dry_run:
        console.print()
        console.print("[yellow]Dry run - no tags applied. Run without --dry-run to apply tags.[/yellow]")


def _apply_tag(uuid: str, title: str, tag: str) -> None:
    """Apply a tag to an item, preserving existing tags."""
    try:
        op = OpClient()
        current_tags = op.get_current_tags(uuid)
        
        if tag in current_tags:
            console.print(f"[dim]Tag '{tag}' already present[/dim]")
            return
        
        new_tags = current_tags + [tag]
        result = op.edit_item_tags(uuid, new_tags)
        
        if result is True:
            console.print(f"[green]✓ Applied tag: {tag}[/green]")
        else:
            console.print(f"[red]✗ Failed to apply tag: {result}[/red]")
    except Exception as e:
        console.print(f"[red]✗ Error applying tag: {e}[/red]")


@app.command("status")
def status_clipboard() -> None:
    """Show detailed passkey structure from clipboard JSON.

    Shows the raw passkey data structure for debugging purposes.
    """
    export_json = get_clipboard_json()

    if not export_json:
        console.print("[red]✗ No valid JSON found in clipboard[/red]")
        raise typer.Exit(1)

    info = get_item_info_from_export(export_json)
    console.print(f"[bold]{info['title']}[/bold]")
    console.print()

    overview = export_json.get("overview", {})
    details = export_json.get("details", {})

    # Check overview.passkey
    if "passkey" in overview:
        pk = overview["passkey"]
        console.print("[green]✓ overview.passkey[/green] (public metadata)")
        console.print(f"  [dim]rpId:[/dim] {pk.get('rpId', 'N/A')}")
        user_handle = pk.get('userHandle', '')
        if user_handle:
            console.print(f"  [dim]userHandle:[/dim] {user_handle[:20]}...")
        else:
            console.print("  [dim]userHandle:[/dim] N/A")
        cred_id = pk.get("credentialId", "")
        if len(cred_id) > 30:
            console.print(f"  [dim]credentialId:[/dim] {cred_id[:30]}...")
        else:
            console.print(f"  [dim]credentialId:[/dim] {cred_id or 'N/A'}")
    else:
        console.print("[dim]○ overview.passkey[/dim] not present")

    console.print()

    # Check details.passkey
    if "passkey" in details:
        pk = details["passkey"]
        console.print("[green]✓ details.passkey[/green] (private key container)")
        if pk.get("privateKey"):
            console.print("  [green]✓ privateKey present[/green]")
        else:
            console.print("  [red]✗ privateKey MISSING[/red]")
    else:
        console.print("[red]✗ details.passkey[/red] not present")

    console.print()

    # Summary
    status = get_passkey_status(export_json)
    console.print(f"[bold]Status:[/bold] {status}")
