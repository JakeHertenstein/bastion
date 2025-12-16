"""Cleanup command helpers for Bastion CLI."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..helpers import get_db_manager
from ...op_client import OpClient
from ...passkey_health import (
    get_clipboard_json,
    get_passkey_status,
    get_item_info_from_export,
)
from ...linking import PASSKEY_TAG

# Tag for items with corrupted/orphaned passkeys (post-cleanup tracking)
PASSKEY_ORPHANED_TAG = "Bastion/Security/Passkey-Corrupted"

console = Console()


def cleanup_duplicate_tags(
    db_path=None,
    batch: bool = False,
    dry_run: bool = False,
    only_uuid: str | None = None,
) -> None:
    """Remove duplicate tags from 1Password items.
    
    Uses the local cache to identify duplicates (fast), then applies fixes
    to 1Password and updates the cache incrementally.
    
    Args:
        db_path: Optional database path
        batch: Whether to run non-interactively
        dry_run: Preview changes without applying
        only_uuid: Optional single account UUID to clean
    """
    from .tags import replace_item_tags
    
    db_mgr = get_db_manager(db_path)
    db = db_mgr.load()
    
    if dry_run:
        console.print("[yellow]DRY RUN - no changes will be made[/yellow]\n")
    
    console.print("[cyan]Scanning cache for duplicate tags...[/cyan]")
    
    items_with_duplicates = []
    
    # Scan cache for duplicates (fast - no 1Password API calls)
    for account in db.accounts.values():
        if only_uuid and account.uuid != only_uuid:
            continue
        
        # Get tags from cache
        current_tags = account.tag_list
        
        if not current_tags:
            continue
        
        # Build deduplicated list (case-insensitive, prefer proper case)
        seen_lower = {}
        duplicates_found = False
        for tag in current_tags:
            tag_lower = tag.lower()
            if tag_lower in seen_lower:
                duplicates_found = True
                existing = seen_lower[tag_lower]
                # Prefer Bastion/ prefixed version
                if tag.startswith("Bastion/") and not existing.startswith("Bastion/"):
                    seen_lower[tag_lower] = tag
            else:
                seen_lower[tag_lower] = tag
        
        if duplicates_found:
            unique_tags = sorted(seen_lower.values())
            items_with_duplicates.append((account, current_tags, unique_tags))
    
    if not items_with_duplicates:
        console.print("[green]✅ No duplicate tags found in cache![/green]")
        return
    
    total = len(items_with_duplicates)
    console.print(f"[yellow]Found {total} items with duplicate tags[/yellow]\n")
    
    cleaned_count = 0
    skipped_count = 0
    
    # Process items with duplicates
    for i, (account, current_tags, unique_tags) in enumerate(items_with_duplicates, 1):
        removed_tags = set(current_tags) - set(unique_tags)
        
        console.print(f"[dim]({i}/{total})[/dim] [bold]{account.title}[/bold]")
        console.print(f"  Current ({len(current_tags)} tags): {', '.join(current_tags)}")
        console.print(f"  After cleanup ({len(unique_tags)} tags): {', '.join(unique_tags)}")
        console.print(f"  [red]Removing:[/red] {', '.join(removed_tags)}")
        
        if dry_run:
            console.print("  [yellow]⏭️  Would clean (dry run)[/yellow]\n")
            continue
        
        if not batch:
            confirm = input("  Clean up duplicates? (y/N): ")
            if confirm.lower() != "y":
                console.print("  [dim]⏭️  Skipped[/dim]\n")
                skipped_count += 1
                continue
        
        # Apply cleanup to 1Password using assignment syntax
        success, error = replace_item_tags(account.uuid, unique_tags)
        
        if success:
            console.print("  [green]✅ Cleaned[/green]\n")
            cleaned_count += 1
            # Update cache immediately
            account.tags = ", ".join(unique_tags)
            db_mgr.save(db)
        else:
            console.print(f"  [red]❌ FAILED: {error}[/red]\n")
    
    # Summary
    console.print("[cyan]" + "=" * 50 + "[/cyan]")
    if dry_run:
        console.print(f"[yellow]DRY RUN - Found {total} items with duplicate tags[/yellow]")
        console.print("[dim]Run without --dry-run to apply changes[/dim]")
    else:
        console.print(f"✅ Cleaned: {cleaned_count}")
        console.print(f"⏭️  Skipped: {skipped_count}")
    console.print("[cyan]" + "=" * 50 + "[/cyan]")


def cleanup_orphaned_passkeys(
    only_uuid: str | None = None,
) -> None:
    """Detect and tag orphaned passkeys in 1Password items.
    
    Orphaned passkeys occur when the 1Password CLI bug deletes the private key
    but leaves the public key metadata. This creates a broken state where:
    - Safari offers to use the passkey for authentication
    - Authentication fails (private key is missing)
    - User has no indication the passkey is corrupted
    
    LIMITATION: The 1Password CLI cannot delete passkey data. This function:
    1. Lists all items tagged Bastion/2FA/Passkey/Software
    2. For each item, prompts user to copy export JSON from 1Password UI
    3. Auto-detects orphaned state from pasted JSON
    4. If orphaned: updates tags (Passkey/Software → Passkey/Corrupted)
    5. Provides instructions for manual passkey deletion in 1Password app
    
    Args:
        only_uuid: Optional single item UUID to process
    """
    op_client = OpClient()
    
    # Header
    console.print(Panel.fit(
        "[bold yellow]⚠️  Orphaned Passkey Detection[/bold yellow]\n\n"
        "This tool detects corrupted passkeys caused by the 1Password CLI bug\n"
        "(see: bastion/support/1PASSWORD-CLI-PASSKEY-BUG.md)\n\n"
        "[dim]Orphaned passkeys show in Safari but fail to authenticate.[/dim]\n\n"
        "[bold]What this tool does:[/bold]\n"
        "  • Detects orphaned passkeys from UI export JSON\n"
        "  • Tags items as [cyan]Bastion/Security/Passkey-Corrupted[/cyan]\n"
        "  • Guides you to manually remove the passkey in 1Password app\n\n"
        "[red]Note:[/red] The CLI cannot delete passkey data - manual removal required.",
        title="Passkey Health Check",
    ))
    
    # Get items to process
    if only_uuid:
        items = [{"id": only_uuid, "title": "Single item"}]
        console.print(f"\n[cyan]Processing single item:[/cyan] {only_uuid}\n")
    else:
        items = op_client.list_items_by_tag(PASSKEY_TAG)
        if not items:
            console.print(f"\n[green]✅ No items found with tag:[/green] {PASSKEY_TAG}")
            console.print("[dim]Nothing to clean up.[/dim]")
            return
        
        console.print(f"\n[cyan]Found {len(items)} items with tag:[/cyan] {PASSKEY_TAG}\n")
    
    # Show items table
    table = Table(title="Items to Check")
    table.add_column("#", style="dim")
    table.add_column("Title")
    table.add_column("UUID", style="dim")
    
    for i, item in enumerate(items, 1):
        table.add_row(str(i), item.get("title", "Unknown"), item.get("id", ""))
    
    console.print(table)
    console.print()
    
    # Process each item
    cleaned_count = 0
    skipped_count = 0
    healthy_count = 0
    error_count = 0
    
    for i, item in enumerate(items, 1):
        item_id = item.get("id", "")
        item_title = item.get("title", "Unknown")
        
        console.print(f"[bold cyan]({i}/{len(items)}) {item_title}[/bold cyan]")
        console.print(f"  UUID: [dim]{item_id}[/dim]")
        console.print()
        
        # Instructions for user
        console.print("  [yellow]📋 Instructions:[/yellow]")
        console.print("     1. Open this item in 1Password app")
        console.print("     2. Right-click → Export → Copy as JSON")
        console.print("     3. Press [bold]Enter[/bold] when JSON is copied to clipboard")
        console.print("     (or type [bold]s[/bold] to skip, [bold]q[/bold] to quit)")
        console.print()
        
        # Wait for user input
        user_input = input("  → ").strip().lower()
        
        if user_input == "q":
            console.print("\n[yellow]Quitting...[/yellow]")
            break
        elif user_input == "s":
            console.print("  [dim]⏭️  Skipped[/dim]\n")
            skipped_count += 1
            continue
        
        # Read from clipboard
        export_json = get_clipboard_json()
        
        if export_json is None:
            console.print("  [red]❌ Could not read JSON from clipboard[/red]")
            console.print("  [dim]Make sure you copied the item export JSON[/dim]\n")
            error_count += 1
            continue
        
        # Validate it's the right item
        item_info = get_item_info_from_export(export_json)
        if item_info["uuid"] != item_id:
            console.print(f"  [red]❌ UUID mismatch![/red]")
            console.print(f"     Expected: {item_id}")
            console.print(f"     Got: {item_info['uuid']}")
            console.print("  [dim]Make sure you copied the correct item[/dim]\n")
            error_count += 1
            continue
        
        # Check passkey status
        status = get_passkey_status(export_json)
        
        if status == "none":
            console.print("  [dim]ℹ️  No passkey found in this item[/dim]\n")
            skipped_count += 1
            continue
        elif status == "healthy":
            console.print("  [green]✅ Passkey is healthy![/green]")
            console.print("  [dim]Private key is present, no cleanup needed[/dim]\n")
            healthy_count += 1
            continue
        elif status == "orphaned":
            console.print("  [red]⚠️  ORPHANED PASSKEY DETECTED![/red]")
            console.print("  [dim]Public key exists but private key is missing[/dim]")
            console.print()
            
            # Auto-proceed with tagging
            console.print("  [yellow]🏷️  Updating tags to track corrupted state...[/yellow]")
            
            # Update tags via safe field assignment (not JSON stdin)
            # This preserves all other item data while just changing tags
            current_tags = op_client.get_current_tags(item_id)
            new_tags = [t for t in current_tags if t != PASSKEY_TAG]
            if PASSKEY_ORPHANED_TAG not in new_tags:
                new_tags.append(PASSKEY_ORPHANED_TAG)
            
            result = op_client.edit_item_tags(item_id, new_tags)
            
            if result is True:
                console.print(f"  [green]✅ Tagged as corrupted[/green]")
                console.print(f"  [dim]Tag: {PASSKEY_TAG} → {PASSKEY_ORPHANED_TAG}[/dim]")
                console.print()
                console.print("  [yellow]⚠️  MANUAL ACTION REQUIRED:[/yellow]")
                console.print("     The passkey metadata cannot be removed via CLI.")
                console.print("     To fully clean up, in 1Password app:")
                console.print("     1. Open this item")
                console.print("     2. Click the passkey section")
                console.print("     3. Delete the passkey")
                console.print("     4. Re-register passkey with the service")
                console.print()
                cleaned_count += 1
            else:
                console.print(f"  [red]❌ Failed to update tags: {result}[/red]\n")
                error_count += 1
    
    # Summary
    console.print()
    console.print("[cyan]" + "=" * 50 + "[/cyan]")
    console.print(f"🏷️  Tagged as corrupted: {cleaned_count}")
    console.print(f"✅ Already healthy: {healthy_count}")
    console.print(f"⏭️  Skipped: {skipped_count}")
    console.print(f"❌ Errors: {error_count}")
    console.print("[cyan]" + "=" * 50 + "[/cyan]")
    
    if cleaned_count > 0:
        console.print()
        console.print("[yellow]📝 Manual cleanup required for tagged items:[/yellow]")
        console.print("   1. Open each item in 1Password app")
        console.print("   2. Delete the broken passkey")
        console.print("   3. Re-register a new passkey with the service")
        console.print("   4. Update tag: Passkey/Corrupted → Passkey/Software")
