"""Tag filtering and bulk operations.

Functions for filtering accounts and performing bulk tag operations.
"""

from __future__ import annotations

import json
import subprocess
from typing import Optional, TYPE_CHECKING

import typer

from ..console import console
from ..helpers import get_db_manager

if TYPE_CHECKING:
    from bastion.op_client import OpClient


def replace_item_tags(item_id: str, new_tags: list[str]) -> tuple[bool, str]:
    """Replace all tags on a 1Password item with a new list.
    
    The 1Password CLI `--tags` flag doesn't properly clear tags with empty values.
    Instead, use assignment syntax: `tags=value1,value2` or `tags=` to clear.
    
    Args:
        item_id: The 1Password item UUID
        new_tags: The complete list of tags to set (empty list = clear all)
        
    Returns:
        Tuple of (success: bool, error_message: str)
    """
    try:
        # Use assignment syntax: tags=value1,value2 or tags= to clear
        # This is more reliable than --tags flag which doesn't handle empty properly
        if new_tags:
            tags_assignment = f"tags={','.join(new_tags)}"
        else:
            tags_assignment = "tags="
        
        result = subprocess.run(
            ["op", "item", "edit", item_id, tags_assignment],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return False, f"Failed to set tags: {result.stderr.strip()}"
        
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError:
        return False, "1Password CLI (op) not found"


def filter_accounts(
    db,  # Database type
    query: Optional[str] = None,
    has_tag: Optional[str] = None,
    missing_tag: Optional[str] = None,
):  # -> dict[str, Account]
    """Filter accounts based on query, has_tag, and missing_tag criteria.
    
    Args:
        db: Database instance containing accounts
        query: Filter string (e.g., 'tier:1', 'vault:Private', 'title:Google')
        has_tag: Only include accounts with this tag
        missing_tag: Only include accounts missing this tag
        
    Returns:
        Dictionary of UUID -> Account for matching accounts
    """
    filtered_accounts = {}
    for uuid, acc in db.accounts.items():
        # Apply query filter
        if query:
            query_lower = query.lower()
            if ":" in query:
                filter_type, filter_value = query.split(":", 1)
                filter_type = filter_type.strip().lower()
                filter_value = filter_value.strip().lower()
                
                if filter_type == "tier" and acc.tier.lower() != f"tier {filter_value}":
                    continue
                elif filter_type == "vault" and filter_value not in acc.vault_name.lower():
                    continue
                elif filter_type == "title" and filter_value not in acc.title.lower():
                    continue
                elif filter_type == "username" and filter_value not in (acc.username or "").lower():
                    continue
            else:
                # Generic search in title
                if query_lower not in acc.title.lower():
                    continue
        
        # Apply has_tag filter
        if has_tag:
            tag_lower = has_tag.lower()
            if not any(t.lower() == tag_lower for t in acc.tag_list):
                continue
        
        # Apply missing_tag filter
        if missing_tag:
            tag_lower = missing_tag.lower()
            if any(t.lower() == tag_lower for t in acc.tag_list):
                continue
        
        filtered_accounts[uuid] = acc
    
    return filtered_accounts


def execute_tag_bulk_operation(
    targets,  # dict[str, Account]
    tag: str,
    action: str,
    new_tag: Optional[str] = None,
    dry_run: bool = False,
    yes: bool = False,
) -> None:
    """Execute bulk tag operation with preview, confirmation, and result reporting.
    
    Args:
        targets: Dictionary of UUID -> Account to operate on
        tag: Tag name for the operation
        action: 'add', 'remove', or 'rename'
        new_tag: New tag name (only for 'rename' action)
        dry_run: If True, show what would be done without making changes
        yes: If True, skip confirmation prompts
    """
    from rich.table import Table
    from bastion.op_client import OpClient
    from bastion.tag_operations import TagOperations
    from bastion.planning import RotationPlanner
    
    action_desc = {
        "add": f"Add tag '{tag}' to {len(targets)} accounts",
        "remove": f"Remove tag '{tag}' from {len(targets)} accounts",
        "rename": f"Rename tag '{tag}' to '{new_tag}' in {len(targets)} accounts",
    }[action]
    
    # Show preview
    console.print(f"\n[cyan]{action_desc}:[/cyan]\n")
    
    table = Table(show_lines=True)
    table.add_column("Title", style="cyan")
    table.add_column("Current Tags", style="yellow")
    
    for acc in list(targets.values())[:10]:  # Show first 10
        tags_display = ", ".join([t for t in acc.tag_list if t.startswith("Bastion/")])
        table.add_row(acc.title, tags_display or "(none)")
    
    console.print(table)
    
    if len(targets) > 10:
        console.print(f"\n[dim]... and {len(targets) - 10} more[/dim]")
    
    if dry_run:
        console.print("\n[yellow]DRY RUN - No changes made[/yellow]")
        return
    
    # Confirm
    if not yes:
        confirm = typer.confirm(f"\n{action_desc}?", default=False)
        if not confirm:
            console.print("[yellow]Cancelled[/yellow]")
            return
    
    # Execute bulk operation
    console.print(f"\n[cyan]Processing {len(targets)} accounts...[/cyan]\n")
    
    op_client = OpClient()
    tag_ops = TagOperations(op_client)
    
    if action == "add":
        results = tag_ops.bulk_add_tag(targets, tag)
    elif action == "remove":
        results = tag_ops.bulk_remove_tag(targets, tag)
    elif action == "rename":
        results = tag_ops.bulk_rename_tag(targets, tag, new_tag)
    
    # Show results
    success_count = sum(1 for success, _ in results.values() if success)
    fail_count = len(results) - success_count
    
    if fail_count > 0:
        console.print("\n[yellow]Failures:[/yellow]")
        for uuid, (success, message) in results.items():
            if not success:
                acc = targets[uuid]
                console.print(f"  ❌ {acc.title}: {message}")
    
    console.print(f"\n[green]✅ Success: {success_count} accounts updated[/green]")
    if fail_count > 0:
        console.print(f"[red]❌ Failed: {fail_count} accounts[/red]")
    
    # Re-sync affected accounts to update database
    console.print("\n[cyan]Re-syncing affected accounts...[/cyan]")
    planner = RotationPlanner()
    db_mgr = get_db_manager(None)
    db = db_mgr.load()
    
    for uuid in results.keys():
        if results[uuid][0]:  # If successful
            item = op_client.get_item(uuid)
            if item:
                account = planner.process_item(item, "2024-01-01")
                db.accounts[uuid] = account
    
    db_mgr.save(db)
    console.print("[green]✅ Database updated[/green]")


def resolve_account_identifier(identifier: str, op_client: "OpClient") -> str:
    """Resolve account identifier (title or UUID) to UUID.
    
    Args:
        identifier: Account title or UUID
        op_client: OpClient instance
        
    Returns:
        UUID string
        
    Raises:
        typer.Exit: If account not found or user cancels selection
    """
    # Check if it's already a UUID (26 alphanumeric characters)
    if len(identifier) == 26 and identifier.isalnum():
        return identifier
    
    # Title search - get all items and filter by title
    console.print(f"[dim]Searching for account: {identifier}[/dim]")
    
    try:
        result = subprocess.run(
            ["op", "item", "list", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        all_items = json.loads(result.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError, subprocess.TimeoutExpired) as e:
        console.print(f"[red]Error fetching items from 1Password: {e}[/red]")
        raise typer.Exit(1)
    
    # Case-insensitive title match
    matches = [item for item in all_items if item.get("title", "").lower() == identifier.lower()]
    
    if not matches:
        console.print(f"[red]Account not found: {identifier}[/red]")
        console.print("[dim]Tip: Use the exact title or UUID from 1Password[/dim]")
        raise typer.Exit(1)
    
    # Single match - return UUID
    if len(matches) == 1:
        uuid = matches[0]["id"]
        console.print(f"[dim]Found: {matches[0]['title']} (UUID: {uuid})[/dim]")
        return uuid
    
    # Multiple matches - show disambiguation UI
    console.print(f"[yellow]Found {len(matches)} accounts with title '{identifier}':[/yellow]\n")
    
    for i, item in enumerate(matches, 1):
        # Get full item details for vault and fields
        try:
            item_result = subprocess.run(
                ["op", "item", "get", item["id"], "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            item_data = json.loads(item_result.stdout)
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
            
            console.print(f"  [cyan]{i}.[/cyan] {item['title']}")
            console.print(f"      Vault: {vault}")
            if website:
                console.print(f"      Website: {website}")
            if username:
                console.print(f"      Username: {username}")
            if email:
                console.print(f"      Email: {email}")
            console.print(f"      UUID: [dim]{item['id']}[/dim]\n")
            
        except (subprocess.CalledProcessError, json.JSONDecodeError, subprocess.TimeoutExpired):
            # Fallback if item fetch fails
            console.print(f"  [cyan]{i}.[/cyan] {item['title']}")
            console.print(f"      Vault: {item.get('vault', {}).get('name', 'Unknown')}")
            console.print(f"      UUID: [dim]{item['id']}[/dim]\n")
    
    # Prompt for selection
    selection = typer.prompt("Select account number", type=int)
    
    if selection < 1 or selection > len(matches):
        console.print(f"[red]Invalid selection: {selection}[/red]")
        raise typer.Exit(1)
    
    selected_item = matches[selection - 1]
    console.print(f"[dim]Selected: {selected_item['title']} (UUID: {selected_item['id']})[/dim]")
    return selected_item["id"]


def add_tag_to_accounts(
    db_path,
    tag: str,
    query: str | None = None,
    has_tag: str | None = None,
    missing_tag: str | None = None,
    dry_run: bool = False,
    yes: bool = False,
) -> None:
    """Add a tag to filtered accounts."""
    from ..helpers import get_db_manager
    
    db_mgr = get_db_manager(db_path)
    db = db_mgr.load()
    
    # Filter accounts
    filtered_accounts = filter_accounts(db, query, has_tag, missing_tag)

    if not filtered_accounts:
        console.print("[yellow]No accounts match the filters[/yellow]")
        return

    # Filter to accounts that don't have the tag
    tag_lower = tag.lower()
    targets = {uuid: acc for uuid, acc in filtered_accounts.items()
              if not any(t.lower() == tag_lower for t in acc.tag_list)}
    
    if not targets:
        console.print(f"[yellow]All filtered accounts already have tag '{tag}'[/yellow]")
        return
    
    execute_tag_bulk_operation(targets, tag, "add", None, dry_run, yes)


def remove_tag_from_accounts(
    db_path,
    tag: str,
    query: str | None = None,
    has_tag: str | None = None,
    missing_tag: str | None = None,
    dry_run: bool = False,
    yes: bool = False,
) -> None:
    """Remove a tag from filtered accounts."""
    from ..helpers import get_db_manager
    
    db_mgr = get_db_manager(db_path)
    db = db_mgr.load()
    
    # Filter accounts
    filtered_accounts = filter_accounts(db, query, has_tag, missing_tag)
    
    if not filtered_accounts:
        console.print("[yellow]No accounts match the filters[/yellow]")
        return
    
    # Filter to accounts that have the tag
    tag_lower = tag.lower()
    targets = {uuid: acc for uuid, acc in filtered_accounts.items()
              if any(t.lower() == tag_lower for t in acc.tag_list)}
    
    if not targets:
        console.print(f"[yellow]No accounts have tag '{tag}'[/yellow]")
        return
    
    execute_tag_bulk_operation(targets, tag, "remove", None, dry_run, yes)


def rename_tag_on_accounts(
    db_path,
    old_name: str,
    new_name: str,
    query: str | None = None,
    has_tag: str | None = None,
    missing_tag: str | None = None,
    dry_run: bool = False,
    yes: bool = False,
) -> None:
    """Rename a tag on filtered accounts."""
    from ..helpers import get_db_manager
    
    db_mgr = get_db_manager(db_path)
    db = db_mgr.load()
    
    # Filter accounts
    filtered_accounts = filter_accounts(db, query, has_tag, missing_tag)
    
    if not filtered_accounts:
        console.print("[yellow]No accounts match the filters[/yellow]")
        return
    
    # Filter to accounts that have the old tag
    old_tag_lower = old_name.lower()
    targets = {uuid: acc for uuid, acc in filtered_accounts.items()
              if any(t.lower() == old_tag_lower for t in acc.tag_list)}
    
    if not targets:
        console.print(f"[yellow]No accounts have tag '{old_name}'[/yellow]")
        return
    
    execute_tag_bulk_operation(targets, old_name, "rename", new_name, dry_run, yes)

def list_tags(db_path) -> None:
    """List all Bastion tags in the database."""
    from rich.table import Table
    
    db_mgr = get_db_manager(db_path)
    db = db_mgr.load()
    
    # Collect all unique tags
    all_tags: dict[str, int] = {}
    for acc in db.accounts.values():
        for tag in acc.tag_list:
            if tag.startswith("Bastion/") or tag.startswith("bastion-"):
                all_tags[tag] = all_tags.get(tag, 0) + 1
    
    if not all_tags:
        console.print("[yellow]No Bastion tags found[/yellow]")
        return
    
    table = Table(title="Bastion Tags")
    table.add_column("Tag", style="cyan")
    table.add_column("Count", style="green", justify="right")
    
    for tag in sorted(all_tags.keys()):
        table.add_row(tag, str(all_tags[tag]))
    
    console.print(table)


def apply_tag(item_id: str, tag: str) -> None:
    """Apply a tag to a 1Password item (adds if not present)."""
    # Get current tags first to avoid duplicates
    try:
        result = subprocess.run(
            ["op", "item", "get", item_id, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            console.print(f"[red]Error:[/red] {result.stderr.strip()}")
            return
        
        item = json.loads(result.stdout)
        current_tags = item.get("tags", []) or []
        
        # Check if tag already exists (case-insensitive)
        if any(t.lower() == tag.lower() for t in current_tags):
            console.print(f"[yellow]Tag '{tag}' already exists on item[/yellow]")
            return
        
        # Add tag and replace all using assignment syntax
        new_tags = current_tags + [tag]
        success, error = replace_item_tags(item_id, new_tags)
        if success:
            console.print(f"[green]✓[/green] Applied tag '{tag}' to {item_id}")
        else:
            console.print(f"[red]Error:[/red] {error}")
    except subprocess.TimeoutExpired:
        console.print("[red]Error:[/red] Command timed out")
    except FileNotFoundError:
        console.print("[red]Error:[/red] 1Password CLI (op) not found")


def remove_tag(item_id: str, tag: str) -> None:
    """Remove a tag from a 1Password item."""
    # First get current tags
    try:
        result = subprocess.run(
            ["op", "item", "get", item_id, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            console.print(f"[red]Error:[/red] {result.stderr.strip()}")
            return
        
        item = json.loads(result.stdout)
        current_tags = item.get("tags", [])
        
        # Filter out the tag to remove
        new_tags = [t for t in current_tags if t.lower() != tag.lower()]
        
        if len(new_tags) == len(current_tags):
            console.print(f"[yellow]Tag '{tag}' not found on item[/yellow]")
            return
        
        # Update with new tags using replace helper
        success, error = replace_item_tags(item_id, new_tags)
        if success:
            console.print(f"[green]✓[/green] Removed tag '{tag}' from {item_id}")
        else:
            console.print(f"[red]Error:[/red] {error}")
    except subprocess.TimeoutExpired:
        console.print("[red]Error:[/red] Command timed out")
    except FileNotFoundError:
        console.print("[red]Error:[/red] 1Password CLI (op) not found")


def rename_tag(db_path, old_tag: str, new_tag: str, dry_run: bool = False, yes: bool = False) -> None:
    """Rename a tag across all items that have it.
    
    Args:
        db_path: Path to the database file
        old_tag: The tag to rename
        new_tag: The new tag name
        dry_run: If True, show what would be done without making changes
        yes: If True, skip confirmation prompts
    """
    from rich.table import Table
    
    db_mgr = get_db_manager(db_path)
    db = db_mgr.load()
    
    # Find all items with the old tag
    old_tag_lower = old_tag.lower()
    items_with_tag = []
    for uuid, acc in db.accounts.items():
        if any(t.lower() == old_tag_lower for t in acc.tag_list):
            items_with_tag.append((uuid, acc))
    
    if not items_with_tag:
        console.print(f"[yellow]No items found with tag '{old_tag}'[/yellow]")
        return
    
    # Show preview
    console.print(f"\n[cyan]Found {len(items_with_tag)} items with tag '{old_tag}':[/cyan]\n")
    
    table = Table()
    table.add_column("Title", style="cyan")
    table.add_column("Vault", style="dim")
    table.add_column("Change", style="yellow")
    
    for uuid, acc in items_with_tag[:20]:
        table.add_row(acc.title, acc.vault_name, f"{old_tag} → {new_tag}")
    
    console.print(table)
    
    if len(items_with_tag) > 20:
        console.print(f"\n[dim]... and {len(items_with_tag) - 20} more items[/dim]")
    
    if dry_run:
        console.print(f"\n[yellow]DRY RUN - Would rename tag on {len(items_with_tag)} items[/yellow]")
        return
    
    if not yes:
        confirm = typer.confirm(f"\nRename '{old_tag}' to '{new_tag}' on {len(items_with_tag)} items?", default=False)
        if not confirm:
            console.print("[yellow]Cancelled[/yellow]")
            return
    
    console.print(f"\n[cyan]Renaming tag on {len(items_with_tag)} items...[/cyan]\n")
    
    success_count = 0
    fail_count = 0
    
    for uuid, acc in items_with_tag:
        try:
            # Get current tags from 1Password
            result = subprocess.run(
                ["op", "item", "get", uuid, "--format", "json"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                console.print(f"[red]❌ {acc.title}: Failed to get item[/red]")
                fail_count += 1
                continue
            
            item = json.loads(result.stdout)
            current_tags = item.get("tags", [])
            
            # Replace old tag with new tag
            new_tags = []
            for t in current_tags:
                if t.lower() == old_tag_lower:
                    if new_tag not in new_tags:
                        new_tags.append(new_tag)
                else:
                    new_tags.append(t)
            
            # Update the item using replace helper (clears then sets)
            success, error = replace_item_tags(uuid, new_tags)
            if success:
                success_count += 1
                console.print(f"[green]✓[/green] {acc.title}")
            else:
                fail_count += 1
                console.print(f"[red]❌ {acc.title}: {error}[/red]")
        except subprocess.TimeoutExpired:
            fail_count += 1
            console.print(f"[red]❌ {acc.title}: Timeout[/red]")
        except Exception as e:
            fail_count += 1
            console.print(f"[red]❌ {acc.title}: {e}[/red]")
    
    console.print(f"\n[green]✅ Renamed tag on {success_count} items[/green]")
    if fail_count > 0:
        console.print(f"[red]❌ Failed on {fail_count} items[/red]")
