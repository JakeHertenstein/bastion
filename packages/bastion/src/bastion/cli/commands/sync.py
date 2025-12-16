"""Sync command helpers for Bastion CLI."""

from datetime import datetime, timezone

from rich.console import Console

from ..helpers import get_encrypted_db_manager
from ...op_client import OpClient
from ...planning import RotationPlanner

console = Console()


def sync_vault(
    db_path=None,
    tier: int | None = None,
    only_uuid: str | None = None,
    all_items: bool = False,
    tags: list[str] | None = None,
    vault: str | None = None,
    quiet: bool = False,
) -> None:
    """Sync database from 1Password vault.
    
    Fetches items in batches with progress indicator.
    
    Args:
        db_path: Optional path to database
        tier: Optional tier filter
        only_uuid: Optional single account UUID
        all_items: Whether to sync all items (not just tagged)
        tags: Optional list of specific tags to filter by
        vault: Optional vault name to sync from
        quiet: If True, suppress item names in output (for demos)
    """
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn, TimeRemainingColumn
    
    vault_msg = f" from vault '{vault}'" if vault else ""
    console.print(f"[cyan]Syncing from 1Password{vault_msg}...[/cyan]")
    
    # Use encrypted cache manager (ignores db_path - always uses ~/.bsec/cache/db.enc)
    cache_mgr = get_encrypted_db_manager()
    op_client = OpClient()
    planner = RotationPlanner()
    
    db = cache_mgr.load()
    
    # Sync logic
    synced_count = 0
    processed_uuids = set()
    
    # First, get item list (quick operation)
    if all_items:
        console.print("[dim]Listing all items...[/dim]")
        items = op_client.list_all_items(vault=vault)
    elif tags:
        # Sync items with specific tags
        console.print(f"[dim]Searching for items with tags: {', '.join(tags)}...[/dim]")
        seen_uuids = set()
        items = []
        for tag in tags:
            tag_items = op_client.list_items_with_tag(tag, vault=vault)
            for item in tag_items:
                if item["id"] not in seen_uuids:
                    seen_uuids.add(item["id"])
                    items.append(item)
    else:
        # Search for Bastion/* tags (primary) and bastion-* tags (legacy flat format)
        console.print("[dim]Searching for tagged items...[/dim]")
        bastion_items = op_client.list_items_with_prefix("Bastion/", vault=vault)
        flat_bastion_items = op_client.list_items_with_prefix("bastion-", vault=vault)
        
        # Merge and deduplicate by UUID
        seen_uuids = set()
        items = []
        for item in bastion_items + flat_bastion_items:
            if item["id"] not in seen_uuids:
                seen_uuids.add(item["id"])
                items.append(item)
    
    console.print(f"[cyan]Found {len(items)} items[/cyan]")
    
    # Apply filters before progress display
    if only_uuid:
        items = [item for item in items if item["id"] == only_uuid]
    
    if tier:
        # Filter by tier if specified
        tier_tag = f"tier{tier}"
        items = [item for item in items if tier_tag in item.get("tags", [])]
    
    if not items:
        console.print("[yellow]No items to sync[/yellow]")
        return
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    ) as progress:
        
        # Fetch items in batches for better progress reporting
        # Use moderate batches (25) - balances progress visibility with speed
        BATCH_SIZE = 25
        full_items_by_uuid = {}
        
        fetch_task = progress.add_task(
            f"Fetching details (0/{len(items)})...", 
            total=len(items)
        )
        
        for i in range(0, len(items), BATCH_SIZE):
            batch = items[i:i + BATCH_SIZE]
            batch_results = op_client.get_items_batch(batch)
            
            for item in batch_results:
                full_items_by_uuid[item["id"]] = item
            
            fetched = min(i + BATCH_SIZE, len(items))
            progress.update(
                fetch_task, 
                completed=fetched,
                description=f"Fetching details ({fetched}/{len(items)})..."
            )
        
        progress.update(fetch_task, description=f"Fetched {len(full_items_by_uuid)} items")
        
        # Process items
        process_task = progress.add_task(
            f"Processing (0/{len(items)})...", 
            total=len(items)
        )
        
        for i, item in enumerate(items, 1):
            uuid = item["id"]
            if uuid in processed_uuids:
                progress.update(process_task, completed=i)
                continue
            
            # Use batch-fetched data
            full_item = full_items_by_uuid.get(uuid)
            if not full_item:
                progress.update(process_task, completed=i)
                continue
            
            account = planner.process_item(full_item, db.metadata.compromise_baseline)
            db.accounts[uuid] = account
            synced_count += 1
            processed_uuids.add(uuid)
            progress.update(
                process_task, 
                completed=i,
                description=f"Processing ({i}/{len(items)}): {account.title[:30]}..."
            )
        
        progress.update(process_task, description=f"Processed {synced_count} items")
    
    # Smart stale detection - only remove items not synced in 30+ days
    # This prevents mass removal when switching sync modes (e.g., --all to tagged-only)
    STALE_THRESHOLD_DAYS = 30
    
    if all_items or not tier:
        # Only clean stale items when syncing all items or all tagged items (not tier-specific syncs)
        not_synced_uuids = set(db.accounts.keys()) - processed_uuids
        
        if not_synced_uuids:
            truly_stale = []
            recently_active = []
            now = datetime.now(timezone.utc)
            
            for uuid in not_synced_uuids:
                account = db.accounts[uuid]
                # Check last_synced timestamp
                if account.last_synced:
                    try:
                        last_sync_str = account.last_synced.replace('Z', '+00:00')
                        last_sync_dt = datetime.fromisoformat(last_sync_str)
                        # Ensure timezone-aware for comparison
                        if last_sync_dt.tzinfo is None:
                            last_sync_dt = last_sync_dt.replace(tzinfo=timezone.utc)
                        days_since_sync = (now - last_sync_dt).days
                        if days_since_sync >= STALE_THRESHOLD_DAYS:
                            truly_stale.append((uuid, account.title, days_since_sync))
                        else:
                            recently_active.append((uuid, account.title, days_since_sync))
                    except (ValueError, AttributeError):
                        # Can't parse date, consider stale
                        truly_stale.append((uuid, account.title, None))
                else:
                    # No last_synced, consider stale
                    truly_stale.append((uuid, account.title, None))
            
            # Report recently active items that weren't in this sync
            if recently_active and not quiet:
                console.print(f"\n[dim]ℹ️  {len(recently_active)} items not in this sync but recently active (kept):[/dim]")
                for uuid, title, days in recently_active[:5]:  # Show first 5
                    console.print(f"  [dim]• {title} (synced {days} days ago)[/dim]")
                if len(recently_active) > 5:
                    console.print(f"  [dim]... and {len(recently_active) - 5} more[/dim]")
            elif recently_active and quiet:
                console.print(f"\n[dim]ℹ️  {len(recently_active)} items not in this sync but recently active (kept)[/dim]")
            
            # Remove truly stale items
            if truly_stale:
                console.print(f"\n[yellow]Found {len(truly_stale)} stale items (not synced in {STALE_THRESHOLD_DAYS}+ days):[/yellow]")
                if not quiet:
                    for uuid, title, days in truly_stale:
                        days_str = f"{days} days ago" if days else "unknown"
                        console.print(f"  [dim]🗑️  {title} (last synced: {days_str})[/dim]")
                for uuid, title, days in truly_stale:
                    del db.accounts[uuid]
                console.print(f"[yellow]Removed {len(truly_stale)} stale accounts[/yellow]")
    
    db.metadata.last_sync = datetime.now(timezone.utc)
    db.metadata.op_cli_version = op_client.version
    
    cache_mgr.save(db)
    
    # Roll encryption key after successful save for forward secrecy
    console.print("[dim]Rolling encryption key...[/dim]")
    cache_mgr.roll_key()
    
    console.print(f"\n[green]✅ Sync complete. Synced {synced_count} accounts.[/green]")
    
    # Show summary counts only (avoid scrolling past with 1000+ entries)
    total = len(db.accounts)
    pre_baseline = sum(1 for a in db.accounts.values() if a.is_pre_baseline)
    overdue = sum(1 for a in db.accounts.values() if a.days_until_rotation is not None and a.days_until_rotation < 0)
    due_soon = sum(1 for a in db.accounts.values() if a.days_until_rotation is not None and 0 <= a.days_until_rotation <= 30)
    
    console.print("\n[bold]📊 Summary:[/bold]")
    console.print(f"  Total Accounts: {total}")
    console.print(f"  🔴 Pre-Baseline (URGENT): {pre_baseline}")
    console.print(f"  🟡 Overdue: {overdue}")
    console.print(f"  🟠 Due Soon (30 days): {due_soon}")
    console.print("\n[dim]Run 'bsec 1p report' for detailed breakdown[/dim]\n")
