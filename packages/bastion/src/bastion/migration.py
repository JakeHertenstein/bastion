"""Tag management utilities for 1Password items."""

from datetime import datetime, timezone

from rich.console import Console

from .models import Database, MigrationEntry
from .op_client import OpClient


class MigrationManager:
    """Manage tag operations on 1Password items."""

    def __init__(self, db: Database, op_client: OpClient, console: Console):
        self.db = db
        self.op_client = op_client
        self.console = console

    def apply_tags(
        self, 
        uuid: str, 
        tags_to_add: list[str], 
        batch_mode: bool = False
    ) -> bool:
        """Apply tags to a single item.
        
        Args:
            uuid: Item UUID
            tags_to_add: List of tags to add
            batch_mode: If True, skip confirmation prompt
            
        Returns:
            True if successful, False otherwise
        """
        account = self.db.accounts.get(uuid)
        if not account:
            self.console.print(f"[red]Account {uuid} not found[/red]")
            return False
        
        if not batch_mode:
            self.console.print(f"[bold]{account.title}[/bold]")
            self.console.print(f"  Current tags: {account.tags or '[dim]none[/dim]'}")
            self.console.print(f"  Will add: [green]{', '.join(tags_to_add)}[/green]")
            confirm = input("  Apply these tags? (y/N): ")
            if confirm.lower() != "y":
                self.console.print("  [dim]⏭️  Skipped[/dim]")
                return False
        
        # Get current tags from 1Password
        current_tags = self.op_client.get_current_tags(uuid)
        
        # Merge tags (case-insensitive dedup)
        seen_lower = {tag.lower(): tag for tag in current_tags}
        for tag in tags_to_add:
            if tag.lower() not in seen_lower:
                seen_lower[tag.lower()] = tag
        
        new_tags = sorted(seen_lower.values())
        
        # Apply
        result = self.op_client.edit_item_tags(uuid, new_tags)
        
        if result is True:
            self.console.print("  [green]✅ Applied[/green]")
            account.tags = ", ".join(new_tags)
            account.migration_history.append(
                MigrationEntry(
                    timestamp=datetime.now(timezone.utc),
                    action="add_tags",
                    tags=", ".join(tags_to_add),
                    result="success",
                    account_uuid=uuid,
                )
            )
            return True
        else:
            if "ssoLogin" in str(result):
                self.console.print("  [red]❌ FAILED: Unsupported field type (ssoLogin)[/red]")
                self.console.print("  [yellow]⚠️  Manual action required in 1Password app[/yellow]")
            else:
                self.console.print(f"  [red]❌ FAILED: {result}[/red]")
            return False

    def remove_tags(
        self, 
        uuid: str, 
        tags_to_remove: list[str], 
        batch_mode: bool = False
    ) -> bool:
        """Remove tags from a single item.
        
        Args:
            uuid: Item UUID
            tags_to_remove: List of tags to remove
            batch_mode: If True, skip confirmation prompt
            
        Returns:
            True if successful, False otherwise
        """
        account = self.db.accounts.get(uuid)
        if not account:
            self.console.print(f"[red]Account {uuid} not found[/red]")
            return False
        
        if not batch_mode:
            self.console.print(f"[bold]{account.title}[/bold]")
            self.console.print(f"  Current tags: {account.tags or '[dim]none[/dim]'}")
            self.console.print(f"  Will remove: [red]{', '.join(tags_to_remove)}[/red]")
            confirm = input("  Remove these tags? (y/N): ")
            if confirm.lower() != "y":
                self.console.print("  [dim]⏭️  Skipped[/dim]")
                return False
        
        # Get current tags from 1Password
        current_tags = self.op_client.get_current_tags(uuid)
        
        # Remove specified tags (case-insensitive)
        remove_lower = {tag.lower() for tag in tags_to_remove}
        new_tags = [tag for tag in current_tags if tag.lower() not in remove_lower]
        
        # Apply
        result = self.op_client.edit_item_tags(uuid, new_tags)
        
        if result is True:
            self.console.print("  [green]✅ Removed[/green]")
            account.tags = ", ".join(new_tags)
            account.migration_history.append(
                MigrationEntry(
                    timestamp=datetime.now(timezone.utc),
                    action="remove_tags",
                    tags=", ".join(tags_to_remove),
                    result="success",
                    account_uuid=uuid,
                )
            )
            return True
        else:
            self.console.print(f"  [red]❌ FAILED: {result}[/red]")
            return False

    def bulk_add_tag(
        self,
        tag: str,
        filter_fn: callable = None,
        batch_mode: bool = False,
    ) -> dict:
        """Add a tag to multiple accounts.
        
        Args:
            tag: Tag to add
            filter_fn: Optional function to filter accounts (receives Account, returns bool)
            batch_mode: If True, skip confirmation prompts
            
        Returns:
            Summary dict with counts
        """
        results = {"applied": 0, "skipped": 0, "failed": 0}
        
        accounts = list(self.db.accounts.values())
        if filter_fn:
            accounts = [a for a in accounts if filter_fn(a)]
        
        self.console.print(f"[cyan]Adding tag '{tag}' to {len(accounts)} accounts...[/cyan]\n")
        
        for account in accounts:
            # Skip if already has tag
            if tag.lower() in [t.lower() for t in account.tag_list]:
                results["skipped"] += 1
                continue
            
            if self.apply_tags(account.uuid, [tag], batch_mode):
                results["applied"] += 1
            else:
                results["failed"] += 1
        
        self.console.print(f"\n[cyan]Summary: {results['applied']} applied, {results['skipped']} already had tag, {results['failed']} failed[/cyan]")
        return results

    def bulk_remove_tag(
        self,
        tag: str,
        filter_fn: callable = None,
        batch_mode: bool = False,
    ) -> dict:
        """Remove a tag from multiple accounts.
        
        Args:
            tag: Tag to remove
            filter_fn: Optional function to filter accounts (receives Account, returns bool)
            batch_mode: If True, skip confirmation prompts
            
        Returns:
            Summary dict with counts
        """
        results = {"removed": 0, "skipped": 0, "failed": 0}
        
        accounts = list(self.db.accounts.values())
        if filter_fn:
            accounts = [a for a in accounts if filter_fn(a)]
        
        self.console.print(f"[cyan]Removing tag '{tag}' from {len(accounts)} accounts...[/cyan]\n")
        
        for account in accounts:
            # Skip if doesn't have tag
            if tag.lower() not in [t.lower() for t in account.tag_list]:
                results["skipped"] += 1
                continue
            
            if self.remove_tags(account.uuid, [tag], batch_mode):
                results["removed"] += 1
            else:
                results["failed"] += 1
        
        self.console.print(f"\n[cyan]Summary: {results['removed']} removed, {results['skipped']} didn't have tag, {results['failed']} failed[/cyan]")
        return results
