"""Find command helpers for Bastion CLI.

Functions for finding accounts by tags and other criteria.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from rich.table import Table

from ..console import console
from .tags import filter_accounts

if TYPE_CHECKING:
    from bastion.db import Database


def find_by_tag(
    db: "Database",
    name: str,
    query: Optional[str] = None,
    has_tag: Optional[str] = None,
    missing_tag: Optional[str] = None,
) -> None:
    """Find and display accounts with a specific tag.
    
    Args:
        db: Database instance
        name: Tag name to search for
        query: Optional query filter
        has_tag: Optional additional tag filter
        missing_tag: Optional missing tag filter
    """
    # Filter accounts
    filtered_accounts = filter_accounts(db, query, has_tag, missing_tag)
    
    if not filtered_accounts:
        console.print("[yellow]No accounts match the filters[/yellow]")
        return
    
    # Show accounts with the tag
    tag_lower = name.lower()
    found = {uuid: acc for uuid, acc in filtered_accounts.items() 
             if any(t.lower() == tag_lower for t in acc.tag_list)}
    
    if not found:
        console.print(f"[yellow]No accounts found with tag '{name}'[/yellow]")
        return
    
    console.print(f"\n[cyan]Found {len(found)} accounts with tag '{name}':[/cyan]\n")
    
    table = Table(show_lines=True)
    table.add_column("Title", style="cyan")
    table.add_column("Vault", style="dim")
    table.add_column("Username", style="dim")
    table.add_column("All Tags", style="yellow")
    
    for acc in found.values():
        tags_display = ", ".join([t for t in acc.tag_list if t.startswith("Bastion/")])
        table.add_row(acc.title, acc.vault_name, acc.username or "(none)", tags_display)
    
    console.print(table)
