"""Relationship commands - links and people management."""

from __future__ import annotations

import typer

from ..console import console
from ...linking import ItemLinker
from ...people import PeopleManager


def list_links(item_identifier: str | None):
    """List all links for an item."""
    if not item_identifier:
        console.print("[red]Error: list links requires an item identifier[/red]")
        console.print("Usage: bastion list links ITEM")
        raise typer.Exit(1)
    
    linker = ItemLinker()
    
    try:
        output = linker.list_all_links(item_identifier)
        console.print(output)
    except RuntimeError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


def list_people(include_recovery: bool = False):
    """List all people."""
    manager = PeopleManager()
    output = manager.list_all_people(include_recovery=include_recovery)
    console.print(output)


def verify_links(item_identifier: str):
    """Verify bidirectional link consistency."""
    linker = ItemLinker()
    
    console.print(f"[cyan]Verifying links for: {item_identifier}[/cyan]\n")
    
    try:
        result = linker.verify_bidirectional_links(item_identifier)
        
        missing = result.get("missing_reverse", [])
        mismatched = result.get("mismatched", [])
        
        if not missing and not mismatched:
            console.print("[green]✓ All links are bidirectional and consistent[/green]")
        else:
            if missing:
                console.print(f"[yellow]Missing reverse links ({len(missing)}):[/yellow]")
                for issue in missing:
                    console.print(f"  • {issue['target']} ({issue['relationship']}) missing reverse: {issue['expected_reverse']}")
            
            if mismatched:
                console.print(f"[yellow]Mismatched relationships ({len(mismatched)}):[/yellow]")
                for issue in mismatched:
                    console.print(f"  • {issue}")
    
    except RuntimeError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


def create_link(source_item: str, target_item: str, bidirectional: bool = True):
    """Create a link between two items."""
    linker = ItemLinker()
    
    console.print(f"[cyan]Creating link: {source_item} ↔ {target_item}[/cyan]")
    
    try:
        linker.create_link(source_item, target_item, bidirectional)
        
        if bidirectional:
            console.print("[green]✓ Created bidirectional links[/green]")
        else:
            console.print(f"[green]✓ Created link: {source_item} → {target_item}[/green]")
            
    except RuntimeError as e:
        console.print(f"[red]Error creating link: {e}[/red]")
        raise typer.Exit(1)


def create_person(
    name: str,
    email: str | None = None,
    phone: str | None = None,
    relationship: str | None = None,
    notes: str | None = None,
):
    """Create a new person in the database."""
    manager = PeopleManager()
    console.print(f"[cyan]Creating person: {name}[/cyan]")
    
    if manager.create_person(name, email, phone, relationship, notes):
        console.print(f"[green]✓ Created person: {name}[/green]")
        
        if relationship:
            console.print(f"[dim]Relationship: {relationship}[/dim]")
        
        console.print("\n[dim]You can now link this person to accounts using:[/dim]")
        console.print(f'[dim]  bastion create link "{name}" "Account Name" --relationship recovers[/dim]')
    else:
        console.print("[red]Failed to create person[/red]")
        raise typer.Exit(1)
