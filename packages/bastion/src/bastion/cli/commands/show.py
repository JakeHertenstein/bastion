"""Show command helpers for Bastion CLI.

Functions for showing configuration, entropy pools, people, and recovery matrices.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer

from ..console import console

if TYPE_CHECKING:
    from bastion.people import PeopleManager


def show_person(
    manager: "PeopleManager",
    person_id: str,
    include_recovery: bool,
) -> None:
    """Show details for a specific person.
    
    Args:
        manager: PeopleManager instance
        person_id: Person name or UUID
        include_recovery: Whether to include recovery network info
    """
    details = manager.get_person_details(person_id)
    if not details:
        console.print(f"[red]Person not found: {person_id}[/red]")
        raise typer.Exit(1)
    
    # Format and display person info
    info = manager.format_person_info(details)
    console.print(info)
    
    # Show recovery network if requested
    if include_recovery:
        console.print("\n[cyan]Recovery Network:[/cyan]")
        network = manager.get_recovery_network(details["id"])
        
        if network["can_recover"]:
            console.print("\n[yellow]Can recover:[/yellow]")
            for target in network["can_recover"]:
                title = target.get("title", target.get("reference", "Unknown"))
                console.print(f"  • {title}")
        
        if network["recovered_by"]:
            console.print("\n[yellow]Can be recovered by:[/yellow]")
            for source in network["recovered_by"]:
                title = source.get("title", source.get("reference", "Unknown"))
                console.print(f"  • {title}")
        
        if not network["can_recover"] and not network["recovered_by"]:
            console.print("[dim]  No recovery relationships[/dim]")


def show_recovery_matrix(manager: "PeopleManager") -> None:
    """Display the recovery matrix for all people.
    
    Args:
        manager: PeopleManager instance
    """
    output = manager.show_recovery_matrix()
    console.print(output)
