"""Relationship commands: link, create, list, verify."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from ..helpers import get_yubikey_cache
from .relationships import (
    list_links,
    list_people,
    verify_links,
    create_link,
    create_person,
)
from .yubikey import yubikey_link_all, link_yubikey_with_uuid

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
    """Register relationship-related commands with the app."""
    
    @app.command("link")
    def link_command(
        noun: Annotated[str, typer.Argument(help="Resource type: yubikey")],
        serial: Annotated[str | None, typer.Argument(help="YubiKey serial number (or use --all)")] = None,
        op_uuid: Annotated[str | None, typer.Argument(help="1Password UUID of YubiKey crypto wallet item (optional - will search by SN field)")] = None,
        all_serials: Annotated[bool, typer.Option("--all", help="Link all YubiKeys in cache to 1Password items with matching SN field")] = False,
        db_path: DbPathOption = None,
    ) -> None:
        """Link YubiKey serial to 1Password crypto wallet item UUID.
        
        This stores the correlation so OATH passwords can be auto-loaded from 1Password.
        If op_uuid is not provided, searches for items with matching SN field.
        
        Examples:
          bastion link yubikey 12345678 abc123def456ghi789jkl012mn
          bastion link yubikey 12345678  # Auto-search by SN field
          bastion link yubikey --all     # Link all YubiKeys in cache
        """
        if noun != "yubikey":
            console.print(f"[red]Error:[/red] Expected 'yubikey', got '{noun}'")
            console.print("Usage: bastion link yubikey SERIAL [OP_UUID]")
            raise typer.Exit(1)
        
        cache = get_yubikey_cache()
        
        # Handle --all option
        if all_serials:
            stats = yubikey_link_all(cache)
            console.print("\n[bold]Summary:[/bold]")
            console.print(f"  Newly linked: {stats['linked']}")
            console.print(f"  Already linked: {stats['already_linked']}")
            console.print(f"  Not found: {stats['not_found']}")
            return
        
        # Single serial logic
        if not serial:
            console.print("[red]Error: Serial number required (or use --all)[/red]")
            console.print("Usage: bastion link yubikey SERIAL [OP_UUID]")
            console.print("   or: bastion link yubikey --all")
            raise typer.Exit(1)
        
        link_yubikey_with_uuid(serial, op_uuid, cache)

    @app.command("create")
    def create_command(
        noun: Annotated[str, typer.Argument(help="Resource type: link, person")],
        source_item: Annotated[str | None, typer.Argument(help="[link] Source item title or UUID")] = None,
        target_item: Annotated[str | None, typer.Argument(help="[link] Target item title or UUID")] = None,
        bidirectional: Annotated[bool, typer.Option("--bidirectional/--no-bidirectional", "-b", help="[link] Also create reverse link")] = True,
        name: Annotated[str | None, typer.Option("--name", help="[person] Person's full name")] = None,
        email: Annotated[str | None, typer.Option("--email", "-e", help="[person] Email address")] = None,
        phone: Annotated[str | None, typer.Option("--phone", "-p", help="[person] Phone number")] = None,
        person_relationship: Annotated[str | None, typer.Option("--person-relationship", help="[person] Relationship (e.g., 'Spouse', 'Emergency Contact')")] = None,
        notes: Annotated[str | None, typer.Option("--notes", "-n", help="[person] Additional notes")] = None,
    ) -> None:
        """Create relationships between items or add new people.
        
        Examples:
          bastion create link "Master Key" "Backup Key"
          bastion create link "API Key" "Service Account" --no-bidirectional
          bastion create person --name "Jane Doe" --email jane@example.com --person-relationship "Spouse"
        """
        
        if noun == "link":
            if not source_item or not target_item:
                console.print("[red]Error: create link requires source_item and target_item[/red]")
                console.print("Usage: bastion create link SOURCE TARGET")
                raise typer.Exit(1)
            create_link(source_item, target_item, bidirectional)
        
        elif noun == "person":
            if not name:
                console.print("[red]Error: create person requires --name[/red]")
                console.print("Usage: bastion create person --name NAME [--email EMAIL] [--person-relationship TYPE]")
                raise typer.Exit(1)
            create_person(name, email, phone, person_relationship, notes)
        
        else:
            console.print(f"[red]Error: Unknown create type '{noun}'[/red]")
            console.print("Available: link, person")
            raise typer.Exit(1)

    @app.command("list")
    def list_command(
        noun: Annotated[str, typer.Argument(help="Resource type: links, people")],
        item_identifier: Annotated[str | None, typer.Argument(help="[links] Item title or UUID to list links for")] = None,
        recovery: Annotated[bool, typer.Option("--recovery", help="[people] Include recovery relationship counts")] = False,
    ) -> None:
        """List relationships or people.
        
        Examples:
          bastion list links "Master Key"
          bastion list links abc123def456ghi789jkl012mn
          bastion list people
          bastion list people --recovery
        """
        
        if noun == "links":
            list_links(item_identifier)
        
        elif noun == "people":
            list_people(recovery)
        
        else:
            console.print(f"[red]Error: Unknown list type '{noun}'[/red]")
            console.print("Available: links, people")
            raise typer.Exit(1)

    @app.command("verify")
    def verify_command(
        noun: Annotated[str, typer.Argument(help="Resource type: links")],
        item_identifier: Annotated[str, typer.Argument(help="Item title or UUID to verify")],
    ) -> None:
        """Verify relationships for consistency.
        
        Examples:
          bastion verify links "Master Key"
          bastion verify links abc123def456ghi789jkl012mn
        """
        
        if noun != "links":
            console.print(f"[red]Error: Unknown verify type '{noun}'[/red]")
            console.print("Available: links")
            raise typer.Exit(1)
        
        verify_links(item_identifier)
