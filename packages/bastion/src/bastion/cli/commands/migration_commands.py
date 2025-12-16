"""Migration commands: migrate, convert, copy."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from .migrations import (
    migrate_tags,
    convert_single_to_note,
    convert_bulk_to_notes,
    migrate_from_bastion_impl,
)
from .yubikey import migrate_yubikey_fields, sync_yubikey_accounts

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
    """Register migration-related commands with the app."""
    
    @app.command("migrate")
    def migrate_command(
        object_type: Annotated[
            str,
            typer.Argument(help="Object type: tags, fields, from-bastion"),
        ],
        second_arg: Annotated[
            Optional[str],
            typer.Argument(help="For fields: resource type (yubikey)"),
        ] = None,
        third_arg: Annotated[
            Optional[str],
            typer.Argument(help="Reserved for future use"),
        ] = None,
        # Common options
        db_path: DbPathOption = None,
        dry_run: Annotated[bool, typer.Option("--dry-run", help="Show what would be done without making changes")] = False,
        yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation prompt")] = False,
        # migrate fields options
        uuid: Annotated[str | None, typer.Option("--uuid", help="[fields] Migrate specific item by UUID")] = None,
        all_items: Annotated[bool, typer.Option("--all", help="[fields] Migrate all items with Bastion/2FA/TOTP/YubiKey tag")] = False,
        non_interactive: Annotated[bool, typer.Option("--non-interactive", help="[fields] Skip confirmation prompts")] = False,
        status: Annotated[bool, typer.Option("--status", help="[fields] Show migration status table and exit")] = False,
        # migrate from-bastion options
        skip_cache: Annotated[bool, typer.Option("--skip-cache", help="[from-bastion] Skip cache migration")] = False,
    ) -> None:
        """Migrate tags, fields, or from legacy Bastion format.
        
        NOTE: For TOTP migration, use 'bastion add totp' instead.
        
        Examples:
            # Migrate tags
            bastion migrate tags --dry-run
            bastion migrate tags --yes
            
            # Migrate YubiKey fields
            bastion migrate fields yubikey --status
            bastion migrate fields yubikey --uuid <UUID>
            bastion migrate fields yubikey --all
            
            # Migrate from legacy Bastion format
            bastion migrate from-bastion --dry-run
            bastion migrate from-bastion
        """
        
        if object_type == "tags":
            # Migrate flat bastion-* tags to nested Bastion/* structure
            migrate_tags(db_path, dry_run, yes)
            
        elif object_type == "fields":
            # bastion migrate fields yubikey [options]
            if not second_arg or second_arg != "yubikey":
                console.print(f"[red]Expected 'yubikey' after 'fields', got '{second_arg}'[/red]")
                console.print("Usage: bastion migrate fields yubikey [--status|--uuid UUID|--all]")
                raise typer.Exit(1)
            
            migrate_yubikey_fields(uuid, all_items, non_interactive, dry_run, status)
        
        elif object_type == "from-bastion":
            # Migrate from legacy Bastion format
            migrate_from_bastion_impl(dry_run=dry_run, skip_cache=skip_cache)
            
        elif object_type == "totp":
            console.print("[yellow]⚠️  'bastion migrate totp' is deprecated[/yellow]")
            console.print("[cyan]Use the new 'bastion add totp' command instead:[/cyan]\n")
            console.print("Examples:")
            console.print("  bastion add totp \"Google\" --yubikey 12345678")
            console.print("  bastion add totp --all --yubikey 12345678")
            console.print("  bastion add totp \"Amazon\" --all-yubikeys")
            console.print("\nRun 'bastion add totp --help' for more options")
            raise typer.Exit(0)
        else:
            console.print(f"[red]Invalid object type: {object_type}[/red]")
            console.print("Valid object types: tags, fields, from-bastion")
            console.print("\nExamples:")
            console.print("  bastion migrate tags --dry-run")
            console.print("  bastion migrate fields yubikey --status")
            console.print("  bastion migrate from-bastion --dry-run")
            console.print("\nFor TOTP migration, use: bastion add totp --help")
            raise typer.Exit(1)

    @app.command("convert")
    def convert_command(
        noun: Annotated[str, typer.Argument(help="Conversion type: to-note, tokens-to-notes")],
        item_uuid: Annotated[str | None, typer.Argument(help="[to-note] Item UUID to convert")] = None,
        tag: Annotated[str, typer.Option("--tag", help="[tokens-to-notes] Tag to filter items")] = "bastion-token",
        dry_run: Annotated[bool, typer.Option("--dry-run", help="Show what would be converted without making changes")] = False,
    ) -> None:
        """Convert CUSTOM items to SECURE_NOTE for compatibility.
        
        CUSTOM items with category_id cannot be edited via 1Password CLI due to a bug.
        Converting them to SECURE_NOTE preserves all data and enables linking.
        
        Examples:
          bastion convert to-note abc123xyz                    # Convert single item
          bastion convert to-note abc123xyz --dry-run          # Preview conversion
          bastion convert tokens-to-notes                      # Convert all bastion-token items
          bastion convert tokens-to-notes --tag bastion-entropy    # Convert items with specific tag
        """
        
        if noun == "to-note":
            if not item_uuid:
                console.print("[red]Error: to-note requires an item UUID[/red]")
                console.print("Usage: bastion convert to-note ITEM_UUID")
                raise typer.Exit(1)
            
            convert_single_to_note(item_uuid, dry_run)
        
        elif noun == "tokens-to-notes":
            convert_bulk_to_notes(tag, dry_run)
        
        else:
            console.print(f"[red]Error: Unknown conversion type '{noun}'[/red]")
            console.print("Available: to-note, tokens-to-notes")
            raise typer.Exit(1)

    @app.command("copy")
    def copy_command(
        noun: Annotated[str, typer.Argument(help="Resource type: accounts")],
        source: Annotated[str, typer.Option("--from", help="Source YubiKey serial")],
        target: Annotated[str, typer.Option("--to", help="Target YubiKey serial or 'all'")],
        db_path: DbPathOption = None,
    ) -> None:
        """Copy OATH accounts between YubiKeys.
        
        Examples:
          bastion copy accounts --from 12345678 --to 24014077    # Copy from one to another
          bastion copy accounts --from 12345678 --to all         # Copy to all other YubiKeys
        """
        if noun == "accounts":
            sync_yubikey_accounts(source, target, db_path)
        else:
            console.print(f"[red]Unknown resource type: {noun}. Expected 'accounts'[/red]")
            raise typer.Exit(1)
