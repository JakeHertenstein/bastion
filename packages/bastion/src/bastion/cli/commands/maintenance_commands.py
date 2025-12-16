"""Maintenance commands: validate, rollback, cleanup."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from .validate import validate_migration, validate_rules
from .rollback import rollback_migration, rollback_yubikey_migration
from .cleanup import cleanup_duplicate_tags, cleanup_orphaned_passkeys

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
    """Register maintenance-related commands with the app."""
    
    @app.command("validate")
    def validate_migration_command(
        noun: Annotated[str, typer.Argument(help="'migration' or 'rules'")] = "migration",
        db_path: DbPathOption = None,
    ) -> None:
        """Validate current tags or security rules."""
        if noun == "migration":
            validate_migration(db_path)
        elif noun == "rules":
            validate_rules(db_path)
        else:
            console.print(f"[red]Error:[/red] Expected 'migration' or 'rules', got '{noun}'")
            console.print("Usage: bastion validate migration [OPTIONS]")
            console.print("       bastion validate rules [OPTIONS]")
            raise typer.Exit(1)

    @app.command("rollback")
    def rollback_command(
        object_type: Annotated[
            str,
            typer.Argument(help="Object type: migration, yubikey"),
        ],
        account_name: Annotated[
            Optional[str],
            typer.Argument(help="[yubikey] Account name to rollback"),
        ] = None,
        db_path: DbPathOption = None,
    ) -> None:
        """Rollback migration from backup or rollback failed YubiKey TOTP migration.
        
        Examples:
            bastion rollback migration
            bastion rollback yubikey "Google"
            bastion rollback yubikey "Amazon"
        """
        
        if object_type == "migration":
            rollback_migration(db_path)
        elif object_type == "yubikey":
            rollback_yubikey_migration(account_name, db_path)
        else:
            console.print(f"[red]Invalid object type: {object_type}[/red]")
            console.print("Valid object types: migration, yubikey")
            console.print("\nExamples:")
            console.print("  bastion rollback migration")
            console.print("  bastion rollback yubikey 'Google'")
            raise typer.Exit(1)

    @app.command("cleanup")
    def cleanup_tags_command(
        noun: Annotated[str, typer.Argument(help="'tags' or 'passkeys'")] = "tags",
        db_path: DbPathOption = None,
        batch: Annotated[bool, typer.Option("--batch", "--yes", help="Non-interactive mode")] = False,
        only_uuid: Annotated[Optional[str], typer.Option("--uuid", help="Process single item by UUID")] = None,
    ) -> None:
        """Clean up duplicate tags or orphaned passkeys.
        
        Examples:
            bastion cleanup tags              # Remove duplicate tags
            bastion cleanup passkeys          # Fix orphaned passkeys
            bastion cleanup passkeys --uuid <id>  # Fix single item
        """
        if noun == "tags":
            try:
                cleanup_duplicate_tags(db_path, batch, only_uuid)
            except RuntimeError as e:
                console.print(f"[red]Error:[/red] {e}")
                raise typer.Exit(1)
        elif noun == "passkeys":
            try:
                cleanup_orphaned_passkeys(only_uuid)
            except RuntimeError as e:
                console.print(f"[red]Error:[/red] {e}")
                raise typer.Exit(1)
        else:
            console.print(f"[red]Error:[/red] Expected 'tags' or 'passkeys', got '{noun}'")
            console.print("Usage: bastion cleanup tags [OPTIONS]")
            console.print("       bastion cleanup passkeys [OPTIONS]")
            raise typer.Exit(1)
