"""Tag commands: add, remove, rename, find, renumber."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from ..helpers import get_db_manager, get_yubikey_cache
from .tags import (
    add_tag_to_accounts,
    remove_tag_from_accounts,
    rename_tag_on_accounts,
)
from .find import find_by_tag
from .tokens import (
    add_token_to_account,
    remove_token_from_account,
    renumber_tokens_on_account,
)
from .yubikey import add_totp_bulk, yubikey_migrate

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
    """Register tag-related commands with the app."""
    
    @app.command("add")
    def add_command(
        object_type: Annotated[
            str,
            typer.Argument(help="Object type: tag, app, sms, totp"),
        ],
        second_arg: Annotated[
            Optional[str],
            typer.Argument(help="For tags: tag name. For tokens: 'token'. For totp: account name or leave empty with --all"),
        ] = None,
        third_arg: Annotated[
            Optional[str],
            typer.Argument(help="For tokens: Account UUID or title"),
        ] = None,
        # Tag-specific options
        db_path: DbPathOption = None,
        query: Annotated[Optional[str], typer.Option("--query", "-q", help="[Tags] Filter accounts (e.g., 'tier:1', 'vault:Private', 'title:Google')")] = None,
        has_tag: Annotated[Optional[str], typer.Option("--has-tag", help="[Tags] Filter to accounts with this tag")] = None,
        missing_tag: Annotated[Optional[str], typer.Option("--missing-tag", help="[Tags] Filter to accounts missing this tag")] = None,
        # Token-specific options
        app: Annotated[
            Optional[str],
            typer.Option("--app", help="[Tokens] App name for Phone App tokens (e.g., 'Google Authenticator')"),
        ] = None,
        identifier: Annotated[
            Optional[str],
            typer.Option("--identifier", help="[Tokens] Unique identifier/serial for token"),
        ] = None,
        oath_name: Annotated[
            Optional[str],
            typer.Option("--oath-name", help="[Tokens] OATH account name (Issuer:Account format)"),
        ] = None,
        phone: Annotated[
            Optional[str],
            typer.Option("--phone", help="[Tokens] Phone number for SMS tokens"),
        ] = None,
        carrier: Annotated[
            Optional[str],
            typer.Option("--carrier", help="[Tokens] Carrier name for SMS tokens (e.g., 'Verizon')"),
        ] = None,
        # TOTP-specific options
        yubikey: Annotated[str | None, typer.Option("--yubikey", help="[TOTP] Target YubiKey serial(s), comma-separated")] = None,
        tag_totp: Annotated[str, typer.Option("--tag", help="[TOTP] Tag to find accounts for bulk add")] = "Bastion/2FA/TOTP/YubiKey",
        all_accounts: Annotated[bool, typer.Option("--all", help="[TOTP] Add all accounts with specified tag")] = False,
        all_yubikeys: Annotated[bool, typer.Option("--all-yubikeys", help="[TOTP] Add to all connected YubiKeys")] = False,
        # Common options
        dry_run: Annotated[
            bool,
            typer.Option("--dry-run", help="Show what would be done without making changes"),
        ] = False,
        yes: Annotated[
            bool,
            typer.Option("--yes", "-y", help="Skip confirmation prompts"),
        ] = False,
    ) -> None:
        """Add tags, authenticator tokens, or TOTP to YubiKeys.
        
        Examples:
            # Add tag to multiple accounts
            bastion add tag Bastion/Capability/Money-Transfer --has-tag Bastion/Type/Bank
            bastion add tag Bastion/Tier/2 --query 'vault:Private'
            
            # Add tokens to single account
            bastion add app token <uuid> --app 'Google Authenticator' --identifier 'Phone-2025'
            bastion add sms token <uuid> --phone '+1-555-123-4567' --carrier 'Verizon'
            
            # Add TOTP to YubiKey(s)
            bastion add totp "Google" --yubikey 12345678
            bastion add totp --all --yubikey 12345678
            bastion add totp "Amazon" --all-yubikeys
        """
        
        # Route based on object type
        if object_type == "totp":
            # TOTP operation: bastion add totp [account_name]
            db_manager = get_db_manager(db_path)
            cache = get_yubikey_cache()
            
            # Determine target YubiKeys
            if all_yubikeys:
                target_serials = list(cache.serials.keys())
                if not target_serials:
                    console.print("[red]No YubiKeys found in cache. Run 'bastion refresh yubikey' first.[/red]")
                    raise typer.Exit(1)
            elif yubikey:
                target_serials = [s.strip() for s in yubikey.split(",")]
            else:
                console.print("[red]Must specify --yubikey or --all-yubikeys[/red]")
                raise typer.Exit(1)
            
            # Add accounts
            if all_accounts:
                add_totp_bulk(tag_totp, target_serials, db_manager, cache)
            elif second_arg:
                yubikey_migrate(second_arg, db_manager, cache, target_serials)
            else:
                console.print("[red]Must specify account name or use --all[/red]")
                raise typer.Exit(1)
            return
        
        elif object_type == "tag":
            # Tag operation: bastion add tag <tagname>
            if not second_arg:
                console.print("[red]Missing tag name[/red]")
                raise typer.Exit(1)
            add_tag_to_accounts(db_path, second_arg, query, has_tag, missing_tag, dry_run, yes)
            
        elif object_type in ("app", "sms"):
            # Token operation: bastion add app token <uuid> OR bastion add sms token <uuid>
            token_type = object_type
            
            if second_arg != "token":
                console.print(f"[red]Expected 'token' as second argument, got '{second_arg}'[/red]")
                console.print(f"Usage: bastion add {token_type} token <uuid>")
                raise typer.Exit(1)
            
            if not third_arg:
                console.print("[red]Missing account UUID or title[/red]")
                console.print(f"Usage: bastion add {token_type} token <uuid>")
                raise typer.Exit(1)
            
            add_token_to_account(third_arg, token_type, app, identifier, oath_name, phone, carrier, dry_run, yes)
        else:
            console.print(f"[red]Invalid object type: {object_type}[/red]")
            console.print("Valid object types: tag, app, sms")
            console.print("\nExamples:")
            console.print("  bastion add tag Bastion/Capability/Money-Transfer --has-tag Bastion/Type/Bank")
            console.print("  bastion add app token <uuid> --app 'Google Authenticator'")
            console.print("  bastion add sms token <uuid> --phone '+1-555-123-4567'")
            raise typer.Exit(1)

    @app.command("remove")
    def remove_command(
        object_type: Annotated[
            str,
            typer.Argument(help="Object type: tag, token"),
        ],
        second_arg: Annotated[
            str,
            typer.Argument(help="For tags: tag name. For tokens: Account UUID or title"),
        ],
        token_number: Annotated[
            Optional[int],
            typer.Argument(help="[Tokens only] Token number to remove"),
        ] = None,
        # Tag-specific options
        db_path: DbPathOption = None,
        query: Annotated[Optional[str], typer.Option("--query", "-q", help="[Tags] Filter accounts (e.g., 'tier:1', 'vault:Private', 'title:Google')")] = None,
        has_tag: Annotated[Optional[str], typer.Option("--has-tag", help="[Tags] Filter to accounts with this tag")] = None,
        missing_tag: Annotated[Optional[str], typer.Option("--missing-tag", help="[Tags] Filter to accounts missing this tag")] = None,
        # Token-specific options
        renumber: Annotated[
            bool,
            typer.Option("--renumber", help="[Tokens] Renumber remaining tokens after removal"),
        ] = False,
        # Common options
        dry_run: Annotated[
            bool,
            typer.Option("--dry-run", help="Show what would be done without making changes"),
        ] = False,
        yes: Annotated[
            bool,
            typer.Option("--yes", "-y", help="Skip confirmation prompts"),
        ] = False,
    ) -> None:
        """Remove tags or authenticator tokens.
        
        Examples:
            # Remove tag from multiple accounts
            bastion remove tag old-tag --query 'title:Google'
            bastion remove tag Bastion/Tier/3 --has-tag Bastion/Type/Bank
            
            # Remove token from single account
            bastion remove token <uuid> 2
            bastion remove token <uuid> 3 --renumber
        """
        
        if object_type == "tag":
            # Tag operation: bastion remove tag <tagname>
            remove_tag_from_accounts(db_path, second_arg, query, has_tag, missing_tag, dry_run, yes)
            
        elif object_type == "token":
            # Token operation: bastion remove token <uuid> <number>
            if token_number is None:
                console.print("[red]Missing token number to remove[/red]")
                console.print("Usage: bastion remove token <uuid> <token_number>")
                raise typer.Exit(1)
            
            remove_token_from_account(second_arg, token_number, renumber, dry_run, yes)
        else:
            console.print(f"[red]Invalid object type: {object_type}[/red]")
            console.print("Valid object types: tag, token")
            console.print("\nExamples:")
            console.print("  bastion remove tag old-tag --query 'title:Google'")
            console.print("  bastion remove token <uuid> 2")
            raise typer.Exit(1)

    @app.command("rename")
    def rename_command(
        object_type: Annotated[
            str,
            typer.Argument(help="Object type: tag"),
        ],
        old_name: Annotated[
            str,
            typer.Argument(help="Old name"),
        ],
        new_name: Annotated[
            str,
            typer.Argument(help="New name"),
        ],
        db_path: DbPathOption = None,
        query: Annotated[Optional[str], typer.Option("--query", "-q", help="Filter accounts (e.g., 'tier:1', 'vault:Private', 'title:Google')")] = None,
        has_tag: Annotated[Optional[str], typer.Option("--has-tag", help="Filter to accounts with this tag")] = None,
        missing_tag: Annotated[Optional[str], typer.Option("--missing-tag", help="Filter to accounts missing this tag")] = None,
        dry_run: Annotated[bool, typer.Option("--dry-run", help="Show what would be changed without making changes")] = False,
        yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation prompt")] = False,
    ) -> None:
        """Rename tags across multiple accounts.
        
        Examples:
            bastion rename tag Bastion/2FA/Passkey Bastion/2FA/FIDO2-Hardware
            bastion rename tag old-tag new-tag --query 'tier:1'
        """
        
        if object_type == "tag":
            rename_tag_on_accounts(db_path, old_name, new_name, query, has_tag, missing_tag, dry_run, yes)
        else:
            console.print(f"[red]Invalid object type: {object_type}[/red]")
            console.print("Valid object types: tag")
            console.print("\nExamples:")
            console.print("  bastion rename tag Bastion/2FA/Passkey Bastion/2FA/FIDO2-Hardware")
            raise typer.Exit(1)

    @app.command("find")
    def find_command(
        object_type: Annotated[
            str,
            typer.Argument(help="Object type: tag"),
        ],
        name: Annotated[
            str,
            typer.Argument(help="Name to find"),
        ],
        db_path: DbPathOption = None,
        query: Annotated[Optional[str], typer.Option("--query", "-q", help="Filter accounts (e.g., 'tier:1', 'vault:Private', 'title:Google')")] = None,
        has_tag: Annotated[Optional[str], typer.Option("--has-tag", help="Filter to accounts with this tag")] = None,
        missing_tag: Annotated[Optional[str], typer.Option("--missing-tag", help="Filter to accounts missing this tag")] = None,
    ) -> None:
        """Find accounts with specific tags.
        
        Examples:
            bastion find tag Bastion/Capability/Identity
            bastion find tag Bastion/Type/Bank --query 'tier:1'
        """
        
        if object_type == "tag":
            db_mgr = get_db_manager(db_path)
            db = db_mgr.load()
            find_by_tag(db, name, query, has_tag, missing_tag)
        else:
            console.print(f"[red]Invalid object type: {object_type}[/red]")
            console.print("Valid object types: tag")
            console.print("\nExamples:")
            console.print("  bastion find tag Bastion/Capability/Identity")
            raise typer.Exit(1)

    @app.command("renumber")
    def renumber_command(
        object_type: Annotated[
            str,
            typer.Argument(help="Object type: token"),
        ],
        uuid: Annotated[
            str,
            typer.Argument(help="Account UUID or title"),
        ],
        dry_run: Annotated[
            bool,
            typer.Option("--dry-run", help="Show what would be done without making changes"),
        ] = False,
        yes: Annotated[
            bool,
            typer.Option("--yes", "-y", help="Skip confirmation prompts"),
        ] = False,
    ) -> None:
        """Renumber tokens to close gaps.
        
        Examples:
            bastion renumber token <uuid>
            bastion renumber token <uuid> --dry-run
        """
        # Validate object type
        if object_type != "token":
            console.print(f"[red]Invalid object type: {object_type}[/red]")
            console.print("Valid object type: token")
            raise typer.Exit(1)
        
        renumber_tokens_on_account(uuid, dry_run, yes)
