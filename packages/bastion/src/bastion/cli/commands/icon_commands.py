"""Icon commands: icons."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from ...icon_manager import IconManager
from .icons import icons_attach_auto, icons_attach_single, icons_export, icons_list

console = Console()


def register_commands(app: typer.Typer) -> None:
    """Register icon-related commands with the app."""
    
    @app.command("icons")
    def icons_command(
        noun: Annotated[str, typer.Argument(help="Object to manage: 'attach', 'export', 'list'")],
        item: Annotated[Optional[str], typer.Option("--item", help="[attach] Item UUID to attach icon to")] = None,
        issuer: Annotated[Optional[str], typer.Option("--issuer", help="[attach] Issuer name for icon matching")] = None,
        icon_file: Annotated[Optional[str], typer.Option("--icon", help="[attach] Specific icon filename to use")] = None,
        output_dir: Annotated[Optional[str], typer.Option("--output", help="[export] Directory to export icons to")] = None,
        auto: Annotated[bool, typer.Option("--auto", help="[attach] Auto-match all YubiKey items")] = False,
        dry_run: Annotated[bool, typer.Option("--dry-run", help="[attach --auto] Show what would be done")] = False,
        force: Annotated[bool, typer.Option("--force", help="[attach --auto] Re-attach icons even if already present")] = False,
        aegis_dir: Annotated[Optional[str], typer.Option("--aegis-dir", help="Path to aegis-icons directory")] = None,
    ) -> None:
        """Manage aegis-icons for YubiKey OATH accounts.
        
        Examples:
          bastion icons attach --item UUID --issuer Google   # Match and attach Google icon
          bastion icons attach --item UUID --icon google.png # Attach specific icon
          bastion icons attach --auto                        # Auto-match all items
          bastion icons attach --auto --dry-run              # Preview auto-matching
          bastion icons export --output ~/Desktop/icons      # Export all attached icons
          bastion icons list                                 # List all items with icons
        """
        icon_manager = IconManager(Path(aegis_dir) if aegis_dir else None)
        
        if noun == "attach":
            if auto:
                icons_attach_auto(icon_manager, dry_run, force)
            elif item:
                icons_attach_single(icon_manager, item, issuer, icon_file)
            else:
                console.print("[red]Error: --item or --auto required[/red]")
                raise typer.Exit(1)
        
        elif noun == "export":
            if not output_dir:
                console.print("[red]Error: --output required[/red]")
                raise typer.Exit(1)
            icons_export(icon_manager, Path(output_dir))
        
        elif noun == "list":
            icons_list(icon_manager)
        
        else:
            console.print(f"[red]Unknown icons command: {noun}[/red]")
            console.print("Valid commands: attach, export, list")
            raise typer.Exit(1)
