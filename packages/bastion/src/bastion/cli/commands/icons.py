"""Icon management operations for Bastion CLI.

Functions for attaching, exporting, and listing aegis-icons for YubiKey OATH accounts.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import typer

from ..console import console

if TYPE_CHECKING:
    from bastion.icon_manager import IconManager


def icons_attach_auto(
    icon_manager: "IconManager",
    dry_run: bool,
    force: bool = False,
) -> None:
    """Auto-match and attach icons to all YubiKey OATH accounts.
    
    Args:
        icon_manager: IconManager instance
        dry_run: If True, show what would be done without making changes
        force: If True, re-attach icons even if already present
    """
    console.print("[cyan]Auto-matching icons for YubiKey OATH accounts...[/cyan]\n")
    
    if not icon_manager.aegis_icons_dir:
        console.print("[red]Error: aegis-icons directory not found![/red]")
        console.print("Download from: https://github.com/aegis-icons/aegis-icons")
        console.print("Or specify path with --aegis-dir")
        raise typer.Exit(1)
    
    stats = icon_manager.auto_match_and_attach_all(dry_run=dry_run, force=force)
    
    console.print("\n[bold]Results:[/bold]")
    console.print(f"  Matched: {stats['matched']}")
    console.print(f"  Attached: {stats['attached']}")
    console.print(f"  Skipped: {stats['skipped']}")
    console.print(f"  Failed: {stats['failed']}")


def icons_attach_single(
    icon_manager: "IconManager",
    item_uuid: str,
    issuer: str | None,
    icon_file: str | None,
) -> None:
    """Attach an icon to a specific 1Password item.
    
    Args:
        icon_manager: IconManager instance
        item_uuid: UUID of the 1Password item
        issuer: Issuer name for icon matching (optional)
        icon_file: Specific icon filename to use (optional)
    """
    if not icon_manager.aegis_icons_dir:
        console.print("[red]Error: aegis-icons directory not found![/red]")
        console.print("Download from: https://github.com/aegis-icons/aegis-icons")
        console.print("Or specify path with --aegis-dir")
        raise typer.Exit(1)
    
    if icon_file:
        # Use specific icon
        if icon_manager.attach_icon_to_item(item_uuid, icon_file):
            console.print(f"[green]✓ Attached {icon_file}[/green]")
        else:
            raise typer.Exit(1)
            
    elif issuer:
        # Match icon from issuer name
        matched_icon = icon_manager.match_icon(issuer)
        if not matched_icon:
            console.print(f"[red]No icon match found for '{issuer}'[/red]")
            raise typer.Exit(1)
        
        console.print(f"[cyan]Matched '{issuer}' → {matched_icon}[/cyan]")
        if icon_manager.attach_icon_to_item(item_uuid, matched_icon):
            console.print(f"[green]✓ Attached {matched_icon}[/green]")
        else:
            raise typer.Exit(1)
    else:
        console.print("[red]Error: --issuer or --icon required for manual attach[/red]")
        raise typer.Exit(1)


def icons_export(
    icon_manager: "IconManager",
    output_path: Path,
) -> None:
    """Export all attached icons to a directory.
    
    Args:
        icon_manager: IconManager instance
        output_path: Directory to export icons to
    """
    console.print(f"[cyan]Exporting icons to {output_path}...[/cyan]\n")
    
    count = icon_manager.export_all_icons(output_path)
    console.print(f"\n[green]✓ Exported {count} icons[/green]")


def icons_list(icon_manager: "IconManager") -> None:
    """List all YubiKey OATH accounts with their icon status.
    
    Args:
        icon_manager: IconManager instance
    """
    try:
        result = subprocess.run(
            ["op", "item", "list", "--tags", "Bastion/2FA/TOTP/YubiKey", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        
        items = json.loads(result.stdout)
        console.print("[bold]YubiKey OATH accounts with icons:[/bold]\n")
        
        for item_info in items:
            uuid = item_info.get("id", "")
            title = item_info.get("title", "")
            
            attachments = icon_manager.get_attached_icons(uuid)
            if attachments:
                icon_names = ", ".join(a["name"] for a in attachments)
                console.print(f"  [green]✓[/green] {title}")
                console.print(f"    [dim]{icon_names}[/dim]")
            else:
                console.print(f"  [yellow]○[/yellow] {title} [dim](no icon)[/dim]")
    
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
