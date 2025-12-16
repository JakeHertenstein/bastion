"""Vault commands: sync, report, export."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from ..helpers import get_db_manager
from ...csv_export import export_to_csv
from ...reports import ReportGenerator
from .sync import sync_vault
from .export import export_tagging_candidates

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
    """Register vault-related commands with the app."""
    
    @app.command("sync")
    def sync_command(
        noun: Annotated[str, typer.Argument(help="Resource type: vault")],
        db_path: DbPathOption = None,
        tier: Annotated[Optional[int], typer.Option(help="Sync specific tier only")] = None,
        only_uuid: Annotated[Optional[str], typer.Option(help="Sync single account")] = None,
        all_items: Annotated[bool, typer.Option("--all", help="Sync all items")] = False,
    ) -> None:
        """Sync database from 1Password.
        
        Examples:
          bastion sync vault              # Sync items with Bastion/* tags
          bastion sync vault --all        # Sync ALL items from 1Password
          bastion sync vault --tier 1     # Sync only Tier 1 items
        """
        if noun == "vault":
            try:
                sync_vault(db_path, tier, only_uuid, all_items)
            except RuntimeError as e:
                console.print(f"[red]Error:[/red] {e}")
                raise typer.Exit(1)
        else:
            console.print(f"[red]Error:[/red] Expected 'vault' or 'yubikey', got '{noun}'")
            console.print("Usage: bastion sync vault [OPTIONS] or bastion sync yubikey --from SERIAL --to SERIAL")
            raise typer.Exit(1)

    @app.command("report")
    def report_status(
        noun: Annotated[str, typer.Argument(help="Must be 'status'")] = "status",
        db_path: DbPathOption = None,
    ) -> None:
        """Generate rotation status report."""
        if noun != "status":
            console.print(f"[red]Error:[/red] Expected 'status', got '{noun}'")
            console.print("Usage: bsec 1p report [OPTIONS]")
            raise typer.Exit(1)
        
        db_mgr = get_db_manager(db_path)
        db = db_mgr.load()
        
        reporter = ReportGenerator(console)
        reporter.generate_report(db)

    @app.command("export")
    def export_command(
        noun: Annotated[str, typer.Argument(help="Export type: 'csv', 'tagging-candidates'")],
        db_path: DbPathOption = None,
        out: Annotated[Path, typer.Option(help="Output file path")] = Path("password-rotation-database.csv"),
        format: Annotated[str, typer.Option(help="[tagging-candidates] Output format: json")] = "json",
    ) -> None:
        """Export database to CSV or find items needing Bastion tags."""
        
        if noun == "csv":
            db_mgr = get_db_manager(db_path)
            db = db_mgr.load()
            
            export_to_csv(db, out)
            console.print(f"[green]✅ Exported to: {out}[/green]")
        
        elif noun == "tagging-candidates":
            if format != "json":
                console.print(f"[red]Unsupported format: {format}[/red]")
                raise typer.Exit(1)
            output_path = out if str(out) != "password-rotation-database.csv" else Path("tagging-candidates.json")
            export_tagging_candidates(output_path)
        
        else:
            console.print(f"[red]Unknown export type: {noun}[/red]")
            console.print("Valid types: csv, tagging-candidates")
            raise typer.Exit(1)
