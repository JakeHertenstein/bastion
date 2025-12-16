"""Visualize commands: visualize."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from .entropy import visualize_entropy_pool, analyze_entropy_pools

console = Console()


def register_commands(app: typer.Typer) -> None:
    """Register visualize-related commands with the app."""
    
    @app.command("visualize")
    def visualize_command(
        noun: Annotated[str, typer.Argument(help="Object to visualize: 'entropy'")],
        pool_uuid: Annotated[str, typer.Argument(help="Pool UUID")],
        output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Save to file instead of attaching to 1Password")] = None,
    ) -> None:
        """Visualize entropy pools.
        
        By default, generates visualizations and attaches them directly to the
        1Password item. Use --output to save to filesystem instead.
        
        Examples:
          bastion visualize entropy <uuid>           # Attach to 1Password item
          bastion visualize entropy <uuid> -o out.png  # Save to file
        """
        
        if noun == "entropy":
            visualize_entropy_pool(pool_uuid, output)
        else:
            console.print(f"[red]Error:[/red] Unknown noun '{noun}'. Expected 'entropy'")
            raise typer.Exit(1)
    
    @app.command("analyze")
    def analyze_command(
        noun: Annotated[str, typer.Argument(help="Object to analyze: 'entropy'")],
        pool_uuid: Annotated[Optional[str], typer.Option("--uuid", "-u", help="Specific pool UUID to analyze")] = None,
        all_pools: Annotated[bool, typer.Option("--all", "-a", help="Analyze all pools missing visualizations")] = False,
        dry_run: Annotated[bool, typer.Option("--dry-run", "-n", help="Preview what would be analyzed")] = False,
        force: Annotated[bool, typer.Option("--force", "-f", help="Skip visualization check, process all pools")] = False,
    ) -> None:
        """Analyze entropy pools and attach visualizations.
        
        Generates visualization images (histogram, chi-square) and attaches them
        to 1Password items. Only processes pools without existing visualizations
        (unless --force is used).
        
        Examples:
          bastion analyze entropy --uuid <uuid>    # Analyze single pool
          bastion analyze entropy --all            # Analyze pools missing viz
          bastion analyze entropy --all --force    # Analyze all pools
          bastion analyze entropy --all --dry-run  # Preview what would be analyzed
        """
        
        if noun == "entropy":
            analyze_entropy_pools(pool_uuid, all_pools, dry_run, force)
        else:
            console.print(f"[red]Error:[/red] Unknown noun '{noun}'. Expected 'entropy'")
            raise typer.Exit(1)
