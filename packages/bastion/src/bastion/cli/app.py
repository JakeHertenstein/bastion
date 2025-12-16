"""Main Bastion CLI application (bsec).

This module creates the Typer application and registers all command modules.
Each domain has its own module with related commands.

CLI entry points:
  - bsec (primary)
  - bastion (backward compatibility alias)

Version 0.3.0 Breaking Changes:
  - CLI renamed from `bastion` to `bsec`
  - Cache directory moved from ~/.bastion to ~/.bsec (auto-migrated)
  - 1Password-specific commands under `bsec 1p` subcommand.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
import click
from rich.console import Console

from .. import __version__


class NaturalOrderGroup(typer.core.TyperGroup):
    """Custom group that lists commands in alphabetical order."""
    def list_commands(self, ctx: click.Context) -> list[str]:
        return sorted(super().list_commands(ctx))


# Create the main app
app = typer.Typer(
    name="bsec",
    help="Bastion Security (bsec) - Ground-level defense for 1Password credential security",
    add_completion=False,
    cls=NaturalOrderGroup,
)

console = Console()

# Global options type annotation
DbPathOption = Annotated[
    Optional[Path],
    typer.Option(
        "--db",
        help="Database file path",
        envvar="PASSWORD_ROTATION_DB",
    ),
]


# =============================================================================
# REGISTER 1PASSWORD SUBCOMMAND
# =============================================================================
# All 1Password-dependent commands are now under `bastion 1p`

from .commands.op_commands import op_app
app.add_typer(op_app, name="1p", help="1Password vault operations")


# =============================================================================
# REGISTER TOP-LEVEL COMMANDS (1Password-independent)
# =============================================================================
# These commands work without 1Password or are general utilities

from .commands.generate_commands import register_commands as register_generate
from .commands.config_commands import register_commands as register_config
from .commands.visualize_commands import register_commands as register_visualize
from .commands.sigchain_commands import register_commands as register_sigchain
from .commands.verify_commands import register_commands as register_verify

# Register top-level command groups
register_generate(app)  # generate entropy, generate username, generate mermaid
register_config(app)    # config management
register_visualize(app) # entropy visualization
register_sigchain(app)  # sigchain, session, ots commands
register_verify(app)    # verify username


# =============================================================================
# APP CALLBACK AND VERSION
# =============================================================================

def _version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        console.print(f"Bastion version: {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version"),
    ] = None,
) -> None:
    """Bastion - Ground-level defense for 1Password credential security.
    
    BREAKING CHANGE (v0.2.0): 1Password commands moved to `bastion 1p` subcommand.
    
    \b
    Examples (new paths):
      bastion 1p sync vault          # Sync from 1Password
      bastion 1p report status       # Rotation status report
      bastion 1p analyze risk        # Risk analysis
      bastion 1p audit no-tags       # Audit for missing tags
      bastion 1p tags list           # List all tags
      bastion 1p yubikey list        # YubiKey assignments
    
    \b
    General utilities (unchanged):
      bastion generate entropy yubikey     # Generate entropy
      bastion generate username domain.com # Generate username
      bastion config show                  # Show configuration
    """
    pass
