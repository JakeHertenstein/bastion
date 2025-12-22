"""Config commands: show, set, init."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ...config import (
    BASTION_CONFIG_PATH,
    BastionConfig,
    get_config,
)
from ...people import PeopleManager
from ..helpers import get_db_manager
from .config import (
    analyze_entropy_pool,
    list_entropy_pools,
    set_username_config,
    show_username_config,
)
from .show import show_person, show_recovery_matrix

console = Console()


def _show_machine_info() -> None:
    """Display machine UUID and identity information."""
    from bastion_core.platform import (
        get_machine_uuid,
        get_machine_identifier,
        is_macos,
        is_linux,
        is_windows,
        architecture,
    )
    
    machine_id = get_machine_identifier()
    machine_uuid = get_machine_uuid()
    
    # Determine UUID source
    uuid_source = "Unknown"
    if is_macos():
        uuid_source = "macOS System Serial (SHA-512)"
    elif is_linux():
        uuid_source = "Primary MAC Address (SHA-512)"
    elif is_windows():
        uuid_source = "Primary MAC Address (SHA-512)"
    
    table = Table(title="Machine Identity", show_header=True, title_style="bold cyan")
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")
    
    table.add_row("Machine UUID", f"[bold]{machine_uuid}[/bold]")
    table.add_row("UUID Source", uuid_source)
    table.add_row("Hostname", machine_id["hostname"])
    table.add_row("Node Name", machine_id["node_name"])
    table.add_row("Architecture", architecture())
    
    console.print()
    console.print(table)
    console.print()
    console.print("[dim]The machine UUID is stable across hostname changes and reboots.[/dim]")
    console.print("[dim]It's derived from hardware identifiers when possible.[/dim]")


def _show_bastion_config() -> None:
    """Display current Bastion configuration from ~/.bsec/config.toml."""
    config = get_config()

    if not BastionConfig.config_exists():
        console.print("[yellow]No configuration file found.[/yellow]")
        console.print(f"Run [cyan]bastion init[/cyan] to create {BASTION_CONFIG_PATH}")
        console.print("\n[dim]Using built-in defaults:[/dim]")
    else:
        console.print(f"[dim]Config file: {BASTION_CONFIG_PATH}[/dim]\n")

    # General section
    table = Table(title="General Settings", show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Default Vault", config.default_vault)
    console.print(table)
    console.print()

    # Entropy section
    table = Table(title="Entropy Settings", show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Default Bits", str(config.entropy_bits))
    table.add_row("Expiry Days", str(config.entropy_expiry_days))
    table.add_row("Quality Threshold", config.get("entropy", "quality_threshold", "GOOD"))
    console.print(table)
    console.print()

    # Username section
    table = Table(title="Username Generator Settings", show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Default Length", str(config.username_length))
    table.add_row("Default Algorithm", config.username_algorithm)
    console.print(table)
    console.print()

    # Rotation section
    table = Table(title="Rotation Settings", show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Default Interval (days)", str(config.rotation_interval_days))
    table.add_row("Warning Days", str(config.get("rotation", "warning_days", 14)))
    console.print(table)
    console.print()

    # YubiKey section
    table = Table(title="YubiKey Settings", show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Default Slot", str(config.yubikey_slot))
    table.add_row("Challenge Iterations", str(config.get("yubikey", "challenge_iterations", 1024)))
    console.print(table)


# Type alias for common db option
DbPathOption = Annotated[
    Path | None,
    typer.Option(
        "--db",
        help="Database file path",
        envvar="PASSWORD_ROTATION_DB",
    ),
]


def register_commands(app: typer.Typer) -> None:
    """Register config-related commands with the app."""

    @app.command("init")
    def init_command(
        force: Annotated[bool, typer.Option("--force", "-f", help="Overwrite existing config")] = False,
        vault: Annotated[str, typer.Option("--vault", help="Default 1Password vault")] = "Private",
        entropy_bits: Annotated[int, typer.Option("--entropy-bits", help="Default entropy size in bits")] = 8192,
        username_length: Annotated[int, typer.Option("--username-length", help="Default username length")] = 16,
        rotation_days: Annotated[int, typer.Option("--rotation-days", help="Default rotation interval")] = 90,
    ) -> None:
        """
        \bInitialize Bastion configuration.

        \bDetails:
            Creates ~/.bsec/config.toml with customizable defaults.
            Run this command on first setup to configure Bastion for your environment.

        \bExamples:
            bsec init                                    # Interactive setup with defaults
            bsec init --vault "Personal"                # Custom vault
            bsec init --entropy-bits 16384              # Larger entropy pools
            bsec init --force                           # Reset to defaults
        """
        if BastionConfig.config_exists() and not force:
            console.print(f"[yellow]Configuration already exists at {BASTION_CONFIG_PATH}[/yellow]")
            console.print("Use --force to overwrite, or edit the file directly.")
            raise typer.Exit(0)

        # Build config from options
        config = {
            "general": {
                "default_vault": vault,
            },
            "entropy": {
                "default_bits": entropy_bits,
                "expiry_days": 90,
                "quality_threshold": "GOOD",
            },
            "username": {
                "default_length": username_length,
                "default_algorithm": "sha512",
            },
            "rotation": {
                "default_interval_days": rotation_days,
                "warning_days": 14,
            },
            "yubikey": {
                "default_slot": 2,
                "challenge_iterations": 1024,
            },
        }

        BastionConfig.save_config(config)

        console.print(Panel.fit(
            f"[green]✅ Configuration initialized![/green]\n\n"
            f"Config file: [cyan]{BASTION_CONFIG_PATH}[/cyan]\n\n"
            f"[dim]Edit this file to customize settings, or use:[/dim]\n"
            f"  bastion show config        [dim]# View current settings[/dim]\n"
            f"  bastion set config ...     [dim]# Modify settings[/dim]",
            title="Bastion Setup Complete",
        ))

    @app.command("show")
    def show_command(
        noun: Annotated[str, typer.Argument(help="Object to show: 'config', 'entropy', 'person', 'recovery-matrix', 'machine'")],
        object_type: Annotated[str | None, typer.Argument(help="[config] Type: 'all', 'username' | [entropy] Show list | [person] Person name/UUID")] = None,
        pool: Annotated[str | None, typer.Option("--pool", help="[entropy] Pool UUID for analysis")] = None,
        services: Annotated[bool, typer.Option("--services", help="[config username] Show service rules")] = False,
        recovery: Annotated[bool, typer.Option("--recovery", help="[person] Include recovery network")] = False,
    ) -> None:
        """
        \bShow configuration, entropy pools, people, recovery matrix, or machine info.

        \bExamples:
            bastion show config                       # Show all Bastion config
            bastion show config username              # Show username generator config
            bastion show config username --services   # Show service rules
            bastion show entropy                      # List entropy pools
            bastion show entropy --pool <uuid>        # Analyze specific pool
            bastion show machine                      # Show machine UUID and identity
        """

        if noun == "config":
            if not object_type or object_type == "all":
                # Show TOML config
                _show_bastion_config()
            elif object_type == "username":
                show_username_config(services=services)
            else:
                console.print(f"[red]Error:[/red] Unknown config type '{object_type}'. Expected 'all' or 'username'")
                raise typer.Exit(1)

        elif noun == "entropy":
            if pool:
                analyze_entropy_pool(pool)
            else:
                list_entropy_pools()

        elif noun == "person":
            manager = PeopleManager()
            show_person(manager, object_type, recovery)

        elif noun == "recovery-matrix":
            manager = PeopleManager()
            show_recovery_matrix(manager)

        elif noun == "machine":
            _show_machine_info()

        else:
            console.print(f"[red]Error:[/red] Unknown noun '{noun}'. Expected 'config', 'entropy', 'person', 'recovery-matrix', or 'machine'")
            raise typer.Exit(1)

    @app.command("set")
    def set_command(
        noun: Annotated[str, typer.Argument(help="Object to set: 'baseline', 'config'")],
        object_type: Annotated[str | None, typer.Argument(help="[config] Type: 'username' | [baseline] Not used")] = None,
        db_path: DbPathOption = None,
        date: Annotated[str, typer.Option(help="[baseline] Baseline date YYYY-MM-DD")] = "2025-01-01",
        owner: Annotated[str | None, typer.Option("--owner", help="[config username] Set default owner email")] = None,
        algorithm: Annotated[str | None, typer.Option("--algorithm", help="[config username] Set algorithm (sha256, sha512, sha3-512)")] = None,
        length: Annotated[int | None, typer.Option("--length", help="[config username] Set default length")] = None,
    ) -> None:
        """
        \bSet baseline date or configuration.

        \bExamples:
            bastion set baseline --date 2025-01-01
            bastion set config username --owner jake@example.com
            bastion set config username --algorithm sha3-512
            bastion set config username --length 20
        """

        if noun == "baseline":
            db_mgr = get_db_manager(db_path)
            db = db_mgr.load()

            db.metadata.compromise_baseline = date
            db_mgr.save(db)

            console.print(f"[green]✅ Baseline updated to: {date}[/green]")
            console.print("[yellow]⚠️  Run 'bastion sync vault' to recalculate pre-baseline status[/yellow]")

        elif noun == "config":
            if not object_type or object_type == "username":
                set_username_config(owner=owner, algorithm=algorithm, length=length)
            else:
                console.print(f"[red]Error:[/red] Unknown config type '{object_type}'. Expected 'username'")
                raise typer.Exit(1)

        else:
            console.print(f"[red]Error:[/red] Unknown noun '{noun}'. Expected 'baseline' or 'config'")
            console.print("Usage: bastion set [baseline|config] [OPTIONS]")
            raise typer.Exit(1)
