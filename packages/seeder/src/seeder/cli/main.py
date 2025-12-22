#!/usr/bin/env python3
"""
Main CLI application for Seeder.

Organized, refactored entry point that imports from the proper package structure.
"""


import typer
from rich.console import Console

from ..core.grid import SeederGrid

# Import from the new organized structure
from ..core.seed_sources import SeedSources
from .commands.analyze import analyze_app
from .commands.export import export_app
from .commands.generate import generate_app
from .commands.verify import verify_app
from .display import create_info_panel, print_grid_table

console = Console()

# Initialize main Typer app
app = typer.Typer(
    name="seeder",
    help="🔢 Seeder Generator - Create secure password token matrices",
    add_completion=True,
    rich_markup_mode="rich"
)

# Add command modules
app.add_typer(generate_app, name="generate")
app.add_typer(verify_app, name="verify")
app.add_typer(export_app, name="export")
app.add_typer(analyze_app, name="analyze")

# Simple standalone commands
show_app = typer.Typer(help="👁️  Display matrices, patterns, and info")
app.add_typer(show_app, name="show")


@show_app.command("grid")
def show_grid(
    simple: str = typer.Option(None, "--simple", "-s", help="Simple seed phrase"),
    bip39: str = typer.Option(None, "--bip39", "-b", help="BIP-39 mnemonic phrase"),
    passphrase: str = typer.Option("", "--passphrase", "-p", help="BIP-39 passphrase"),
    iterations: int = typer.Option(2048, "--iterations", "-i", help="PBKDF2 iterations"),
    with_hash: bool = typer.Option(True, "--hash/--no-hash", help="Show SHA-512 hash")
):
    """👁️ Display token grid in table format."""
    try:
        if simple:
            seed_bytes = SeedSources.simple_to_seed(simple)
        elif bip39:
            seed_bytes = SeedSources.bip39_to_seed(bip39, passphrase, iterations)
        else:
            console.print("❌ Error: Must specify a seed source", style="bold red")
            raise typer.Exit(1)

        grid = SeederGrid(seed_bytes)
        print_grid_table(grid)

        if with_hash:
            from ..core.crypto import SeedCardDigest
            hash_value = SeedCardDigest.generate_sha512_hash(seed_bytes)
            console.print(f"\n🔍 SHA-512: [cyan]{hash_value}[/cyan]")

    except Exception as e:
        console.print(f"❌ Error: {e}", style="bold red")
        raise typer.Exit(1)


@show_app.command("info")
def show_info():
    """ℹ️ Show system information and available commands."""
    console.print(create_info_panel())


@app.command()
def demo(
    output_format: str = typer.Option("table", "--format", "-f", help="Output format: table, plain")
):
    """🎮 Run demo with default BIP-39 test vector."""
    console.print("🎮 Running demo with BIP-39 test vector", style="bold cyan")
    default_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    try:
        seed_bytes = SeedSources.bip39_to_seed(default_mnemonic, "")
        grid = SeederGrid(seed_bytes)

        if output_format == "table":
            print_grid_table(grid)
        else:
            for r in range(10):
                row_letter = chr(ord('A') + r)
                row_vals = [grid.get_token(f"{row_letter}{c}") for c in range(10)]
                typer.echo(" ".join(row_vals))

        console.print("\n💡 Use [cyan]--help[/cyan] for more commands")

    except Exception as e:
        console.print(f"❌ Error: {e}", style="bold red")
        raise typer.Exit(1)


def main():
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
