"""
Display utilities for Seeder CLI.

Rich-based display functions for formatting output consistently.
"""

import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Import from the new organized structure
try:
    from ..core.crypto import SeedCardDigest
    from ..core.grid import SeederGrid
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("💡 Make sure you're running from the Seeder directory")
    sys.exit(1)

console = Console()


def print_grid_table(grid: SeederGrid) -> None:
    """Print matrix as formatted table.

    Spreadsheet convention: letter=column (A-J), number=row (0-9)
    """
    table = Table(title="🔢 Token Matrix", show_header=True, header_style="bold cyan")

    # Add column headers: " ", "A", "B", "C", ... "J" (letters for columns)
    table.add_column(" ", style="bold yellow", width=2)
    for col in range(10):
        col_letter = chr(ord('A') + col)
        table.add_column(col_letter, justify="center", style="white", width=5)

    # Add rows 0-9 (numbers for rows)
    for row in range(10):
        row_data = [str(row)]

        for col in range(10):
            col_letter = chr(ord('A') + col)
            coord = f"{col_letter}{row}"
            token = grid.get_token(coord)
            row_data.append(token)

        table.add_row(*row_data)

    console.print(table)


def print_hash_info(seed_bytes: bytes) -> None:
    """Print SHA-512 hash information."""
    hash_value = SeedCardDigest.generate_sha512_hash(seed_bytes)
    console.print(f"\n🔍 SHA-512: [cyan]{hash_value}[/cyan]")


def print_success_message(message: str) -> None:
    """Print a success message in green."""
    console.print(f"✅ {message}", style="bold green")


def print_error_message(message: str) -> None:
    """Print an error message in red."""
    console.print(f"❌ {message}", style="bold red")


def print_info_message(message: str) -> None:
    """Print an info message in cyan."""
    console.print(f"ℹ️ {message}", style="cyan")


def print_warning_message(message: str) -> None:
    """Print a warning message in yellow."""
    console.print(f"⚠️ {message}", style="yellow")


def create_info_panel() -> Panel:
    """Create the system information panel."""
    return Panel.fit(
        "[bold cyan]🔢 Seeder Generator[/bold cyan]\n\n"
        "A secure tool for generating password token matrices.\n"
        "Uses deterministic cryptographic tokens for air-gapped password generation.\n\n"
        "[bold red]⚠️  SECURITY WARNING:[/bold red]\n"
        "• Designed for [yellow]online passwords with low lockout thresholds[/yellow]\n"
        "• [red]NOT recommended for scenarios where offline attacks are likely[/red]\n"
        "• [cyan]Always use 2FA for sensitive accounts[/cyan]\n\n"
        "[bold]Available Commands:[/bold]\n"
        "• [cyan]generate grid[/cyan] - Create token matrices\n"
        "• [cyan]generate patterns[/cyan] - Create password patterns\n"
        "• [cyan]verify tokens[/cyan] - Verify token sequences\n"
        "• [cyan]show grid[/cyan] - Display formatted grids\n"
        "• [cyan]export csv[/cyan] - Export to CSV files\n\n"
        "[bold]Base90 Conversion:[/bold]\n"
        "• Uses rejection sampling to avoid modulo bias\n"
        "• ~6.49 bits per character, 4 chars = ~26 bits entropy\n"
        "• 32 bits would need ~5 Base90 digits for perfect representation\n\n"
        "[bold]Seed Sources:[/bold]\n"
        "• Simple phrases (SHA-512)\n"
        "• BIP-39 mnemonics (PBKDF2)\n"
        "• SLIP-39 shares (Shamir's Secret Sharing)",
        title="System Info"
    )


def create_patterns_table(patterns: list[tuple[str, str]], grid: SeederGrid, count: int) -> Table:
    """Create a table showing password patterns."""
    table = Table(title="🎯 Password Patterns", show_header=True, header_style="bold green")
    table.add_column("#", style="bold yellow", width=3)
    table.add_column("Pattern", style="cyan", width=20)
    table.add_column("Password", style="white", width=20)
    table.add_column("Description", style="dim", width=30)

    for i, (pattern_coords, description) in enumerate(patterns[:count], 1):
        coords = pattern_coords.split()
        password_parts = []

        for coord in coords:
            try:
                token = grid.get_token(coord)
                password_parts.append(token)
            except Exception:  # noqa: BLE001
                password_parts.append("???")

        password = "".join(password_parts)

        table.add_row(
            str(i),
            pattern_coords,
            password,
            description
        )

    return table


def create_shares_table(shares: list[str]) -> Table:
    """Create a table showing SLIP-39 shares."""
    table = Table(title="🔑 SLIP-39 Test Shares", show_header=True, header_style="bold blue")
    table.add_column("Share #", style="bold yellow")
    table.add_column("Mnemonic", style="white")

    for i, share in enumerate(shares, 1):
        table.add_row(f"Share {i}", share)

    return table
    return table
