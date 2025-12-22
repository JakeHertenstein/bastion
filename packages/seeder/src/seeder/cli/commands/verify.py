"""
Verify commands for Seeder CLI.

Commands for verifying tokens and validating seeds.
"""

import sys
from pathlib import Path

import typer
from rich.console import Console

# Add the parent directory to Python path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from ..display import (
        print_error_message,
        print_grid_table,
        print_hash_info,
        print_success_message,
    )
    from ..helpers import create_grid_from_args, get_password_from_pattern
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("💡 Make sure you're running from the Seeder directory")
    sys.exit(1)

console = Console()

# Create the verify app
verify_app = typer.Typer(help="✅ Verify tokens and validate seeds")


@verify_app.command("tokens")
def verify_tokens(
    tokens: str = typer.Argument(..., help="Space-separated tokens to verify"),
    simple: str | None = typer.Option(None, "--simple", "-s", help="Simple seed phrase"),
    bip39: str | None = typer.Option(None, "--bip39", "-b", help="BIP-39 mnemonic phrase"),
    slip39: list[str] | None = typer.Option(None, "--slip39", help="SLIP-39 shares"),
    passphrase: str = typer.Option("", "--passphrase", "-p", help="BIP-39 passphrase"),
    iterations: int = typer.Option(2048, "--iterations", "-i", help="PBKDF2 iterations")
):
    """✅ Verify that seed produces expected tokens in sequence."""
    try:
        grid, seed_bytes, _ = create_grid_from_args(simple, bip39, slip39, passphrase, iterations)

        expected_list = tokens.split()
        actual_tokens = []

        # Get tokens in A0, A1, A2... order
        for r in range(10):
            for c in range(10):
                coord = f"{chr(ord('A') + r)}{c}"
                actual_tokens.append(grid.get_token(coord))

        # Check verification
        if len(expected_list) > len(actual_tokens):
            print_error_message("Too many expected tokens")
            raise typer.Exit(1)

        success = True
        for i, expected in enumerate(expected_list):
            if actual_tokens[i] != expected:
                success = False
                break

        if success:
            print_success_message("VERIFICATION PASSED")
            console.print("✓ Seed produces expected tokens in sequence", style="green")
            print_hash_info(seed_bytes)
        else:
            print_error_message("VERIFICATION FAILED")
            console.print("✗ Seed does not produce expected tokens", style="red")
            print_grid_table(grid)
            raise typer.Exit(1)

    except Exception as e:
        print_error_message(f"Error: {e}")
        raise typer.Exit(1)


@verify_app.command("pattern")
def verify_pattern(
    pattern: str = typer.Argument(..., help="Coordinate pattern (e.g., 'A0 B1 C2')"),
    expected: str = typer.Argument(..., help="Expected password from pattern"),
    simple: str | None = typer.Option(None, "--simple", "-s", help="Simple seed phrase"),
    bip39: str | None = typer.Option(None, "--bip39", "-b", help="BIP-39 mnemonic phrase"),
    slip39: list[str] | None = typer.Option(None, "--slip39", help="SLIP-39 shares"),
    passphrase: str = typer.Option("", "--passphrase", "-p", help="BIP-39 passphrase"),
    iterations: int = typer.Option(2048, "--iterations", "-i", help="PBKDF2 iterations")
):
    """🎯 Verify that a coordinate pattern produces expected password."""
    try:
        grid, _, _ = create_grid_from_args(simple, bip39, slip39, passphrase, iterations)

        # Generate password from pattern
        actual_password = get_password_from_pattern(grid, pattern)

        if actual_password == expected:
            print_success_message("PATTERN VERIFICATION PASSED")
            console.print(f"✓ Pattern '{pattern}' → '{actual_password}'", style="green")
        else:
            print_error_message("PATTERN VERIFICATION FAILED")
            console.print(f"✗ Expected: '{expected}'", style="red")
            console.print(f"✗ Actual:   '{actual_password}'", style="red")
            raise typer.Exit(1)

    except Exception as e:
        print_error_message(f"Error: {e}")
        raise typer.Exit(1)
