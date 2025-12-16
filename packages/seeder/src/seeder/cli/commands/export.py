"""
Export commands for Seeder CLI.

Commands for exporting grids to various formats.
"""

import csv
import sys
from datetime import date
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console

# Add the parent directory to Python path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from ...core.crypto import SeedCardDigest
    from ..display import print_error_message, print_success_message
    from ..helpers import create_grid_with_desc
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("💡 Make sure you're running from the Seeder directory")
    sys.exit(1)

console = Console()

# Create the export app
export_app = typer.Typer(help="💾 Export to CSV, files, and formats")


@export_app.command("csv")
def export_csv(
    card_id: str = typer.Argument(..., help="Card ID (e.g., SYS.01.01)"),
    simple: Optional[str] = typer.Option(None, "--simple", "-s", help="Simple seed phrase"),
    bip39: Optional[str] = typer.Option(None, "--bip39", "-b", help="BIP-39 mnemonic phrase"),
    slip39: Optional[List[str]] = typer.Option(None, "--slip39", help="SLIP-39 shares"),
    passphrase: str = typer.Option("", "--passphrase", "-p", help="BIP-39 passphrase"),
    iterations: int = typer.Option(2048, "--iterations", "-i", help="PBKDF2 iterations"),
    file: str = typer.Option("token_matrices.csv", "--file", "-f", help="Output CSV file"),
    card_date: Optional[str] = typer.Option(None, "--date", help="Card date/label for tracking (e.g., 2025, 2025-03)"),
    base: str = typer.Option("base90", "--base", help="Base system: base10, base62, or base90")
):
    """💾 Export grid to CSV file for matrix generation."""
    try:
        grid, seed_bytes, seed_desc = create_grid_with_desc(simple, bip39, slip39, passphrase, iterations, card_id, card_date, base)
        
        # Check if file exists to determine if we need header
        file_exists = Path(file).exists()
        
        with open(file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            if not file_exists:
                writer.writerow(['ID', 'Date', 'SHORT_HASH', 'SHA512', 'TOKENS', 'ENCODING'])
            
            # Format tokens for CSV (newline-separated rows)
            token_rows = []
            for r in range(10):
                row_tokens = [grid.get_token(f"{chr(ord('A') + r)}{c}") for c in range(10)]
                token_rows.append(" ".join(row_tokens))
            
            tokens_csv = "\n".join(token_rows)
            
            # Write row
            today = date.today().strftime('%Y-%m-%d')
            hash_value = SeedCardDigest.generate_sha512_hash(seed_bytes)
            short_hash = hash_value[:6].upper()  # First 6 chars in uppercase for Code39 barcode
            encoding_name = base.capitalize()  # base90 -> Base90
            writer.writerow([card_id, today, short_hash, hash_value, tokens_csv, encoding_name])
        
        print_success_message(f"Matrix data exported to {file}")
        console.print(f"📋 Matrix ID: {card_id}")
        console.print(f"🔑 Seed: {seed_desc}")
        console.print(f"🔤 Encoding: {encoding_name}")
        
        hash_value = SeedCardDigest.generate_sha512_hash(seed_bytes)
        console.print(f"🔍 SHA-512: [cyan]{hash_value}[/cyan]")
        
    except Exception as e:
        print_error_message(f"Error: {e}")
        raise typer.Exit(1)
