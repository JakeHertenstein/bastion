"""
CLI helper utilities for Seeder.

Common functionality shared across CLI commands.
"""

import sys
from datetime import date
from pathlib import Path
from typing import List, Optional, Tuple

from rich.console import Console

# Import from the new organized structure
try:
    from ..core.config import (
        ARGON2_MEMORY_COST_KB,
        ARGON2_MEMORY_COST_MB,
        ARGON2_PARALLELISM,
        ARGON2_TIME_COST,
        encode_argon2_params,
        get_auto_parallelism,
    )
    from ..core.crypto import build_label, generate_nonce
    from ..core.exceptions import CoordinateError
    from ..core.grid import SeederGrid
    from ..core.seed_sources import SeedSources
    console = Console()
except ImportError as e:
    print(f"Import error: {e}")
    print("Run from project root with: python -m seeder.cli")
    sys.exit(1)


def _create_enhanced_card_id(card_id: Optional[str], card_date: Optional[str]) -> Optional[str]:
    """Create enhanced card ID with date labeling for HMAC domain separation.
    
    DEPRECATED: Use create_grid_from_args_v2 with full Argon2 label instead.
    Kept for backward compatibility with legacy SHA-512 mode.
    """
    if not card_date:
        return card_id
    
    # Sanitize date for safe label use - allow ASCII alphanumeric, hyphens, underscores
    safe_date = "".join(c if c.isalnum() or c in "-_" else "-" for c in card_date)
    safe_date = safe_date.strip("-").replace("--", "-")  # Clean up multiple separators
    
    if not safe_date:
        console.print("⚠️  Warning: Card date sanitization resulted in empty string, ignoring", style="yellow")
        return card_id
    
    # Create enhanced card ID for HMAC label
    if card_id:
        return f"{card_id}|{safe_date}"  # Use | as separator (simple, visible, ASCII-safe)
    else:
        return f"CARD|{safe_date}"


def _display_label_info(label: str, kdf: str = "ARGON2") -> None:
    """Display the derivation label information to the user for transparency."""
    console.print(f"🏷️  Label: [cyan]{label}[/cyan]", style="dim")
    if kdf == "ARGON2":
        console.print("🔐 Using Argon2id (memory-hard KDF) - resistant to GPU attacks", style="dim")
    else:
        console.print(f"🔑 Using {kdf} derivation", style="dim")


def create_grid_from_args(
    simple: Optional[str] = None,
    bip39: Optional[str] = None,
    slip39: Optional[List[str]] = None,
    passphrase: str = "",
    iterations: int = 2048,
    card_id: Optional[str] = None,
    card_date: Optional[str] = None,
    base: str = "base90",
    # Argon2 parameters
    nonce: Optional[str] = None,
    memory_mb: int = ARGON2_MEMORY_COST_MB,
    time_cost: int = ARGON2_TIME_COST,
    parallelism: Optional[int] = None,
    card_index: str = "A0",
    use_argon2: bool = True,
) -> Tuple[SeederGrid, bytes, str]:
    """
    Create a token grid from command arguments.
    
    Returns: (grid, seed_bytes, label)
        - grid: The SeederGrid object
        - seed_bytes: The derived 64-byte seed
        - label: Full derivation label for CSV export (v1 9-field format)
    """
    # Auto-detect parallelism if not specified
    if parallelism is None:
        parallelism = get_auto_parallelism()
    
    # Determine seed source type
    if simple:
        source_type = "SIMPLE"
        seed_phrase = simple
    elif bip39:
        source_type = "BIP39"
        seed_phrase = bip39
    elif slip39:
        source_type = "SLIP39"
        seed_phrase = " | ".join(slip39)
    else:
        console.print("❌ Error: Must specify a seed source", style="bold red")
        raise ValueError("No seed source specified")
    
    # For --simple with Argon2 (new default)
    if simple and use_argon2:
        # Generate nonce if not provided
        if nonce is None:
            nonce = generate_nonce()
        
        # Use today's date if no card_date specified
        card_date_val = card_date or date.today().strftime('%Y-%m-%d')
        
        # Build the full v1 label (9-field format matching web app)
        kdf_params = encode_argon2_params(time_cost, memory_mb, parallelism)
        label = build_label(
            seed_type=source_type,
            kdf="ARGON2",
            kdf_params=kdf_params,
            base=base.upper(),
            date=card_date_val,
            nonce=nonce,
            card_id=card_id or "",
            card_index=card_index,
        )
        
        _display_label_info(label, "ARGON2")
        
        # Convert memory from MB to KB for argon2-cffi
        memory_kb = memory_mb * 1024
        
        # Use label as salt for Argon2 derivation
        seed_bytes = SeedSources.argon2_to_seed(
            seed_phrase=seed_phrase,
            salt=label.encode('utf-8'),
            time_cost=time_cost,
            memory_cost_kb=memory_kb,
            parallelism=parallelism,
        )
        
        return SeederGrid(seed_bytes, card_id, base, card_index), seed_bytes, label
    
    # Legacy mode: BIP-39, SLIP-39, or --simple with --no-argon2
    if simple:
        console.print("🔑 Using simple SHA-512 seed derivation (legacy)", style="dim")
        seed_bytes = SeedSources.simple_to_seed(simple)
        kdf = "SHA512"
    elif bip39:
        console.print(f"🔐 Using BIP-39 mnemonic with {iterations} iterations", style="dim")
        seed_bytes = SeedSources.bip39_to_seed(bip39, passphrase, iterations)
        kdf = "PBKDF2"
    elif slip39:
        console.print("🔒 Using SLIP-39 shares", style="dim")
        seed_bytes = SeedSources.slip39_to_seed(slip39)
        kdf = "SLIP39"
    
    # Create legacy enhanced card_id with date if provided
    enhanced_card_id = _create_enhanced_card_id(card_id, card_date)
    
    # Build a simple label for legacy mode
    card_date_val = card_date or date.today().strftime('%Y-%m-%d')
    label = f"legacy|{source_type}|{kdf}|{base.upper()}|{card_date_val}|{card_id or ''}"
    
    if enhanced_card_id:
        console.print(f"🏷️  Using card ID: [cyan]{enhanced_card_id}[/cyan]", style="dim")
    
    return SeederGrid(seed_bytes, enhanced_card_id, base), seed_bytes, label


def create_grid_with_desc(
    simple: Optional[str] = None,
    bip39: Optional[str] = None,
    slip39: Optional[List[str]] = None,
    passphrase: str = "",
    iterations: int = 2048,
    card_id: Optional[str] = None,
    card_date: Optional[str] = None,
    base: str = "base90"
) -> Tuple[SeederGrid, bytes, str]:
    """Create a token grid with seed description for CSV export.
    
    DEPRECATED: Use create_grid_from_args which now returns label as third element.
    """
    grid, seed_bytes, label = create_grid_from_args(
        simple=simple,
        bip39=bip39,
        slip39=slip39,
        passphrase=passphrase,
        iterations=iterations,
        card_id=card_id,
        card_date=card_date,
        base=base,
    )
    
    # Create a seed description for backward compatibility
    if simple:
        seed_desc = simple
    elif bip39:
        seed_desc = " ".join(bip39.split()[:3]) + "..."
    elif slip39:
        seed_desc = f"{len(slip39)} SLIP-39 shares"
    else:
        seed_desc = "unknown"
    
    return grid, seed_bytes, seed_desc


def get_password_from_pattern(grid: SeederGrid, pattern: str) -> str:
    """Generate password from coordinate pattern."""
    coords = pattern.split()
    password_parts = []
    
    for coord in coords:
        coord = coord.upper().strip()
        try:
            token = grid.get_token(coord)
            password_parts.append(token)
        except CoordinateError as e:
            raise ValueError(f"Invalid coordinate: {coord}") from e
    
    return "".join(password_parts)


def validate_coordinates(coordinates: List[str]) -> List[str]:
    """Validate and normalize coordinate format."""
    validated = []
    for coord in coordinates:
        coord = coord.upper().strip()
        if not (len(coord) == 2 and coord[0] in 'ABCDEFGHIJ' and coord[1] in '0123456789'):
            raise ValueError(f"Invalid coordinate format: {coord}")
        validated.append(coord)
    return validated


def show_security_warning():
    """Display security warning panel."""
    from rich.panel import Panel
    
    console.print(Panel.fit(
        "[bold red]⚠️  SECURITY WARNING[/bold red]\n\n"
        "This tool is designed for [yellow]online passwords with low lockout thresholds[/yellow].\n"
        "[red]NOT recommended for scenarios where offline attacks are likely.[/red]\n\n"
        "[dim]2025 Reality: Modern GPUs can test 7+ billion password combinations per second.[/dim]\n"
        "[cyan]Always use 2FA for sensitive accounts.[/cyan]",
        border_style="red",
        title="🔒 Security Notice"
    ))
    console.print()  # Add spacing
    console.print()  # Add spacing
