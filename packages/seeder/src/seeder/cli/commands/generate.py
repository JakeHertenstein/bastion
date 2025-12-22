"""
Generate commands for Seeder CLI.

Commands for generating grids, patterns, shares, and words.
"""

import asyncio
import csv
import sys
from datetime import date
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

# Import from the new organized structure
try:
    from ...core.crypto import SeedCardDigest
    from ...core.grid import SeederGrid
    from ...core.seed_sources import SeedSources
    from ...core.word_generator import DictionaryWordGenerator, WordGenerator
    from ..display import (
        create_patterns_table,
        create_shares_table,
        print_error_message,
        print_grid_table,
        print_hash_info,
        print_success_message,
    )
    from ..helpers import create_grid_from_args, show_security_warning
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("💡 Make sure you're running from the Seeder directory")
    sys.exit(1)

console = Console()

# Create the generate app
generate_app = typer.Typer(help="🔄 Generate tokens, matrices, and patterns")


@generate_app.command("grid")
def generate_grid(
    simple: str | None = typer.Option(None, "--simple", "-s", help="Simple seed phrase"),
    bip39: str | None = typer.Option(None, "--bip39", "-b", help="BIP-39 mnemonic phrase"),
    slip39: list[str] | None = typer.Option(None, "--slip39", help="SLIP-39 shares"),
    passphrase: str = typer.Option("", "--passphrase", "-p", help="BIP-39 passphrase"),
    iterations: int = typer.Option(2048, "--iterations", "-i", help="PBKDF2 iterations"),
    output_format: str = typer.Option("table", "--format", "-f", help="Output format: table, plain, compact"),
    save: bool = typer.Option(False, "--save", help="Auto-save to 1Password"),
    export: str | None = typer.Option(None, "--export", help="Export to CSV file (specify filename)"),
    card_id: str | None = typer.Option(None, "--id", help="Custom card ID (default: YYYY-MM-DD)"),
    card_date: str | None = typer.Option(None, "--date", help="Card date/label for tracking (e.g., 2025, 2025-03, PROD-2025-A)"),
    base: str = typer.Option("base90", "--base", help="Base system: base10, base62, or base90"),
    # Argon2 options
    nonce: str | None = typer.Option(None, "--nonce", help="8-character nonce for unique derivation (auto-generated if not specified)"),
    memory: int = typer.Option(2048, "--memory", "-m", help="Argon2 memory cost in MB (default: 2048 = 2GB)"),
    time_cost: int = typer.Option(3, "--time-cost", "-t", help="Argon2 time cost / iterations (default: 3)"),
    parallelism: int | None = typer.Option(None, "--parallelism", "-P", help="Argon2 parallelism / lanes (default: auto-detect CPU cores, max 16)"),
    card_index: str = typer.Option("A0", "--card-index", help="Card index for batch generation (A0-J9)"),
    no_argon2: bool = typer.Option(False, "--no-argon2", help="Use legacy SHA-512 instead of Argon2 for --simple"),
):
    """🔄 Generate a 10×10 token grid from seed material."""

    # Display security warning for first-time users
    show_security_warning()

    try:
        grid, seed_bytes, label = create_grid_from_args(
            simple, bip39, slip39, passphrase, iterations,
            card_id, card_date, base,
            nonce=nonce, memory_mb=memory, use_argon2=not no_argon2,
            time_cost=time_cost, parallelism=parallelism, card_index=card_index
        )

        if output_format == "table":
            print_grid_table(grid)
        elif output_format == "plain":
            for r in range(10):
                row_letter = chr(ord('A') + r)
                row_vals = [grid.get_token(f"{row_letter}{c}") for c in range(10)]
                typer.echo(" ".join(row_vals))
        elif output_format == "compact":
            tokens = []
            for r in range(10):
                for c in range(10):
                    coord = f"{chr(ord('A') + r)}{c}"
                    tokens.append(grid.get_token(coord))
            typer.echo(" ".join(tokens))

        # Show integrity hash
        print_hash_info(seed_bytes)

        # Auto-save to 1Password if requested
        if save:
            from ...integrations.onepassword_integration import (
                OnePasswordError,
                OnePasswordSession,
                validate_seed_for_1password,
            )

            async def auto_save():
                try:
                    # Determine seed type and phrase
                    if simple:
                        seed_phrase, seed_type = simple, "Simple"
                    elif bip39:
                        seed_phrase, seed_type = bip39, "BIP-39"
                    elif slip39:
                        seed_phrase, seed_type = " | ".join(slip39), "SLIP-39"
                    else:
                        seed_phrase, seed_type = "unknown", "unknown"

                    # Validate seed data
                    if not validate_seed_for_1password(seed_phrase, seed_type):
                        print_error_message("Invalid seed data for 1Password storage")
                        return

                    # Generate hash for integrity
                    sha512_hash = SeedCardDigest.generate_sha512_hash(seed_bytes)

                    # Create card ID - use custom ID or default to simple ISO date
                    if card_id:
                        final_card_id = card_id
                    else:
                        final_card_id = f"{date.today().strftime('%Y-%m-%d')}"

                    console.print(f"🎴 Generated seed card: {final_card_id}", style="green")
                    console.print(f"🔑 SHA-512: {sha512_hash[:16]}...", style="dim")

                    # Save to 1Password
                    async with OnePasswordSession() as op:
                        # Get the first available vault (or use a default)
                        vaults = await op.list_vaults()
                        if not vaults:
                            raise OnePasswordError("No vaults available")
                        default_vault_id = vaults[0]["id"]

                        await op.save_seed_card(
                            card_id=final_card_id,
                            seed_phrase=seed_phrase,
                            seed_type=seed_type,
                            sha512_hash=sha512_hash,
                            vault_id=default_vault_id
                        )
                        print_success_message(f"Saved seed card {final_card_id} to 1Password")

                except OnePasswordError as e:
                    print_error_message(f"1Password error: {e}")
                except Exception as e:
                    print_error_message(f"Error: {e}")

            # Run the async auto-save
            asyncio.run(auto_save())

        # Auto-export to CSV if requested
        if export:
            try:
                # Generate card ID for CSV - use custom ID or default to simple ISO date
                if card_id:
                    final_card_id = card_id
                else:
                    final_card_id = f"{date.today().strftime('%Y-%m-%d')}"

                # Check if file exists to determine if we need header
                file_exists = Path(export).exists()

                with open(export, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)

                    if not file_exists:
                        # New CSV format with Label column for Argon2 parameters
                        writer.writerow(['ID', 'Date', 'Label', 'SHORT_HASH', 'SHA512', 'Tokens'])

                    # Format tokens for CSV (newline-separated rows)
                    token_rows = []
                    for r in range(10):  # r is row index 0-9, which maps to rows A-J
                        row_tokens = [grid.get_token(f"{chr(ord('A') + r)}{c}") for c in range(10)]
                        token_rows.append(" ".join(row_tokens))

                    tokens_csv = "\n".join(token_rows)

                    # Write row with new Label column
                    today = date.today().strftime('%Y-%m-%d')
                    hash_value = SeedCardDigest.generate_sha512_hash(seed_bytes)
                    short_hash = hash_value[:6].upper()  # First 6 chars in uppercase for Code39 barcode
                    writer.writerow([final_card_id, today, label, short_hash, hash_value, tokens_csv])

                print_success_message(f"Exported to CSV: {export}")
                console.print(f"📋 Card ID: {final_card_id}", style="dim")
                console.print(f"🏷️  Label: {label}", style="dim")

            except Exception as e:
                print_error_message(f"Export error: {e}")

    except Exception as e:
        print_error_message(f"Error: {e}")
        raise typer.Exit(1)


@generate_app.command("batch")
def generate_batch(
    simple: str | None = typer.Option(None, "--simple", "-s", help="Simple seed phrase"),
    bip39: str | None = typer.Option(None, "--bip39", "-b", help="BIP-39 mnemonic phrase"),
    slip39: list[str] | None = typer.Option(None, "--slip39", help="SLIP-39 shares"),
    passphrase: str = typer.Option("", "--passphrase", "-p", help="BIP-39 passphrase"),
    iterations: int = typer.Option(2048, "--iterations", "-i", help="PBKDF2 iterations"),
    output: str = typer.Option("batch_cards.csv", "--output", "-o", help="Output CSV file"),
    card_id: str | None = typer.Option(None, "--id", help="Base card ID (will be suffixed with card index)"),
    card_date: str | None = typer.Option(None, "--date", help="Card date/label for tracking"),
    base: str = typer.Option("base90", "--base", help="Base system: base10, base62, or base90"),
    # Argon2 options
    nonce: str | None = typer.Option(None, "--nonce", help="8-character batch nonce (auto-generated if not specified)"),
    memory: int = typer.Option(2048, "--memory", "-m", help="Argon2 memory cost in MB (default: 2048 = 2GB)"),
    time_cost: int = typer.Option(3, "--time-cost", "-t", help="Argon2 time cost / iterations (default: 3)"),
    parallelism: int | None = typer.Option(None, "--parallelism", "-P", help="Argon2 parallelism / lanes (default: auto-detect CPU cores, max 16)"),
):
    """📦 Generate a batch of 100 cards (A0-J9) with unique labels per card index.

    This generates 100 seed cards in a single CSV file, each with a unique card_index
    from A0 to J9 (matching the web app's batch generation).

    Example:
        seeder generate batch --simple "my secret" --output cards.csv
    """
    from ...core.config import TOKENS_TALL, TOKENS_WIDE, encode_argon2_params
    from ...core.crypto import SeedCardDigest, build_label
    from ...core.crypto import generate_nonce as gen_nonce
    from ...core.grid import SeederGrid
    from ...core.seed_sources import SeedSources
    from ..helpers import get_auto_parallelism

    # Auto-detect parallelism if not specified
    if parallelism is None:
        parallelism = get_auto_parallelism()

    # Determine seed source type
    if simple:
        source_type = "SIMPLE"
        seed_phrase = simple
        use_argon2 = True
    elif bip39:
        source_type = "BIP39"
        seed_phrase = bip39
        use_argon2 = False
    elif slip39:
        source_type = "SLIP39"
        seed_phrase = " | ".join(slip39)
        use_argon2 = False
    else:
        print_error_message("Must specify a seed source (--simple, --bip39, or --slip39)")
        raise typer.Exit(1)

    # Generate batch nonce if not provided
    if nonce is None:
        nonce = gen_nonce()

    # Use today's date if not specified
    card_date_val = card_date or date.today().strftime('%Y-%m-%d')
    base_card_id = card_id or "BATCH"

    console.print("📦 Generating batch of 100 cards (A0-J9)...", style="bold")
    console.print(f"🔑 Seed type: {source_type}", style="dim")
    console.print(f"🎲 Batch nonce: {nonce}", style="dim")
    console.print(f"💾 Output: {output}", style="dim")

    # Generate all 100 cards
    cards = []

    with console.status("[bold green]Generating cards...") as status:
        for row in range(TOKENS_TALL):  # 0-9
            for col in range(TOKENS_WIDE):  # A-J
                card_index = f"{chr(ord('A') + col)}{row}"
                status.update(f"[bold green]Generating card {card_index}...")

                if use_argon2:
                    # Build the v1 label for this card
                    kdf_params = encode_argon2_params(time_cost, memory, parallelism)
                    label = build_label(
                        seed_type=source_type,
                        kdf="ARGON2",
                        kdf_params=kdf_params,
                        base=base.upper(),
                        date=card_date_val,
                        nonce=nonce,
                        card_id=base_card_id,
                        card_index=card_index,
                    )

                    # Derive seed using label as salt
                    memory_kb = memory * 1024
                    seed_bytes = SeedSources.argon2_to_seed(
                        seed_phrase=seed_phrase,
                        salt=label.encode('utf-8'),
                        time_cost=time_cost,
                        memory_cost_kb=memory_kb,
                        parallelism=parallelism,
                    )
                else:
                    # Legacy mode for BIP-39/SLIP-39
                    if bip39:
                        seed_bytes = SeedSources.bip39_to_seed(bip39, passphrase, iterations)
                    elif slip39:
                        seed_bytes = SeedSources.slip39_to_seed(slip39)
                    label = f"legacy|{source_type}|{base.upper()}|{card_date_val}|{base_card_id}|{card_index}"

                # Generate grid
                grid = SeederGrid(seed_bytes, base_card_id, base, card_index)

                # Format tokens
                token_rows = []
                for r in range(10):
                    row_tokens = [grid.get_token(f"{chr(ord('A') + c)}{r}") for c in range(10)]
                    token_rows.append(" ".join(row_tokens))
                tokens_csv = "\n".join(token_rows)

                # Generate hashes
                hash_value = SeedCardDigest.generate_sha512_hash(seed_bytes)
                short_hash = hash_value[:6].upper()

                cards.append({
                    "card_index": card_index,
                    "card_id": f"{base_card_id}-{card_index}",
                    "date": card_date_val,
                    "label": label,
                    "short_hash": short_hash,
                    "sha512": hash_value,
                    "tokens": tokens_csv,
                })

    # Write CSV
    try:
        with open(output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['CARD_INDEX', 'ID', 'Date', 'Label', 'SHORT_HASH', 'SHA512', 'Tokens'])

            for card in cards:
                writer.writerow([
                    card["card_index"],
                    card["card_id"],
                    card["date"],
                    card["label"],
                    card["short_hash"],
                    card["sha512"],
                    card["tokens"],
                ])

        print_success_message(f"Generated {len(cards)} cards to {output}")
        console.print("📊 CSV columns: CARD_INDEX, ID, Date, Label, SHORT_HASH, SHA512, Tokens", style="dim")

    except Exception as e:
        print_error_message(f"Error writing CSV: {e}")
        raise typer.Exit(1)


@generate_app.command("patterns")
def generate_patterns(
    simple: str | None = typer.Option(None, "--simple", "-s", help="Simple seed phrase"),
    bip39: str | None = typer.Option(None, "--bip39", "-b", help="BIP-39 mnemonic phrase"),
    slip39: list[str] | None = typer.Option(None, "--slip39", help="SLIP-39 shares"),
    passphrase: str = typer.Option("", "--passphrase", "-p", help="BIP-39 passphrase"),
    iterations: int = typer.Option(2048, "--iterations", "-i", help="PBKDF2 iterations"),
    count: int = typer.Option(6, "--count", "-c", help="Number of patterns to show")
):
    """🎯 Generate password patterns from grid coordinates."""
    try:
        grid, _, _ = create_grid_from_args(simple, bip39, slip39, passphrase, iterations)

        # Simple predefined patterns for demo
        patterns = [
            ("A0 B1 C2 D3", "Top-left diagonal"),
            ("A9 B8 C7 D6", "Top-right diagonal"),
            ("A0 A1 A2 A3", "Top row"),
            ("J0 J1 J2 J3", "Bottom row"),
            ("A0 B0 C0 D0", "Left column"),
            ("B3 F7 D1 H5", "Scattered pattern"),
        ]

        table = create_patterns_table(patterns, grid, count)
        console.print(table)

        console.print("\n💡 Usage: Select coordinates from your card using patterns you can remember")
        console.print(f"Example: For banking, always use pattern 1: '{patterns[0][0]}'")

    except Exception as e:
        print_error_message(f"Error: {e}")
        raise typer.Exit(1)


@generate_app.command("shares")
def generate_shares(
    phrase: str = typer.Argument(..., help="Secret phrase to create shares from"),
    threshold: int = typer.Option(2, "--threshold", "-t", help="Minimum shares needed"),
    total: int = typer.Option(3, "--total", "-n", help="Total shares to create")
):
    """🔑 Generate SLIP-39 test shares for development/demo."""
    try:
        console.print(f"🔧 Generating {total} SLIP-39 shares (threshold: {threshold})")
        shares = SeedSources.create_test_slip39_shares(phrase, threshold, total)

        table = create_shares_table(shares)
        console.print(table)

        console.print("\n💡 Example usage:")
        console.print(f"[cyan]seeder generate grid --slip39 \"{shares[0]}\" \"{shares[1]}\"[/cyan]")

    except Exception as e:
        print_error_message(f"Error: {e}")
        raise typer.Exit(1)


@generate_app.command("words")
def generate_words(
    length: int = typer.Argument(..., help="Word length (3-12 characters for pronounceable, 3-15 for dictionary)"),
    count: int = typer.Option(10, "--count", "-c", help="Number of words to generate"),
    word_type: str = typer.Option("pronounceable", "--type", "-t", help="Word type: pronounceable, common, nouns, verbs, adjectives, all"),
    simple: str | None = typer.Option(None, "--simple", "-s", help="Simple seed phrase"),
    bip39: str | None = typer.Option(None, "--bip39", "-b", help="BIP-39 mnemonic phrase"),
    slip39: list[str] | None = typer.Option(None, "--slip39", help="SLIP-39 shares"),
    passphrase: str = typer.Option("", "--passphrase", "-p", help="BIP-39 passphrase"),
    iterations: int = typer.Option(2048, "--iterations", "-i", help="PBKDF2 iterations"),
    max_length: int | None = typer.Option(None, "--max-length", help="Maximum length for dictionary words (default: same as length)")
):
    """🎲 Generate pronounceable or dictionary words for memorized password components.

    ⚠️  NOTE: This generates custom words for PASSWORD COMPONENTS,
        not BIP-39/SLIP-39 mnemonic words. These are for memorized parts of passwords.

    Word types:
    - pronounceable: Custom generated pronounceable words (3-12 chars)
    - common: Common English dictionary words
    - nouns: Dictionary nouns only
    - verbs: Dictionary verbs only
    - adjectives: Dictionary adjectives only
    - all: All dictionary word types
    """
    try:
        # Validate count
        if count < 1 or count > 50:
            print_error_message(f"Count must be 1-50, got {count}")
            raise typer.Exit(1)

        # Validate word type and length
        if word_type == "pronounceable":
            supported_lengths = WordGenerator.get_supported_lengths()
            if length not in supported_lengths:
                print_error_message(f"Unsupported word length for pronounceable: {length}")
                console.print(f"💡 Supported lengths: {', '.join(map(str, supported_lengths))}")
                raise typer.Exit(1)
        else:
            # Dictionary words
            if not DictionaryWordGenerator.is_available():
                print_error_message("Dictionary word generation not available")
                console.print("💡 Install the required dictionary package for dictionary words")
                raise typer.Exit(1)

            supported_types = DictionaryWordGenerator.get_supported_types()
            if word_type not in supported_types:
                print_error_message(f"Unsupported word type: {word_type}")
                console.print(f"💡 Supported types: {', '.join(supported_types)}")
                raise typer.Exit(1)

            if length < 3 or length > 15:
                print_error_message(f"Word length must be 3-15 for dictionary words, got {length}")
                raise typer.Exit(1)

        # Get seed bytes using same logic as grid generation
        if simple:
            console.print("🔑 Using simple SHA-512 seed derivation", style="dim")
            seed_bytes = SeedSources.simple_to_seed(simple)
        elif bip39:
            console.print(f"🔐 Using BIP-39 mnemonic with {iterations} iterations", style="dim")
            seed_bytes = SeedSources.bip39_to_seed(bip39, passphrase, iterations)
        elif slip39:
            console.print("🔒 Using SLIP-39 shares", style="dim")
            seed_bytes = SeedSources.slip39_to_seed(slip39)
        else:
            print_error_message("Must specify a seed source")
            raise typer.Exit(1)

        # Generate words based on type
        if word_type == "pronounceable":
            words = WordGenerator.generate_word_list(seed_bytes, length, count)
            entropy = WordGenerator.calculate_word_entropy(length)
            word_type_display = "Pronounceable"

            # Create display table for pronounceable words
            table = Table(
                title=f"🎲 {length}-Character {word_type_display} Words",
                show_header=True,
                header_style="bold blue"
            )
            table.add_column("Index", style="bold yellow", width=8)
            table.add_column("Word", style="bright_green", width=15)
            table.add_column("Pattern", style="cyan", width=12)

            for i, word in enumerate(words, 1):
                pattern = WordGenerator.get_pattern(word)
                table.add_row(str(i), word, pattern)

        else:
            # Dictionary words
            actual_max_length = max_length if max_length else length
            if actual_max_length < length:
                print_error_message("Max length cannot be less than minimum length")
                raise typer.Exit(1)

            try:
                words = DictionaryWordGenerator.generate_word_list(
                    seed_bytes, count, length, actual_max_length, word_type
                )
                entropy = DictionaryWordGenerator.calculate_word_entropy(length, actual_max_length, word_type)
                word_type_display = word_type.title()

                # Create display table for dictionary words
                table = Table(
                    title=f"🎲 {length}-{actual_max_length} Character {word_type_display} Words",
                    show_header=True,
                    header_style="bold blue"
                )
                table.add_column("Index", style="bold yellow", width=8)
                table.add_column("Word", style="bright_green", width=15)
                table.add_column("Length", style="cyan", width=8)

                for i, word in enumerate(words, 1):
                    table.add_row(str(i), word, str(len(word)))

            except Exception as e:
                print_error_message(f"Dictionary word generation failed: {e}")
                raise typer.Exit(1)

        console.print(table)

        # Show entropy information
        from rich.panel import Panel
        entropy_panel = Panel(
            f"[bold green]Estimated Entropy: ~{entropy:.1f} bits[/bold green]\n"
            f"[yellow]Word Length: {length} characters[/yellow]\n"
            f"[cyan]Pattern Types: C=Consonant, V=Vowel[/cyan]",
            title="📊 Word Statistics",
            border_style="green"
        )
        console.print(entropy_panel)

        # Usage suggestions
        console.print("\n💡 [bold]Usage Tips:[/bold]")
        console.print("   • Use these words as memorized components in composite passwords")
        console.print(f"   • Combine with tokens: [cyan]Token1-Token2-{words[0]}![/cyan]")
        console.print("   • Longer words provide more entropy but may be harder to remember")
        console.print(f"   • Consider {length}-char words for {entropy:.0f}-bit memorized component")

    except Exception as e:
        print_error_message(f"Error: {e}")
        raise typer.Exit(1)


@generate_app.command("examples")
def generate_password_examples(
    simple: str | None = typer.Option(None, "--simple", "-s", help="Simple seed phrase"),
    bip39: str | None = typer.Option(None, "--bip39", "-b", help="BIP-39 mnemonic phrase"),
    slip39: list[str] | None = typer.Option(None, "--slip39", help="SLIP-39 shares"),
    passphrase: str = typer.Option("", "--passphrase", "-p", help="BIP-39 passphrase"),
    iterations: int = typer.Option(2048, "--iterations", "-i", help="PBKDF2 iterations"),
    format_type: str = typer.Option("card", "--format", "-f", help="Format type: card, sheet, compact, text"),
    include_memorized: bool = typer.Option(False, "--include-memorized", help="Include memorized word examples"),
    memorized_length: int = typer.Option(6, "--memorized-length", help="Length of memorized word component"),
    separators: bool = typer.Option(True, "--separators/--no-separators", help="Include separator characters"),
    # Composite password analysis options (same as analyze composite)
    fixed: int = typer.Option(2, "--fixed", help="Number of fixed tokens from grid"),
    rolling: int = typer.Option(1, "--rolling", help="Number of rolling/rotating tokens"),
    separator_count: int = typer.Option(3, "--separator-count", help="Number of separator characters"),
    rotation_days: int = typer.Option(90, "--rotation-days", help="Days between rolling token changes"),
    no_order: bool = typer.Option(False, "--no-order", help="Exclude component ordering entropy")
):
    """🎯 Generate example passwords for reference cheat sheet."""
    try:
        grid, seed_bytes, _ = create_grid_from_args(simple, bip39, slip39, passphrase, iterations)

        # Define pattern categories for comprehensive examples - reuse analyzer patterns
        pattern_categories = {
            "Basic Patterns": [
                ("A0 B1 C2 D3", "Top-left diagonal", "Standard 4-token diagonal"),
                ("A0 A1 A2 A3", "Top row", "Easy to remember row"),
                ("A0 B0 C0 D0", "Left column", "Vertical pattern"),
            ],
            "Secure Patterns": [
                ("B3 F7 D1 H5", "Scattered", "High security spread"),
                ("A9 B8 C7 D6", "Top-right diagonal", "Reverse diagonal"),
                ("C3 G8 A5 F1 J9", "5-token spread", "Extended pattern"),
            ],
            "Memorable Patterns": [
                ("A0 B1 C2", "Short diagonal", "3-token pattern"),
                ("J0 J1 J2 J3", "Bottom row", "Bottom focus"),
                ("A0 J0 A9 J9", "Corner points", "Card corners"),
            ]
        }

        if format_type == "card":
            # Compact format suitable for card back
            _print_card_format_examples(grid, pattern_categories, include_memorized, memorized_length, separators, seed_bytes, fixed, rolling, separator_count, rotation_days, no_order)
        elif format_type == "sheet":
            # Detailed format for separate reference sheet
            _print_sheet_format_examples(grid, pattern_categories, include_memorized, memorized_length, separators, seed_bytes, fixed, rolling, separator_count, rotation_days, no_order)
        elif format_type == "compact":
            # Very compact format for minimal space
            _print_compact_format_examples(grid, pattern_categories, include_memorized, memorized_length, separators, fixed, rolling, separator_count, rotation_days, no_order)
        elif format_type == "text":
            # Plain text format for copy/paste into card designer
            _print_text_format_examples(grid, pattern_categories, include_memorized, memorized_length, separators, seed_bytes, fixed, rolling, separator_count, rotation_days, no_order)
        else:
            print_error_message(f"Unknown format type: {format_type}")
            raise typer.Exit(1)

    except Exception as e:
        print_error_message(f"Error: {e}")
        raise typer.Exit(1)


def _print_card_format_examples(
    grid: SeederGrid,
    pattern_categories: dict[str, list[tuple[str, str, str]]],
    include_memorized: bool,
    memorized_length: int,
    separators: bool,
    seed_bytes: bytes,
    fixed: int,
    rolling: int,
    separator_count: int,
    rotation_days: int,
    no_order: bool
) -> None:
    """Print examples formatted for card back."""
    console.print("\n[bold blue]🎯 Password Examples for Card Reference[/bold blue]")

    # Show key patterns with actual passwords
    table = Table(title="Quick Reference", show_header=True, header_style="bold green", width=70)
    table.add_column("Type", style="cyan", width=12)
    table.add_column("Pattern", style="white", width=15)
    table.add_column("Password", style="green", width=15)
    table.add_column("Use Case", style="dim", width=20)

    # Add examples from each category (limited for card space)
    for category, patterns in pattern_categories.items():
        for pattern_coords, _, use_case in patterns[:1]:  # Just first from each category
            coords = pattern_coords.split()
            password = "".join([grid.get_token(coord) for coord in coords])

            if separators:
                # Add separators between tokens
                formatted_password = "-".join([grid.get_token(coord) for coord in coords])
            else:
                formatted_password = password

            table.add_row(category.split()[0], pattern_coords, formatted_password, use_case)

    console.print(table)

    if include_memorized:
        # Generate sample memorized words
        from ...core.word_generator import WordGenerator
        sample_words = WordGenerator.generate_word_list(seed_bytes, memorized_length, 3)

        console.print(f"\n[bold]📝 Memorized Components ({memorized_length} chars):[/bold]")
        console.print(f"Examples: [green]{sample_words[0]}[/green], [green]{sample_words[1]}[/green], [green]{sample_words[2]}[/green]")
        console.print(f"Format: [cyan]A0-B1-{sample_words[0]}![/cyan] or [cyan]{sample_words[0]}A0B1[/cyan]")


def _print_sheet_format_examples(
    grid: SeederGrid,
    pattern_categories: dict[str, list[tuple[str, str, str]]],
    include_memorized: bool,
    memorized_length: int,
    separators: bool,
    seed_bytes: bytes,
    fixed: int,
    rolling: int,
    separator_count: int,
    rotation_days: int,
    no_order: bool
) -> None:
    """Print detailed examples for reference sheet."""
    console.print("\n[bold blue]📋 Comprehensive Password Reference Sheet[/bold blue]")

    for category, patterns in pattern_categories.items():
        console.print(f"\n[bold cyan]== {category} ==[/bold cyan]")

        table = Table(show_header=True, header_style="bold yellow")
        table.add_column("Pattern", style="white", width=15)
        table.add_column("Password", style="green", width=20)
        table.add_column("With Separators", style="blue", width=25)
        table.add_column("Description", style="dim", width=25)

        for pattern_coords, name, description in patterns:
            coords = pattern_coords.split()
            password = "".join([grid.get_token(coord) for coord in coords])

            if separators:
                with_seps = "-".join([grid.get_token(coord) for coord in coords])
            else:
                with_seps = "N/A"

            table.add_row(pattern_coords, password, with_seps, f"{name} - {description}")

        console.print(table)

    if include_memorized:
        console.print("\n[bold magenta]🧠 Memorized Word Integration[/bold magenta]")
        from ...core.word_generator import WordGenerator
        sample_words = WordGenerator.generate_word_list(seed_bytes, memorized_length, 5)

        # Show different combination formats
        example_pattern = "A0 B1 C2"
        example_tokens = [grid.get_token(coord) for coord in example_pattern.split()]
        base_password = "".join(example_tokens)

        formats_table = Table(title="Memorized Word Formats", show_header=True, header_style="bold green")
        formats_table.add_column("Format", style="cyan", width=20)
        formats_table.add_column("Example", style="green", width=30)
        formats_table.add_column("Description", style="dim", width=30)

        formats_table.add_row("Tokens + Word", f"{base_password}{sample_words[0]}", "Concatenated format")
        formats_table.add_row("Word + Tokens", f"{sample_words[0]}{base_password}", "Word first format")
        formats_table.add_row("Separated", f"{'-'.join(example_tokens)}-{sample_words[0]}", "Dash-separated format")
        formats_table.add_row("Mixed Case", f"{sample_words[0].upper()}{base_password.lower()}", "Case variation")
        formats_table.add_row("With Symbols", f"{sample_words[0]}!{base_password}?", "Symbol padding")

        console.print(formats_table)


def _print_compact_format_examples(
    grid: SeederGrid,
    pattern_categories: dict[str, list[tuple[str, str, str]]],
    include_memorized: bool,
    memorized_length: int,
    separators: bool,
    fixed: int,
    rolling: int,
    separator_count: int,
    rotation_days: int,
    no_order: bool
) -> None:
    """Print very compact examples for minimal space."""
    console.print("\n[bold]🎯 Quick Examples[/bold]")

    # Just show the most essential patterns
    essential_patterns = [
        ("A0 B1 C2", "Diagonal"),
        ("A0 A1 A2", "Row"),
        ("B3 F7 D1", "Scattered"),
    ]

    for pattern_coords, name in essential_patterns:
        coords = pattern_coords.split()
        password = "".join([grid.get_token(coord) for coord in coords])
        console.print(f"[cyan]{pattern_coords}[/cyan] → [green]{password}[/green] ({name})")

    if include_memorized:
        console.print(f"\n[dim]+ Add {memorized_length}-char word: wordA0B1 or A0B1word[/dim]")


def _print_text_format_examples(
    grid: SeederGrid,
    pattern_categories: dict[str, list[tuple[str, str, str]]],
    include_memorized: bool,
    memorized_length: int,
    separators: bool,
    seed_bytes: bytes,
    fixed: int,
    rolling: int,
    separator_count: int,
    rotation_days: int,
    no_order: bool
) -> None:
    """Print plain text examples for copy/paste into card designer."""

    print("PASSWORD EXAMPLES")
    print("================")
    print()

    # Print all patterns as plain text
    for category, patterns in pattern_categories.items():
        print(f"{category.upper()}:")
        print("-" * len(category))

        for pattern_coords, _, description in patterns:
            coords = pattern_coords.split()
            password = "".join([grid.get_token(coord) for coord in coords])

            if separators:
                password_with_sep = "-".join([grid.get_token(coord) for coord in coords])
                print(f"{pattern_coords:<12} = {password:<16} (or {password_with_sep})")
            else:
                print(f"{pattern_coords:<12} = {password:<16}")
            print(f"             {description}")
        print()

    if include_memorized:
        # Generate sample memorized words
        from ...core.word_generator import WordGenerator
        sample_words = WordGenerator.generate_word_list(seed_bytes, memorized_length, 3)

        print(f"MEMORIZED WORDS ({memorized_length} characters):")
        print("-" * 25)
        for i, word in enumerate(sample_words, 1):
            print(f"{i}. {word}")
        print()

        print("COMBINATION FORMATS:")
        print("-------------------")
        example_pattern = "A0 B1 C2"
        example_tokens = [grid.get_token(coord) for coord in example_pattern.split()]
        base_password = "".join(example_tokens)

        print(f"Tokens first:    {base_password}{sample_words[0]}")
        print(f"Word first:      {sample_words[0]}{base_password}")
        print(f"With dashes:     {'-'.join(example_tokens)}-{sample_words[0]}")
        print(f"With symbols:    {sample_words[0]}!{base_password}?")
        print()

    print("USAGE INSTRUCTIONS:")
    print("==================")
    print("1. Choose a pattern you can remember")
    print("2. Find the coordinates on your card")
    print("3. Concatenate the tokens at those positions")
    print("4. Optionally add separators (-) between tokens")
    print("5. Consider adding a memorized word component")
    print()
    print("SECURITY LEVELS:")
    print("===============")
    print("• 3 tokens  = Medium security (most online services)")
    print("• 4+ tokens = High security (financial/critical)")
    print("• Scattered patterns > predictable rows/columns")
    print("• Add memorized words for maximum security")
    print()

    # Show comprehensive composite password examples using the options
    print("COMPOSITE PASSWORD VARIATIONS:")
    print("=============================")

    # Add password structure explanation
    print("PASSWORD STRUCTURE EXPLAINED:")
    print("----------------------------")
    if include_memorized:
        print("Structure: [FixedToken1][Sep1][FixedToken2][Sep2][RollingToken][Sep3][MemWord][Sep4]")
        print("Shorthand: F1-F2-R1-MW!")
        print()
        # Get actual tokens for a concrete example
        example_fixed = ["A0", "B1"] if fixed >= 2 else ["A0"]
        example_rolling = ["C2"] if rolling >= 1 else []

        fixed_tokens = [grid.get_token(coord) for coord in example_fixed]
        rolling_tokens = [grid.get_token(coord) for coord in example_rolling] if example_rolling else []

        from ...core.word_generator import WordGenerator
        sample_words = WordGenerator.generate_word_list(seed_bytes, memorized_length, 1)
        word = sample_words[0]

        # Build concrete example
        all_tokens = fixed_tokens + rolling_tokens
        if separators:
            concrete_example = "-".join(all_tokens) + f"-{word}!"
            shorthand_example = "-".join([f"F{i+1}" for i in range(len(fixed_tokens))] +
                                       [f"R{i+1}" for i in range(len(rolling_tokens))]) + "-MW!"
        else:
            concrete_example = "".join(all_tokens) + word
            shorthand_example = "".join([f"F{i+1}" for i in range(len(fixed_tokens))] +
                                      [f"R{i+1}" for i in range(len(rolling_tokens))]) + "MW"

        print(f"Example:   {concrete_example}")
        print(f"Shorthand: {shorthand_example}")
        print()
        print("Components Explained:")
        print(f"  • Fixed Tokens (F1, F2...): Always use same coordinates ({', '.join(example_fixed)})")
        print(f"  • Rolling Token (R1...): Changes every {rotation_days} days ({example_rolling[0] if example_rolling else 'none'})")
        print(f"  • Memorized Word (MW): Your chosen word ({word})")
        print("  • Separators: Dashes (-) and symbols (!) for readability")
    else:
        print("Structure: [FixedToken1][Sep1][FixedToken2][Sep2][RollingToken]")
        print("Shorthand: F1-F2-R1")
        print()
        # Simpler example without memorized words
        example_fixed = ["A0", "B1"] if fixed >= 2 else ["A0"]
        example_rolling = ["C2"] if rolling >= 1 else []

        fixed_tokens = [grid.get_token(coord) for coord in example_fixed]
        rolling_tokens = [grid.get_token(coord) for coord in example_rolling] if example_rolling else []

        all_tokens = fixed_tokens + rolling_tokens
        if separators:
            concrete_example = "-".join(all_tokens)
            shorthand_example = "-".join([f"F{i+1}" for i in range(len(fixed_tokens))] +
                                       [f"R{i+1}" for i in range(len(rolling_tokens))])
        else:
            concrete_example = "".join(all_tokens)
            shorthand_example = "".join([f"F{i+1}" for i in range(len(fixed_tokens))] +
                                      [f"R{i+1}" for i in range(len(rolling_tokens))])

        print(f"Example:   {concrete_example}")
        print(f"Shorthand: {shorthand_example}")
        print()
        print("Components Explained:")
        print(f"  • Fixed Tokens (F1, F2...): Always use same coordinates ({', '.join(example_fixed)})")
        if example_rolling:
            print(f"  • Rolling Token (R1...): Changes every {rotation_days} days ({example_rolling[0]})")
        print("  • Separators: Dashes (-) for readability")
    print()

    # Show different pattern combinations based on fixed/rolling configuration
    print(f"Configuration: {fixed} fixed + {rolling} rolling tokens, {separator_count} separators")
    print()

    # Generate examples with different patterns
    fixed_patterns = [
        ("A0 B1", "Top-left start"),
        ("E5 F5", "Center row"),
        ("H3 I4", "Right side"),
    ]

    # Adjust patterns based on the fixed token count
    if fixed == 1:
        fixed_patterns = [
            ("A0", "Top-left"),
            ("E5", "Center"),
            ("H3", "Right side"),
        ]
    elif fixed == 3:
        fixed_patterns = [
            ("A0 B1 C2", "Top diagonal"),
            ("E5 F5 G5", "Center row"),
            ("H3 I4 J5", "Right diagonal"),
        ]
    elif fixed == 4:
        fixed_patterns = [
            ("A0 B1 C2 D3", "Main diagonal"),
            ("E4 E5 E6 E7", "Center line"),
            ("G7 H7 I7 J7", "Bottom line"),
        ]

    # Adjust rolling patterns based on rolling token count
    if rolling == 1:
        rolling_patterns = [
            ("C2", "Today"),
            ("D3", "Next rotation"),
            ("G7", "Alternative"),
        ]
    elif rolling == 2:
        rolling_patterns = [
            ("C2 D2", "Today"),
            ("E4 F4", "Next rotation"),
            ("G7 H7", "Alternative"),
        ]
    else:  # rolling >= 3
        rolling_patterns = [
            ("C2 D2 E2", "Today"),
            ("F4 G4 H4", "Next rotation"),
            ("I6 J6 A7", "Alternative"),
        ]

    print("PATTERN COMBINATIONS:")
    print("--------------------")

    for i, (fixed_pattern, fixed_desc) in enumerate(fixed_patterns, 1):
        fixed_tokens = [grid.get_token(coord) for coord in fixed_pattern.split()]

        for _, (rolling_pattern, rolling_desc) in enumerate(rolling_patterns[:1], 1):  # Show first rolling option
            rolling_tokens = [grid.get_token(coord) for coord in rolling_pattern.split()]

            base_password = "".join(fixed_tokens + rolling_tokens)
            separators_str = "!" * separator_count

            print(f"{i}. Fixed: {fixed_pattern} = {''.join(fixed_tokens)} ({fixed_desc})")
            print(f"   Rolling: {rolling_pattern} = {''.join(rolling_tokens)} ({rolling_desc})")

            if include_memorized:
                from ...core.word_generator import WordGenerator
                sample_words = WordGenerator.generate_word_list(seed_bytes, memorized_length, 1)
                word = sample_words[0]

                print(f"   Memorized: {word}")
                print(f"   Separators: {separators_str}")
                print()
                print("   Examples:")
                print(f"     Simple:     {base_password}{word}")
                print(f"     Separated:  {'!'.join(fixed_tokens)}!{''.join(rolling_tokens)}!{word}")
                print(f"     Word first: {word}!{base_password}")
                print(f"     Complex:    {word}{separators_str}{'!'.join(fixed_tokens)}!{''.join(rolling_tokens)}")
            else:
                print(f"   Separators: {separators_str}")
                print()
                print("   Examples:")
                print(f"     Simple:     {base_password}")
                print(f"     Separated:  {'!'.join(fixed_tokens)}!{''.join(rolling_tokens)}")
                print(f"     With seps:  {base_password}{separators_str}")
                print(f"     Complex:    {separators_str}{'!'.join(fixed_tokens)}!{''.join(rolling_tokens)}")
            print()

    print("ROTATION SCHEDULE:")
    print("-----------------")
    print(f"• Rolling tokens change every {rotation_days} days")
    print("• Fixed tokens stay the same (memorize these coordinates)")
    print("• Separators and memorized words stay the same")
    print("• Only the rolling token positions change")
    print()

    print("EXAMPLE ROTATION:")
    print("----------------")
    example_fixed = "A0 B1"
    example_rolling_positions = ["C2", "D3", "E4", "F5"]
    fixed_tokens = [grid.get_token(coord) for coord in example_fixed.split()]

    print(f"Fixed part (always): {example_fixed} = {''.join(fixed_tokens)}")
    print("Rolling part rotates:")
    for i, pos in enumerate(example_rolling_positions):
        rolling_token = grid.get_token(pos)
        days = i * rotation_days
        print(f"  Days {days:3d}-{days+rotation_days-1:3d}: {pos} = {rolling_token}")
    print()
    print()
