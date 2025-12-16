"""Physical dice entropy collection with base-6 encoding.

This module collects entropy from physical casino dice rolls.
Uses base-6 encoding for efficient entropy extraction from standard dice.

ENTROPY EXPLANATION:
- Physical dice rolls are fundamentally random events governed by chaotic physics
- Each die roll has 6 equally probable outcomes (assuming fair dice)
- Each single die: log2(6) ≈ 2.585 bits of entropy
- Five dice rolled together: log2(6^5) = log2(7776) ≈ 12.92 bits of entropy
- 198 rolls of 5 dice = ~2560 bits of entropy (more than 512 bits target)
- Physical randomness is considered true entropy (not pseudorandom)
"""

import math
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.prompt import Prompt


class DiceEntropyError(Exception):
    """Error during dice entropy collection."""
    pass


def base6_to_bytes(base6_digits: list[int]) -> bytes:
    """Convert base-6 digits to bytes.
    
    Args:
        base6_digits: List of integers 0-5 (representing dice values 1-6 as 0-5)
        
    Returns:
        Bytes representation of the base-6 number
    """
    if not base6_digits:
        return b''
    
    # Convert base-6 digits to a large integer
    value = 0
    for digit in base6_digits:
        value = value * 6 + digit
    
    # Convert integer to bytes
    byte_length = (value.bit_length() + 7) // 8
    if byte_length == 0:
        return b'\x00'
    
    return value.to_bytes(byte_length, byteorder='big')


def calculate_rolls_needed(target_bits: int, dice_count: int = 5) -> int:
    """Calculate number of rolls needed for target entropy.
    
    Args:
        target_bits: Target entropy in bits
        dice_count: Number of dice per roll (1-5, default 5)
        
    Returns:
        Number of rolls required
    """
    # Entropy per roll: log2(6^dice_count)
    bits_per_roll = dice_count * math.log2(6)
    rolls_needed = math.ceil(target_bits / bits_per_roll)
    return rolls_needed


def collect_dice_entropy(
    bits: int = 512,
    dice_count: int = 5,
) -> bytes:
    """Collect entropy from physical dice rolls.
    
    Physical dice rolls provide true randomness from chaotic physics.
    Each die face (1-6) has equal probability, providing log2(6) ≈ 2.585 bits
    of entropy per die. Multiple dice multiply the possibilities exponentially.
    
    Entropy per roll:
    - 1 die: ~2.585 bits
    - 2 dice: ~5.170 bits
    - 5 dice: ~12.92 bits
    
    Args:
        bits: Target entropy in bits (minimum 256)
        dice_count: Number of dice per roll (1-5, default 5 for efficiency)
        
    Returns:
        Entropy bytes derived from dice rolls
        
    Raises:
        DiceEntropyError: If collection fails
        ValueError: If bits < 256 or dice_count invalid
    """
    if bits < 256:
        raise ValueError("Minimum 256 bits required for cryptographic entropy")
    
    if dice_count < 1 or dice_count > 5:
        raise ValueError("dice_count must be between 1 and 5")
    
    console = Console()
    
    # Calculate rolls needed
    rolls_needed = calculate_rolls_needed(bits, dice_count)
    bits_per_roll = dice_count * math.log2(6)
    
    console.print("\n[bold cyan]Dice Entropy Collection[/bold cyan]")
    console.print(f"Target: {bits} bits")
    console.print(f"Dice per roll: {dice_count}")
    console.print(f"Entropy per roll: {bits_per_roll:.2f} bits")
    console.print(f"Rolls needed: {rolls_needed}")
    console.print(f"\n[yellow]Roll {dice_count} dice together and enter the values (1-6)[/yellow]")
    console.print(f"[dim]Example for {dice_count} dice: {''.join(['1' for _ in range(dice_count)])} or {''.join(['6' for _ in range(dice_count)])}[/dim]\n")
    
    # Collect rolls
    base6_digits: list[int] = []
    
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total} rolls)"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting entropy", total=rolls_needed)
        
        for roll_num in range(rolls_needed):
            while True:
                # Prompt for dice values
                prompt_text = f"Roll {roll_num + 1}/{rolls_needed}"
                roll_str = Prompt.ask(prompt_text)
                
                # Validate input
                roll_str = roll_str.strip().replace(' ', '').replace(',', '')
                
                if len(roll_str) != dice_count:
                    console.print(f"[red]Error: Expected {dice_count} digits, got {len(roll_str)}[/red]")
                    continue
                
                try:
                    digits = [int(d) for d in roll_str]
                except ValueError:
                    console.print("[red]Error: Only digits 1-6 allowed[/red]")
                    continue
                
                if not all(1 <= d <= 6 for d in digits):
                    console.print("[red]Error: Each die must show 1-6[/red]")
                    continue
                
                # Convert to base-6 (0-5)
                base6_roll = [d - 1 for d in digits]
                base6_digits.extend(base6_roll)
                
                progress.update(task, advance=1)
                break
    
    # Convert base-6 digits to bytes
    entropy_bytes = base6_to_bytes(base6_digits)
    
    # Ensure we have enough bytes
    target_bytes = (bits + 7) // 8
    if len(entropy_bytes) < target_bytes:
        # Pad with zeros if needed (shouldn't happen with proper calculation)
        entropy_bytes = entropy_bytes + b'\x00' * (target_bytes - len(entropy_bytes))
    
    # Truncate to exact byte count
    entropy_bytes = entropy_bytes[:target_bytes]
    
    # Show summary
    actual_bits = len(entropy_bytes) * 8
    console.print(f"\n[green]✓[/green] Collected {len(entropy_bytes)} bytes ({actual_bits} bits) from {rolls_needed} rolls")
    
    return entropy_bytes


def estimate_collection_time(bits: int, dice_count: int = 5) -> tuple[int, float]:
    """Estimate time to collect entropy from dice.
    
    Args:
        bits: Target entropy in bits
        dice_count: Number of dice per roll
        
    Returns:
        Tuple of (rolls_needed, estimated_minutes)
    """
    rolls_needed = calculate_rolls_needed(bits, dice_count)
    
    # Assume ~5 seconds per roll (pick up dice, roll, record)
    estimated_seconds = rolls_needed * 5.0
    estimated_minutes = estimated_seconds / 60.0
    
    return (rolls_needed, estimated_minutes)
