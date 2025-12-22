"""
Analyze commands for Seeder CLI.

Commands for analyzing password entropy and security.
"""

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

# Add the parent directory to Python path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from ...core.config import BASE_CONFIGS
    from ...core.crypto import PasswordEntropyAnalyzer
    from ..display import print_error_message
    from ..helpers import validate_coordinates
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("💡 Make sure you're running from the Seeder directory")
    sys.exit(1)

console = Console()

# Create the analyze app
analyze_app = typer.Typer(help="🔍 Analyze password entropy and security (RFC 4086 compliant)")


@analyze_app.command("entropy")
def analyze_entropy(
    pattern: str = typer.Argument(..., help="Coordinate pattern (e.g., 'A0 B1 C2 D3')"),
    online_rate: int = typer.Option(1000, "--online-rate", help="Online attack rate (guesses/sec)"),
    offline_rate: int = typer.Option(1000000, "--offline-rate", help="Offline attack rate (guesses/sec)")
):
    """🔍 Analyze password entropy for a coordinate pattern."""
    try:
        # Parse and validate coordinates
        coordinates = pattern.strip().split()
        coordinates = validate_coordinates(coordinates)

        # Analyze the pattern
        analysis = PasswordEntropyAnalyzer.analyze_coordinate_pattern(coordinates)

        # Create main analysis table
        table = Table(title="🔍 Password Entropy Analysis", show_header=True, header_style="bold blue")
        table.add_column("Property", style="bold yellow", width=25)
        table.add_column("Value", style="white", width=30)
        table.add_column("Details", style="dim", width=40)

        # Add rows to table
        table.add_row("Pattern", " ".join(coordinates), "Coordinate sequence")
        table.add_row("Tokens", str(analysis["num_tokens"]), "Number of tokens in password")
        table.add_row("Token Entropy", f"{analysis['token_entropy_bits']} bits/token", f"Base90 alphabet ({analysis['alphabet_size']} chars)")
        table.add_row("Total Token Entropy", f"{analysis['total_token_entropy']} bits", "Combined entropy from all tokens")
        table.add_row("Pattern Entropy", f"{analysis['pattern_entropy_bits']} bits", "Coordinate selection entropy")
        table.add_row("Effective Entropy", f"{analysis['effective_entropy_bits']} bits", "Limiting factor (weaker of token/pattern)")

        # Security level with color
        security_color = analysis["security_color"]
        table.add_row("Security Level", f"[{security_color}]{analysis['security_level']}[/{security_color}]", "Based on effective entropy")

        console.print(table)

        # Attack scenario analysis
        online_attack = analysis["online_attack"]
        offline_attack = analysis["offline_attack"]

        # Online attack table
        online_table = Table(title="🌐 Online Attack Analysis", show_header=True, header_style="bold green")
        online_table.add_column("Metric", style="bold yellow")
        online_table.add_column("Value", style="white")

        online_table.add_row("Attack Rate", f"{online_rate:,} guesses/sec")
        online_table.add_row("Total Combinations", online_attack["total_combinations"])
        online_table.add_row("Average Crack Time", online_attack["avg_crack_time"])
        online_table.add_row("Worst Case (99%)", online_attack["worst_crack_time"])

        console.print(online_table)

        # Offline attack table
        offline_table = Table(title="💻 Offline Attack Analysis", show_header=True, header_style="bold red")
        offline_table.add_column("Metric", style="bold yellow")
        offline_table.add_column("Value", style="white")

        offline_table.add_row("Attack Rate", f"{offline_rate:,} guesses/sec")
        offline_table.add_row("Total Combinations", offline_attack["total_combinations"])
        offline_table.add_row("Average Crack Time", offline_attack["avg_crack_time"])
        offline_table.add_row("Worst Case (99%)", offline_attack["worst_crack_time"])

        console.print(offline_table)

        # Security recommendations
        effective_entropy = float(analysis["effective_entropy_bits"])
        console.print("\n🛡️  Security Recommendations:", style="bold cyan")

        if effective_entropy < 25:
            console.print("⚠️  [red]Low security pattern[/red] - Consider using more tokens or less predictable coordinates")
        elif effective_entropy < 35:
            console.print("⚡ [yellow]Medium security pattern[/yellow] - Acceptable for most online services with rate limiting")
        else:
            console.print("✅ [green]High security pattern[/green] - Strong protection against online attacks")

        console.print("\n💡 Tips:")
        console.print("• Use 4+ tokens for better security")
        console.print("• Avoid predictable patterns (rows, columns, diagonals)")
        console.print("• Scatter coordinates across the grid")
        console.print("• Always use 2FA for sensitive accounts")

    except Exception as e:
        print_error_message(f"Error: {e}")
        raise typer.Exit(1)


@analyze_app.command("compare")
def analyze_compare(
    patterns: list[str] = typer.Argument(..., help="Multiple patterns to compare (e.g., 'A0 B1' 'C2 D3')")
):
    """🔍 Compare entropy of multiple coordinate patterns."""
    try:
        analyses = []

        for pattern in patterns:
            coordinates = pattern.strip().split()
            coordinates = validate_coordinates(coordinates)
            analysis = PasswordEntropyAnalyzer.analyze_coordinate_pattern(coordinates)
            analysis["pattern_string"] = " ".join(coordinates)
            analyses.append(analysis)

        # Create comparison table
        table = Table(title="🔍 Pattern Entropy Comparison", show_header=True, header_style="bold blue")
        table.add_column("#", style="bold yellow", width=3)
        table.add_column("Pattern", style="cyan", width=20)
        table.add_column("Tokens", style="white", width=8)
        table.add_column("Effective Entropy", style="white", width=15)
        table.add_column("Security Level", style="white", width=15)
        table.add_column("Online Crack Time", style="white", width=20)

        for i, analysis in enumerate(analyses, 1):
            security_color = analysis["security_color"]
            security_text = f"[{security_color}]{analysis['security_level']}[/{security_color}]"

            table.add_row(
                str(i),
                analysis["pattern_string"],
                str(analysis["num_tokens"]),
                f"{analysis['effective_entropy_bits']} bits",
                security_text,
                analysis["online_attack"]["avg_crack_time"]
            )

        console.print(table)

        # Find best and worst patterns
        best_entropy = max(float(a["effective_entropy_bits"]) for a in analyses)
        worst_entropy = min(float(a["effective_entropy_bits"]) for a in analyses)

        console.print(f"\n🏆 Best pattern: {best_entropy:.1f} bits entropy")
        console.print(f"⚠️  Worst pattern: {worst_entropy:.1f} bits entropy")
        console.print(f"📊 Entropy range: {best_entropy - worst_entropy:.1f} bits difference")

    except Exception as e:
        print_error_message(f"Error: {e}")
        raise typer.Exit(1)


@analyze_app.command("composite")
def analyze_composite_password(
    fixed: int = typer.Option(2, "--fixed", help="Number of fixed tokens from grid"),
    rolling: int = typer.Option(1, "--rolling", help="Number of rolling/rotating tokens"),
    memorized: int = typer.Option(6, "--memorized", help="Length of memorized word component"),
    separators: int = typer.Option(3, "--separators", help="Number of separator characters"),
    rotation_days: int = typer.Option(90, "--rotation-days", help="Days between rolling token changes"),
    no_order: bool = typer.Option(False, "--no-order", help="Exclude component ordering entropy")
):
    """🔍 Analyze composite password entropy (tokens + memorized components)."""
    try:
        include_order = not no_order

        analysis = PasswordEntropyAnalyzer.analyze_composite_password(
            num_fixed_tokens=fixed,
            num_rolling_tokens=rolling,
            memorized_word_length=memorized,
            num_separators=separators,
            rotation_days=rotation_days,
            include_order_entropy=include_order
        )

        # Create detailed breakdown table
        table = Table(title="🔍 Composite Password Analysis", show_header=True, header_style="bold blue")
        table.add_column("Component", style="cyan", width=20)
        table.add_column("Value", style="white", width=15)
        table.add_column("Entropy", style="green", width=15)
        table.add_column("Notes", style="dim", width=35)

        # Add component rows
        table.add_row("Fixed Tokens", str(fixed), f"{float(analysis['fixed_token_entropy']):.1f} bits", "Static grid tokens")
        table.add_row("Rolling Tokens", str(rolling), f"{float(analysis['rolling_token_entropy']):.1f} bits", "Periodically rotating tokens")
        table.add_row("Memorized Word", f"{memorized} chars", f"{float(analysis['memorized_word_entropy']):.1f} bits", "User-memorized component")
        table.add_row("Separators", str(separators), f"{float(analysis['separator_entropy']):.1f} bits", "Punctuation characters")

        if include_order:
            table.add_row("Order Entropy", "Variable", f"{float(analysis['order_entropy']):.1f} bits", "Component arrangement")

        # Total row
        table.add_row("", "", "", "", style="dim")
        table.add_row("[bold]TOTAL[/bold]", "", f"[bold green]{float(analysis['total_entropy']):.1f} bits[/bold green]",
                     f"[bold]{analysis['security_level']}[/bold]")

        console.print(table)

        # Security assessment
        total_bits = float(analysis['total_entropy'])
        if total_bits >= 80:
            security_color = "bright_green"
            security_level = "EXCELLENT"
        elif total_bits >= 64:
            security_color = "green"
            security_level = "STRONG"
        elif total_bits >= 48:
            security_color = "yellow"
            security_level = "GOOD"
        elif total_bits >= 29:
            security_color = "orange"
            security_level = "BASIC"
        else:
            security_color = "red"
            security_level = "INSUFFICIENT"

        console.print(f"\n🛡️  Security Level: [{security_color}]{security_level}[/{security_color}]")
        console.print(f"📊 Format: {fixed} fixed + {rolling} rolling + {memorized}-char word + {separators} separators")

        # Practical recommendations
        console.print("\n💡 Recommendations:")
        if total_bits < 48:
            console.print("• Consider increasing memorized word length")
            console.print("• Add more fixed tokens from grid")
        elif total_bits < 64:
            console.print("• Strong for most use cases")
            console.print("• Consider 2FA for high-value accounts")
        else:
            console.print("• Excellent security for online accounts")
            console.print("• Suitable for high-value targets with 2FA")

    except Exception as e:
        print_error_message(f"Error: {e}")
        raise typer.Exit(1)


@analyze_app.command("threat")
def analyze_threat_scenarios(
    fixed: int = typer.Option(2, "--fixed", help="Number of fixed tokens from grid"),
    rolling: int = typer.Option(1, "--rolling", help="Number of rolling tokens"),
    memorized: int = typer.Option(6, "--memorized", help="Length of memorized word component"),
    separators: int = typer.Option(3, "--separators", help="Number of separator characters"),
    no_order: bool = typer.Option(False, "--no-order", help="Exclude component ordering entropy")
):
    """🚨 Analyze threat scenarios (matrix compromised vs. secrets intact)."""
    try:
        include_order = not no_order

        # Analyze compromised card scenario
        threat_analysis = PasswordEntropyAnalyzer.analyze_compromised_card_scenario(
            num_fixed_tokens=fixed,
            num_rolling_tokens=rolling,
            memorized_word_length=memorized,
            num_separators=separators,
            include_order_entropy=include_order
        )

        # Create threat scenarios table
        table = Table(title="🚨 Threat Analysis Matrix", show_header=True, header_style="bold red")
        table.add_column("Scenario", style="cyan", width=25)
        table.add_column("Attacker Knowledge", style="yellow", width=30)
        table.add_column("Remaining Entropy", style="green", width=18)
        table.add_column("Security Level", style="white", width=20)

        # Scenario 1: Full security (nothing compromised)
        full_entropy = float(threat_analysis['full_entropy'])
        full_color = "bright_green" if full_entropy >= 64 else "green" if full_entropy >= 48 else "yellow"
        table.add_row(
            "🛡️  Full Security",
            "Nothing compromised",
            f"{full_entropy:.1f} bits",
            f"[{full_color}]STRONG[/{full_color}]"
        )

        # Scenario 2: Card compromised but secrets intact
        card_entropy = float(threat_analysis['compromised_entropy'])
        card_color = "green" if card_entropy >= 29 else "yellow" if card_entropy >= 20 else "red"
        card_level = "ADEQUATE" if card_entropy >= 29 else "WEAK" if card_entropy >= 20 else "CRITICAL"
        table.add_row(
            "🎴 Card Compromised",
            "Grid visible, secrets intact",
            f"{card_entropy:.1f} bits",
            f"[{card_color}]{card_level}[/{card_color}]"
        )

        # For the other scenarios, let me calculate them based on the analysis
        # Scenario 3: Memorized word compromised (remove memorized entropy)
        memo_entropy = full_entropy - float(threat_analysis['memorized_entropy'])
        memo_color = "green" if memo_entropy >= 48 else "yellow" if memo_entropy >= 29 else "red"
        memo_level = "STRONG" if memo_entropy >= 48 else "BASIC" if memo_entropy >= 29 else "WEAK"
        table.add_row(
            "🧠 Word Compromised",
            "Memorized component known",
            f"{memo_entropy:.1f} bits",
            f"[{memo_color}]{memo_level}[/{memo_color}]"
        )

        # Scenario 4: Both compromised (worst case) - only coordinate selection and order remain
        worst_entropy = float(threat_analysis['coordinate_selection_entropy']) + float(threat_analysis['order_entropy'])
        worst_color = "red" if worst_entropy < 10 else "yellow"
        worst_level = "CRITICAL" if worst_entropy < 10 else "MINIMAL"
        table.add_row(
            "💥 Both Compromised",
            "Grid + memorized word known",
            f"{worst_entropy:.1f} bits",
            f"[{worst_color}]{worst_level}[/{worst_color}]"
        )

        console.print(table)

        # Threat assessment summary
        console.print("\n📊 Threat Assessment Summary:")
        console.print(f"• Format: {fixed} fixed + {rolling} rolling + {memorized}-char word + {separators} separators")
        console.print(f"• Vulnerability ratio: {threat_analysis['vulnerability_ratio']}")
        console.print(f"• Entropy loss if card compromised: {threat_analysis['entropy_loss']} bits")

        # Security recommendations based on weakest link
        min_entropy = min(card_entropy, memo_entropy)
        console.print("\n💡 Security Recommendations:")

        if min_entropy < 20:
            console.print("⚠️  [red]HIGH RISK[/red]: System vulnerable to focused attacks")
            console.print("• Immediately implement 2FA or additional authentication")
            console.print("• Consider increasing memorized word length")
            console.print("• Add more tokens to password format")
        elif min_entropy < 29:
            console.print("⚠️  [yellow]MODERATE RISK[/yellow]: Adequate for rate-limited systems")
            console.print("• Strongly recommend 2FA for important accounts")
            console.print("• Monitor for unusual login activity")
        else:
            console.print("✅ [green]ACCEPTABLE RISK[/green]: Good security with proper usage")
            console.print("• 2FA recommended for high-value targets")
            console.print("• Regular password rotation advised")

    except Exception as e:
        print_error_message(f"Error: {e}")
        raise typer.Exit(1)


@analyze_app.command("bases")
def analyze_bases(
    num_tokens: int = typer.Option(4, "--tokens", "-t", help="Number of tokens in password")
):
    """🔍 Compare entropy across different base systems."""
    try:
        console.print("\n📊 Token Entropy Comparison\n", style="bold cyan")

        # Create comparison table
        table = Table(show_header=True, header_style="bold blue")
        table.add_column("Base System", style="bold yellow", width=15)
        table.add_column("Alphabet", style="white", width=25)
        table.add_column("Per-Token", style="green", width=15)
        table.add_column(f"For {num_tokens} Tokens", style="cyan", width=18)
        table.add_column("Description", style="dim", width=30)

        for base_name, base_config in BASE_CONFIGS.items():
            alphabet = base_config["alphabet"]
            alphabet_size = len(alphabet)

            # Calculate entropy for this base
            per_token_entropy = PasswordEntropyAnalyzer.calculate_token_entropy(alphabet_size)
            total_entropy = PasswordEntropyAnalyzer.calculate_password_entropy(num_tokens, alphabet_size)

            # Show sample alphabet (first 20 chars)
            sample = "".join(alphabet[:20])
            if len(alphabet) > 20:
                sample += "..."

            table.add_row(
                base_name.capitalize(),
                sample,
                f"{per_token_entropy:.1f} bits",
                f"{total_entropy:.1f} bits",
                base_config["description"]
            )

        console.print(table)

        # Summary info
        console.print("\n💡 Notes:", style="bold yellow")
        console.print("• Base10 (PIN mode) reduces entropy but provides simpler memorization")
        console.print("• Base62 balances between security and usability")
        console.print("• Base90 provides maximum entropy with full character set")
        console.print("• All modes generate 4-character tokens from 10×10 grid")

    except Exception as e:
        print_error_message(f"Error: {e}")
        raise typer.Exit(1)
