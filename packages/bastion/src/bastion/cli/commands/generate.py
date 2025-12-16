"""Generate command helpers for Bastion CLI.

This module contains the logic for the generate command subcommands:
- generate mermaid (diagram generation)
- generate username (deterministic username generation)
- generate entropy (entropy pool creation)
"""

from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
import typer

from ...models import Database
from ...username_generator import UsernameGenerator, UsernameGeneratorConfig, LabelParser
from ...mermaid import generate_mermaid_diagram
from ..commands.entropy import generate_entropy
from ...entropy import EntropyPool
from ...entropy_infnoise import check_infnoise_available
from ...entropy_yubikey import check_yubikey_available

console = Console()


def generate_mermaid(
    db: Database,
    output_path: Path,
) -> None:
    """Generate a mermaid diagram from the database.
    
    Args:
        db: Password rotation database
        output_path: Path to write the diagram to
    """
    generate_mermaid_diagram(db, output_path)
    console.print(f"[green]✅ Mermaid diagram generated: {output_path}[/green]")


def username_init(
    generator: UsernameGenerator,
    vault: str,
    entropy_source: str | None,
) -> None:
    """Initialize username generator with salt.
    
    Args:
        generator: UsernameGenerator instance
        vault: 1Password vault name
        entropy_source: Optional entropy pool UUID
    """
    console.print("[cyan]Initializing username generator...[/cyan]")
    
    # Check if salt already exists
    salt_result = generator.get_latest_salt_by_serial()
    if salt_result:
        salt_value, salt_uuid_val, serial = salt_result
        console.print(f"[green]✅ Salt already exists: {generator.SALT_ITEM_PREFIX} #{serial}[/green]")
        console.print(f"[dim]UUID: {salt_uuid_val}[/dim]")
        console.print(f"[dim]Salt preview (first 16 chars): {salt_value[:16]}...[/dim]")
        return
    
    # Determine entropy source for salt
    selected_entropy_uuid = entropy_source
    
    if not selected_entropy_uuid:
        selected_entropy_uuid = _prompt_entropy_source(vault)
    
    # Create salt with selected entropy source
    if selected_entropy_uuid:
        console.print(f"[cyan]Deriving salt from entropy pool {selected_entropy_uuid[:8]}...[/cyan]")
    else:
        console.print("[cyan]Generating salt using system RNG...[/cyan]")
    
    salt_value, salt_uuid_val, serial = generator.create_salt_item(
        vault=vault,
        entropy_pool_uuid=selected_entropy_uuid,
    )
    console.print(f"[green]✅ Created salt: {generator.SALT_ITEM_PREFIX} #{serial}[/green]")
    if selected_entropy_uuid:
        console.print("[green]✓[/green] Derived from entropy pool (HKDF-SHA512)")
        console.print(f"[dim]Entropy source: {selected_entropy_uuid}[/dim]")
    console.print("[yellow]⚠️  CRITICAL: Back up this item! Losing the salt means losing all username traceability.[/yellow]")
    console.print(f"[dim]UUID: {salt_uuid_val}[/dim]")
    console.print(f"[dim]Salt preview (first 16 chars): {salt_value[:16]}...[/dim]")


def _prompt_entropy_source(vault: str) -> str | None:
    """Prompt user to select an entropy source for salt derivation.
    
    Args:
        vault: Vault name for new entropy pools
        
    Returns:
        Selected entropy pool UUID, or None for system RNG
    """
    pool_manager = EntropyPool()
    available_pools = pool_manager.list_pools(include_consumed=False)
    
    # Filter pools with sufficient size (≥512 bits = 64 bytes)
    suitable_pools = [
        p for p in available_pools 
        if p.get("byte_count", 0) >= 64
    ]
    
    # Check hardware availability
    infnoise_available, _ = check_infnoise_available()
    yubikey_available = check_yubikey_available()
    
    # Build options list with availability status
    options = []
    default_choice = "1"
    
    # Option 1: Existing entropy pool (best - already verified)
    if suitable_pools:
        options.append(("1", "Use existing entropy pool", True, "pool"))
        default_choice = "1"
    
    # Option 2: Infinite Noise TRNG (hardware, fast)
    opt_num = str(len(options) + 1)
    if infnoise_available:
        options.append((opt_num, "Generate from Infinite Noise TRNG", True, "infnoise"))
        if not suitable_pools:
            default_choice = opt_num
    else:
        options.append((opt_num, "Infinite Noise TRNG [dim](not connected)[/dim]", False, "infnoise"))
    
    # Option 3: YubiKey HMAC (hardware, slower)
    opt_num = str(len(options) + 1)
    if yubikey_available:
        options.append((opt_num, "Generate from YubiKey HMAC", True, "yubikey"))
        if not suitable_pools and not infnoise_available:
            default_choice = opt_num
    else:
        options.append((opt_num, "YubiKey HMAC [dim](not connected)[/dim]", False, "yubikey"))
    
    # Option 4: System RNG (always available, fallback)
    opt_num = str(len(options) + 1)
    options.append((opt_num, "System RNG (Python secrets module)", True, "system"))
    if not suitable_pools and not infnoise_available and not yubikey_available:
        default_choice = opt_num
    
    # Display options
    console.print("\n[cyan]Select entropy source for salt derivation:[/cyan]")
    for num, label, available, _ in options:
        if available:
            console.print(f"  [bold]{num}[/bold] - {label}")
        else:
            console.print(f"  [dim]{num} - {label}[/dim]")
    
    console.print()
    valid_choices = [num for num, _, available, _ in options if available]
    choice = Prompt.ask(
        "Enter choice",
        choices=valid_choices,
        default=default_choice
    )
    
    # Find selected option
    selected_source = None
    for num, _, _, source_type in options:
        if num == choice:
            selected_source = source_type
            break
    
    return _handle_entropy_source_selection(selected_source, suitable_pools, vault, pool_manager)


def _handle_entropy_source_selection(
    selected_source: str | None,
    suitable_pools: list[dict],
    vault: str,
    pool_manager: EntropyPool,
) -> str | None:
    """Handle the selected entropy source and return UUID.
    
    Args:
        selected_source: Source type ('system', 'yubikey', 'infnoise', 'pool')
        suitable_pools: List of available entropy pools
        vault: Vault name for new pools
        pool_manager: EntropyPool instance
        
    Returns:
        Selected entropy pool UUID, or None for system RNG
    """
    if selected_source == "system":
        console.print("[cyan]Using system RNG (secrets.token_hex)...[/cyan]")
        return None
        
    elif selected_source == "yubikey":
        console.print("[cyan]Generating entropy from YubiKey...[/cyan]")
        try:
            generate_entropy(
                source="yubikey",
                bits="8192",
                dice_count=5,
                yubikey_slot=2,
                analyze=True,
                vault=vault,
                output_path=None,
            )
            new_pools = pool_manager.list_pools(include_consumed=False)
            if new_pools:
                newest = max(new_pools, key=lambda p: int(p.get("serial") or 0))
                return newest.get("uuid")
        except Exception as e:
            console.print(f"[red]Error generating YubiKey entropy:[/red] {e}")
            console.print("[yellow]Falling back to system RNG[/yellow]")
            return None
            
    elif selected_source == "infnoise":
        console.print("[cyan]Generating entropy from Infinite Noise TRNG...[/cyan]")
        try:
            generate_entropy(
                source="infnoise",
                bits="8192",
                dice_count=5,
                yubikey_slot=2,
                analyze=True,
                vault=vault,
                output_path=None,
            )
            new_pools = pool_manager.list_pools(include_consumed=False)
            if new_pools:
                newest = max(new_pools, key=lambda p: int(p.get("serial") or 0))
                return newest.get("uuid")
        except Exception as e:
            console.print(f"[red]Error generating infnoise entropy:[/red] {e}")
            console.print("[yellow]Falling back to system RNG[/yellow]")
            return None
            
    elif selected_source == "pool" and suitable_pools:
        return _select_from_existing_pools(suitable_pools)
    
    return None


def _select_from_existing_pools(suitable_pools: list[dict]) -> str | None:
    """Display pool selection table and get user choice.
    
    Args:
        suitable_pools: List of available entropy pools
        
    Returns:
        Selected pool UUID
    """
    console.print("\n[cyan]Available entropy pools (≥512 bits):[/cyan]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("#", style="dim", width=3)
    table.add_column("Source", width=15)
    table.add_column("Size", width=10)
    table.add_column("Quality", width=10)
    table.add_column("Created", width=12)
    table.add_column("UUID", width=36)
    
    for i, p in enumerate(suitable_pools, 1):
        quality = p.get("quality_rating", "N/A")
        quality_style = (
            "green" if quality == "EXCELLENT" else
            "green" if quality == "GOOD" else
            "yellow" if quality == "FAIR" else
            "red"
        )
        table.add_row(
            str(i),
            p.get("source", "unknown"),
            f"{p.get('bit_count', 0)} bits",
            f"[{quality_style}]{quality}[/{quality_style}]",
            p.get("created_at", "")[:10] if p.get("created_at") else "N/A",
            p.get("uuid", ""),
        )
    
    console.print(table)
    
    pool_choice = Prompt.ask("Enter pool number", default="1")
    
    if pool_choice.isdigit():
        idx = int(pool_choice) - 1
        if 0 <= idx < len(suitable_pools):
            return suitable_pools[idx].get("uuid")
        else:
            console.print("[yellow]Invalid selection, using first pool[/yellow]")
            return suitable_pools[0].get("uuid")
    else:
        # Assume UUID
        return pool_choice


def username_verify(
    generator: UsernameGenerator,
    label: str,
    username: str,
) -> None:
    """Verify a username against its label.
    
    Args:
        generator: UsernameGenerator instance
        label: Full label string
        username: Username to verify
    """
    is_valid = generator.verify(label, username)
    if is_valid:
        console.print(f"[green]✅ Username '{username}' matches label '{label}'[/green]")
        
        # Parse and display label details
        parser = LabelParser(label)
        if parser.is_valid():
            console.print("\n[dim]Label details:[/dim]")
            console.print(f"   Version: {parser.version}")
            console.print(f"   Algorithm: {parser.algorithm}")
            console.print(f"   Owner: {parser.owner}")
            console.print(f"   Domain: {parser.domain}")
            console.print(f"   Date: {parser.date}")
    else:
        console.print(f"[red]✗ Username '{username}' does NOT match label '{label}'[/red]")
        console.print("[dim]Username may have been generated with different label or salt[/dim]")


def username_generate(
    generator: UsernameGenerator,
    config: UsernameGeneratorConfig,
    domain: str,
    owner: str | None,
    algorithm: str | None,
    date: str | None,
    length: int | None,
    title: str | None,
    vault: str,
    tags: str | None,
    salt_uuid: str | None,
    interactive: bool,
    no_save: bool,
    use_nonce: bool = False,
    encoding: int = 36,
) -> None:
    """Generate a deterministic username and optionally save to 1Password.
    
    Args:
        generator: UsernameGenerator instance
        config: Username generator configuration
        domain: Domain/URL to generate for
        owner: Owner email (optional, uses config default)
        algorithm: Hash algorithm (optional, uses config default)
        date: Date string YYYY-MM-DD (optional, uses today)
        length: Username length (optional, uses config default)
        title: 1Password item title (optional, uses domain)
        vault: 1Password vault name
        tags: Comma-separated tags (optional)
        salt_uuid: Specific salt UUID to use (optional)
        interactive: Enable interactive prompts
        no_save: Don't save to 1Password
        use_nonce: Generate with random nonce (stolen seed protection)
        encoding: Output encoding (10=numeric, 36=alphanumeric, 64=base64)
    """
    import re
    from ...username_generator import generate_nonce
    
    # Validate encoding
    if encoding not in (10, 36, 64):
        console.print(f"[red]Error:[/red] Invalid encoding {encoding}. Must be 10, 36, or 64.")
        raise typer.Exit(1)
    
    # Normalize domain (strip https://, http://, www.)
    clean_domain = re.sub(r'^https?://(www\.)?', '', domain)
    clean_domain = clean_domain.rstrip('/')
    
    # Interactive mode: prompt for missing components
    if interactive:
        owner, algorithm, date, length = _interactive_username_prompts(
            config, clean_domain, owner, algorithm, date, length
        )
    
    # Apply defaults from config
    if not owner:
        owner = config.get_default_owner()
    if not algorithm:
        algorithm = config.get_default_algorithm()
    if not date:
        date = datetime.now().strftime("%Y-%m-%d")
    if not length:
        length = config.get_default_length()
    
    # Generate nonce if requested
    nonce_value = generate_nonce() if use_nonce else None
    
    # Build label (VERSION param auto-populated with Bastion __version__)
    label = LabelParser.build_label(
        version="v1",  # Ignored, VERSION param uses Bastion SemVer
        algorithm=algorithm,
        domain=clean_domain,
        date=date,
        length=length,
        nonce=nonce_value,
        encoding=encoding,
    )
    
    # Validate label
    parser = LabelParser(label)
    if not parser.is_valid():
        console.print(f"[red]Error:[/red] Invalid label format: {label}")
        console.print("[dim]Expected: Bastion/USER/ALGO:domain:date#PARAMS[/dim]")
        raise typer.Exit(1)
    
    # Check for collision
    collision_uuid = generator.check_label_collision(label)
    if collision_uuid:
        _handle_collision(generator, label, clean_domain, collision_uuid)
    
    # Generate username with nonce and encoding
    username = generator.generate(label, length, salt_uuid=salt_uuid, nonce=nonce_value, encoding=encoding)
    
    console.print(f"[cyan]Generated username:[/cyan] [bold]{username}[/bold]")
    console.print(f"[dim]Label: {label}[/dim]")
    
    # Show encoding info
    encoding_names = {10: "numeric (base10)", 36: "alphanumeric (base36)", 64: "base64"}
    console.print(f"[dim]Algorithm: {parser.algorithm}, Length: {length}, Encoding: {encoding_names.get(encoding, str(encoding))}[/dim]")
    
    # Show nonce warning if used
    if use_nonce:
        console.print("[yellow]⚠️  Nonce mode: This username cannot be regenerated without the label![/yellow]")
    
    # Auto-save to 1Password (unless --no-save specified)
    if not no_save:
        _save_username_to_1password(
            generator, username, label, clean_domain, title, vault, tags, salt_uuid, length
        )
    else:
        console.print("\n[dim]Skipped saving to 1Password (--no-save specified)[/dim]")


def _interactive_username_prompts(
    config: UsernameGeneratorConfig,
    clean_domain: str,
    owner: str | None,
    algorithm: str | None,
    date: str | None,
    length: int | None,
) -> tuple[str, str, str, int]:
    """Prompt user for missing username generation parameters.
    
    Returns:
        Tuple of (owner, algorithm, date, length)
    """
    console.print("[cyan]Interactive username generation[/cyan]\n")
    console.print(f"Domain: [bold]{clean_domain}[/bold]\n")
    
    # Owner
    if not owner:
        default_owner = config.get_default_owner()
        owner_prompt = typer.prompt("Owner email", default=default_owner)
        owner = owner_prompt.strip()
    
    # Algorithm
    if not algorithm:
        default_algo = config.get_default_algorithm()
        console.print("\nAvailable algorithms:")
        console.print("  sha256     - Legacy (51 char max)")
        console.print("  sha512     - Standard (100 char max)")
        console.print("  sha3-512   - Quantum-resistant [RECOMMENDED] (100 char max)")
        algo_prompt = typer.prompt("Algorithm", default=default_algo)
        algorithm = algo_prompt.strip()
    
    # Date
    if not date:
        default_date = datetime.now().strftime("%Y-%m-%d")
        date_prompt = typer.prompt("Date (YYYY-MM-DD)", default=default_date)
        date = date_prompt.strip()
    
    # Length
    if not length:
        default_length = config.get_default_length()
        length_prompt = typer.prompt("Username length", default=default_length, type=int)
        length = length_prompt
    
    console.print()  # Blank line
    return owner, algorithm, date, length


def _handle_collision(
    generator: UsernameGenerator,
    label: str,
    clean_domain: str,
    collision_uuid: str,
) -> None:
    """Handle label collision by showing alternatives and exiting.
    
    Args:
        generator: UsernameGenerator instance
        label: The colliding label
        clean_domain: Domain being generated for
        collision_uuid: UUID of existing item with this label
    """
    console.print("[yellow]⚠️  Label collision detected![/yellow]")
    console.print(f"[dim]Label '{label}' already exists (UUID: {collision_uuid})[/dim]")
    
    # Suggest alternative labels
    suggestions = generator.suggest_collision_suffix(label)
    console.print("\n[cyan]Suggested alternative labels:[/cyan]")
    for i, suggestion in enumerate(suggestions, 1):
        console.print(f"  {i}. {suggestion}")
    
    console.print("\n[dim]To use an alternative, generate with the suggested date suffix:[/dim]")
    if suggestions:
        first_suggestion = LabelParser(suggestions[0])
        console.print(f"[dim]Example: bastion generate username {clean_domain} --date {first_suggestion.date}[/dim]")
    raise typer.Exit(1)


def _save_username_to_1password(
    generator: UsernameGenerator,
    username: str,
    label: str,
    clean_domain: str,
    title: str | None,
    vault: str,
    tags: str | None,
    salt_uuid: str | None,
    length: int,
) -> None:
    """Save generated username to 1Password as a login item.
    
    Args:
        generator: UsernameGenerator instance
        username: Generated username
        label: Full label string
        clean_domain: Normalized domain
        title: Item title (optional)
        vault: Vault name
        tags: Comma-separated tags (optional)
        salt_uuid: Salt UUID used
        length: Username length
    """
    console.print("\n[cyan]Saving to 1Password...[/cyan]")
    
    # Determine title
    if not title:
        title = clean_domain.split('.')[0].capitalize()
    
    # Build website URL from domain
    website = f"https://{clean_domain}"
    
    # Tag list from user input only (algorithm tag added by generator)
    tag_list = None
    if tags:
        tag_list = [t.strip() for t in tags.split(",")]
    
    result = generator.create_login_with_username(
        title=title,
        label=label,
        website=website,
        vault=vault,
        length=length,
        tags=tag_list,
        salt_uuid=salt_uuid,
    )
    
    console.print("[green]✅ Created login item:[/green]")
    console.print(f"   Title: {result['title']}")
    console.print(f"   Username: {result['username']}")
    console.print(f"   Website: {website}")
    console.print(f"   UUID: {result['uuid']}")
    console.print(f"   Vault: {result['vault']}")
    console.print("\n[dim]Metadata fields:[/dim]")
    console.print(f"   username_label: {result['label']}")
    console.print(f"   username_salt_uuid: {result['salt_uuid']}")
    console.print(f"   username_algorithm: {result['algorithm']}")
    console.print(f"   username_length: {result['length']}")
