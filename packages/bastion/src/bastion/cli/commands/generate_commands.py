"""Generate commands: mermaid, username, entropy."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from ..helpers import get_db_manager
from ...username_generator import UsernameGenerator
from .generate import (
    generate_mermaid,
    username_init,
    username_verify,
    username_generate,
)
from .entropy import (
    generate_entropy,
    batch_infnoise_entropy,
    batch_yubikey_entropy,
    batch_system_entropy,
    combine_from_sources,
)

console = Console()

# Type alias for common db option
DbPathOption = Annotated[
    Optional[Path],
    typer.Option(
        "--db",
        help="Database file path",
        envvar="PASSWORD_ROTATION_DB",
    ),
]


def register_commands(app: typer.Typer) -> None:
    """Register generate-related commands with the app."""
    
    @app.command("generate")
    def generate_command(
        noun: Annotated[str, typer.Argument(help="'mermaid', 'username', or 'entropy'")],
        object_type: Annotated[str | None, typer.Argument(help="[username] Domain/URL | [entropy] Source: yubikey, dice, infnoise, combined, batch-{infnoise,yubikey,system}, combine")] = None,
        db_path: DbPathOption = None,
        out: Annotated[Path | None, typer.Option(help="[mermaid] Output Markdown file")] = None,
        owner: Annotated[str | None, typer.Option("--owner", help="[username] Owner email (default from config)")] = None,
        algorithm: Annotated[str | None, typer.Option("--algorithm", "-a", help="[username] Algorithm: sha256, sha512, sha3-512 (default from config)")] = None,
        date: Annotated[str | None, typer.Option("--date", help="[username] Date in ISO format YYYY-MM-DD (default today)")] = None,
        title: Annotated[str | None, typer.Option("--title", help="[username] 1Password item title (default: domain)")] = None,
        vault: Annotated[str, typer.Option("--vault", "-v", help="[username|entropy] 1Password vault")] = "Private",
        length: Annotated[int | None, typer.Option("--length", "-l", help="[username] Username length (default from config)")] = None,
        tags: Annotated[str | None, typer.Option("--tags", "-t", help="[username] Comma-separated additional tags")] = None,
        init: Annotated[bool, typer.Option("--init", help="[username] Initialize salt item in 1Password")] = False,
        verify: Annotated[str | None, typer.Option("--verify", help="[username] Verify username against full label")] = None,
        interactive: Annotated[bool, typer.Option("--interactive", "-i", help="[username] Interactive mode with prompts")] = False,
        salt_uuid: Annotated[str | None, typer.Option("--salt-uuid", help="[username] Use specific salt UUID")] = None,
        no_save: Annotated[bool, typer.Option("--no-save", help="[username] Don't save to 1Password (display only)")] = False,
        nonce: Annotated[bool, typer.Option("--nonce", help="[username] Generate with random nonce (stolen seed protection)")] = False,
        encoding: Annotated[int, typer.Option("--encoding", "-e", help="[username] Output encoding: 10 (numeric), 36 (alphanumeric), 64 (base64)")] = 36,
        entropy_source: Annotated[str | None, typer.Option("--entropy-source", help="[username --init] Entropy pool UUID for salt derivation")] = None,
        bits: Annotated[str, typer.Option("--bits", help="[entropy] Bits per source. Combined: 'yubikey:4096,infnoise:8192'. Batch default: 32768")] = "8192",
        dice_count: Annotated[int, typer.Option("--dice", help="[entropy] Dice per roll (1-5)")] = 5,
        yubikey_slot: Annotated[int, typer.Option("--slot", help="[entropy] YubiKey slot (1 or 2)")] = 2,
        analyze: Annotated[bool, typer.Option("--analyze", help="[entropy] Run ENT analysis")] = True,
        output: Annotated[Optional[Path], typer.Option("--output", help="[entropy] Output path for visualization")] = None,
        sources: Annotated[str | None, typer.Option("--sources", help="[entropy combined] Comma-separated sources: yubikey,infnoise,dice")] = None,
        count: Annotated[int, typer.Option("--count", "-n", help="[entropy batch-*] Number of pools to collect")] = 100,
        min_quality: Annotated[str, typer.Option("--min-quality", help="[entropy batch-*] Minimum quality: EXCELLENT, GOOD, FAIR")] = "EXCELLENT",
        batch_bits: Annotated[int, typer.Option("--batch-bits", help="[entropy batch-*] Bits per pool (16KB=131072 recommended for EXCELLENT)")] = 131072,
        extend_bits: Annotated[Optional[int], typer.Option("--extend-bits", help="[entropy combine] Extend output using SHAKE256")] = None,
    ) -> None:
        """Generate mermaid diagrams, deterministic usernames, or entropy pools.
        
        Mermaid examples:
          bastion generate mermaid --out diagram.md
        
        Username examples:
          bastion generate username --init                              # Setup with interactive entropy selection
          bastion generate username --init --entropy-source <uuid>      # Setup using specific entropy pool
          bastion generate username github.com                          # Auto-saves to 1Password
          bastion generate username github.com --no-save                # Display only, don't save
          bastion generate username https://aws.amazon.com -i           # Interactive mode
          bastion generate username github.com --algorithm sha3-512     # Use SHA3-512 (quantum-resistant)
          bastion generate username github.com --encoding 10            # Numeric only username
          bastion generate username github.com --nonce                  # Stolen seed protection
          bastion generate username github.com --date 2025-11-21
        
        Entropy examples:
          bastion generate entropy infnoise                             # Single pool from Infinite Noise TRNG
          bastion generate entropy batch-infnoise --count 100           # 100 TRNG pools (16KB each)
          bastion generate entropy batch-yubikey --count 100            # 100 YubiKey HMAC pools
          bastion generate entropy batch-system --count 100             # 100 system RNG pools
          bastion generate entropy combine --sources infnoise,yubikey,system   # Combine 1 pool from each
          bastion generate entropy combine --sources infnoise,yubikey --count 10   # Create 10 derived pools
        
        Note: Larger samples yield more accurate ENT statistics. Default 16KB for EXCELLENT quality.
        Combine consumes source pools and creates derived pools with XOR+SHAKE256.
        
        Label format: Bastion/USER/ALGO:domain:date#PARAMS
        Default algorithm: sha3-512 (quantum-resistant)
        Date format: ISO 8601 (YYYY-MM-DD)
        """
        
        if noun == "mermaid":
            # Mermaid diagram generation
            output_path = out or Path("password-rotation-database-diagram.md")
            db_mgr = get_db_manager(db_path)
            db = db_mgr.load()
            generate_mermaid(db, output_path)
            
        elif noun == "username":
            from bastion.username_generator import UsernameGeneratorConfig
            
            # Load configuration
            try:
                config = UsernameGeneratorConfig()
            except RuntimeError as e:
                console.print(f"[red]Error loading config:[/red] {e}")
                raise typer.Exit(1)
            
            # Username generation
            generator = UsernameGenerator(config=config)
            
            # Handle initialization
            if init:
                try:
                    username_init(generator, vault, entropy_source)
                except RuntimeError as e:
                    console.print(f"[red]Error:[/red] {e}")
                    raise typer.Exit(1)
                return
            
            # Handle verification
            if verify:
                if not object_type:
                    console.print("[red]Error:[/red] Full label required for verification")
                    console.print("Usage: bastion generate username --verify 'v1:sha3-512:owner:domain:date' <username>")
                    raise typer.Exit(1)
                
                try:
                    username_verify(generator, verify, object_type)
                except RuntimeError as e:
                    console.print(f"[red]Error:[/red] {e}")
                    raise typer.Exit(1)
                return
            
            # Require domain for generation
            if not object_type:
                console.print("[red]Error:[/red] DOMAIN argument required (e.g., 'github.com', 'https://aws.amazon.com')")
                console.print("Usage: bastion generate username DOMAIN [OPTIONS]")
                console.print("Tip: Use --interactive for guided setup")
                raise typer.Exit(1)
            
            try:
                username_generate(
                    generator=generator,
                    config=config,
                    domain=object_type,
                    owner=owner,
                    algorithm=algorithm,
                    date=date,
                    length=length,
                    title=title,
                    vault=vault,
                    tags=tags,
                    salt_uuid=salt_uuid,
                    interactive=interactive,
                    no_save=no_save,
                    use_nonce=nonce,
                    encoding=encoding,
                )
            except RuntimeError as e:
                console.print(f"[red]Error:[/red] {e}")
                raise typer.Exit(1)
        elif noun == "entropy":
            if not object_type:
                console.print("[red]Error:[/red] Source required for entropy generation")
                console.print("Usage: bastion generate entropy {yubikey|dice|infnoise|combined|batch-infnoise} [OPTIONS]")
                raise typer.Exit(1)
            
            # Handle batch and combine commands
            obj_lower = object_type.lower()
            
            if obj_lower == "batch-infnoise":
                batch_infnoise_entropy(
                    count=count,
                    bits=batch_bits,
                    min_quality=min_quality,
                    vault=vault,
                )
            elif obj_lower == "batch-yubikey":
                batch_yubikey_entropy(
                    count=count,
                    bits=batch_bits,
                    min_quality=min_quality,
                    vault=vault,
                    slot=yubikey_slot,
                )
            elif obj_lower == "batch-system":
                batch_system_entropy(
                    count=count,
                    bits=batch_bits,
                    min_quality=min_quality,
                    vault=vault,
                )
            elif obj_lower == "combine":
                if not sources:
                    console.print("[red]Error:[/red] --sources required for combine")
                    console.print("Example: bastion generate entropy combine --sources infnoise,yubikey,system")
                    raise typer.Exit(1)
                combine_from_sources(
                    sources=sources,
                    min_bits=batch_bits,
                    extend_bits=extend_bits,
                    count=count,
                    vault=vault,
                )
            else:
                generate_entropy(
                    source=object_type,
                    bits=bits,
                    dice_count=dice_count,
                    yubikey_slot=yubikey_slot,
                    analyze=analyze,
                    vault=vault,
                    output_path=output,
                    sources=sources,
                )
        
        else:
            console.print(f"[red]Error:[/red] Unknown noun '{noun}'. Expected 'mermaid', 'username', or 'entropy'")
            console.print("Usage: bastion generate {{mermaid|username|entropy}} [OPTIONS]")
            raise typer.Exit(1)
