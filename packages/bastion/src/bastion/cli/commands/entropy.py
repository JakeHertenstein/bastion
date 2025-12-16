"""Entropy generation and management commands.

This module contains functions for generating, storing, and analyzing
entropy from various hardware sources (YubiKey, Infinite Noise TRNG, dice).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

import typer

from ..console import console


def generate_entropy(
    source: str,
    bits: str,
    dice_count: int,
    yubikey_slot: int,
    analyze: bool,
    vault: str,
    output_path: Optional[Path],
    sources: Optional[str] = None,
) -> None:
    """Generate entropy from specified source.
    
    Args:
        source: Entropy source ('yubikey', 'dice', 'infnoise', 'combined')
        bits: Bits to collect (single value or per-source 'yubikey:4096,infnoise:8192')
        dice_count: Number of dice per roll (1-5)
        yubikey_slot: YubiKey slot (1 or 2)
        analyze: Whether to run ENT analysis
        vault: 1Password vault for storage
        output_path: Optional path for visualization output
        sources: For combined mode, comma-separated source list
    """
    from bastion.entropy import EntropyPool, combine_entropy_sources, analyze_entropy_with_ent
    from bastion.entropy_yubikey import collect_yubikey_entropy, check_yubikey_available, YubiKeyEntropyError
    from bastion.entropy_dice import collect_dice_entropy, DiceEntropyError
    from bastion.entropy_infnoise import collect_infnoise_entropy, check_infnoise_available, InfNoiseError
    from bastion.entropy_visual import visualize_entropy
    
    # Parse bits - can be single value "8192" or per-source "yubikey:4096,infnoise:8192"
    default_bits = 8192
    source_bits: dict[str, int] = {}
    
    if ":" in bits:
        # Per-source format: "yubikey:4096,infnoise:8192"
        for part in bits.split(","):
            if ":" in part:
                src, b = part.strip().split(":", 1)
                source_bits[src.lower()] = int(b)
    else:
        # Single value applies to all
        default_bits = int(bits)
    
    def get_bits_for_source(src: str) -> int:
        return source_bits.get(src, default_bits)
    
    # Validate minimum bits
    min_bits = min([default_bits] + list(source_bits.values())) if source_bits else default_bits
    if min_bits < 256:
        console.print("[red]Error: Minimum 256 bits required for cryptographic use[/red]")
        raise typer.Exit(1)
    
    source = source.lower()
    
    if source not in ("yubikey", "dice", "infnoise", "combined"):
        console.print(f"[red]Error: Invalid source '{source}'. Must be: yubikey, dice, infnoise, or combined[/red]")
        raise typer.Exit(1)
    
    # Collect entropy based on source
    metadata = None  # Will be set for infnoise source
    try:
        if source == "yubikey":
            src_bits = get_bits_for_source("yubikey")
            console.print(f"[cyan]Collecting {src_bits} bits from YubiKey HMAC-SHA1...[/cyan]")
            
            if not check_yubikey_available():
                console.print("[red]Error: YubiKey not found[/red]")
                console.print("Please insert YubiKey and ensure ykman is installed:")
                console.print("  macOS: brew install ykman")
                console.print("  Linux: apt install yubikey-manager")
                raise typer.Exit(1)
            
            entropy_bytes = collect_yubikey_entropy(
                bits=src_bits,
                slot=yubikey_slot,
            )
            source_label = "yubikey"
            
        elif source == "dice":
            src_bits = get_bits_for_source("dice")
            console.print(f"[cyan]Collecting {src_bits} bits from dice rolls...[/cyan]")
            entropy_bytes = collect_dice_entropy(
                bits=src_bits,
                dice_count=dice_count,
            )
            source_label = "dice"
        
        elif source == "infnoise":
            console.print(f"[cyan]Collecting {default_bits} bits from Infinite Noise TRNG...[/cyan]")
            
            available, error = check_infnoise_available()
            if not available:
                console.print("[red]Error: Infinite Noise TRNG not available[/red]")
                console.print(f"  {error}")
                console.print("\nPlease connect device and install driver:")
                console.print("  https://github.com/leetronics/infnoise")
                raise typer.Exit(1)
            
            entropy_bytes, metadata = collect_infnoise_entropy(bits=default_bits)
            source_label = "infnoise"
            console.print(f"  Device serial: {metadata.serial}")
            console.print(f"  Whitened: {metadata.whitened}")
        
        elif source == "combined":
            # Parse sources list or use default (yubikey+dice for backward compat)
            if sources:
                source_list = [s.strip().lower() for s in sources.split(",")]
            else:
                # Default: interactive selection
                from rich.prompt import Prompt
                
                console.print("\n[cyan]Select sources to combine (at least 2):[/cyan]")
                
                available = []
                if check_yubikey_available():
                    available.append(("yubikey", "YubiKey HMAC"))
                else:
                    console.print("  [dim]yubikey - YubiKey HMAC (not connected)[/dim]")
                
                infnoise_ok, _ = check_infnoise_available()
                if infnoise_ok:
                    available.append(("infnoise", "Infinite Noise TRNG"))
                else:
                    console.print("  [dim]infnoise - Infinite Noise TRNG (not connected)[/dim]")
                
                available.append(("dice", "Dice rolls (manual)"))
                
                for code, label in available:
                    console.print(f"  [bold]{code}[/bold] - {label}")
                
                console.print()
                source_input = Prompt.ask(
                    "Enter sources (comma-separated)",
                    default="yubikey,dice" if check_yubikey_available() else "dice"
                )
                source_list = [s.strip().lower() for s in source_input.split(",")]
            
            # Validate sources
            valid_sources = {"yubikey", "infnoise", "dice"}
            invalid = set(source_list) - valid_sources
            if invalid:
                console.print(f"[red]Error: Invalid sources: {invalid}. Valid: yubikey, infnoise, dice[/red]")
                raise typer.Exit(1)
            
            if len(source_list) < 2:
                console.print("[red]Error: Combined mode requires at least 2 sources[/red]")
                raise typer.Exit(1)
            
            console.print(f"[cyan]Collecting entropy from {len(source_list)} sources...[/cyan]")
            console.print("[dim]Combine method: XOR+SHAKE256[/dim]")
            
            collected_bytes = []
            source_sizes = []
            step = 1
            
            for src in source_list:
                src_bits = get_bits_for_source(src)
                if src == "yubikey":
                    console.print(f"\n[yellow]Step {step}: YubiKey entropy ({src_bits} bits)[/yellow]")
                    if not check_yubikey_available():
                        console.print("[red]Error: YubiKey not found[/red]")
                        raise typer.Exit(1)
                    src_bytes = collect_yubikey_entropy(bits=src_bits, slot=yubikey_slot)
                    collected_bytes.append(src_bytes)
                    source_sizes.append(len(src_bytes))
                    console.print(f"  [green]✓[/green] Collected {len(src_bytes)} bytes")
                    
                elif src == "infnoise":
                    console.print(f"\n[yellow]Step {step}: Infinite Noise TRNG ({src_bits} bits)[/yellow]")
                    available, _ = check_infnoise_available()
                    if not available:
                        console.print("[red]Error: Infinite Noise TRNG not found[/red]")
                        raise typer.Exit(1)
                    src_bytes, _ = collect_infnoise_entropy(bits=src_bits)
                    collected_bytes.append(src_bytes)
                    source_sizes.append(len(src_bytes))
                    console.print(f"  [green]✓[/green] Collected {len(src_bytes)} bytes")
                    
                elif src == "dice":
                    console.print(f"\n[yellow]Step {step}: Dice entropy ({src_bits} bits)[/yellow]")
                    src_bytes = collect_dice_entropy(bits=src_bits, dice_count=dice_count)
                    collected_bytes.append(src_bytes)
                    source_sizes.append(len(src_bytes))
                    console.print(f"  [green]✓[/green] Collected {len(src_bytes)} bytes")
                
                step += 1
            
            # Show size comparison
            if len(set(source_sizes)) > 1:
                console.print(f"\n[dim]Source sizes: {source_sizes} bytes[/dim]")
                console.print(f"[dim]Output will be {max(source_sizes)} bytes (largest source)[/dim]")
            
            # Combine sources
            console.print(f"\n[cyan]Combining {len(collected_bytes)} sources with XOR+SHAKE256...[/cyan]")
            entropy_bytes = combine_entropy_sources(*collected_bytes)
            source_label = "+".join(source_list)
        
        else:
            raise ValueError(f"Unknown source: {source}")
        
        console.print(f"\n[green]✓[/green] Collected {len(entropy_bytes)} bytes ({len(entropy_bytes) * 8} bits)")
        
        # Analyze with ENT if requested
        analysis = None
        if analyze:
            console.print("\n[cyan]Running ENT statistical analysis...[/cyan]")
            analysis = analyze_entropy_with_ent(entropy_bytes)
            
            if analysis is None:
                console.print("[yellow]Warning: ENT not installed, skipping analysis[/yellow]")
                console.print("Install: brew install ent (macOS) or apt install ent (Linux)")
            else:
                console.print(f"  Entropy: {analysis.entropy_bits_per_byte:.6f} bits/byte (ideal: 8.0)")
                console.print(f"  Chi-square p-value: {analysis.chi_square_pvalue:.6f} (ideal: 0.5, acceptable: 0.01-0.99)")
                console.print(f"  Mean: {analysis.arithmetic_mean:.4f} (ideal: 127.5)")
                console.print(f"  Serial correlation: {analysis.serial_correlation:.6f} (ideal: 0.0)")
                console.print(f"  Quality: [bold]{analysis.quality_rating()}[/bold]")
                
                if not analysis.is_acceptable():
                    console.print("[yellow]Warning: Entropy quality below acceptable threshold[/yellow]")
        
        # Store in 1Password
        console.print(f"\n[cyan]Storing entropy pool in 1Password ({vault})...[/cyan]")
        pool = EntropyPool()
        
        # Get device metadata if available (infnoise source)
        device_meta = metadata.to_dict() if source == "infnoise" and metadata else None
        
        # For combined sources, pass derivation method
        derivation_method = "xor_shake256" if source == "combined" else None
        
        pool_uuid, serial = pool.create_pool(
            entropy_bytes=entropy_bytes,
            source=source_label,
            analysis=analysis,
            vault=vault,
            device_metadata=device_meta,
            derivation_method=derivation_method,
        )
        
        console.print(f"[green]✓[/green] Created entropy pool #{serial}")
        console.print(f"[green]✓[/green] UUID: {pool_uuid}")
        
        # Generate visualization if analysis was done
        if analysis and output_path:
            console.print("\n[cyan]Generating visualization...[/cyan]")
            viz_path = visualize_entropy(entropy_bytes, output_path, f"Entropy Pool v1 #{serial}")
            console.print(f"[green]✓[/green] Saved to: {viz_path}")
        
    except typer.Exit:
        raise
    except (YubiKeyEntropyError, DiceEntropyError, InfNoiseError, ValueError) as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
    except RuntimeError as e:
        console.print(f"[red]Error storing pool: {e}[/red]")
        raise typer.Exit(1)


def visualize_entropy_pool(
    pool_uuid: str,
    output: Path | None = None,
    attach: bool = True,
) -> None:
    """Visualize an entropy pool.
    
    By default, attaches visualization images directly to the 1Password item.
    Use --output to save to filesystem instead.
    
    Args:
        pool_uuid: UUID of the entropy pool
        output: Output path for visualization (saves to file instead of attaching)
        attach: Whether to attach to 1Password item (default True, ignored if output is set)
    """
    import typer
    from bastion.entropy import EntropyPool, attach_visualization_to_pool
    from bastion.entropy_visual import visualize_entropy, visualize_chi_square
    
    console.print(f"[cyan]Visualizing entropy pool {pool_uuid[:8]}...[/cyan]\n")
    
    pool = EntropyPool()
    result = pool.get_pool(pool_uuid)
    
    if not result:
        console.print(f"[red]Error: Pool {pool_uuid} not found[/red]")
        raise typer.Exit(1)
    
    entropy_bytes, metadata = result
    serial = metadata.get("serial", "unknown")
    title = f"Entropy Pool v1-{serial}"
    
    # If output path specified, save to filesystem
    if output is not None:
        console.print("Generating visualization to file...")
        viz_path = visualize_entropy(entropy_bytes, output, title)
        console.print(f"[green]✓[/green] Saved to: {viz_path}")
        
        chi_output = output.with_stem(f"{output.stem}_chisquare")
        chi_path = visualize_chi_square(entropy_bytes, chi_output, f"{title} - Chi-Square Analysis")
        console.print(f"[green]✓[/green] Chi-square plot: {chi_path}")
        return
    
    # Default: attach to 1Password item
    console.print("Generating visualizations...")
    histogram_pdf = visualize_entropy(entropy_bytes, title=title, return_bytes=True)
    chi_square_pdf = visualize_chi_square(entropy_bytes, title=f"{title} - Chi-Square Analysis", return_bytes=True)
    
    console.print("Attaching to 1Password item...")
    try:
        attach_visualization_to_pool(pool_uuid, histogram_pdf, chi_square_pdf)
        console.print(f"[green]✓[/green] Attached Histogram and Chi-Square visualizations to pool {pool_uuid[:8]}")
    except RuntimeError as e:
        console.print(f"[red]Error attaching visualization: {e}[/red]")
        raise typer.Exit(1)


def analyze_entropy_pools(
    pool_uuid: str | None = None,
    all_pools: bool = False,
    dry_run: bool = False,
    force: bool = False,
) -> None:
    """Analyze entropy pools and attach visualizations.
    
    Generates visualization images and attaches them to 1Password items.
    Only processes pools that don't already have visualizations attached
    (unless --force is used).
    
    Args:
        pool_uuid: Specific pool UUID to analyze (optional)
        all_pools: Analyze all pools missing visualizations
        dry_run: Preview what would be analyzed without making changes
        force: Skip check for existing visualizations (process all pools)
    """
    import typer
    from bastion.entropy import EntropyPool, attach_visualization_to_pool, pool_has_visualization
    from bastion.entropy_visual import visualize_entropy, visualize_chi_square
    
    pool = EntropyPool()
    
    if pool_uuid:
        # Analyze single pool
        if not force and pool_has_visualization(pool_uuid):
            console.print(f"[yellow]Pool {pool_uuid[:8]} already has visualization attached[/yellow]")
            console.print("[dim]Use --force to overwrite[/dim]")
            return
        
        if dry_run:
            console.print(f"[cyan]Would analyze:[/cyan] {pool_uuid}")
            return
        
        visualize_entropy_pool(pool_uuid)
        return
    
    if not all_pools:
        console.print("[red]Error: Must specify --uuid or --all[/red]")
        raise typer.Exit(1)
    
    # Find all entropy pools (lightweight - just list, no details)
    console.print("[cyan]Finding entropy pools...[/cyan]")
    import subprocess
    import json as json_module
    
    try:
        result = subprocess.run(
            ["op", "item", "list", "--tags", pool.POOL_TAG, "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        pools = json_module.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error listing pools: {e.stderr}[/red]")
        raise typer.Exit(1)
    
    if not pools:
        console.print("[yellow]No entropy pools found[/yellow]")
        return
    
    console.print(f"Found {len(pools)} entropy pools")
    
    # Helper to extract serial number from title (e.g., "Entropy Pool v1 #42" -> 42)
    def extract_serial(p: dict) -> int:
        title = p.get("title", "")
        import re
        match = re.search(r'#(\d+)', title)
        return int(match.group(1)) if match else 999999
    
    # Sort pools by serial number (lowest first)
    pools = sorted(pools, key=extract_serial)
    
    # Filter to pools without visualization (unless --force)
    if force:
        pools_to_analyze = pools
        console.print(f"[yellow]Force mode: will process all {len(pools)} pools[/yellow]")
    else:
        console.print("Checking for existing visualizations...")
        # Check each pool for Visualization section (this requires individual op item get calls)
        from rich.progress import Progress, SpinnerColumn, TextColumn
        
        pools_to_analyze = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Checking pools...", total=len(pools))
            for p in pools:
                uuid = p.get("id")
                title = p.get("title", "Unknown")
                progress.update(task, description=f"Checking {title[:30]}...")
                if uuid and not pool_has_visualization(uuid):
                    pools_to_analyze.append(p)
                progress.advance(task)
        
        if not pools_to_analyze:
            console.print(f"[green]All {len(pools)} pools already have visualizations[/green]")
            return
        
        console.print(f"Found {len(pools_to_analyze)} pools without visualization (of {len(pools)} total)\n")
    
    if dry_run:
        console.print("[cyan]Would analyze (sorted by serial number):[/cyan]")
        for p in pools_to_analyze[:20]:  # Limit output for large lists
            title = p.get("title", "Unknown")
            uuid = p.get("id", "")[:8]
            serial = extract_serial(p)
            console.print(f"  • #{serial}: {title} ({uuid})")
        if len(pools_to_analyze) > 20:
            console.print(f"  ... and {len(pools_to_analyze) - 20} more")
        return
    
    # Process each pool
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing pools...", total=len(pools_to_analyze))
        
        success = 0
        failed = 0
        
        for p in pools_to_analyze:
            uuid = p.get("id")
            title = p.get("title", "Unknown")
            serial = extract_serial(p)
            progress.update(task, description=f"Analyzing #{serial}...")
            
            try:
                result = pool.get_pool(uuid)
                if not result:
                    console.print(f"[red]✗[/red] Failed to get pool {uuid[:8]}")
                    failed += 1
                    progress.advance(task)
                    continue
                
                entropy_bytes, metadata = result
                serial = metadata.get("serial", "unknown")
                pool_title = f"Entropy Pool v1-{serial}"
                
                # Generate visualizations
                histogram_pdf = visualize_entropy(entropy_bytes, title=pool_title, return_bytes=True)
                chi_square_pdf = visualize_chi_square(entropy_bytes, title=f"{pool_title} - Chi-Square Analysis", return_bytes=True)
                
                # Attach to item
                attach_visualization_to_pool(uuid, histogram_pdf, chi_square_pdf)
                success += 1
                
            except Exception as e:
                console.print(f"[red]✗[/red] {title}: {e}")
                failed += 1
            
            progress.advance(task)
    
    console.print(f"\n[green]✓[/green] Analyzed {success} pools")
    if failed:
        console.print(f"[red]✗[/red] Failed: {failed} pools")


def batch_infnoise_entropy(
    count: int = 100,
    bits: int = 32768,
    min_quality: str = "GOOD",
    vault: str = "Private",
) -> None:
    """Collect multiple entropy pools from Infinite Noise TRNG.
    
    Automatically collects high-quality entropy pools, retrying indefinitely
    until each pool meets the minimum quality threshold. Uses ENT statistical
    analysis to validate each pool.
    
    Note: Larger samples yield more accurate ENT statistics:
      - 32768 bits (4KB): Reliable GOOD ratings
      - 65536 bits (8KB): Consistent GOOD/EXCELLENT
      - 131072 bits (16KB): Reliable EXCELLENT ratings
    
    Args:
        count: Number of pools to collect (default 100)
        bits: Bits per pool (default 32768 = 4KB for reliable GOOD quality)
        min_quality: Minimum quality threshold: EXCELLENT, GOOD, FAIR (default GOOD)
        vault: 1Password vault for storage (default "Private")
    """
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
    from bastion.entropy import EntropyPool, analyze_entropy_with_ent, QualityThreshold
    from bastion.entropy_infnoise import collect_infnoise_entropy, check_infnoise_available, InfNoiseError
    
    # Validate minimum quality threshold
    try:
        threshold = QualityThreshold(min_quality.upper())
    except ValueError:
        console.print(f"[red]Error: Invalid quality threshold '{min_quality}'[/red]")
        console.print("Valid thresholds: EXCELLENT, GOOD, FAIR, POOR")
        raise typer.Exit(1)
    
    # Check device availability
    available, error = check_infnoise_available()
    if not available:
        console.print("[red]Error: Infinite Noise TRNG not available[/red]")
        console.print(f"  {error}")
        console.print("\nPlease connect device and install driver:")
        console.print("  https://github.com/leetronics/infnoise")
        raise typer.Exit(1)
    
    # Validate bits (must be >= 1024 for ENT analysis)
    if bits < 1024:
        console.print("[yellow]Warning: Minimum 1024 bits (128 bytes) required for ENT analysis[/yellow]")
        console.print("Setting bits to 8192 (1KB) for meaningful statistical analysis")
        bits = 8192
    
    # Determine next batch ID and cache max serial in one 1Password call
    pool = EntropyPool()
    next_batch_id, max_serial = _find_batch_id_and_max_serial(pool)
    
    console.print("\n[bold cyan]═══ Batch Entropy Collection ═══[/bold cyan]")
    console.print(f"  Target: {count} pools × {bits} bits = {count * bits // 8 // 1024:.1f} KB total")
    console.print(f"  Min quality: {min_quality.upper()}")
    console.print(f"  Batch ID: {next_batch_id}")
    console.print(f"  Vault: {vault}")
    console.print()
    
    # Statistics tracking
    # For large pools (>64KB), show progress after each pool since they take several seconds
    progress_interval = 1 if bits >= 65536 else 5
    
    stats = {
        "collected": 0,
        "rejected": 0,
        "retries": 0,
        "quality_counts": {"EXCELLENT": 0, "GOOD": 0, "FAIR": 0, "POOR": 0},
        "start_time": time.time(),
    }
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Collecting {count} pools...", total=count)
            
            pool_num = 0
            while stats["collected"] < count:
                pool_num += 1
                retries_for_pool = 0
                
                while True:  # Keep trying until quality threshold met
                    try:
                        # Collect entropy
                        entropy_bytes, metadata = collect_infnoise_entropy(bits=bits)
                        
                        # Analyze quality
                        analysis = analyze_entropy_with_ent(entropy_bytes)
                        
                        if analysis is None:
                            console.print("\n[red]Error: ENT not installed, cannot validate quality[/red]")
                            console.print("Install: brew install ent (macOS) or apt install ent (Linux)")
                            raise typer.Exit(1)
                        
                        quality = analysis.quality_rating()
                        stats["quality_counts"][quality] += 1
                        
                        # Check quality threshold
                        if QualityThreshold.meets_threshold(quality, threshold):
                            # Store the pool with auth retry handling
                            from bastion.op_client import OPAuthError, wait_for_auth
                            
                            device_meta = metadata.to_dict()
                            stored = False
                            
                            while not stored:
                                try:
                                    pool_uuid, serial = pool.create_pool(
                                        entropy_bytes=entropy_bytes,
                                        source="infnoise",
                                        analysis=analysis,
                                        vault=vault,
                                        device_metadata=device_meta,
                                        batch_id=next_batch_id,
                                    )
                                    stored = True
                                    
                                except OPAuthError:
                                    # Pause progress display
                                    progress.stop()
                                    console.print("\n[yellow]⏸ 1Password locked - waiting for unlock...[/yellow]")
                                    console.print("  [dim]Entropy is safely held in memory[/dim]")
                                    
                                    # Wait for auth (with notification and bell)
                                    wait_for_auth()
                                    
                                    console.print("[green]✓ 1Password unlocked - resuming...[/green]\n")
                                    progress.start()
                                    # Loop will retry create_pool
                                    
                                except RuntimeError as e:
                                    # Non-auth 1Password error - exit gracefully without traceback
                                    progress.stop()
                                    # Clear sensitive data before exiting
                                    del entropy_bytes
                                    del device_meta
                                    console.print(f"\n[red]1Password error: {e}[/red]")
                                    console.print("[dim]Entropy has been discarded from memory[/dim]")
                                    raise typer.Exit(1)
                            
                            # Clear entropy from memory after successful storage
                            del entropy_bytes
                            del device_meta
                            
                            stats["collected"] += 1
                            progress.update(task, completed=stats["collected"])
                            
                            # Show periodic progress (adaptive interval based on pool size)
                            if stats["collected"] % progress_interval == 0 or stats["collected"] == count:
                                _show_batch_progress(stats, count)
                            
                            break  # Success, move to next pool
                        else:
                            # Quality below threshold - keep trying (never accept lower quality)
                            stats["rejected"] += 1
                            stats["retries"] += 1
                            retries_for_pool += 1
                            
                            # Clear rejected entropy from memory
                            del entropy_bytes
                            
                            progress.update(task, description=f"Pool {pool_num}: retry {retries_for_pool} (got {quality})")
                            # Continue loop - no break, no max retries limit
                                
                    except InfNoiseError as e:
                        console.print(f"\n[red]Device error: {e}[/red]")
                        console.print("Please check device connection and try again")
                        raise typer.Exit(1)
                    
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠ Interrupted by user[/yellow]")
        console.print("  [dim]Any pending entropy has been discarded[/dim]")
    
    # Final summary
    _show_batch_summary(stats, count, next_batch_id, vault)


def _find_batch_id_and_max_serial(pool: "EntropyPool") -> tuple[int, int]:
    """Find the next batch ID and max serial from a single 1Password query.
    
    This function optimizes batch operations by:
    1. Making a single `op item list` call
    2. Extracting max serial from titles (for serial cache)
    3. Checking only recent pools for batch ID
    
    The max serial is also cached in the pool instance for subsequent
    create_pool() calls, avoiding redundant 1Password queries.
    
    Args:
        pool: EntropyPool instance
        
    Returns:
        Tuple of (next_batch_id, max_serial)
    """
    import subprocess
    import json
    
    try:
        result = subprocess.run(
            ["op", "item", "list", "--tags", pool.POOL_TAG, "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=120,  # Longer timeout for large pool counts (200+)
        )
        
        items = json.loads(result.stdout)
        
        if not items:
            pool.set_cached_serial(0)
            return (1, 0)
        
        # Parse serial from title: "Bastion Entropy Source #123"
        def get_serial(item: dict) -> int:
            title = item.get("title", "")
            if "#" in title:
                try:
                    return int(title.split("#")[-1])
                except ValueError:
                    return 0
            return 0
        
        # Sort descending by serial
        items.sort(key=get_serial, reverse=True)
        
        # Max serial is from the first item (highest serial)
        max_serial = get_serial(items[0]) if items else 0
        
        # Cache the max serial for create_pool() to use
        pool.set_cached_serial(max_serial)
        
        # Only check the 10 most recent pools for batch ID
        max_batch_id = 0
        for item in items[:10]:
            try:
                detail_result = subprocess.run(
                    ["op", "item", "get", item.get("id", ""), "--format", "json"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=10,
                )
                detail_data = json.loads(detail_result.stdout)
                
                for field in detail_data.get("fields", []):
                    if field.get("label") == "Batch ID":
                        try:
                            batch_id = int(field.get("value", 0))
                            max_batch_id = max(max_batch_id, batch_id)
                        except (ValueError, TypeError):
                            pass
                        break
            except (subprocess.CalledProcessError, json.JSONDecodeError):
                continue
        
        return (max_batch_id + 1, max_serial)
        
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return (1, 0)


def _show_batch_progress(stats: dict, target: int) -> None:
    """Show progress summary during batch collection."""
    elapsed = time.time() - stats["start_time"]
    rate = stats["collected"] / elapsed if elapsed > 0 else 0
    remaining = target - stats["collected"]
    eta = remaining / rate if rate > 0 else 0
    
    console.print(
        f"\n  [cyan]Progress:[/cyan] {stats['collected']}/{target} collected, "
        f"{stats['rejected']} rejected, {stats['retries']} retries"
    )
    console.print(
        f"  [dim]Rate: {rate:.1f} pools/sec | ETA: {eta:.0f}s remaining[/dim]"
    )


def _show_batch_summary(stats: dict, target: int, batch_id: int, vault: str) -> None:
    """Show final summary of batch collection."""
    elapsed = time.time() - stats["start_time"]
    
    console.print("\n[bold cyan]═══ Batch Collection Summary ═══[/bold cyan]")
    console.print(f"  Batch ID: {batch_id}")
    console.print(f"  Vault: {vault}")
    console.print(f"  Target: {target} pools")
    console.print(f"  Collected: {stats['collected']} pools")
    console.print(f"  Rejected: {stats['rejected']} (retried)")
    console.print(f"  Time: {elapsed:.1f}s ({stats['collected']/elapsed:.1f} pools/sec)")
    console.print()
    console.print("  [bold]Quality Distribution:[/bold]")
    for quality in ["EXCELLENT", "GOOD", "FAIR", "POOR"]:
        count = stats["quality_counts"][quality]
        if count > 0:
            pct = count / (stats["collected"] + stats["rejected"]) * 100
            bar = "█" * int(pct / 5)
            console.print(f"    {quality:10} {count:4} ({pct:5.1f}%) {bar}")
    
    if stats["collected"] >= target:
        console.print(f"\n[green]✓ Successfully collected {stats['collected']} entropy pools[/green]")
    else:
        console.print(f"\n[yellow]⚠ Collected {stats['collected']}/{target} pools (interrupted)[/yellow]")


def batch_yubikey_entropy(
    count: int = 100,
    bits: int = 131072,
    min_quality: str = "EXCELLENT",
    vault: str = "Private",
    slot: int = 2,
) -> None:
    """Collect multiple entropy pools from YubiKey HMAC-SHA1.
    
    Automatically collects high-quality entropy pools using YubiKey's
    challenge-response function. Each pool is validated with ENT statistical
    analysis before storage.
    
    Note: YubiKey collection is slower than TRNG (~0.5s per HMAC response).
    For 16KB pools (131072 bits), expect ~26 seconds per pool.
    
    Args:
        count: Number of pools to collect (default 100)
        bits: Bits per pool (default 131072 = 16KB for EXCELLENT quality)
        min_quality: Minimum quality threshold: EXCELLENT, GOOD, FAIR (default EXCELLENT)
        vault: 1Password vault for storage (default "Private")
        slot: YubiKey OTP slot (1 or 2, default 2)
    """
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
    from bastion.entropy import EntropyPool, analyze_entropy_with_ent, QualityThreshold
    from bastion.entropy_yubikey import collect_yubikey_entropy, check_yubikey_available, YubiKeyEntropyError, estimate_collection_time
    
    # Validate minimum quality threshold
    try:
        threshold = QualityThreshold(min_quality.upper())
    except ValueError:
        console.print(f"[red]Error: Invalid quality threshold '{min_quality}'[/red]")
        console.print("Valid thresholds: EXCELLENT, GOOD, FAIR, POOR")
        raise typer.Exit(1)
    
    # Check device availability
    if not check_yubikey_available():
        console.print("[red]Error: YubiKey not available[/red]")
        console.print("Please insert YubiKey and ensure ykman is installed:")
        console.print("  brew install ykman (macOS) or apt install yubikey-manager (Linux)")
        raise typer.Exit(1)
    
    # Validate bits
    if bits < 1024:
        console.print("[red]Error: Minimum 1024 bits required for ENT analysis[/red]")
        raise typer.Exit(1)
    
    # Estimate collection time
    challenges, time_per_pool = estimate_collection_time(bits)
    total_time_estimate = time_per_pool * count
    
    # Initialize pool manager and get batch ID + max serial in one call
    pool = EntropyPool()
    next_batch_id, max_serial = _find_batch_id_and_max_serial(pool)
    
    # Calculate total KB
    bytes_per_pool = bits // 8
    total_kb = (bytes_per_pool * count) / 1024
    
    console.print()
    console.print("[bold cyan]═══ Batch YubiKey Entropy Collection ═══[/bold cyan]")
    console.print(f"  Target: {count} pools × {bits} bits = {total_kb:.1f} KB total")
    console.print(f"  Min quality: {min_quality}")
    console.print(f"  YubiKey slot: {slot}")
    console.print(f"  Batch ID: {next_batch_id}")
    console.print(f"  Vault: {vault}")
    console.print(f"  Estimated time: {total_time_estimate/60:.1f} minutes ({time_per_pool:.1f}s per pool)")
    console.print()
    
    # Progress update interval (show every pool for YubiKey since it's slow)
    progress_interval = 1
    
    stats = {
        "collected": 0,
        "rejected": 0,
        "retries": 0,
        "quality_counts": {"EXCELLENT": 0, "GOOD": 0, "FAIR": 0, "POOR": 0},
        "start_time": time.time(),
    }
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Collecting {count} YubiKey pools...", total=count)
            
            pool_num = 0
            while stats["collected"] < count:
                pool_num += 1
                retries_for_pool = 0
                
                while True:  # Keep trying until quality threshold met
                    try:
                        # Collect entropy from YubiKey
                        entropy_bytes = collect_yubikey_entropy(bits=bits, slot=slot)
                        
                        # Analyze quality
                        analysis = analyze_entropy_with_ent(entropy_bytes)
                        
                        if analysis is None:
                            console.print("\n[red]Error: ENT not installed, cannot validate quality[/red]")
                            console.print("Install: brew install ent (macOS) or apt install ent (Linux)")
                            raise typer.Exit(1)
                        
                        quality = analysis.quality_rating()
                        stats["quality_counts"][quality] += 1
                        
                        # Check quality threshold
                        if QualityThreshold.meets_threshold(quality, threshold):
                            # Store the pool with auth retry handling
                            from bastion.op_client import OPAuthError, wait_for_auth
                            
                            device_meta = {"Slot": str(slot), "Collection Method": "ykman otp calculate"}
                            stored = False
                            
                            while not stored:
                                try:
                                    pool_uuid, serial = pool.create_pool(
                                        entropy_bytes=entropy_bytes,
                                        source="yubikey",
                                        analysis=analysis,
                                        vault=vault,
                                        source_type="yubikey_hmac",
                                        device_metadata=device_meta,
                                        batch_id=next_batch_id,
                                    )
                                    stored = True
                                    
                                except OPAuthError:
                                    progress.stop()
                                    console.print("\n[yellow]⏸ 1Password locked - waiting for unlock...[/yellow]")
                                    console.print("  [dim]Entropy is safely held in memory[/dim]")
                                    wait_for_auth()
                                    console.print("[green]✓ 1Password unlocked - resuming...[/green]\n")
                                    progress.start()
                                    
                                except RuntimeError as e:
                                    progress.stop()
                                    del entropy_bytes
                                    del device_meta
                                    console.print(f"\n[red]1Password error: {e}[/red]")
                                    console.print("[dim]Entropy has been discarded from memory[/dim]")
                                    raise typer.Exit(1)
                            
                            # Clear entropy from memory after successful storage
                            del entropy_bytes
                            del device_meta
                            
                            stats["collected"] += 1
                            progress.update(task, completed=stats["collected"])
                            
                            if stats["collected"] % progress_interval == 0 or stats["collected"] == count:
                                _show_batch_progress(stats, count)
                            
                            break  # Success, move to next pool
                        else:
                            # Quality below threshold - retry
                            stats["rejected"] += 1
                            stats["retries"] += 1
                            retries_for_pool += 1
                            del entropy_bytes
                            progress.update(task, description=f"Pool {pool_num}: retry {retries_for_pool} (got {quality})")
                                
                    except YubiKeyEntropyError as e:
                        # Check if this is a transient connection error
                        error_msg = str(e).lower()
                        is_connection_error = any(phrase in error_msg for phrase in [
                            "failed opening device",
                            "failed to connect",
                            "failed to open connection",
                            "connection type required",
                        ])
                        
                        if is_connection_error:
                            # Transient USB error - exponential backoff with max 30s
                            stats["retries"] += 1
                            retries_for_pool += 1
                            backoff = min(5 * (2 ** (retries_for_pool - 1)), 30)
                            progress.stop()
                            console.print(f"\n[yellow]⚠ YubiKey connection lost - waiting {backoff}s to reconnect...[/yellow]")
                            console.print(f"  [dim]Retry {retries_for_pool} for pool {pool_num}[/dim]")
                            if retries_for_pool >= 3:
                                console.print("  [dim]Tip: Close browsers/apps that may trigger FIDO2 prompts[/dim]")
                            print("\a", end="", flush=True)  # Terminal bell
                            time.sleep(backoff)
                            console.print("[green]✓ Retrying...[/green]\n")
                            progress.start()
                            # Continue the while loop to retry
                        else:
                            # Non-transient error - exit
                            console.print(f"\n[red]YubiKey error: {e}[/red]")
                            console.print("Please check YubiKey connection and slot configuration")
                            raise typer.Exit(1)
                    
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠ Interrupted by user[/yellow]")
        console.print("  [dim]Any pending entropy has been discarded[/dim]")
    
    _show_batch_summary(stats, count, next_batch_id, vault)


def batch_system_entropy(
    count: int = 100,
    bits: int = 131072,
    min_quality: str = "EXCELLENT",
    vault: str = "Private",
) -> None:
    """Collect multiple entropy pools from system RNG (/dev/urandom).
    
    Collects cryptographically secure random bytes from the operating system's
    entropy source. System RNG is fast and always produces near-perfect ENT
    statistics since it's algorithmically whitened.
    
    The value of system entropy is for combining with hardware sources
    (YubiKey, Infinite Noise TRNG) for defense-in-depth.
    
    Args:
        count: Number of pools to collect (default 100)
        bits: Bits per pool (default 131072 = 16KB)
        min_quality: Minimum quality threshold (default EXCELLENT, nearly always passes)
        vault: 1Password vault for storage (default "Private")
    """
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
    from bastion.entropy import EntropyPool, analyze_entropy_with_ent, QualityThreshold
    from bastion.entropy_system_rng import collect_urandom_entropy, check_system_rng_available, SystemRNGError
    
    # Validate minimum quality threshold
    try:
        threshold = QualityThreshold(min_quality.upper())
    except ValueError:
        console.print(f"[red]Error: Invalid quality threshold '{min_quality}'[/red]")
        console.print("Valid thresholds: EXCELLENT, GOOD, FAIR, POOR")
        raise typer.Exit(1)
    
    # Check device availability
    availability = check_system_rng_available()
    if not availability.get("urandom", False):
        console.print("[red]Error: /dev/urandom not available[/red]")
        console.print(f"  OS: {availability.get('os_name', 'unknown')}")
        raise typer.Exit(1)
    
    # Validate bits
    if bits < 1024:
        console.print("[red]Error: Minimum 1024 bits required for ENT analysis[/red]")
        raise typer.Exit(1)
    
    # Initialize pool manager and get batch ID + max serial in one call
    pool = EntropyPool()
    next_batch_id, max_serial = _find_batch_id_and_max_serial(pool)
    
    # Calculate total KB
    bytes_per_pool = bits // 8
    total_kb = (bytes_per_pool * count) / 1024
    
    console.print()
    console.print("[bold cyan]═══ Batch System RNG Entropy Collection ═══[/bold cyan]")
    console.print(f"  Target: {count} pools × {bits} bits = {total_kb:.1f} KB total")
    console.print(f"  Min quality: {min_quality}")
    console.print("  Source: /dev/urandom")
    console.print(f"  Batch ID: {next_batch_id}")
    console.print(f"  Vault: {vault}")
    console.print()
    
    # Progress update interval (adaptive based on pool size)
    bytes_per_pool = bits // 8
    if bytes_per_pool >= 65536:
        progress_interval = 1
    elif bytes_per_pool >= 16384:
        progress_interval = 5
    else:
        progress_interval = 10
    
    stats = {
        "collected": 0,
        "rejected": 0,
        "retries": 0,
        "quality_counts": {"EXCELLENT": 0, "GOOD": 0, "FAIR": 0, "POOR": 0},
        "start_time": time.time(),
    }
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Collecting {count} system pools...", total=count)
            
            pool_num = 0
            while stats["collected"] < count:
                pool_num += 1
                retries_for_pool = 0
                
                while True:  # Keep trying until quality threshold met
                    try:
                        # Collect entropy from system RNG
                        entropy_bytes, metadata = collect_urandom_entropy(bits=bits)
                        
                        # Analyze quality
                        analysis = analyze_entropy_with_ent(entropy_bytes)
                        
                        if analysis is None:
                            console.print("\n[red]Error: ENT not installed, cannot validate quality[/red]")
                            console.print("Install: brew install ent (macOS) or apt install ent (Linux)")
                            raise typer.Exit(1)
                        
                        quality = analysis.quality_rating()
                        stats["quality_counts"][quality] += 1
                        
                        # Check quality threshold
                        if QualityThreshold.meets_threshold(quality, threshold):
                            # Store the pool with auth retry handling
                            from bastion.op_client import OPAuthError, wait_for_auth
                            
                            device_meta = metadata.to_dict()
                            stored = False
                            
                            while not stored:
                                try:
                                    pool_uuid, serial = pool.create_pool(
                                        entropy_bytes=entropy_bytes,
                                        source="system",
                                        analysis=analysis,
                                        vault=vault,
                                        source_type="system_urandom",
                                        device_metadata=device_meta,
                                        batch_id=next_batch_id,
                                    )
                                    stored = True
                                    
                                except OPAuthError:
                                    progress.stop()
                                    console.print("\n[yellow]⏸ 1Password locked - waiting for unlock...[/yellow]")
                                    console.print("  [dim]Entropy is safely held in memory[/dim]")
                                    wait_for_auth()
                                    console.print("[green]✓ 1Password unlocked - resuming...[/green]\n")
                                    progress.start()
                                    
                                except RuntimeError as e:
                                    progress.stop()
                                    del entropy_bytes
                                    del device_meta
                                    console.print(f"\n[red]1Password error: {e}[/red]")
                                    console.print("[dim]Entropy has been discarded from memory[/dim]")
                                    raise typer.Exit(1)
                            
                            # Clear entropy from memory after successful storage
                            del entropy_bytes
                            del device_meta
                            
                            stats["collected"] += 1
                            progress.update(task, completed=stats["collected"])
                            
                            if stats["collected"] % progress_interval == 0 or stats["collected"] == count:
                                _show_batch_progress(stats, count)
                            
                            break  # Success, move to next pool
                        else:
                            # Quality below threshold - retry (rare for system RNG)
                            stats["rejected"] += 1
                            stats["retries"] += 1
                            retries_for_pool += 1
                            del entropy_bytes
                            progress.update(task, description=f"Pool {pool_num}: retry {retries_for_pool} (got {quality})")
                                
                    except SystemRNGError as e:
                        console.print(f"\n[red]System RNG error: {e}[/red]")
                        raise typer.Exit(1)
                    
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠ Interrupted by user[/yellow]")
        console.print("  [dim]Any pending entropy has been discarded[/dim]")
    
    _show_batch_summary(stats, count, next_batch_id, vault)


def combine_from_sources(
    sources: str,
    min_bits: int = 131072,
    extend_bits: Optional[int] = None,
    count: int = 1,
    vault: str = "Private",
) -> None:
    """Combine entropy from multiple source types into derived pools.
    
    For each derived pool, selects the first unconsumed pool of each specified
    source type (meeting the minimum bit requirement), combines them using
    XOR+SHAKE256, and marks the source pools as consumed.
    
    This provides defense-in-depth by combining independent entropy sources:
    - Hardware TRNG (infnoise)
    - Hardware HMAC (yubikey)
    - System CSPRNG (system)
    
    Args:
        sources: Comma-separated source types (e.g., 'infnoise,yubikey,system')
        min_bits: Minimum bits required per source pool (default 131072 = 16KB)
        extend_bits: Optional target output size (default: max of input sizes)
        count: Number of derived pools to create (default 1)
        vault: 1Password vault for storage (default "Private")
    """
    from bastion.entropy import EntropyPool, combine_entropy_sources, analyze_entropy_with_ent
    from bastion.op_client import OPAuthError, wait_for_auth
    
    # Parse source types
    source_types = [s.strip().lower() for s in sources.split(",") if s.strip()]
    
    if len(source_types) < 2:
        console.print("[red]Error: At least 2 source types required for combining[/red]")
        console.print("Example: --sources infnoise,yubikey,system")
        raise typer.Exit(1)
    
    console.print()
    console.print("[bold cyan]═══ Entropy Source Combination ═══[/bold cyan]")
    console.print(f"  Sources: {', '.join(source_types)}")
    console.print(f"  Min bits per source: {min_bits}")
    console.print(f"  Target derived pools: {count}")
    if extend_bits:
        console.print(f"  Extend output to: {extend_bits} bits")
    console.print(f"  Vault: {vault}")
    console.print()
    
    pool = EntropyPool()
    created_count = 0
    
    for i in range(count):
        console.print(f"[cyan]Creating derived pool {i+1}/{count}...[/cyan]")
        
        # Find first available pool for each source type
        source_pools = []
        source_entropies = []
        
        for source_type in source_types:
            pool_meta = pool.get_first_available_pool(source=source_type, min_bits=min_bits)
            
            if pool_meta is None:
                console.print(f"  [red]✗ No unconsumed {source_type} pool with {min_bits}+ bits available[/red]")
                if i == 0:
                    console.print()
                    console.print("[yellow]Available pools by source:[/yellow]")
                    for st in source_types:
                        available = pool.list_pools_by_source(source=st, min_bits=min_bits, include_consumed=False)
                        console.print(f"  {st}: {len(available)} available")
                    raise typer.Exit(1)
                else:
                    console.print(f"\n[yellow]⚠ Created {created_count}/{count} derived pools (ran out of {source_type} pools)[/yellow]")
                    return
            
            console.print(f"  [green]✓[/green] Found {source_type} pool: #{pool_meta.get('serial')} ({pool_meta.get('bit_count', 0)} bits)")
            source_pools.append(pool_meta)
        
        # Retrieve entropy from each source pool
        console.print("  Retrieving entropy from source pools...")
        for pool_meta in source_pools:
            pool_data = pool.get_pool(pool_meta["uuid"])
            if pool_data is None:
                console.print(f"  [red]✗ Failed to retrieve pool {pool_meta['uuid']}[/red]")
                raise typer.Exit(1)
            
            entropy_bytes, metadata = pool_data
            source_entropies.append((pool_meta["source"], entropy_bytes))
        
        # Combine entropy sources
        console.print("  Combining with XOR+SHAKE256...")
        all_bytes = [entropy for _, entropy in source_entropies]
        combined_bytes = combine_entropy_sources(*all_bytes)
        
        # Extend if requested
        if extend_bits and extend_bits > len(combined_bytes) * 8:
            import hashlib
            target_bytes = extend_bits // 8
            shake = hashlib.shake_256(combined_bytes)
            combined_bytes = shake.digest(target_bytes)
            console.print(f"  Extended to {extend_bits} bits using SHAKE256")
        
        # Analyze combined entropy
        analysis = analyze_entropy_with_ent(combined_bytes)
        
        if analysis:
            console.print(f"  Combined quality: {analysis.quality_rating()} ({analysis.entropy_bits_per_byte:.6f} bits/byte)")
        
        # Store derived pool with auth retry
        source_label = "+".join(source_types)
        source_uuids = [p["uuid"] for p in source_pools]
        
        stored = False
        while not stored:
            try:
                derived_uuid, serial = pool.create_pool(
                    entropy_bytes=combined_bytes,
                    source=source_label,
                    analysis=analysis,
                    vault=vault,
                    pool_type="derived",
                    source_uuids=source_uuids,
                    derivation_method="xor_shake256",
                )
                stored = True
                
            except OPAuthError:
                console.print("\n[yellow]⏸ 1Password locked - waiting for unlock...[/yellow]")
                wait_for_auth()
                console.print("[green]✓ 1Password unlocked - resuming...[/green]\n")
                
            except RuntimeError as e:
                del combined_bytes
                console.print(f"\n[red]1Password error: {e}[/red]")
                raise typer.Exit(1)
        
        console.print(f"  [green]✓[/green] Created derived pool #{serial} ({len(combined_bytes) * 8} bits)")
        
        # Mark source pools as consumed
        console.print("  Marking source pools as consumed...")
        for pool_meta in source_pools:
            try:
                pool.mark_consumed(pool_meta["uuid"])
                console.print(f"    [dim]✓ Consumed: {pool_meta['source']} #{pool_meta.get('serial')}[/dim]")
            except RuntimeError as e:
                console.print(f"    [yellow]⚠ Failed to mark consumed: {e}[/yellow]")
        
        # Clear from memory
        del combined_bytes
        for _, entropy in source_entropies:
            del entropy
        
        created_count += 1
        console.print()
    
    console.print(f"[green]✓ Successfully created {created_count} derived entropy pools[/green]")
