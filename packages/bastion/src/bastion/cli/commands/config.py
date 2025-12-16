"""Configuration display and modification commands.

This module contains helper functions for displaying and modifying
the username generator configuration and entropy pool management.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer

from ..console import console

if TYPE_CHECKING:
    pass


def show_username_config(services: bool = False) -> None:
    """Show username generator configuration.
    
    Args:
        services: If True, show service rules instead of general config
    """
    from bastion.username_generator import UsernameGeneratorConfig
    
    try:
        config = UsernameGeneratorConfig()
    except RuntimeError as e:
        console.print(f"[red]Error loading config:[/red] {e}")
        raise typer.Exit(1)
    
    if services:
        console.print("\n[cyan]Service Rules:[/cyan]")
        service_rules = config.get_service_rules()
        if not service_rules:
            console.print("[dim]No service rules defined[/dim]")
        else:
            # Sort by service name
            sorted_services = sorted(service_rules.items())
            for service_name, rules in sorted_services:
                min_len = rules.get("min", "N/A")
                max_len = rules.get("max", "N/A")
                desc = rules.get("description", "")
                console.print(f"  {service_name:15} min={str(min_len):>3} max={str(max_len):>3}  {desc}")
    else:
        console.print("[cyan]Username Generator Configuration:[/cyan]\n")
        console.print(f"  Default owner:     {config.get_default_owner()}")
        console.print(f"  Default algorithm: {config.get_default_algorithm()}")
        console.print(f"  Default length:    {config.get_default_length()}")
        
        # Show service count
        service_rules = config.get_service_rules()
        console.print(f"  Service rules:     {len(service_rules)} defined")
        console.print("\n[dim]Use 'bastion set config username' to modify settings[/dim]")
        console.print("[dim]Use 'bastion show config username --services' to list service constraints[/dim]")


def set_username_config(
    owner: str | None = None,
    algorithm: str | None = None,
    length: int | None = None
) -> None:
    """Set username generator configuration.
    
    Args:
        owner: Default owner email
        algorithm: Default algorithm (sha256, sha512, sha3-512)
        length: Default username length
    """
    from bastion.username_generator import UsernameGeneratorConfig
    
    try:
        config = UsernameGeneratorConfig()
    except RuntimeError as e:
        console.print(f"[red]Error loading config:[/red] {e}")
        raise typer.Exit(1)
    
    modified = False
    
    if owner:
        config.set_default_owner(owner)
        console.print(f"[green]✅ Set default owner:[/green] {owner}")
        modified = True
    
    if algorithm:
        if algorithm not in ["sha256", "sha512", "sha3-512"]:
            console.print(f"[red]Error:[/red] Invalid algorithm '{algorithm}'")
            console.print("[dim]Valid: sha256, sha512, sha3-512[/dim]")
            raise typer.Exit(1)
        config.set_default_algorithm(algorithm)
        console.print(f"[green]✅ Set default algorithm:[/green] {algorithm}")
        modified = True
    
    if length:
        if length < 1 or length > 100:
            console.print("[red]Error:[/red] Length must be 1-100")
            raise typer.Exit(1)
        config.set_default_length(length)
        console.print(f"[green]✅ Set default length:[/green] {length}")
        modified = True
    
    if not modified:
        console.print("[yellow]No changes specified. Use --owner, --algorithm, or --length[/yellow]")


def list_entropy_pools() -> None:
    """List all unconsumed entropy pools."""
    from rich.table import Table
    from bastion.entropy import EntropyPool
    
    console.print("[cyan]Entropy Pools:[/cyan]\n")
    pool = EntropyPool()
    pools = pool.list_pools(include_consumed=False)
    
    if not pools:
        console.print("[yellow]No unconsumed entropy pools found[/yellow]")
        console.print("Generate one with: bastion generate entropy yubikey --bits 512")
    else:
        table = Table(title="Available Entropy Pools")
        table.add_column("Serial", style="cyan")
        table.add_column("Source", style="green")
        table.add_column("Size", style="yellow")
        table.add_column("Quality", style="magenta")
        table.add_column("Created", style="dim")
        table.add_column("UUID", style="dim")
        
        for pool_info in pools:
            table.add_row(
                pool_info.get("serial", "?"),
                pool_info.get("source", "?"),
                pool_info.get("bit_count", "?"),
                pool_info.get("quality", "N/A"),
                pool_info.get("created_at", "?")[:19] if pool_info.get("created_at") else "?",
                pool_info.get("uuid", "?")[:8] + "...",
            )
        
        console.print(table)


def analyze_entropy_pool(pool_uuid: str) -> None:
    """Analyze a specific entropy pool.
    
    Args:
        pool_uuid: UUID of the entropy pool to analyze
    """
    from bastion.entropy import EntropyPool, analyze_entropy_with_ent
    
    console.print(f"[cyan]Analyzing entropy pool {pool_uuid[:8]}...[/cyan]\n")
    
    pool = EntropyPool()
    result = pool.get_pool(pool_uuid)
    
    if not result:
        console.print(f"[red]Error: Pool {pool_uuid} not found[/red]")
        raise typer.Exit(1)
    
    entropy_bytes, metadata = result
    
    console.print(f"Source: {metadata.get('source', 'unknown')}")
    console.print(f"Size: {metadata.get('byte_count', len(entropy_bytes))} bytes ({len(entropy_bytes) * 8} bits)")
    console.print(f"Created: {metadata.get('created_at', 'unknown')}")
    console.print(f"Consumed: {metadata.get('consumed', False)}")
    
    # Run ENT analysis
    console.print("\n[cyan]Running ENT analysis...[/cyan]")
    analysis = analyze_entropy_with_ent(entropy_bytes)
    
    if analysis is None:
        console.print("[yellow]ENT not installed[/yellow]")
        console.print("Install: brew install ent (macOS) or apt install ent (Linux)")
    else:
        console.print(f"  Entropy: {analysis.entropy_bits_per_byte:.6f} bits/byte")
        console.print(f"  Chi-square: {analysis.chi_square:.2f}")
        console.print(f"  Chi-square p-value: {analysis.chi_square_pvalue:.6f}")
        console.print(f"  Mean: {analysis.arithmetic_mean:.4f}")
        console.print(f"  Monte Carlo π: {analysis.monte_carlo_pi:.6f} (error: {analysis.monte_carlo_error:.2f}%)")
        console.print(f"  Serial correlation: {analysis.serial_correlation:.6f}")
        console.print(f"  Quality: [bold]{analysis.quality_rating()}[/bold]")
        console.print(f"  Acceptable: {analysis.is_acceptable()}")
