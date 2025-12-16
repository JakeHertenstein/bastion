"""Update command helpers for Bastion CLI."""

from typing import Optional

import typer
from rich.console import Console

console = Console()


def update_metadata_show(uuid: str) -> None:
    """Show current Bastion Metadata for an item.
    
    Args:
        uuid: 1Password item UUID
    """
    from bastion.bastion_metadata import get_bastion_metadata
    
    metadata = get_bastion_metadata(uuid)
    if not metadata:
        console.print("[yellow]No Bastion Metadata found for this item[/yellow]")
    else:
        console.print("\n[cyan]Bastion Metadata:[/cyan]\n")
        if metadata.password_changed:
            console.print(f"  Password Changed: {metadata.password_changed}")
        if metadata.password_expires:
            console.print(f"  Password Expires: {metadata.password_expires}")
        if metadata.totp_seed_issued:
            console.print(f"  TOTP Seed Issued: {metadata.totp_seed_issued}")
        if metadata.last_security_review:
            console.print(f"  Last Security Review: {metadata.last_security_review}")
        if metadata.next_review_due:
            console.print(f"  Next Review Due: {metadata.next_review_due}")
        if metadata.breach_detected:
            console.print(f"  Breach Detected: {metadata.breach_detected}")
        if metadata.risk_level:
            console.print(f"  Risk Level: {metadata.risk_level}")
        if metadata.bastion_notes:
            console.print(f"  Bastion Notes: {metadata.bastion_notes}")


def update_metadata(
    uuid: str,
    password_changed: Optional[str] = None,
    password_expires: Optional[str] = None,
    totp_issued: Optional[str] = None,
    last_review: Optional[str] = None,
    next_review: Optional[str] = None,
    breach_detected: Optional[str] = None,
    risk_level: Optional[str] = None,
    bastion_notes: Optional[str] = None,
) -> None:
    """Update Bastion Metadata for an item.
    
    Args:
        uuid: 1Password item UUID
        password_changed: Password change date YYYY-MM-DD
        password_expires: Password expiry date YYYY-MM-DD
        totp_issued: TOTP seed issue date YYYY-MM-DD
        last_review: Last security review date YYYY-MM-DD
        next_review: Next review due date YYYY-MM-DD
        breach_detected: Breach detection date YYYY-MM-DD
        risk_level: Risk level: CRITICAL/HIGH/MEDIUM/LOW
        bastion_notes: Security notes
    """
    from bastion.bastion_metadata import update_bastion_metadata
    
    updates = {}
    if password_changed:
        updates['password_changed'] = password_changed
    if password_expires:
        updates['password_expires'] = password_expires
    if totp_issued:
        updates['totp_seed_issued'] = totp_issued
    if last_review:
        updates['last_security_review'] = last_review
    if next_review:
        updates['next_review_due'] = next_review
    if breach_detected:
        updates['breach_detected'] = breach_detected
    if risk_level:
        if risk_level.upper() not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            console.print("[red]Error: Risk level must be CRITICAL, HIGH, MEDIUM, or LOW[/red]")
            raise typer.Exit(1)
        updates['risk_level'] = risk_level.upper()
    if bastion_notes:
        updates['bastion_notes'] = bastion_notes
    
    if not updates:
        console.print("[yellow]No fields specified to update. Use --show to view current metadata.[/yellow]")
        raise typer.Exit(1)
    
    console.print(f"[cyan]Updating Bastion Metadata for {uuid[:8]}...[/cyan]")
    success = update_bastion_metadata(uuid, **updates)
    
    if success:
        console.print("[green]✓ Bastion Metadata updated successfully[/green]")
        for key, value in updates.items():
            console.print(f"  {key.replace('_', ' ').title()}: {value}")
    else:
        console.print("[red]✗ Failed to update Bastion Metadata[/red]")
        raise typer.Exit(1)
