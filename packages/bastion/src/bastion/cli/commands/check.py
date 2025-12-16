"""Check commands - rotation status and breach detection."""

from __future__ import annotations

import typer

from ..console import console
from ..helpers import get_db_manager
from ...breach_detection import BreachDetector
from ...op_client import OpClient
from ...reports import ReportGenerator


def check_rotation(db_path):
    """Check password rotation status."""
    db_mgr = get_db_manager(db_path)
    db = db_mgr.load()
    
    needs_rotation = sum(
        1 for acc in db.accounts.values()
        if acc.is_pre_baseline or (acc.days_until_rotation is not None and acc.days_until_rotation < 0)
    )
    
    if needs_rotation > 0:
        console.print(f"[red]⚠️  {needs_rotation} password(s) need immediate rotation[/red]")
        reporter = ReportGenerator(console)
        reporter.generate_report(db)
        raise typer.Exit(1)
    else:
        console.print("[green]✅ All passwords current[/green]")


def check_breaches(db_path, update_tags: bool = False):
    """Scan passwords against Have I Been Pwned database."""
    db_mgr = get_db_manager(db_path)
    db = db_mgr.load()
    
    try:
        op_client = OpClient()
        detector = BreachDetector(console)
        
        console.print("[cyan]Scanning passwords against Have I Been Pwned database...[/cyan]")
        console.print("[dim]This uses k-anonymity - your passwords are never sent to HIBP[/dim]\n")
        
        results = detector.scan_all_accounts(db, op_client, update_tags=update_tags)
        
        breached_count = sum(1 for is_breached, _ in results.values() if is_breached)
        
        if breached_count > 0:
            if update_tags:
                db_mgr.save(db)
                console.print("\n[green]✅ Database updated with breach tags[/green]")
            
            console.print("\n[red]Use 'bastion analyze risk --has-tag bastion-sec-breach-exposed' to see all breached accounts[/red]")
            raise typer.Exit(1)
    
    except RuntimeError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
