"""Validation commands - tag and rule validation."""

from __future__ import annotations

import typer

from ..console import console
from ..helpers import get_db_manager
from ...validation import validate_tags
from ...validation_rules import ValidationEngine


def validate_migration(db_path):
    """Validate migration tags."""
    db_mgr = get_db_manager(db_path)
    db = db_mgr.load()
    
    errors = validate_tags(db)
    
    if errors:
        console.print("[red]❌ Validation FAILED[/red]")
        for error in errors:
            console.print(f"  - {error}")
        raise typer.Exit(1)
    else:
        console.print("[green]✅ Validation passed. No issues found.[/green]")


def validate_rules(db_path):
    """Validate accounts against security rules."""
    db_mgr = get_db_manager(db_path)
    db = db_mgr.load()
    
    engine = ValidationEngine()
    violations = engine.validate_all(db.accounts)
    
    engine.print_report(violations, console)
    
    # Exit with error if critical violations found
    if engine.has_critical_violations(violations):
        console.print("\n[red bold]❌ CRITICAL violations found - must be fixed![/red bold]")
        raise typer.Exit(1)
    elif violations:
        console.print("\n[yellow]⚠️  Warnings found - review recommended[/yellow]")
    else:
        console.print("\n[green]✅ All validation rules passed![/green]")
