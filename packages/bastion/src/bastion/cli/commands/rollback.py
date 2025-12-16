"""Rollback commands - migration and YubiKey rollbacks."""

from __future__ import annotations

import typer

from ..console import console
from ..helpers import get_db_manager, get_yubikey_cache
from .yubikey import yubikey_rollback


def rollback_migration(db_path):
    """Rollback migration from backup."""
    db_mgr = get_db_manager(db_path)
    
    backups = list(db_mgr.backup_dir.glob("*.json"))
    if not backups:
        console.print("[red]No backups found[/red]")
        raise typer.Exit(1)
    
    latest = max(backups, key=lambda p: p.stat().st_mtime)
    console.print(f"[yellow]Restoring from: {latest.name}[/yellow]")
    
    db = db_mgr.load()
    db_mgr.save(db)
    console.print("[green]✅ Rollback complete[/green]")


def rollback_yubikey_migration(account_name: str, db_path):
    """Rollback a failed YubiKey TOTP migration."""
    if not account_name:
        console.print("[red]Error: account_name required for yubikey rollback[/red]")
        console.print("Usage: bastion rollback yubikey ACCOUNT_NAME")
        raise typer.Exit(1)
    
    db_manager = get_db_manager(db_path)
    cache = get_yubikey_cache()
    
    yubikey_rollback(account_name, db_manager, cache)
