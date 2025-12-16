"""Analyze command helpers for Bastion CLI."""

from typing import Optional

import typer
from rich.console import Console

from ..helpers import get_db_manager
from ...risk_analysis import RiskAnalyzer, RiskLevel
from ...models import TwoFAMethod

console = Console()


def analyze_risk(
    db_path=None,
    level: Optional[str] = None,
    has_tag: Optional[str] = None,
    has_capability: Optional[str] = None,
    weakest_2fa: Optional[str] = None,
) -> None:
    """Analyze account risk with optional filters.
    
    Args:
        db_path: Optional database path
        level: Filter by risk level (critical/high/medium/low)
        has_tag: Filter by tag
        has_capability: Filter by capability
        weakest_2fa: Filter by weakest 2FA method
    """
    db_mgr = get_db_manager(db_path)
    db = db_mgr.load()
    analyzer = RiskAnalyzer(db.accounts)
    
    results = None
    
    if level:
        try:
            risk_level = RiskLevel(level.lower())
            results = analyzer.filter_by_risk_level(risk_level)
        except ValueError:
            console.print(f"[red]Invalid risk level: {level}[/red]")
            console.print("Valid levels: critical, high, medium, low")
            raise typer.Exit(1)
    
    elif has_tag:
        results = analyzer.filter_by_tag(has_tag)
    
    elif has_capability:
        cap = has_capability if has_capability.startswith("bastion-cap-") else f"bastion-cap-{has_capability}"
        results = analyzer.filter_by_tag(cap)
        
        # Further filter by weakest 2FA if specified
        if weakest_2fa:
            try:
                method = TwoFAMethod(weakest_2fa.lower())
                filtered_uuids = {r["uuid"] for r in results}
                filtered_accounts = {
                    uuid: acc for uuid, acc in db.accounts.items()
                    if uuid in filtered_uuids and acc.weakest_2fa == method
                }
                analyzer_filtered = RiskAnalyzer(filtered_accounts)
                results = analyzer_filtered.analyze_all()
            except ValueError:
                console.print(f"[red]Invalid 2FA method: {weakest_2fa}[/red]")
                console.print("Valid methods: fido2, totp, push, sms, email, none")
                raise typer.Exit(1)
    
    elif weakest_2fa:
        try:
            method = TwoFAMethod(weakest_2fa.lower())
            results = analyzer.filter_by_weakest_2fa(method)
        except ValueError:
            console.print(f"[red]Invalid 2FA method: {weakest_2fa}[/red]")
            console.print("Valid methods: fido2, totp, push, sms, email, none")
            raise typer.Exit(1)
    
    analyzer.print_risk_report(console, results)


def analyze_dependencies(db_path=None, account: str = "") -> None:
    """Analyze account dependencies.
    
    Args:
        db_path: Optional database path
        account: Account title to analyze
    """
    if not account:
        console.print("[red]Error:[/red] --account required for dependency analysis")
        console.print("Usage: bastion analyze dependencies --account <name>")
        raise typer.Exit(1)
    
    db_mgr = get_db_manager(db_path)
    db = db_mgr.load()
    analyzer = RiskAnalyzer(db.accounts)
    
    analyzer.print_dependency_graph(console, account)


def query_accounts(
    db_path=None,
    has_tag: Optional[list[str]] = None,
    has_capability: Optional[str] = None,
    weakest_2fa: Optional[str] = None,
    show_breach_exposed: bool = False,
    show_no_rate_limit: bool = False,
    show_shared_access: bool = False,
    with_flat_tags: bool = False,
    limit: Optional[int] = 20,
) -> None:
    """Query accounts with flexible filtering.
    
    Args:
        db_path: Optional database path
        has_tag: Filter by tag(s) (AND logic)
        has_capability: Filter by capability
        weakest_2fa: Filter by weakest 2FA method
        show_breach_exposed: Show breach-exposed only
        show_no_rate_limit: Show accounts without rate limiting
        show_shared_access: Show shared access accounts
        with_flat_tags: Show accounts with legacy flat bastion-* tags
        limit: Limit results (0 = show all)
    """
    db_mgr = get_db_manager(db_path)
    db = db_mgr.load()
    analyzer = RiskAnalyzer(db.accounts)
    
    results = None
    
    if with_flat_tags:
        # Filter to accounts with any legacy flat bastion-* tag
        filtered_accounts = {
            uuid: acc for uuid, acc in db.accounts.items()
            if any(tag.startswith("bastion-") for tag in acc.tag_list)
        }
        analyzer_filtered = RiskAnalyzer(filtered_accounts)
        results = analyzer_filtered.analyze_all()
    
    elif show_breach_exposed:
        results = analyzer.get_breach_exposed()
    
    elif show_no_rate_limit:
        results = analyzer.get_no_rate_limit()
    
    elif show_shared_access:
        results = analyzer.get_shared_access()
    
    elif has_tag:
        # Filter by multiple tags (AND logic)
        filtered_accounts = db.accounts
        for tag in has_tag:
            filtered_accounts = {
                uuid: acc for uuid, acc in filtered_accounts.items()
                if tag in acc.tag_list
            }
        analyzer_filtered = RiskAnalyzer(filtered_accounts)
        results = analyzer_filtered.analyze_all()
    
    elif has_capability:
        cap = has_capability if has_capability.startswith("bastion-cap-") else f"bastion-cap-{has_capability}"
        results = analyzer.filter_by_tag(cap)
    
    elif weakest_2fa:
        try:
            method = TwoFAMethod(weakest_2fa.lower())
            results = analyzer.filter_by_weakest_2fa(method)
        except ValueError:
            console.print(f"[red]Invalid 2FA method: {weakest_2fa}[/red]")
            raise typer.Exit(1)
    
    else:
        console.print("[yellow]No filters specified, showing all accounts[/yellow]")
        results = analyzer.analyze_all()
    
    # Apply additional weakest_2fa filter if specified alongside other filters
    if weakest_2fa and not results:
        try:
            method = TwoFAMethod(weakest_2fa.lower())
            if results:
                filtered_uuids = {r["uuid"] for r in results}
                filtered_accounts = {
                    uuid: acc for uuid, acc in db.accounts.items()
                    if uuid in filtered_uuids and acc.weakest_2fa == method
                }
                analyzer_filtered = RiskAnalyzer(filtered_accounts)
                results = analyzer_filtered.analyze_all()
        except ValueError:
            pass
    
    # Convert limit (0 means no limit)
    display_limit = None if limit == 0 else limit
    analyzer.print_risk_report(console, results, limit=display_limit)
