"""Analysis commands: analyze, query, audit, check."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from ..helpers import get_db_manager, get_yubikey_cache
from ...op_client import OpClient
from .analyze import analyze_risk, analyze_dependencies, query_accounts
from .audit import (
    audit_no_tags,
    audit_untagged_2fa,
    audit_missing_email,
    audit_same_domain,
    audit_same_apps,
    audit_sso_signin,
)
from .check import check_rotation, check_breaches
from .yubikey import yubikey_audit_slots

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
    """Register analysis-related commands with the app."""
    
    @app.command("analyze")
    def analyze_command(
        noun: Annotated[str, typer.Argument(help="'risk' or 'dependencies'")] = "risk",
        db_path: DbPathOption = None,
        level: Annotated[Optional[str], typer.Option(help="Filter by risk level (critical/high/medium/low)")] = None,
        has_tag: Annotated[Optional[str], typer.Option(help="Filter by tag")] = None,
        has_capability: Annotated[Optional[str], typer.Option(help="Filter by capability (e.g., money-transfer)")] = None,
        weakest_2fa: Annotated[Optional[str], typer.Option(help="Filter by weakest 2FA (fido2/totp/sms/none)")] = None,
        account: Annotated[Optional[str], typer.Option(help="Account title for dependency analysis")] = None,
    ) -> None:
        """Analyze account risk or dependencies.
        
        Examples:
          bastion analyze risk                           # Show all accounts by risk
          bastion analyze risk --level critical          # Show only CRITICAL accounts
          bastion analyze risk --has-tag bastion-2fa-sms     # Show accounts with SMS enabled
          bastion analyze risk --has-capability money-transfer --weakest-2fa sms
          bastion analyze dependencies --account Gmail   # Show dependency tree
        """
        if noun == "risk":
            analyze_risk(db_path, level, has_tag, has_capability, weakest_2fa)
        elif noun == "dependencies":
            analyze_dependencies(db_path, account or "")
        else:
            console.print(f"[red]Error:[/red] Expected 'risk' or 'dependencies', got '{noun}'")
            console.print("Usage: bastion analyze <risk|dependencies> [OPTIONS]")
            raise typer.Exit(1)

    @app.command("query")
    def query_command(
        db_path: DbPathOption = None,
        has_tag: Annotated[Optional[list[str]], typer.Option(help="Filter by tag (can specify multiple)")] = None,
        has_capability: Annotated[Optional[str], typer.Option(help="Filter by capability")] = None,
        weakest_2fa: Annotated[Optional[str], typer.Option(help="Filter by weakest 2FA method")] = None,
        show_breach_exposed: Annotated[bool, typer.Option("--breach-exposed", help="Show breach-exposed only")] = False,
        show_no_rate_limit: Annotated[bool, typer.Option("--no-rate-limit", help="Show accounts without rate limiting")] = False,
        show_shared_access: Annotated[bool, typer.Option("--shared-access", help="Show shared access accounts")] = False,
        with_flat_tags: Annotated[bool, typer.Option("--with-flat-tags", help="Show all accounts with legacy flat bastion-* tags")] = False,
        limit: Annotated[Optional[int], typer.Option(help="Limit results (0 = show all, default: 20)")] = 20,
    ) -> None:
        """Query accounts with flexible filtering.
        
        Examples:
          bastion query --with-flat-tags                                  # All accounts with legacy flat bastion-* tags
          bastion query --with-flat-tags --limit 0                        # Show all (no limit)
          bastion query --has-tag bastion-2fa-sms                            # All with SMS
          bastion query --has-capability money-transfer                  # Money transfer accounts
          bastion query --breach-exposed                                 # Compromised passwords
          bastion query --has-capability money-transfer --weakest-2fa sms  # High risk combo
          bastion query --shared-access --has-capability money-transfer    # Shared financial accounts
        """
        query_accounts(
            db_path, has_tag, has_capability, weakest_2fa,
            show_breach_exposed, show_no_rate_limit, show_shared_access,
            with_flat_tags, limit
        )

    @app.command("audit")
    def audit_command(
        noun: Annotated[str, typer.Argument(help="Audit type: 'no-tags', 'untagged-2fa', 'missing-email', 'same-domain', 'same-apps', 'sso-signin', 'yubikey'")],
        db_path: DbPathOption = None,
        csv_output: Annotated[Optional[Path], typer.Option("--csv", help="Export results to CSV file")] = None,
        limit: Annotated[Optional[int], typer.Option(help="Limit results (0 = show all, default: 20)")] = 20,
    ) -> None:
        """Audit accounts for missing data or tagging issues.
        
        Examples:
          bastion audit no-tags                    # Items with no bastion-* tags
          bastion audit no-tags --csv untagged.csv # Export to CSV
          bastion audit untagged-2fa               # Has 2FA field but no bastion-2fa-* tag
          bastion audit missing-email              # No email/username field
          bastion audit same-domain                # Group by domain
          bastion audit same-apps                  # Group by apps
          bastion audit sso-signin                 # Items with "Sign in with"
          bastion audit yubikey                    # YubiKey slot usage and gaps
        """
        db_mgr = get_db_manager(db_path)
        db = db_mgr.load()
        op_client = OpClient()
        
        if noun == "no-tags":
            audit_no_tags(db, limit, csv_output)
        
        elif noun == "untagged-2fa":
            audit_untagged_2fa(db, limit)
        
        elif noun == "missing-email":
            audit_missing_email(db, limit)
        
        elif noun == "same-domain":
            audit_same_domain(db)
        
        elif noun == "same-apps":
            audit_same_apps(db, op_client)
        
        elif noun == "sso-signin":
            audit_sso_signin(db, limit)
        
        elif noun == "yubikey":
            # YubiKey slot usage audit
            cache = get_yubikey_cache()
            yubikey_audit_slots(db_mgr, cache)
        
        else:
            console.print(f"[red]Unknown audit type: {noun}[/red]")
            console.print("[yellow]Available types: no-tags, untagged-2fa, missing-email, same-domain, same-apps, sso-signin, yubikey[/yellow]")
            raise typer.Exit(1)

    @app.command("check")
    def check_command(
        noun: Annotated[str, typer.Argument(help="'rotation' or 'breaches'")] = "rotation",
        db_path: DbPathOption = None,
        update_tags: Annotated[bool, typer.Option("--update-tags", help="Add bastion-sec-breach-exposed tag to breached accounts")] = False,
    ) -> None:
        """Check for passwords needing rotation or breached passwords.
        
        Examples:
          bastion check rotation                 # Check rotation status (exit 1 if any overdue)
          bastion check breaches                 # Scan all passwords against HIBP
          bastion check breaches --update-tags   # Scan and tag breached accounts in 1Password
        """
        if noun == "rotation":
            check_rotation(db_path)
        
        elif noun == "breaches":
            check_breaches(db_path, update_tags)
        
        else:
            console.print(f"[red]Error:[/red] Expected 'rotation' or 'breaches', got '{noun}'")
            console.print("Usage: bastion check <rotation|breaches> [OPTIONS]")
            raise typer.Exit(1)
