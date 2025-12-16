"""1Password commands: All operations requiring 1Password integration.

This module consolidates all commands that interact with 1Password under
the `bastion 1p` subcommand. Commands include sync, report, analyze,
query, audit, validate, cleanup, tags, link/unlink, yubikey, and icons.

Breaking change in v0.2.0: Commands moved from top-level to `1p` subcommand.
  Old: bastion sync vault
  New: bastion 1p sync vault
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

# Create the 1Password app
op_app = typer.Typer(
    name="1p",
    help="1Password vault operations",
    no_args_is_help=True,
)

console = Console()

# Register passkey subcommand
from .passkey import app as passkey_app
op_app.add_typer(passkey_app, name="passkey", help="Passkey health detection")

# Register yubikey commands
from .yubikey_commands import register_commands as register_yubikey
register_yubikey(op_app)

# Type alias for common db option
DbPathOption = Annotated[
    Optional[Path],
    typer.Option(
        "--db",
        help="Database file path",
        envvar="PASSWORD_ROTATION_DB",
    ),
]


# =============================================================================
# VAULT COMMANDS: sync, report, export
# =============================================================================

@op_app.command("sync")
def sync_command(
    noun: Annotated[str, typer.Argument(help="Resource type: vault")] = "vault",
    db_path: DbPathOption = None,
    tier: Annotated[Optional[int], typer.Option(help="Sync specific tier only")] = None,
    only_uuid: Annotated[Optional[str], typer.Option(help="Sync single account")] = None,
    all_items: Annotated[bool, typer.Option("--all", help="Sync all items")] = False,
    tags: Annotated[Optional[list[str]], typer.Option("--tags", "-t", help="Sync items with specific tag(s)")] = None,
    vault: Annotated[Optional[str], typer.Option("--vault", "-v", help="Sync from specific vault only")] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Suppress item names (for demos)")] = False,
) -> None:
    """Sync database from 1Password.
    
    Examples:
      bastion 1p sync vault              # Sync items with Bastion/* tags
      bastion 1p sync vault --all        # Sync ALL items from 1Password
      bastion 1p sync vault --tier 1     # Sync only Tier 1 items
      bastion 1p sync vault --tags YubiKey/Token  # Sync YubiKey items only
      bastion 1p sync vault --vault Bastion       # Sync from specific vault
      bastion 1p sync vault --quiet               # Hide item names (demo mode)
    """
    from .sync import sync_vault
    
    if noun == "vault":
        try:
            sync_vault(db_path, tier, only_uuid, all_items, tags, vault, quiet)
        except RuntimeError as e:
            console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(1)
    else:
        console.print(f"[red]Error:[/red] Expected 'vault', got '{noun}'")
        console.print("Usage: bastion 1p sync vault [OPTIONS]")
        raise typer.Exit(1)


@op_app.command("report")
def report_status(
    noun: Annotated[str, typer.Argument(help="Must be 'status'")] = "status",
) -> None:
    """Generate rotation status report.
    
    Examples:
      bastion 1p report status
    """
    from ..helpers import get_encrypted_db_manager
    from ...reports import ReportGenerator
    
    if noun != "status":
        console.print(f"[red]Error:[/red] Expected 'status', got '{noun}'")
        console.print("Usage: bastion 1p report status [OPTIONS]")
        raise typer.Exit(1)
    
    cache_mgr = get_encrypted_db_manager()
    db = cache_mgr.load()
    
    reporter = ReportGenerator(console)
    reporter.generate_report(db)


@op_app.command("export")
def export_command(
    noun: Annotated[str, typer.Argument(help="Export type: 'csv', 'tagging-candidates'")],
    out: Annotated[Path, typer.Option(help="Output file path")] = Path("password-rotation-database.csv"),
) -> None:
    """Export data from database.
    
    Examples:
      bastion 1p export csv                          # Export to CSV
      bastion 1p export csv --out my-export.csv     # Custom filename
      bastion 1p export tagging-candidates          # Export untagged items
    """
    from ..helpers import get_encrypted_db_manager
    from ...csv_export import export_to_csv
    from .export import export_tagging_candidates
    
    cache_mgr = get_encrypted_db_manager()
    db = cache_mgr.load()
    
    if noun == "csv":
        export_to_csv(db, out)
        console.print(f"[green]✓[/green] Exported to {out}")
    elif noun == "tagging-candidates":
        export_tagging_candidates(db, out)
    else:
        console.print(f"[red]Error:[/red] Expected 'csv' or 'tagging-candidates', got '{noun}'")
        raise typer.Exit(1)


# =============================================================================
# ANALYSIS COMMANDS: analyze, query, audit, check
# =============================================================================

@op_app.command("analyze")
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
      bastion 1p analyze risk                           # Show all accounts by risk
      bastion 1p analyze risk --level critical          # Show only CRITICAL accounts
      bastion 1p analyze risk --has-tag bastion-2fa-sms # Show accounts with SMS enabled
      bastion 1p analyze dependencies --account Gmail   # Show dependency tree
    """
    from .analyze import analyze_risk, analyze_dependencies
    
    if noun == "risk":
        analyze_risk(db_path, level, has_tag, has_capability, weakest_2fa)
    elif noun == "dependencies":
        analyze_dependencies(db_path, account or "")
    else:
        console.print(f"[red]Error:[/red] Expected 'risk' or 'dependencies', got '{noun}'")
        raise typer.Exit(1)


@op_app.command("query")
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
      bastion 1p query --with-flat-tags                 # All with legacy tags
      bastion 1p query --has-tag bastion-2fa-sms        # All with SMS
      bastion 1p query --breach-exposed                 # Compromised passwords
    """
    from .analyze import query_accounts
    
    query_accounts(
        db_path, has_tag, has_capability, weakest_2fa,
        show_breach_exposed, show_no_rate_limit, show_shared_access,
        with_flat_tags, limit
    )


@op_app.command("audit")
def audit_command(
    noun: Annotated[Optional[str], typer.Argument(help="Audit type: 'no-tags', 'untagged-2fa', 'missing-email', 'same-domain', 'same-apps', 'sso-signin', 'yubikey'")] = None,
    csv_output: Annotated[Optional[Path], typer.Option("--csv", help="Export results to CSV file")] = None,
    limit: Annotated[Optional[int], typer.Option(help="Limit results (0 = show all, default: 20)")] = 20,
) -> None:
    """Audit accounts for missing data or tagging issues.
    
    Examples:
      bastion 1p audit no-tags                    # Items with no bastion-* tags
      bastion 1p audit no-tags --csv untagged.csv # Export to CSV
      bastion 1p audit untagged-2fa               # Has 2FA field but no bastion-2fa-* tag
      bastion 1p audit yubikey                    # YubiKey slot usage and gaps
    """
    if noun is None:
        console.print("[yellow]Available audit types:[/yellow]")
        console.print("  no-tags       - Items with no Bastion/* tags")
        console.print("  untagged-2fa  - Has 2FA field but no Bastion/2FA/* tag")
        console.print("  missing-email - Items missing email/username")
        console.print("  same-domain   - Multiple accounts for same domain")
        console.print("  same-apps     - Duplicate app entries")
        console.print("  sso-signin    - SSO sign-in accounts")
        console.print("  yubikey       - YubiKey slot usage and gaps")
        console.print("\n[dim]Example: bsec 1p audit no-tags[/dim]")
        raise typer.Exit(0)
    from ..helpers import get_encrypted_db_manager, get_yubikey_cache
    from ...op_client import OpClient
    from .audit import (
        audit_no_tags,
        audit_untagged_2fa,
        audit_missing_email,
        audit_same_domain,
        audit_same_apps,
        audit_sso_signin,
    )
    from .yubikey import yubikey_audit_slots
    
    cache_mgr = get_encrypted_db_manager()
    db = cache_mgr.load()
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
        cache = get_yubikey_cache()
        yubikey_audit_slots(cache_mgr, cache)
    else:
        console.print(f"[red]Unknown audit type: {noun}[/red]")
        console.print("[yellow]Available types: no-tags, untagged-2fa, missing-email, same-domain, same-apps, sso-signin, yubikey[/yellow]")
        raise typer.Exit(1)


@op_app.command("check")
def check_command(
    noun: Annotated[str, typer.Argument(help="'rotation' or 'breaches'")] = "rotation",
    db_path: DbPathOption = None,
    update_tags: Annotated[bool, typer.Option("--update-tags", help="Add bastion-sec-breach-exposed tag to breached accounts")] = False,
) -> None:
    """Check for passwords needing rotation or breached passwords.
    
    Examples:
      bastion 1p check rotation                 # Check rotation status
      bastion 1p check breaches                 # Scan against HIBP
      bastion 1p check breaches --update-tags   # Tag breached accounts
    """
    from .check import check_rotation, check_breaches
    
    if noun == "rotation":
        check_rotation(db_path)
    elif noun == "breaches":
        check_breaches(db_path, update_tags)
    else:
        console.print(f"[red]Error:[/red] Expected 'rotation' or 'breaches', got '{noun}'")
        raise typer.Exit(1)


# =============================================================================
# MAINTENANCE COMMANDS: validate, rollback, cleanup
# =============================================================================

@op_app.command("validate")
def validate_command(
    noun: Annotated[str, typer.Argument(help="'tags' or 'rules'")] = "tags",
    db_path: DbPathOption = None,
) -> None:
    """Validate database entries for issues.
    
    Examples:
      bastion 1p validate tags    # Validate tag consistency
      bastion 1p validate rules   # Validate against security rules
    """
    from .validate import validate_migration, validate_rules
    
    if noun == "tags":
        validate_migration(db_path)
    elif noun == "rules":
        validate_rules(db_path)
    else:
        console.print(f"[red]Error:[/red] Expected 'tags' or 'rules', got '{noun}'")
        raise typer.Exit(1)


@op_app.command("rollback")
def rollback_command(
    uuid: Annotated[str, typer.Argument(help="Item UUID to rollback")],
    version: Annotated[Optional[int], typer.Option(help="Target version (default: previous)")] = None,
) -> None:
    """Rollback item to previous version.
    
    Examples:
      bastion 1p rollback abc123          # Rollback to previous version
      bastion 1p rollback abc123 --version 5  # Rollback to specific version
    """
    from .rollback import rollback_item
    rollback_item(uuid, version)


@op_app.command("cleanup")
def cleanup_command(
    noun: Annotated[str, typer.Argument(help="'tags' or 'passkeys'")] = "tags",
    db_path: DbPathOption = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preview changes without applying")] = False,
    batch: Annotated[bool, typer.Option("--batch", "-y", help="Run non-interactively")] = False,
) -> None:
    """Cleanup duplicate tags or orphaned passkeys.
    
    Examples:
      bastion 1p cleanup tags             # Remove duplicate tags (interactive)
      bastion 1p cleanup tags --batch     # Remove duplicate tags (non-interactive)
      bastion 1p cleanup passkeys         # Detect orphaned passkeys
    """
    from .cleanup import cleanup_duplicate_tags, cleanup_orphaned_passkeys
    
    if noun == "tags":
        cleanup_duplicate_tags(db_path, batch=batch, dry_run=dry_run)
    elif noun == "passkeys":
        cleanup_orphaned_passkeys()
    else:
        console.print(f"[red]Error:[/red] Expected 'tags' or 'passkeys', got '{noun}'")
        raise typer.Exit(1)


# =============================================================================
# TAG COMMANDS
# =============================================================================

@op_app.command("tags")
def tags_command(
    action: Annotated[str, typer.Argument(help="'list', 'apply', 'remove', 'rename', or 'migrate'")] = "list",
    db_path: DbPathOption = None,
    tag: Annotated[Optional[str], typer.Option(help="Tag to apply, remove, or rename (old tag)")] = None,
    new_tag: Annotated[Optional[str], typer.Option("--new-tag", help="New tag name for rename action")] = None,
    item_id: Annotated[Optional[str], typer.Option(help="Item UUID (for apply/remove on single item)")] = None,
    migration_type: Annotated[Optional[str], typer.Option(help="Migration type for 'migrate' action")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preview changes")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation prompts")] = False,
) -> None:
    """Manage 1Password tags.
    
    Examples:
      bsec 1p tags list                                 # List all Bastion tags
      bsec 1p tags apply --tag Bastion/Tier/1 --item-id abc123
      bsec 1p tags remove --tag old-tag --item-id abc123
      bsec 1p tags rename --tag old-tag --new-tag new-tag --dry-run
      bsec 1p tags migrate --migration-type tier-restructure --dry-run
    """
    from .tags import list_tags, apply_tag, remove_tag, rename_tag
    from .migrations import run_migration
    
    if action == "list":
        list_tags(db_path)
    elif action == "apply":
        if not tag or not item_id:
            console.print("[red]Error: --tag and --item-id required for apply[/red]")
            raise typer.Exit(1)
        apply_tag(item_id, tag)
    elif action == "remove":
        if not tag or not item_id:
            console.print("[red]Error: --tag and --item-id required for remove[/red]")
            raise typer.Exit(1)
        remove_tag(item_id, tag)
    elif action == "rename":
        if not tag or not new_tag:
            console.print("[red]Error: --tag and --new-tag required for rename[/red]")
            raise typer.Exit(1)
        rename_tag(db_path, tag, new_tag, dry_run, yes)
    elif action == "migrate":
        if not migration_type:
            console.print("[red]Error: --migration-type required for migrate[/red]")
            raise typer.Exit(1)
        run_migration(migration_type, db_path, dry_run)
    else:
        console.print(f"[red]Error:[/red] Expected 'list', 'apply', 'remove', 'rename', or 'migrate', got '{action}'")
        raise typer.Exit(1)


# =============================================================================
# RELATIONSHIP COMMANDS: link, unlink
# =============================================================================

@op_app.command("link")
def link_command(
    db_path: DbPathOption = None,
    parent: Annotated[Optional[str], typer.Option(help="Parent account UUID or title")] = None,
    child: Annotated[Optional[str], typer.Option(help="Child account UUID or title")] = None,
) -> None:
    """Link two accounts (parent-child relationship).
    
    Examples:
      bastion 1p link --parent Gmail --child GitHub
    """
    from .relationships import link_accounts
    
    if not parent or not child:
        console.print("[red]Error: --parent and --child required[/red]")
        raise typer.Exit(1)
    
    link_accounts(db_path, parent, child)


@op_app.command("unlink")
def unlink_command(
    db_path: DbPathOption = None,
    parent: Annotated[Optional[str], typer.Option(help="Parent account UUID or title")] = None,
    child: Annotated[Optional[str], typer.Option(help="Child account UUID or title")] = None,
) -> None:
    """Unlink two accounts.
    
    Examples:
      bastion 1p unlink --parent Gmail --child GitHub
    """
    from .relationships import unlink_accounts
    
    if not parent or not child:
        console.print("[red]Error: --parent and --child required[/red]")
        raise typer.Exit(1)
    
    unlink_accounts(db_path, parent, child)


# =============================================================================
# ICON COMMANDS
# =============================================================================

@op_app.command("icons")
def icons_command(
    action: Annotated[str, typer.Argument(help="'status', 'apply', 'scan', or 'update'")] = "status",
    db_path: DbPathOption = None,
    item_id: Annotated[Optional[str], typer.Option(help="Item UUID")] = None,
    force: Annotated[bool, typer.Option("--force", help="Force update even if icon exists")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preview changes")] = False,
) -> None:
    """Manage account icons from aegis-icons.
    
    Examples:
      bastion 1p icons status                    # Show icon coverage
      bastion 1p icons apply --item-id abc123    # Apply icon to item
      bastion 1p icons scan                      # Scan for missing icons
      bastion 1p icons update --dry-run          # Preview icon updates
    """
    from .icons import icons_status, apply_icon, scan_missing_icons, update_icons
    
    if action == "status":
        icons_status(db_path)
    elif action == "apply":
        if not item_id:
            console.print("[red]Error: --item-id required for apply[/red]")
            raise typer.Exit(1)
        apply_icon(item_id, force)
    elif action == "scan":
        scan_missing_icons(db_path)
    elif action == "update":
        update_icons(db_path, force, dry_run)
    else:
        console.print(f"[red]Error:[/red] Expected 'status', 'apply', 'scan', or 'update', got '{action}'")
        raise typer.Exit(1)
