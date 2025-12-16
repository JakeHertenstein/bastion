"""Audit operations for Bastion CLI.

Functions for auditing accounts for missing data, tagging issues, and YubiKey slot usage.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from rich.table import Table

from ..console import console

if TYPE_CHECKING:
    from bastion.models import PasswordDatabase
    from bastion.op_client import OpClient


def audit_no_tags(db: "PasswordDatabase", limit: int | None, csv_output: Path | None) -> None:
    """Audit items with no Bastion/* tags."""
    untagged = {
        uuid: acc for uuid, acc in db.accounts.items()
        if not any(tag.startswith("Bastion/") for tag in acc.tag_list)
    }
    
    if not untagged:
        console.print("[green]✅ All items have Bastion/* tags[/green]")
        return
    
    console.print(f"\n[yellow]Found {len(untagged)} items without Bastion/* tags:[/yellow]\n")
    
    table = Table(title="Untagged Items", show_lines=True)
    table.add_column("Title", style="cyan")
    table.add_column("Vault", style="dim")
    table.add_column("Username", style="dim")
    table.add_column("URLs", style="dim")
    
    display_limit = None if limit == 0 else limit
    items_to_show = list(untagged.values())[:display_limit] if display_limit else list(untagged.values())
    
    for acc in items_to_show:
        urls = acc.urls.split(", ")[0] if acc.urls else ""
        table.add_row(acc.title, acc.vault_name, acc.username, urls)
    
    console.print(table)
    
    if display_limit and len(untagged) > display_limit:
        console.print(f"\n[dim]... and {len(untagged) - display_limit} more (use --limit 0 to show all)[/dim]")
    
    # CSV export
    if csv_output:
        with open(csv_output, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["UUID", "Title", "Vault", "Username", "URLs", "Tags"])
            for acc in untagged.values():
                writer.writerow([acc.uuid, acc.title, acc.vault_name, acc.username, acc.urls, acc.tags])
        console.print(f"\n[green]✅ Exported {len(untagged)} items to {csv_output}[/green]")


def audit_untagged_2fa(db: "PasswordDatabase", limit: int | None) -> None:
    """Audit items with 2FA fields but no Bastion/2FA/* tags."""
    console.print("[cyan]Checking for 2FA fields without tags (using cached data)...[/cyan]\n")
    
    untagged_2fa = []
    skipped = 0
    
    for uuid, acc in db.accounts.items():
        # Check if account has 2FA info but no Bastion/2FA tags
        has_2fa_tag = any(tag.startswith("Bastion/2FA/") for tag in acc.tag_list)
        
        if not has_2fa_tag:
            # Use cached fields - only check items with cached data
            if not acc.fields_cache:
                skipped += 1
                continue
            
            # Check for passkey/FIDO2/TOTP in cached fields
            for field in acc.fields_cache:
                field_type = field.get("type", "")
                field_label = field.get("label", "").lower()
                
                if field_type == "TOTP":
                    untagged_2fa.append((acc, "TOTP authenticator found"))
                    break
                elif "passkey" in field_label or field_type == "PASSKEY":
                    untagged_2fa.append((acc, "Passkey found"))
                    break
    
    if skipped > 0:
        console.print(f"[dim]Note: Skipped {skipped} items without cached data. Run 'bastion sync vault --all' to cache all items.[/dim]\n")
    
    if not untagged_2fa:
        console.print("[green]✅ All items with 2FA have appropriate tags[/green]")
        return
    
    console.print(f"[yellow]Found {len(untagged_2fa)} items with 2FA but no Bastion/2FA/* tags:[/yellow]\n")
    
    table = Table(title="Untagged 2FA Items", show_lines=True)
    table.add_column("Title", style="cyan")
    table.add_column("2FA Type", style="yellow")
    table.add_column("Current Tags", style="dim")
    
    display_limit = None if limit == 0 else limit
    items_to_show = untagged_2fa[:display_limit] if display_limit else untagged_2fa
    
    for acc, twofa_type in items_to_show:
        tags = ", ".join([t for t in acc.tag_list if t.startswith("Bastion/")]) or "(none)"
        table.add_row(acc.title, twofa_type, tags)
    
    console.print(table)
    
    if display_limit and len(untagged_2fa) > display_limit:
        console.print(f"\n[dim]... and {len(untagged_2fa) - display_limit} more (use --limit 0 to show all)[/dim]")


def audit_missing_email(db: "PasswordDatabase", limit: int | None) -> None:
    """Audit items with no username/email in any field."""
    console.print("[cyan]Checking for missing email addresses (using cached data)...[/cyan]\n")
    
    missing_email = []
    skipped = 0
    
    for uuid, acc in db.accounts.items():
        if acc.username:
            continue  # Has username, skip
        
        # Use cached fields - only check items with cached data
        if not acc.fields_cache:
            skipped += 1
            continue
        
        # Check all fields for email type
        has_email = False
        for field in acc.fields_cache:
            if field.get("type") == "EMAIL" and field.get("value"):
                has_email = True
                break
        
        if not has_email:
            missing_email.append(acc)
    
    if skipped > 0:
        console.print(f"[dim]Note: Skipped {skipped} items without cached data. Run 'bastion sync vault --all' to cache all items.[/dim]\n")
    
    if not missing_email:
        console.print("[green]✅ All items have email addresses[/green]")
        return
    
    console.print(f"\n[yellow]Found {len(missing_email)} items without email:[/yellow]\n")
    
    table = Table(title="Missing Email", show_lines=True)
    table.add_column("Title", style="cyan")
    table.add_column("Vault", style="dim")
    table.add_column("URLs", style="dim")
    
    display_limit = None if limit == 0 else limit
    items_to_show = missing_email[:display_limit] if display_limit else missing_email
    
    for acc in items_to_show:
        urls = acc.urls.split(", ")[0] if acc.urls else ""
        table.add_row(acc.title, acc.vault_name, urls)
    
    console.print(table)
    
    if display_limit and len(missing_email) > display_limit:
        console.print(f"\n[dim]... and {len(missing_email) - display_limit} more (use --limit 0 to show all)[/dim]")


def audit_same_domain(db: "PasswordDatabase") -> None:
    """Group items by domain - show domains with multiple accounts."""
    domain_groups = defaultdict(set)  # Use set to avoid counting same account multiple times
    
    for acc in db.accounts.values():
        domains_for_account = set()
        if acc.urls:
            for url in acc.urls.split(", "):
                if url:
                    try:
                        parsed = urlparse(url if "://" in url else f"https://{url}")
                        domain = parsed.netloc or parsed.path
                        # Remove www. prefix for grouping
                        if domain.startswith("www."):
                            domain = domain[4:]
                        if domain:
                            domains_for_account.add(domain)
                    except Exception:
                        pass
        
        # Add this account to all its domains
        for domain in domains_for_account:
            domain_groups[domain].add(acc.uuid)
    
    # Convert sets to lists of accounts and show only domains with multiple ACCOUNTS
    multi_domains = {}
    for domain, uuids in domain_groups.items():
        if len(uuids) > 1:
            accs = [db.accounts[uuid] for uuid in uuids if uuid in db.accounts]
            if len(accs) > 1:
                multi_domains[domain] = accs
    
    if not multi_domains:
        console.print("[green]✅ No duplicate domains found[/green]")
        return
    
    console.print(f"\n[yellow]Found {len(multi_domains)} domains with multiple accounts:[/yellow]\n")
    
    for domain, accs in sorted(multi_domains.items(), key=lambda x: len(x[1]), reverse=True):
        console.print(f"\n[cyan bold]{domain}[/cyan bold] ({len(accs)} accounts):")
        for acc in accs:
            console.print(f"  • {acc.title} ({acc.username or 'no email'})")


def audit_same_apps(db: "PasswordDatabase", op_client: "OpClient") -> None:
    """Group items by apps (requires fetching from 1Password)."""
    console.print("[cyan]Fetching app associations from 1Password...[/cyan]\n")
    
    app_groups = defaultdict(list)
    
    for uuid, acc in db.accounts.items():
        item = op_client.get_item(uuid)
        if item and "associatedApps" in item:
            apps = item["associatedApps"]
            for app_item in apps:
                app_name = app_item.get("name", "")
                if app_name:
                    app_groups[app_name].append(acc)
    
    # Show only apps with multiple accounts
    multi_apps = {a: accs for a, accs in app_groups.items() if len(accs) > 1}
    
    if not multi_apps:
        console.print("[green]✅ No apps with multiple accounts found[/green]")
        return
    
    console.print(f"\n[yellow]Found {len(multi_apps)} apps with multiple accounts:[/yellow]\n")
    
    for app_name, accs in sorted(multi_apps.items(), key=lambda x: len(x[1]), reverse=True):
        console.print(f"\n[cyan bold]{app_name}[/cyan bold] ({len(accs)} accounts):")
        for acc in accs:
            console.print(f"  • {acc.title} ({acc.username or 'no email'})")


def audit_sso_signin(db: "PasswordDatabase", limit: int | None) -> None:
    """Audit items with specific 'Sign in with' field containing email."""
    console.print("[cyan]Searching for SSO/federated sign-in accounts (using cached data)...[/cyan]\n")
    
    sso_items = []
    skipped = 0
    
    for uuid, acc in db.accounts.items():
        # Use cached fields - only check items with cached data
        if not acc.fields_cache:
            skipped += 1
            continue
        
        # Look for fields labeled "sign in with" containing an email
        found_sso = False
        sso_email = ""
        
        for field in acc.fields_cache:
            field_label = field.get("label", "").lower()
            field_value = str(field.get("value", ""))
            
            # Be specific: look for "sign in with" in label AND email-like value
            if "sign in with" in field_label and "@" in field_value:
                found_sso = True
                sso_email = field_value
                break
        
        if found_sso:
            sso_items.append((acc, sso_email))
    
    if skipped > 0:
        console.print(f"[dim]Note: Skipped {skipped} items without cached data. Run 'bastion sync vault --all' to cache all items.[/dim]\n")
    
    if not sso_items:
        console.print("[green]✅ No SSO sign-in items found[/green]")
        return
    
    console.print(f"\n[yellow]Found {len(sso_items)} items with SSO sign-in:[/yellow]\n")
    
    table = Table(title="SSO Sign-in Items", show_lines=True)
    table.add_column("Title", style="cyan")
    table.add_column("SSO Email", style="yellow")
    table.add_column("Username", style="dim")
    
    display_limit = None if limit == 0 else limit
    items_to_show = sso_items[:display_limit] if display_limit else sso_items
    
    for acc, sso_email in items_to_show:
        table.add_row(acc.title, sso_email, acc.username or "(none)")
    
    console.print(table)
    
    if display_limit and len(sso_items) > display_limit:
        console.print(f"\n[dim]... and {len(sso_items) - display_limit} more (use --limit 0 to show all)[/dim]")
