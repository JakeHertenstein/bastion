"""Migration-related CLI helper functions.

Extracted from cli_legacy.py to improve modularity.
Functions for tag migrations and item type conversions.
"""

from __future__ import annotations

import json
import subprocess
from typing import TYPE_CHECKING

import typer

from bastion.cli.console import console
from bastion.cli.helpers import get_db_manager
from bastion.op_client import OpClient
from bastion.planning import RotationPlanner

if TYPE_CHECKING:
    pass


# Tag migration mapping from old flat format to new hierarchical format
TAG_MIGRATIONS = {
    # Capability tags
    "bastion-cap-money-transfer": "Bastion/Capability/Money-Transfer",
    "bastion-cap-recovery": "Bastion/Capability/Recovery",
    "bastion-cap-identity": "Bastion/Capability/Identity",
    "bastion-cap-crypto": "Bastion/Capability/Crypto",
    "bastion-cap-ice": "Bastion/Capability/ICE",
    "bastion-cap-device-control": "Bastion/Capability/Device-Control",
    "bastion-cap-secrets": "Bastion/Capability/Secrets",
    "bastion-cap-shared-family": "Bastion/Capability/Shared-Family",
    "bastion-cap-shared-executor": "Bastion/Capability/Shared-Executor",
    "bastion-cap-device-mgmt": "Bastion/Capability/Device-Management",
    "bastion-cap-credit-access": "Bastion/Capability/Credit-Access",
    "bastion-cap-data-export": "Bastion/Capability/Data-Export",
    "bastion-cap-shared-beneficiary": "Bastion/Capability/Shared-Beneficiary",
    "bastion-cap-shared-business": "Bastion/Capability/Shared-Business",
    # Type tags
    "bastion-type-bank": "Bastion/Type/Bank",
    "bastion-type-blockchain": "Bastion/Type/Blockchain",
    "bastion-type-healthcare": "Bastion/Type/Healthcare",
    "bastion-type-email": "Bastion/Type/Email",
    "bastion-type-password-manager": "Bastion/Type/Password-Manager",
    "bastion-type-cloud": "Bastion/Type/Cloud",
    "bastion-type-phone": "Bastion/Type/Phone",
    "bastion-type-investment": "Bastion/Type/Investment",
    "bastion-type-credit-card": "Bastion/Type/Credit-Card",
    "bastion-type-insurance": "Bastion/Type/Insurance",
    "bastion-type-utility": "Bastion/Type/Utility",
    "bastion-type-shopping": "Bastion/Type/Shopping",
    "bastion-type-payment": "Bastion/Type/Payment",
    "bastion-type-tax-service": "Bastion/Type/Tax-Service",
    "bastion-type-credit-monitoring": "Bastion/Type/Credit-Monitoring",
    "bastion-type-loan": "Bastion/Type/Loan",
    "bastion-type-mortgage": "Bastion/Type/Mortgage",
    "bastion-type-aggregator": "Bastion/Type/Aggregator",
    # Dependency, 2FA, Security, Compliance, PII, Why/Sharing, Rotation, Tier tags...
    "bastion-dep-no-email-recovery": "Bastion/Dependency/No-Email-Recovery",
    "bastion-dep-phone-sms": "Bastion/Dependency/Phone-SMS",
    "bastion-dep-secret-key": "Bastion/Dependency/Secret-Key",
    "bastion-dep-backup-codes": "Bastion/Dependency/Backup-Codes",
    "bastion-dep-trusted-device": "Bastion/Dependency/Trusted-Device",
    "bastion-dep-yubikey": "Bastion/Dependency/YubiKey",
    "bastion-dep-recovery-contacts": "Bastion/Dependency/Recovery-Contacts",
    "bastion-dep-trusted-contact": "Bastion/Dependency/Trusted-Contact",
    "bastion-2fa-fido2-hw-passkey": "Bastion/2FA/FIDO2-Hardware",
    "bastion-2fa-fido2-sw-passkey": "Bastion/2FA/Passkey/Software",  # Renamed from FIDO2-Software
    "bastion-2fa-fido2": "Bastion/2FA/FIDO2",
    "bastion-2fa-totp": "Bastion/2FA/TOTP",
    "bastion-2fa-push": "Bastion/2FA/Push",
    "bastion-2fa-sms": "Bastion/2FA/SMS",
    "bastion-2fa-email": "Bastion/2FA/Email",
    "bastion-2fa-none": "Bastion/2FA/None",
    "bastion-sec-rate-limited": "Bastion/Security/Rate-Limited",
    "bastion-sec-human-verification": "Bastion/Security/Human-Verification",
    "bastion-sec-breach-exposed": "Bastion/Security/Breach-Exposed",
    "bastion-sec-weak-password": "Bastion/Security/Weak-Password",
    "bastion-sec-shared-password": "Bastion/Security/Shared-Password",
    "bastion-sec-leaked": "Bastion/Security/Leaked",
    "bastion-sec-compromised": "Bastion/Security/Compromised",
    "bastion-sec-suspicious": "Bastion/Security/Suspicious",
    "bastion-sec-locked": "Bastion/Security/Locked",
    "bastion-sec-disabled": "Bastion/Security/Disabled",
    "bastion-sec-expired": "Bastion/Security/Expired",
    "bastion-compliance-hipaa": "Bastion/Compliance/HIPAA",
    "bastion-compliance-hippa": "Bastion/Compliance/HIPAA",
    "bastion-compliance-pci": "Bastion/Compliance/PCI",
    "bastion-compliance-glba": "Bastion/Compliance/GLBA",
    "bastion-compliance-gdpr": "Bastion/Compliance/GDPR",
    "bastion-compliance-sox": "Bastion/Compliance/SOX",
    "bastion-pii-financial": "Bastion/PII/Financial",
    "bastion-pii-health": "Bastion/PII/Health",
    "bastion-pii-blockchain": "Bastion/PII/Blockchain",
    "bastion-pii-contact": "Bastion/PII/Contact",
    "bastion-pii-ssn": "Bastion/PII/SSN",
    "bastion-why-joint-account": "Bastion/Why/Joint-Account",
    "bastion-why-executor-access": "Bastion/Why/Executor-Access",
    "bastion-why-beneficiary-info": "Bastion/Why/Beneficiary-Info",
    "bastion-why-business-shared": "Bastion/Why/Business-Shared",
    "bastion-why-family-emergency": "Bastion/Why/Family-Emergency",
    "bastion-why-estate-planning": "Bastion/Why/Estate-Planning",
    "bastion-rotation-90d": "Bastion/Rotation/90d",
    "bastion-rotation-180d": "Bastion/Rotation/180d",
    "bastion-rotation-365d": "Bastion/Rotation/365d",
    "bastion-rotation-never": "Bastion/Rotation/Never",
    # DEPRECATED v0.3.0: Tier tags are deprecated in favor of 1Password Watchtower
    # These mappings remain for backward compatibility during migration
    "tier-1": "Bastion/Tier/1",  # DEPRECATED
    "tier-2": "Bastion/Tier/2",  # DEPRECATED
    "tier-3": "Bastion/Tier/3",  # DEPRECATED
}


def run_migration(migration_type: str, db_path, dry_run: bool) -> None:
    """Run a specific tag migration.
    
    Args:
        migration_type: Type of migration to run (e.g., 'tags', 'tier-restructure')
        db_path: Path to the database file
        dry_run: If True, show what would be done without making changes
    """
    if migration_type in ("tags", "tier-restructure", "flat-to-hierarchical"):
        migrate_tags(db_path, dry_run, yes=False)
    else:
        console.print(f"[red]Unknown migration type: {migration_type}[/red]")
        console.print("Available migrations: tags, tier-restructure, flat-to-hierarchical")
        raise typer.Exit(1)


def migrate_tags(db_path, dry_run: bool, yes: bool) -> None:
    """Migrate flat bastion-* tags to nested Bastion/* structure.
    
    Finds all accounts with legacy flat tags (e.g., bastion-type-bank)
    and migrates them to the new hierarchical format (e.g., Bastion/Type/Bank).
    
    Args:
        db_path: Path to the database file
        dry_run: If True, show what would be done without making changes
        yes: If True, skip confirmation prompts
    """
    db_mgr = get_db_manager(db_path)
    db = db_mgr.load()
    op_client = OpClient()
    
    # Find accounts with tags to migrate
    accounts_to_migrate = {}
    for uuid, acc in db.accounts.items():
        old_tags = []
        for tag in acc.tag_list:
            tag_lower = tag.lower()
            for old_tag, new_tag in TAG_MIGRATIONS.items():
                if tag_lower == old_tag.lower():
                    old_tags.append((tag, new_tag))
                    break
        if old_tags:
            accounts_to_migrate[uuid] = (acc, old_tags)
    
    if not accounts_to_migrate:
        console.print("[green]✅ No tags need migration - all tags are already in Bastion/* format[/green]")
        return
    
    # Show preview
    console.print(f"\n[cyan]Found {len(accounts_to_migrate)} accounts with tags to migrate:[/cyan]\n")
    
    from rich.table import Table
    table = Table(show_lines=True)
    table.add_column("Title", style="cyan")
    table.add_column("Old Tag", style="red")
    table.add_column("New Tag", style="green")
    
    preview_count = 0
    for acc, tag_pairs in list(accounts_to_migrate.values())[:10]:
        for old_tag, new_tag in tag_pairs:
            table.add_row(acc.title, old_tag, new_tag)
            preview_count += 1
            if preview_count >= 20:
                break
        if preview_count >= 20:
            break
    
    console.print(table)
    
    if len(accounts_to_migrate) > 10:
        console.print(f"\n[dim]... and {len(accounts_to_migrate) - 10} more accounts[/dim]")
    
    total_migrations = sum(len(tag_pairs) for _, tag_pairs in accounts_to_migrate.values())
    console.print(f"\n[yellow]Total: {total_migrations} tags to migrate across {len(accounts_to_migrate)} accounts[/yellow]")
    
    if dry_run:
        console.print("\n[yellow]DRY RUN - No changes made[/yellow]")
        return
    
    if not yes:
        confirm = typer.confirm(f"\nMigrate {total_migrations} tags?", default=False)
        if not confirm:
            console.print("[yellow]Cancelled[/yellow]")
            return
    
    console.print("\n[cyan]Migrating tags...[/cyan]\n")
    
    success_count = 0
    fail_count = 0
    
    for uuid, (acc, tag_pairs) in accounts_to_migrate.items():
        current_tags = acc.tag_list.copy()
        new_tags = current_tags.copy()
        
        for old_tag, new_tag in tag_pairs:
            old_tag_lower = old_tag.lower()
            new_tags = [t for t in new_tags if t.lower() != old_tag_lower]
            if new_tag not in new_tags:
                new_tags.append(new_tag)
        
        result = op_client.edit_item_tags(uuid, new_tags)
        if result is True:
            success_count += 1
            item = op_client.get_item(uuid)
            if item:
                planner = RotationPlanner()
                account = planner.process_item(item, "2024-01-01")
                db.accounts[uuid] = account
        else:
            fail_count += 1
            console.print(f"[red]❌ {acc.title}: {result}[/red]")
    
    if success_count > 0:
        db_mgr.save(db)
        console.print(f"\n[green]✅ Successfully migrated {success_count} accounts[/green]")
    
    if fail_count > 0:
        console.print(f"[red]❌ Failed to migrate {fail_count} accounts[/red]")


def convert_single_to_note(item_uuid: str, dry_run: bool = False) -> None:
    """Convert a single item to SECURE_NOTE by creating a new item.
    
    Creates a new SECURE_NOTE item with all fields copied from the original,
    and tags the original item as 'converted-to-note' for later cleanup.
    
    Args:
        item_uuid: UUID of the item to convert
        dry_run: If True, show what would be done without making changes
    """
    try:
        # Get current item data
        result = subprocess.run(
            ["op", "item", "get", item_uuid, "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        item_data = json.loads(result.stdout)
        
        title = item_data.get("title", "Unknown")
        category = item_data.get("category", "")
        vault = item_data.get("vault", {}).get("name", "Private")
        tags = item_data.get("tags", [])
        has_category_id = bool(item_data.get("category_id"))
        
        console.print(f"\n[cyan]Item:[/cyan] {title}")
        console.print(f"[cyan]UUID:[/cyan] {item_uuid}")
        console.print(f"[cyan]Current Category:[/cyan] {category}")
        console.print(f"[cyan]Vault:[/cyan] {vault}")
        console.print(f"[cyan]Has category_id:[/cyan] {has_category_id}")
        
        # Check if conversion is needed
        if category == "SECURE_NOTE":
            console.print("\n[yellow]⚠ Item is already a SECURE_NOTE[/yellow]")
            return
        
        if category != "CUSTOM":
            console.print(f"\n[yellow]⚠ Item is {category}, not CUSTOM. Conversion may not be necessary.[/yellow]")
            if not typer.confirm("Continue anyway?"):
                return
        
        if not has_category_id:
            console.print("\n[yellow]⚠ Item has no category_id. It should already be editable.[/yellow]")
            if not typer.confirm("Continue anyway?"):
                return
        
        if dry_run:
            console.print("\n[yellow]DRY RUN - No changes will be made[/yellow]")
            console.print(f"[dim]Would create new SECURE_NOTE item: {title}[/dim]")
            console.print(f"[dim]Would copy {len(item_data.get('fields', []))} fields[/dim]")
            console.print(f"[dim]Would copy tags: {', '.join(tags) if tags else 'none'}[/dim]")
            console.print("[dim]Original item would be tagged 'converted-to-note'[/dim]")
            return
        
        # Create new SECURE_NOTE item with field-by-field copy
        console.print("\n[cyan]Creating new SECURE_NOTE item...[/cyan]")
        
        # Build new item template
        new_item = {
            "title": title,
            "category": "SECURE_NOTE",
            "vault": {"name": vault},
            "tags": tags + ["converted-from-custom"],
            "fields": []
        }
        
        # Copy all fields from original (preserving types and values)
        for field in item_data.get("fields", []):
            # Skip fields that don't have required properties
            if not field.get("label"):
                continue
                
            # Create new field structure
            new_field = {
                "label": field.get("label"),
                "type": field.get("type", "STRING"),
            }
            
            # Copy value if present
            if "value" in field:
                new_field["value"] = field["value"]
            
            # Copy section if present
            if "section" in field:
                new_field["section"] = field["section"]
            
            # Copy purpose if present (for specific field types)
            if "purpose" in field:
                new_field["purpose"] = field["purpose"]
            
            new_item["fields"].append(new_field)
        
        # Add a note about the conversion
        new_item["fields"].append({
            "type": "STRING",
            "label": "conversion_note",
            "value": f"Converted from {category} item (UUID: {item_uuid})"
        })
        
        # Copy notes if they exist
        if item_data.get("notes"):
            new_item["notes"] = item_data["notes"]
        
        # Copy sections if they exist
        if item_data.get("sections"):
            new_item["sections"] = item_data["sections"]
        
        # Create the new item using JSON stdin
        result = subprocess.run(
            ["op", "item", "create", "-", "--format", "json"],
            input=json.dumps(new_item),
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        
        if not result.stdout.strip():
            raise ValueError("No output from op item create command")
        
        new_item_data = json.loads(result.stdout)
        new_uuid = new_item_data.get("id")
        
        console.print(f"[green]✓ Created new SECURE_NOTE: {title}[/green]")
        console.print(f"[dim]New UUID: {new_uuid}[/dim]")
        
        # Tag the original item as converted (use assignment syntax for proper replacement)
        console.print("\n[cyan]Tagging original item as 'converted-to-note'...[/cyan]")
        # Get current tags first
        get_result = subprocess.run(
            ["op", "item", "get", item_uuid, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        current_tags = []
        if get_result.returncode == 0:
            item_data = json.loads(get_result.stdout)
            current_tags = item_data.get("tags", []) or []
        if "converted-to-note" not in current_tags:
            new_tags = current_tags + ["converted-to-note"]
            subprocess.run(
                ["op", "item", "edit", item_uuid, f"tags={','.join(new_tags)}"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
        
        console.print("[green]✓ Tagged original item[/green]")
        console.print("\n[bold]Next steps:[/bold]")
        console.print("1. Verify the new item has all necessary data")
        console.print(f"2. Update any references to use new UUID: {new_uuid}")
        console.print(f"3. Create links: [dim]bastion create link \"{title}\" \"Target Item\"[/dim]")
        console.print(f"4. If satisfied, delete original: [dim]op item delete {item_uuid}[/dim]")
        
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr if e.stderr else str(e)
        console.print(f"[red]Failed to convert item: {error_msg}[/red]")
        raise typer.Exit(1)
    except (json.JSONDecodeError, KeyError) as e:
        console.print(f"[red]Failed to parse item data: {e}[/red]")
        raise typer.Exit(1)


def convert_bulk_to_notes(tag: str, dry_run: bool = False) -> None:
    """Convert all CUSTOM items with a tag to SECURE_NOTE.
    
    Finds all items with the specified tag that are CUSTOM type with
    category_id (indicating they need conversion) and converts each
    to a SECURE_NOTE.
    
    Args:
        tag: Tag to filter items by
        dry_run: If True, show what would be done without making changes
    """
    console.print(f"[cyan]Finding items with tag: {tag}[/cyan]\n")
    
    try:
        # Get all items with tag
        result = subprocess.run(
            ["op", "item", "list", "--tags", tag, "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        items = json.loads(result.stdout)
        
        if not items:
            console.print(f"[yellow]No items found with tag: {tag}[/yellow]")
            return
        
        console.print(f"Found {len(items)} items with tag '{tag}'\n")
        
        # Track results
        results = {
            "converted": [],
            "skipped": [],
            "failed": [],
        }
        
        # Process each item
        for item in items:
            item_uuid = item["id"]
            item_title = item.get("title", "Unknown")
            
            try:
                # Get full item details
                detail_result = subprocess.run(
                    ["op", "item", "get", item_uuid, "--format", "json"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
                item_data = json.loads(detail_result.stdout)
                
                category = item_data.get("category", "")
                has_category_id = bool(item_data.get("category_id"))
                
                # Skip if already SECURE_NOTE
                if category == "SECURE_NOTE":
                    console.print(f"[dim]⊘ {item_title}: Already SECURE_NOTE[/dim]")
                    results["skipped"].append({
                        "title": item_title,
                        "uuid": item_uuid,
                        "reason": "Already SECURE_NOTE"
                    })
                    continue
                
                # Skip if not CUSTOM with category_id
                if category != "CUSTOM" or not has_category_id:
                    console.print(f"[dim]⊘ {item_title}: {category} without category_id (safe to edit)[/dim]")
                    results["skipped"].append({
                        "title": item_title,
                        "uuid": item_uuid,
                        "reason": f"{category} without category_id"
                    })
                    continue
                
                # This item needs conversion
                if dry_run:
                    console.print(f"[yellow]→ {item_title}: Would create new SECURE_NOTE[/yellow]")
                    results["converted"].append({
                        "title": item_title,
                        "uuid": item_uuid
                    })
                else:
                    # Create new SECURE_NOTE item with field-by-field copy
                    console.print(f"[cyan]→ {item_title}: Creating SECURE_NOTE...[/cyan]")
                    
                    vault = item_data.get("vault", {}).get("name", "Private")
                    tags_list = item_data.get("tags", [])
                    
                    # Build new item template
                    new_item = {
                        "title": item_title,
                        "category": "SECURE_NOTE",
                        "vault": {"name": vault},
                        "tags": tags_list + ["converted-from-custom"],
                        "fields": []
                    }
                    
                    # Copy all fields from original
                    for field in item_data.get("fields", []):
                        if not field.get("label"):
                            continue
                        
                        new_field = {
                            "label": field.get("label"),
                            "type": field.get("type", "STRING"),
                        }
                        
                        if "value" in field:
                            new_field["value"] = field["value"]
                        if "section" in field:
                            new_field["section"] = field["section"]
                        if "purpose" in field:
                            new_field["purpose"] = field["purpose"]
                        
                        new_item["fields"].append(new_field)
                    
                    # Add conversion note
                    new_item["fields"].append({
                        "type": "STRING",
                        "label": "conversion_note",
                        "value": f"Converted from {category} (UUID: {item_uuid})"
                    })
                    
                    # Copy notes and sections
                    if item_data.get("notes"):
                        new_item["notes"] = item_data["notes"]
                    if item_data.get("sections"):
                        new_item["sections"] = item_data["sections"]
                    
                    # Create new item using template
                    create_result = subprocess.run(
                        ["op", "item", "create", "-", "--format", "json"],
                        input=json.dumps(new_item),
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=30,
                    )
                    
                    new_item_data = json.loads(create_result.stdout)
                    new_uuid = new_item_data.get("id")
                    
                    # Tag original as converted (use assignment syntax)
                    orig_tags = item_data.get("tags", []) or []
                    if "converted-to-note" not in orig_tags:
                        new_tags_list = orig_tags + ["converted-to-note"]
                        subprocess.run(
                            ["op", "item", "edit", item_uuid, f"tags={','.join(new_tags_list)}"],
                            capture_output=True,
                            text=True,
                            timeout=30,
                        )
                    
                    console.print(f"[green]✓ {item_title}: Created new item {new_uuid}[/green]")
                    results["converted"].append({
                        "title": item_title,
                        "old_uuid": item_uuid,
                        "new_uuid": new_uuid
                    })
                
            except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
                error_msg = str(e)
                if isinstance(e, subprocess.CalledProcessError) and e.stderr:
                    error_msg = e.stderr
                console.print(f"[red]✗ {item_title}: Failed - {error_msg}[/red]")
                results["failed"].append({
                    "title": item_title,
                    "uuid": item_uuid,
                    "error": error_msg
                })
        
        # Print summary
        console.print("\n" + "=" * 60)
        if dry_run:
            console.print("[yellow]DRY RUN SUMMARY[/yellow]")
        else:
            console.print("[bold]CONVERSION SUMMARY[/bold]")
        console.print("=" * 60)
        
        console.print(f"  Converted: {len(results['converted'])}")
        console.print(f"  Skipped: {len(results['skipped'])}")
        console.print(f"  Failed: {len(results['failed'])}")
        
        if dry_run and results["converted"]:
            console.print("\n[yellow]Run without --dry-run to perform conversion[/yellow]")
        elif results["converted"]:
            console.print(f"\n[green]✓ Successfully converted {len(results['converted'])} items[/green]")
        
        if results["failed"]:
            console.print("\n[red]Failed items:[/red]")
            for item in results["failed"]:
                console.print(f"  • {item['title']}: {item['error']}")
        
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr if e.stderr else str(e)
        console.print(f"[red]Failed to list items: {error_msg}[/red]")
        raise typer.Exit(1)
    except json.JSONDecodeError as e:
        console.print(f"[red]Failed to parse JSON: {e}[/red]")
        raise typer.Exit(1)


def migrate_from_bastion_impl(dry_run: bool = False, skip_cache: bool = False) -> None:
    """Migration from Bastion to Bastion format.
    
    This command migrates:
    - Tags: bastion-* and Bastion/* → Bastion/*
    - Sections: "Bastion Metadata" → "Bastion Metadata"
    - Fields: "Bastion Notes" → "Bastion Notes"
    - Cache: password-rotation-database.json → ~/.bsec/cache.db.enc (encrypted)
    
    Args:
        dry_run: If True, show what would be done without making changes
        skip_cache: If True, skip cache infrastructure and migration
    """
    from datetime import datetime
    from pathlib import Path
    
    from bastion.db import BastionCacheManager, DatabaseManager, BASTION_DIR, BASTION_CACHE_FILE
    from bastion.op_client import OpClient, is_legacy_tag
    
    console.print("[bold blue]═══ Bastion Migration: Bastion → Bastion ═══[/bold blue]\n")
    
    if dry_run:
        console.print("[yellow]DRY RUN MODE - No changes will be made[/yellow]\n")
    
    op = OpClient()
    
    # Stats tracking
    stats = {
        "items_scanned": 0,
        "items_with_legacy_tags": 0,
        "tags_converted": 0,
        "sections_renamed": 0,
        "fields_renamed": 0,
        "cache_migrated": False,
        "yubikey_cache_migrated": False,
        "key_created": False,
    }
    
    # Tag conversion mapping
    def convert_tag(tag: str) -> str | None:
        """Convert legacy tag to Bastion format. Returns None if no conversion needed."""
        # Bastion/* nested format → Bastion/*
        if tag.startswith("Bastion/"):
            return "Bastion/" + tag[4:]
        
        # bastion-* flat format → Bastion/* nested
        flat_to_nested = {
            # Type tags
            "bastion-type-bank": "Bastion/Type/Bank",
            "bastion-type-brokerage": "Bastion/Type/Brokerage",
            "bastion-type-crypto": "Bastion/Type/Crypto",
            "bastion-type-email": "Bastion/Type/Email",
            "bastion-type-social": "Bastion/Type/Social",
            "bastion-type-shopping": "Bastion/Type/Shopping",
            "bastion-type-utility": "Bastion/Type/Utility",
            "bastion-type-healthcare": "Bastion/Type/Healthcare",
            "bastion-type-government": "Bastion/Type/Government",
            "bastion-type-work": "Bastion/Type/Work",
            "bastion-type-entertainment": "Bastion/Type/Entertainment",
            "bastion-type-developer": "Bastion/Type/Developer",
            # 2FA tags
            "bastion-2fa-fido2-hw-passkey": "Bastion/2FA/FIDO2-Hardware",
            "bastion-2fa-fido2-sw-passkey": "Bastion/2FA/Passkey/Software",  # Renamed from FIDO2-Software
            "bastion-2fa-fido2": "Bastion/2FA/FIDO2",
            "bastion-2fa-totp": "Bastion/2FA/TOTP",
            "bastion-2fa-push": "Bastion/2FA/Push",
            "bastion-2fa-sms": "Bastion/2FA/SMS",
            "bastion-2fa-email": "Bastion/2FA/Email",
            "bastion-2fa-none": "Bastion/2FA/None",
            # Capability tags
            "bastion-cap-money-transfer": "Bastion/Capability/Money-Transfer",
            "bastion-cap-recovery": "Bastion/Capability/Recovery",
            "bastion-cap-secrets": "Bastion/Capability/Secrets",
            "bastion-cap-identity": "Bastion/Capability/Identity",
            "bastion-cap-aggregator": "Bastion/Capability/Aggregator",
            "bastion-cap-device-mgmt": "Bastion/Capability/Device-Mgmt",
            "bastion-cap-credit-access": "Bastion/Capability/Credit-Access",
            "bastion-cap-data-export": "Bastion/Capability/Data-Export",
            "bastion-cap-shared-access": "Bastion/Capability/Shared-Access",
            # Security tags
            "bastion-sec-breach-exposed": "Bastion/Security/Breach-Exposed",
            "bastion-sec-rate-limited": "Bastion/Security/Rate-Limited",
            "bastion-sec-no-rate-limit": "Bastion/Security/No-Rate-Limit",
            "bastion-sec-human-verification": "Bastion/Security/Human-Verification",
            "bastion-sec-device-binding": "Bastion/Security/Device-Binding",
            "bastion-sec-ip-restrictions": "Bastion/Security/IP-Restrictions",
            "bastion-sec-session-timeout": "Bastion/Security/Session-Timeout",
            "bastion-sec-password-max-length": "Bastion/Security/Password-Max-Length",
            "bastion-sec-password-no-special": "Bastion/Security/Password-No-Special",
            # PII tags
            "bastion-pii-financial": "Bastion/PII/Financial",
            "bastion-pii-government": "Bastion/PII/Government",
            "bastion-pii-health": "Bastion/PII/Health",
            # Compliance tags
            "bastion-compliance-fdic": "Bastion/Compliance/FDIC",
            "bastion-compliance-sipc": "Bastion/Compliance/SIPC",
            # Dependency tags - generic pattern
            "bastion-dep-": "Bastion/Dependency/",
        }
        
        if tag in flat_to_nested:
            return flat_to_nested[tag]
        
        # Handle dependency tags with suffix
        if tag.startswith("bastion-dep-"):
            suffix = tag[8:]  # Remove "bastion-dep-"
            # Convert to title case
            suffix_parts = suffix.split("-")
            suffix_title = "-".join(p.title() for p in suffix_parts)
            return f"Bastion/Dependency/{suffix_title}"
        
        # Generic bastion-* pattern (catch remaining)
        if tag.startswith("bastion-"):
            # Convert bastion-category-value to Bastion/Category/Value
            parts = tag[4:].split("-", 1)  # Remove "bastion-" and split once
            if len(parts) == 2:
                category = parts[0].title()
                value = "-".join(p.title() for p in parts[1].split("-"))
                return f"Bastion/{category}/{value}"
            elif len(parts) == 1:
                return f"Bastion/Tag/{parts[0].title()}"
        
        return None  # No conversion needed
    
    # -------------------------------------------------------------------------
    # Step 1: Create encryption infrastructure
    # -------------------------------------------------------------------------
    console.print("[bold]Step 1: Create encryption infrastructure[/bold]")
    
    if not skip_cache:
        cache_mgr = BastionCacheManager()
        
        if not cache_mgr.key_exists():
            if dry_run:
                console.print(f"  [dim]Would create {BASTION_DIR} directory[/dim]")
                console.print("  [dim]Would generate Fernet encryption key[/dim]")
                console.print("  [dim]Would store key in 1Password as 'Bastion Cache Key'[/dim]")
            else:
                console.print(f"  Creating {BASTION_DIR} directory...")
                cache_mgr.ensure_infrastructure()
                
                console.print("  Generating Fernet encryption key...")
                try:
                    cache_mgr.create_encryption_key()
                    console.print("  [green]✓ Encryption key stored in 1Password[/green]")
                    stats["key_created"] = True
                except Exception as e:
                    console.print(f"  [red]✗ Failed to create encryption key: {e}[/red]")
                    raise typer.Exit(1)
        else:
            console.print("  [dim]Encryption key already exists in 1Password[/dim]")
    else:
        console.print("  [dim]Skipping cache infrastructure (--skip-cache)[/dim]")
    
    # -------------------------------------------------------------------------
    # Step 2: Scan and migrate tags
    # -------------------------------------------------------------------------
    console.print("\n[bold]Step 2: Migrate tags (bastion-*/Bastion/* → Bastion/*)[/bold]")
    
    # Get all items
    console.print("  Scanning all 1Password items...")
    all_items = op.list_all_items()
    stats["items_scanned"] = len(all_items)
    console.print(f"  Found {len(all_items)} items")
    
    items_to_update = []
    
    for item in all_items:
        tags = item.get("tags", [])
        if not tags:
            continue
        
        # Check for legacy tags
        legacy_tags = [t for t in tags if is_legacy_tag(t)]
        if not legacy_tags:
            continue
        
        stats["items_with_legacy_tags"] += 1
        
        # Build new tag list
        new_tags = []
        conversions = []
        for tag in tags:
            converted = convert_tag(tag)
            if converted:
                new_tags.append(converted)
                conversions.append((tag, converted))
                stats["tags_converted"] += 1
            else:
                new_tags.append(tag)
        
        items_to_update.append({
            "uuid": item.get("id"),
            "title": item.get("title"),
            "old_tags": tags,
            "new_tags": new_tags,
            "conversions": conversions,
        })
    
    console.print(f"  Found {stats['items_with_legacy_tags']} items with legacy tags")
    
    # Apply tag updates
    if items_to_update:
        console.print(f"\n  Migrating tags on {len(items_to_update)} items...")
        
        for item_info in items_to_update:
            if dry_run:
                console.print(f"    [dim]{item_info['title']}:[/dim]")
                for old, new in item_info["conversions"]:
                    console.print(f"      [dim]{old} → {new}[/dim]")
            else:
                result = op.edit_item_tags(item_info["uuid"], item_info["new_tags"])
                if result is True:
                    console.print(f"    [green]✓[/green] {item_info['title']}")
                else:
                    console.print(f"    [red]✗[/red] {item_info['title']}: {result}")
    
    # -------------------------------------------------------------------------
    # Step 3: Rename sections and fields
    # -------------------------------------------------------------------------
    console.print("\n[bold]Step 3: Rename sections (Bastion Metadata → Bastion Metadata)[/bold]")
    
    section_updates = []
    
    for item in all_items:
        uuid = item.get("id")
        title = item.get("title")
        
        # Get full item details to check sections
        full_item = op.get_item(uuid)
        if not full_item:
            continue
        
        # Check for Bastion Metadata section
        has_metadata_section = False
        has_bastion_notes = False
        
        for section in full_item.get("sections", []):
            if section.get("label") == "Bastion Metadata":
                has_metadata_section = True
                break
        
        for field in full_item.get("fields", []):
            if field.get("label") == "Bastion Notes":
                has_bastion_notes = True
                break
        
        if has_metadata_section or has_bastion_notes:
            section_updates.append({
                "uuid": uuid,
                "title": title,
                "has_metadata_section": has_metadata_section,
                "has_bastion_notes": has_bastion_notes,
            })
    
    console.print(f"  Found {len(section_updates)} items with Bastion sections/fields")
    
    if section_updates:
        console.print(f"\n  Renaming sections on {len(section_updates)} items...")
        
        for item_info in section_updates:
            if dry_run:
                changes = []
                if item_info["has_metadata_section"]:
                    changes.append("Bastion Metadata → Bastion Metadata")
                    stats["sections_renamed"] += 1
                if item_info["has_bastion_notes"]:
                    changes.append("Bastion Notes → Bastion Notes")
                    stats["fields_renamed"] += 1
                console.print(f"    [dim]{item_info['title']}: {', '.join(changes)}[/dim]")
            else:
                # Use op item edit with JSON to rename sections
                # Note: Section renaming via op CLI is limited - may need manual intervention
                # For now, we'll create new fields and leave old ones (user can clean up)
                try:
                    uuid = item_info["uuid"]
                    
                    # Get current item data
                    full_item = op.get_item(uuid)
                    if not full_item:
                        continue
                    
                    # For section rename, we need to use JSON editing
                    # This is complex - for MVP, just log what needs manual attention
                    console.print(f"    [yellow]![/yellow] {item_info['title']}: Manual section rename needed")
                    console.print("        [dim]Rename 'Bastion Metadata' section to 'Bastion Metadata' in 1Password app[/dim]")
                    
                    if item_info["has_metadata_section"]:
                        stats["sections_renamed"] += 1
                    if item_info["has_bastion_notes"]:
                        stats["fields_renamed"] += 1
                        
                except Exception as e:
                    console.print(f"    [red]✗[/red] {item_info['title']}: {e}")
    
    # -------------------------------------------------------------------------
    # Step 4: Migrate local cache
    # -------------------------------------------------------------------------
    console.print("\n[bold]Step 4: Migrate local cache[/bold]")
    
    if skip_cache:
        console.print("  [dim]Skipping cache migration (--skip-cache)[/dim]")
    else:
        # Look for legacy database file
        legacy_db_paths = [
            Path.cwd() / "password-rotation-database.json",
            Path.cwd() / "password_rotation.db",
        ]
        
        legacy_db_path = None
        for path in legacy_db_paths:
            if path.exists():
                legacy_db_path = path
                break
        
        if legacy_db_path:
            console.print(f"  Found legacy cache: {legacy_db_path}")
            
            if dry_run:
                console.print(f"  [dim]Would read {legacy_db_path}[/dim]")
                console.print(f"  [dim]Would encrypt and write to {BASTION_CACHE_FILE}[/dim]")
                console.print(f"  [dim]Would backup original to {BASTION_DIR}/legacy/[/dim]")
            else:
                try:
                    # Load legacy database
                    legacy_mgr = DatabaseManager(legacy_db_path)
                    db = legacy_mgr.load()
                    
                    # Update tags in cached accounts
                    for uuid, account in db.accounts.items():
                        if account.tags:
                            old_tags = [t.strip() for t in account.tags.split(",") if t.strip()]
                            new_tags = []
                            for tag in old_tags:
                                converted = convert_tag(tag)
                                new_tags.append(converted if converted else tag)
                            account.tags = ",".join(new_tags)
                    
                    # Save to encrypted cache
                    cache_mgr = BastionCacheManager()
                    cache_mgr.save(db)
                    console.print(f"  [green]✓ Encrypted cache saved to {BASTION_CACHE_FILE}[/green]")
                    
                    # Backup original
                    legacy_backup_dir = BASTION_DIR / "legacy"
                    legacy_backup_dir.mkdir(exist_ok=True)
                    import shutil
                    backup_name = f"{legacy_db_path.stem}-{datetime.now().strftime('%Y%m%d-%H%M%S')}{legacy_db_path.suffix}"
                    shutil.copy2(legacy_db_path, legacy_backup_dir / backup_name)
                    console.print(f"  [green]✓ Original backed up to {legacy_backup_dir / backup_name}[/green]")
                    
                    stats["cache_migrated"] = True
                    
                except Exception as e:
                    console.print(f"  [red]✗ Cache migration failed: {e}[/red]")
        else:
            console.print("  [dim]No legacy cache file found[/dim]")
    
    # -------------------------------------------------------------------------
    # Step 5: Migrate YubiKey cache to encrypted storage
    # -------------------------------------------------------------------------
    console.print("\n[bold]Step 5: Migrate YubiKey cache to encrypted storage[/bold]")
    
    if skip_cache:
        console.print("  [dim]Skipping YubiKey cache migration (--skip-cache)[/dim]")
    else:
        from bastion.config import get_yubikey_cache_path
        
        legacy_yubikey_path = get_yubikey_cache_path()
        
        if legacy_yubikey_path.exists():
            console.print(f"  Found legacy YubiKey cache: {legacy_yubikey_path}")
            
            if dry_run:
                console.print(f"  [dim]Would read {legacy_yubikey_path}[/dim]")
                console.print("  [dim]Would encrypt and merge into db.enc[/dim]")
                console.print(f"  [dim]Would backup original to {BASTION_DIR}/legacy/[/dim]")
            else:
                try:
                    import json
                    
                    # Load legacy YubiKey cache
                    with open(legacy_yubikey_path, "r") as f:
                        legacy_yubikey_data = json.load(f)
                    
                    console.print(f"  Loaded {len(legacy_yubikey_data.get('slots', {}))} YubiKey slot mappings")
                    
                    # Load current encrypted database
                    cache_mgr = BastionCacheManager()
                    db = cache_mgr.load()
                    
                    # Merge YubiKey cache into database
                    db.yubikey_cache = legacy_yubikey_data
                    
                    # Save encrypted
                    cache_mgr.save(db)
                    console.print(f"  [green]✓ YubiKey cache merged into encrypted storage[/green]")
                    
                    # Backup original
                    legacy_backup_dir = BASTION_DIR / "legacy"
                    legacy_backup_dir.mkdir(exist_ok=True)
                    backup_name = f"{legacy_yubikey_path.stem}-{datetime.now().strftime('%Y%m%d-%H%M%S')}{legacy_yubikey_path.suffix}"
                    shutil.copy2(legacy_yubikey_path, legacy_backup_dir / backup_name)
                    console.print(f"  [green]✓ Original backed up to {legacy_backup_dir / backup_name}[/green]")
                    
                    # Delete original plaintext file (security: remove sensitive data)
                    legacy_yubikey_path.unlink()
                    console.print(f"  [green]✓ Deleted plaintext file {legacy_yubikey_path}[/green]")
                    
                    stats["yubikey_cache_migrated"] = True
                    
                except Exception as e:
                    console.print(f"  [red]✗ YubiKey cache migration failed: {e}[/red]")
        else:
            console.print("  [dim]No legacy YubiKey cache file found[/dim]")
    
    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    console.print("\n[bold blue]═══ Migration Summary ═══[/bold blue]")
    console.print(f"  Items scanned: {stats['items_scanned']}")
    console.print(f"  Items with legacy tags: {stats['items_with_legacy_tags']}")
    console.print(f"  Tags converted: {stats['tags_converted']}")
    console.print(f"  Sections to rename: {stats['sections_renamed']}")
    console.print(f"  Fields to rename: {stats['fields_renamed']}")
    console.print(f"  Cache migrated: {'Yes' if stats['cache_migrated'] else 'No'}")
    console.print(f"  YubiKey cache migrated: {'Yes' if stats['yubikey_cache_migrated'] else 'No'}")
    console.print(f"  Encryption key created: {'Yes' if stats['key_created'] else 'No (already existed)'}")
    
    if dry_run:
        console.print("\n[yellow]DRY RUN COMPLETE - Run without --dry-run to apply changes[/yellow]")
    else:
        console.print("\n[green]✓ Migration complete![/green]")
        console.print("\n[bold]Next steps:[/bold]")
        console.print("  1. Run 'bastion sync accounts' to verify")
        console.print("  2. Manually rename 'Bastion Metadata' sections in 1Password app")
        console.print("  3. Delete legacy cache file after verifying encrypted cache works")
        # TODO: Implement 'bastion rotate cache-key' for periodic key rotation
