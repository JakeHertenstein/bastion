"""Two-phase migration tool for authenticator token traceability fields.

Migrates from flat custom fields (yubikey_oath_name, yubikey_serials) to
individual Token sections with type-specific fields.

New structure:
- Token 1, Token 2, etc. sections with:
  - Serial: YubiKey serial or phone identifier
  - Type: "YubiKey", "Phone App", or "SMS"
  - Type-specific fields (OATH Name for YubiKey/Phone App, Phone Number for SMS)

Phase 1: Add new token sections alongside old flat fields
Phase 2: Delete old flat fields after validation

Auto-detects phase based on item state:
- Old fields only → Phase 1 (add new)
- Both old and new → Phase 2 (delete old)
- New fields only → Already migrated (skip)
"""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.prompt import Confirm

console = Console()


class YubiKeyFieldMigration:
    """Two-phase migration manager for authenticator token traceability fields."""
    
    # Old field names
    OLD_OATH_NAME_FIELD = "yubikey_oath_name"
    OLD_SERIALS_FIELD = "yubikey_serials"
    
    # Token section prefix (sections named "Token 1", "Token 2", etc.)
    TOKEN_SECTION_PREFIX = "Token"
    
    def __init__(self, dry_run: bool = False):
        """Initialize migration manager.
        
        Args:
            dry_run: If True, only show what would be done without making changes
        """
        self.dry_run = dry_run
        self.migration_log: list[dict] = []
    
    def get_item_by_uuid(self, uuid: str) -> Optional[dict]:
        """Fetch 1Password item by UUID.
        
        Args:
            uuid: 1Password item UUID
            
        Returns:
            Item data dictionary or None if not found
        """
        try:
            result = subprocess.run(
                ["op", "item", "get", uuid, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            return json.loads(result.stdout)
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return None
    
    def get_items_with_yubikey_totp(self) -> list[dict]:
        """Get all login items with Bastion/2FA/TOTP/YubiKey tag.
        
        Returns:
            List of item dictionaries with basic info (id, title, vault)
        """
        try:
            result = subprocess.run(
                ["op", "item", "list", "--tags", "Bastion/2FA/TOTP/YubiKey", "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            return json.loads(result.stdout)
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return []
    
    def analyze_item_state(self, item_data: dict) -> dict:
        """Analyze current state of authenticator token fields in an item.
        
        Args:
            item_data: Full item data from 1Password
            
        Returns:
            Dictionary with state analysis:
            {
                "has_old_fields": bool,
                "has_legacy_fields": bool,  # YubiKey TOTP + Tokens sections (intermediate format)
                "has_new_fields": bool,
                "old_oath_name": str,
                "old_serials": list[str],
                "legacy_oath_name": str,
                "legacy_serials": list[str],
                "new_tokens": dict[int, dict],  # token_num -> {serial, type, oath_name, ...}
                "phase": "add" | "delete" | "convert_legacy" | "done" | "none"
            }
        """
        state = {
            "has_old_fields": False,
            "has_legacy_fields": False,
            "has_new_fields": False,
            "old_oath_name": "",
            "old_serials": [],
            "legacy_oath_name": "",
            "legacy_serials": [],
            "new_tokens": {},
            "phase": "none"
        }
        
        fields = item_data.get("fields", [])
        
        for field in fields:
            section = field.get("section", {})
            section_label = section.get("label", "") if section else ""
            field_label = field.get("label", "")
            field_value = field.get("value", "")
            
            # Check for old flat fields
            if not section_label:
                if field_label == self.OLD_OATH_NAME_FIELD:
                    state["has_old_fields"] = True
                    state["old_oath_name"] = field_value
                elif field_label == self.OLD_SERIALS_FIELD:
                    state["has_old_fields"] = True
                    if field_value:
                        state["old_serials"] = [s.strip() for s in field_value.split(",")]
            
            # Check for legacy YubiKey TOTP section (intermediate format)
            elif section_label == "YubiKey TOTP":
                state["has_legacy_fields"] = True
                if field_label == "oath_name":
                    state["legacy_oath_name"] = field_value
                elif field_label == "serials":
                    if field_value:
                        state["legacy_serials"] = [s.strip() for s in field_value.split(",")]
            
            # Check for legacy Tokens section (intermediate format)
            elif section_label == "Tokens":
                state["has_legacy_fields"] = True
                # token_1, token_2, etc. - don't mark as has_new_fields
            
            # Check for new Token N sections
            elif section_label.startswith(f"{self.TOKEN_SECTION_PREFIX} "):
                state["has_new_fields"] = True
                # Extract token number from section name (e.g., "Token 1" -> 1)
                try:
                    token_num = int(section_label.split(" ")[1])
                    if token_num not in state["new_tokens"]:
                        state["new_tokens"][token_num] = {}
                    
                    # Store all fields in the token dict
                    if field_label in ["Serial", "Type", "OATH Name", "TOTP Enabled", "PassKey Enabled",
                                      "App Name", "Phone Number", "Carrier Name"]:
                        state["new_tokens"][token_num][field_label] = field_value
                except (IndexError, ValueError):
                    pass
        
        # Determine phase
        if state["has_old_fields"] and not state["has_legacy_fields"] and not state["has_new_fields"]:
            state["phase"] = "add"
        elif state["has_old_fields"] and (state["has_legacy_fields"] or state["has_new_fields"]):
            state["phase"] = "delete"
        elif state["has_legacy_fields"] and state["has_new_fields"]:
            state["phase"] = "delete_legacy"  # Delete legacy sections, keep Token sections
        elif state["has_legacy_fields"] and not state["has_new_fields"]:
            state["phase"] = "convert_legacy"
        elif not state["has_old_fields"] and not state["has_legacy_fields"] and state["has_new_fields"]:
            state["phase"] = "done"
        else:
            state["phase"] = "none"
        
        return state
    
    def validate_migration(self, state: dict) -> tuple[bool, list[str]]:
        """Validate that new token sections match old fields.
        
        Args:
            state: Item state from analyze_item_state()
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        if not state["has_new_fields"]:
            errors.append("New token sections not found")
            return (False, errors)
        
        # Validate serials count matches tokens count
        old_serial_count = len(state["old_serials"])
        new_token_count = len(state["new_tokens"])
        
        if old_serial_count != new_token_count:
            errors.append(
                f"Token count mismatch: {old_serial_count} serials "
                f"vs {new_token_count} token sections"
            )
        
        # Validate token numbering is sequential (1, 2, 3...)
        if state["new_tokens"]:
            expected_nums = set(range(1, new_token_count + 1))
            actual_nums = set(state["new_tokens"].keys())
            
            if expected_nums != actual_nums:
                errors.append(
                    f"Token numbering not sequential: expected {sorted(expected_nums)} "
                    f"got {sorted(actual_nums)}"
                )
        
        # Validate each token has required fields based on type
        new_serials = []
        for token_num, token_data in state["new_tokens"].items():
            if "Serial" not in token_data:
                errors.append(f"Token {token_num} missing 'Serial' field")
            else:
                new_serials.append(token_data["Serial"])
            
            if "Type" not in token_data:
                errors.append(f"Token {token_num} missing 'Type' field")
            else:
                token_type = token_data["Type"]
                if token_type not in ["YubiKey", "Phone App", "SMS"]:
                    errors.append(
                        f"Token {token_num} has invalid Type: '{token_type}' "
                        f"(must be 'YubiKey', 'Phone App', or 'SMS')"
                    )
                
                # Type-specific validation
                if token_type in ["YubiKey", "Phone App"]:
                    if "OATH Name" not in token_data:
                        errors.append(f"Token {token_num} ({token_type}) missing 'OATH Name' field")
                    # Validate OATH Name matches old oath_name for backward compat
                    elif state["old_oath_name"] and token_data["OATH Name"] != state["old_oath_name"]:
                        errors.append(
                            f"Token {token_num} OATH Name mismatch: "
                            f"old='{state['old_oath_name']}' vs new='{token_data['OATH Name']}'"
                        )
                elif token_type == "SMS":
                    if "Phone Number" not in token_data:
                        errors.append(f"Token {token_num} (SMS) missing 'Phone Number' field")
        
        # Validate token serials match old serials (order may differ)
        old_serials_set = set(state["old_serials"])
        new_serials_set = set(new_serials)
        
        if old_serials_set != new_serials_set:
            missing = old_serials_set - new_serials_set
            extra = new_serials_set - old_serials_set
            
            if missing:
                errors.append(f"Missing serials in token sections: {sorted(missing)}")
            if extra:
                errors.append(f"Extra serials in token sections: {sorted(extra)}")
        
        return (len(errors) == 0, errors)
    
    def add_new_fields(self, uuid: str, item_data: dict, state: dict) -> bool:
        """Phase 1: Add new section-based fields.
        
        Args:
            uuid: Item UUID
            item_data: Full item data
            state: Item state from analyze_item_state()
            
        Returns:
            True if successful, False otherwise
        """
        if self.dry_run:
            console.print(f"[dim]DRY RUN: Would add new fields to {uuid}[/dim]")
            return True
        
        title = item_data.get("title", "Unknown")
        
        # Build edit command with individual Token sections
        edit_fields = []
        
        # Add individual token sections (Token 1, Token 2, ...)
        # All tokens from old format are YubiKey type with shared OATH Name
        for i, serial in enumerate(state['old_serials'], start=1):
            section_name = f"{self.TOKEN_SECTION_PREFIX} {i}"
            edit_fields.extend([
                f"{section_name}.Serial[text]={serial}",
                f"{section_name}.Type[text]=YubiKey",
                f"{section_name}.OATH Name[text]={state['old_oath_name']}",
                f"{section_name}.TOTP Enabled[text]=yes",
                f"{section_name}.PassKey Enabled[text]=",
            ])
        
        try:
            subprocess.run(
                ["op", "item", "edit", uuid] + edit_fields,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            console.print(f"[green]✓ Added new token sections to {title}[/green]")
            console.print(f"  OATH Name: {state['old_oath_name']}")
            console.print(f"  Token sections: {len(state['old_serials'])} created (Type: YubiKey)")
            
            self.migration_log.append({
                "uuid": uuid,
                "title": title,
                "phase": "add",
                "timestamp": datetime.now().isoformat(),
                "success": True
            })
            
            return True
            
        except subprocess.CalledProcessError as e:
            console.print(f"[red]✗ Failed to add fields to {title}: {e.stderr}[/red]")
            
            self.migration_log.append({
                "uuid": uuid,
                "title": title,
                "phase": "add",
                "timestamp": datetime.now().isoformat(),
                "success": False,
                "error": e.stderr
            })
            
            return False
    
    def delete_old_fields(self, uuid: str, item_data: dict, state: dict) -> bool:
        """Phase 2: Delete old flat fields after validation.
        
        Args:
            uuid: Item UUID
            item_data: Full item data
            state: Item state from analyze_item_state()
            
        Returns:
            True if successful, False otherwise
        """
        if self.dry_run:
            console.print(f"[dim]DRY RUN: Would delete old fields from {uuid}[/dim]")
            return True
        
        title = item_data.get("title", "Unknown")
        
        # Find field IDs for old fields
        old_field_ids = []
        for field in item_data.get("fields", []):
            section = field.get("section", {})
            section_label = section.get("label", "") if section else ""
            field_label = field.get("label", "")
            field_id = field.get("id", "")
            
            if not section_label and field_id:
                if field_label in [self.OLD_OATH_NAME_FIELD, self.OLD_SERIALS_FIELD]:
                    old_field_ids.append((field_id, field_label))
        
        if not old_field_ids:
            console.print(f"[yellow]⚠ No old fields found to delete in {title}[/yellow]")
            return False
        
        # Delete each old field by ID
        success_count = 0
        for field_id, field_label in old_field_ids:
            try:
                subprocess.run(
                    ["op", "item", "edit", uuid, f"{field_label}[delete]"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
                console.print(f"[green]✓ Deleted {field_label}[/green]")
                success_count += 1
                
            except subprocess.CalledProcessError as e:
                console.print(f"[red]✗ Failed to delete {field_label}: {e.stderr}[/red]")
        
        if success_count == len(old_field_ids):
            console.print(f"[green]✓ Completed migration for {title}[/green]")
            
            self.migration_log.append({
                "uuid": uuid,
                "title": title,
                "phase": "delete",
                "timestamp": datetime.now().isoformat(),
                "success": True
            })
            
            return True
        else:
            self.migration_log.append({
                "uuid": uuid,
                "title": title,
                "phase": "delete",
                "timestamp": datetime.now().isoformat(),
                "success": False,
                "error": f"Deleted {success_count}/{len(old_field_ids)} fields"
            })
            
            return False
    
    def convert_legacy_tokens(self, uuid: str, item_data: dict, state: dict) -> bool:
        """Phase 3: Convert legacy YubiKey TOTP + Tokens sections to individual Token sections.
        
        Args:
            uuid: Item UUID
            item_data: Full item data
            state: Item state from analyze_item_state()
            
        Returns:
            True if successful, False otherwise
        """
        if self.dry_run:
            console.print(f"[dim]DRY RUN: Would convert legacy sections in {uuid}[/dim]")
            return True
        
        title = item_data.get("title", "Unknown")
        
        # Build edit fields for new Token section format
        edit_fields = []
        
        # Add individual Token sections from legacy serials
        for i, serial in enumerate(sorted(state['legacy_serials']), start=1):
            section_name = f"{self.TOKEN_SECTION_PREFIX} {i}"
            edit_fields.extend([
                f"{section_name}.Serial[text]={serial}",
                f"{section_name}.Type[text]=YubiKey",
                f"{section_name}.OATH Name[text]={state['legacy_oath_name']}",
                f"{section_name}.TOTP Enabled[text]=yes",
                f"{section_name}.PassKey Enabled[text]=",
            ])
        
        try:
            subprocess.run(
                ["op", "item", "edit", uuid] + edit_fields,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            console.print(f"[green]✓ Created {len(state['legacy_serials'])} new Token sections[/green]")
            
        except subprocess.CalledProcessError as e:
            console.print(f"[red]✗ Failed to create Token sections: {e.stderr}[/red]")
            return False
        
        # Now delete legacy YubiKey TOTP and Tokens section fields
        fields_to_delete = ["oath_name", "serials"]  # From YubiKey TOTP section
        for i in range(1, len(state['legacy_serials']) + 1):
            fields_to_delete.append(f"token_{i}")  # From Tokens section
        
        delete_commands = []
        for field_name in fields_to_delete:
            delete_commands.append(f"{field_name}[delete]")
        
        try:
            subprocess.run(
                ["op", "item", "edit", uuid] + delete_commands,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            console.print("[green]✓ Deleted legacy YubiKey TOTP and Tokens section fields[/green]")
            
        except subprocess.CalledProcessError as e:
            console.print(f"[yellow]⚠ Could not delete all legacy fields: {e.stderr}[/yellow]")
        
        console.print(f"[green]✓ Completed legacy format conversion for {title}[/green]")
        
        self.migration_log.append({
            "uuid": uuid,
            "title": title,
            "phase": "convert_legacy",
            "timestamp": datetime.now().isoformat(),
            "success": True
        })
        
        return True
    
    def delete_legacy_fields(self, uuid: str, item_data: dict, state: dict) -> bool:
        """Delete legacy YubiKey TOTP and Tokens section fields (when Token sections already exist).
        
        Args:
            uuid: Item UUID
            item_data: Full item data
            state: Item state from analyze_item_state()
            
        Returns:
            True if successful, False otherwise
        """
        if self.dry_run:
            console.print(f"[dim]DRY RUN: Would delete legacy fields from {uuid}[/dim]")
            return True
        
        title = item_data.get("title", "Unknown")
        
        # Build list of fields to delete
        fields_to_delete = []
        
        # Delete YubiKey TOTP section fields
        for field in item_data.get("fields", []):
            section = field.get("section", {})
            section_label = section.get("label", "") if section else ""
            field_label = field.get("label", "")
            
            if section_label == "YubiKey TOTP" or section_label == "Tokens":
                fields_to_delete.append(f"{field_label}[delete]")
        
        if not fields_to_delete:
            console.print(f"[yellow]⚠ No legacy fields found to delete in {title}[/yellow]")
            return False
        
        try:
            subprocess.run(
                ["op", "item", "edit", uuid] + fields_to_delete,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            console.print(f"[green]✓ Deleted {len(fields_to_delete)} legacy fields from {title}[/green]")
            
            self.migration_log.append({
                "uuid": uuid,
                "title": title,
                "phase": "delete_legacy",
                "timestamp": datetime.now().isoformat(),
                "success": True
            })
            
            return True
            
        except subprocess.CalledProcessError as e:
            console.print(f"[red]✗ Failed to delete legacy fields: {e.stderr}[/red]")
            return False
    
    def migrate_item(self, uuid: str, interactive: bool = True) -> bool:
        """Migrate a single item with auto-phase detection.
        
        Args:
            uuid: Item UUID
            interactive: If True, prompt for confirmation
            
        Returns:
            True if migration performed, False if skipped/failed
        """
        # Fetch item
        item_data = self.get_item_by_uuid(uuid)
        if not item_data:
            console.print(f"[red]✗ Item {uuid} not found[/red]")
            return False
        
        title = item_data.get("title", "Unknown")
        
        # Analyze state
        state = self.analyze_item_state(item_data)
        
        console.print(f"\n[cyan]Item: {title}[/cyan]")
        console.print(f"UUID: {uuid}")
        console.print(f"Phase: [yellow]{state['phase']}[/yellow]")
        
        # Handle based on phase
        if state["phase"] == "none":
            console.print("[dim]No YubiKey fields found, skipping[/dim]")
            return False
        
        elif state["phase"] == "done":
            console.print("[green]Already migrated, skipping[/green]")
            return False
        
        elif state["phase"] == "add":
            # Phase 1: Add new token sections
            console.print("[yellow]Phase 1: Add new token sections[/yellow]")
            console.print(f"  Old OATH Name: {state['old_oath_name']}")
            console.print(f"  Old serials: {', '.join(state['old_serials'])}")
            console.print(f"\n[cyan]Will create {len(state['old_serials'])} Token sections:[/cyan]")
            for i, serial in enumerate(state['old_serials'], start=1):
                console.print(f"  • Token {i}: Serial={serial}, Type=YubiKey, OATH Name={state['old_oath_name']}")
            
            if interactive and not self.dry_run:
                if not Confirm.ask("Add new token sections?"):
                    console.print("[dim]Skipped[/dim]")
                    return False
            
            return self.add_new_fields(uuid, item_data, state)
        
        elif state["phase"] == "convert_legacy":
            # Phase 3: Convert legacy YubiKey TOTP + Tokens sections to Token N sections
            console.print("[yellow]Phase 3: Convert legacy format to Token sections[/yellow]")
            console.print(f"  Legacy OATH Name: {state['legacy_oath_name']}")
            console.print(f"  Legacy serials: {', '.join(state['legacy_serials'])}")
            console.print(f"\n[cyan]Will create {len(state['legacy_serials'])} Token sections:[/cyan]")
            for i, serial in enumerate(sorted(state['legacy_serials']), start=1):
                console.print(f"  • Token {i}: Serial={serial}, Type=YubiKey, OATH Name={state['legacy_oath_name']}")
            console.print("\n[yellow]Will delete legacy YubiKey TOTP and Tokens sections[/yellow]")
            
            if interactive and not self.dry_run:
                if not Confirm.ask("Convert to Token sections?"):
                    console.print("[dim]Skipped[/dim]")
                    return False
            
            return self.convert_legacy_tokens(uuid, item_data, state)
        
        elif state["phase"] == "delete_legacy":
            # Phase 4: Delete legacy sections while keeping Token sections
            console.print("[yellow]Phase 4: Delete legacy YubiKey TOTP and Tokens sections[/yellow]")
            console.print(f"  Token sections exist: {len(state['new_tokens'])} tokens")
            console.print("  Legacy sections will be deleted")
            
            if interactive and not self.dry_run:
                if not Confirm.ask("Delete legacy sections?"):
                    console.print("[dim]Skipped[/dim]")
                    return False
            
            return self.delete_legacy_fields(uuid, item_data, state)
        
        elif state["phase"] == "delete":
            # Phase 2: Validate and delete old fields
            console.print("[yellow]Phase 2: Validate and delete old fields[/yellow]")
            
            # Validate migration
            is_valid, errors = self.validate_migration(state)
            
            if not is_valid:
                console.print("[red]✗ Validation failed:[/red]")
                for error in errors:
                    console.print(f"  • {error}")
                
                if interactive:
                    if not Confirm.ask("Continue anyway? (NOT RECOMMENDED)"):
                        return False
                else:
                    return False
            else:
                console.print("[green]✓ Validation passed[/green]")
            
            # Show what will be deleted
            console.print("\n[yellow]Will delete:[/yellow]")
            console.print(f"  • {self.OLD_OATH_NAME_FIELD}: {state['old_oath_name']}")
            console.print(f"  • {self.OLD_SERIALS_FIELD}: {', '.join(state['old_serials'])}")
            
            console.print("\n[green]Will keep:[/green]")
            for token_num in sorted(state['new_tokens'].keys()):
                token = state['new_tokens'][token_num]
                console.print(f"  • Token {token_num}: {token.get('Type', 'Unknown')} - {token.get('Serial', 'Unknown')}")
            
            if interactive and not self.dry_run:
                if not Confirm.ask("Delete old fields?"):
                    console.print("[dim]Skipped[/dim]")
                    return False
            
            return self.delete_old_fields(uuid, item_data, state)
        
        return False
    
    def migrate_all(self, interactive: bool = True) -> dict:
        """Migrate all items with Bastion/TOTP/YubiKey tag.
        
        Args:
            interactive: If True, prompt for confirmation per item
            
        Returns:
            Dictionary with migration statistics
        """
        items = self.get_items_with_yubikey_totp()
        
        if not items:
            console.print("[yellow]No items found with Bastion/TOTP/YubiKey tag[/yellow]")
            return {"total": 0, "migrated": 0, "skipped": 0, "failed": 0}
        
        console.print(f"\n[cyan]Found {len(items)} items with YubiKey TOTP[/cyan]\n")
        
        stats = {"total": len(items), "migrated": 0, "skipped": 0, "failed": 0}
        
        for item in items:
            uuid = item.get("id", "")
            
            try:
                result = self.migrate_item(uuid, interactive=interactive)
                if result:
                    stats["migrated"] += 1
                else:
                    stats["skipped"] += 1
            except Exception as e:
                console.print(f"[red]✗ Error migrating {uuid}: {e}[/red]")
                stats["failed"] += 1
        
        return stats
    
    def show_status_table(self) -> None:
        """Show status table of all items."""
        items = self.get_items_with_yubikey_totp()
        
        if not items:
            console.print("[yellow]No items found with Bastion/TOTP/YubiKey tag[/yellow]")
            return
        
        table = Table(title="Authenticator Token Migration Status")
        table.add_column("Title", style="cyan")
        table.add_column("UUID", style="dim")
        table.add_column("Phase", style="yellow")
        table.add_column("OATH Name", style="white")
        table.add_column("Tokens", justify="right")
        table.add_column("Status", style="green")
        
        for item in items:
            uuid = item.get("id", "")
            title = item.get("title", "Unknown")
            
            item_data = self.get_item_by_uuid(uuid)
            if not item_data:
                continue
            
            state = self.analyze_item_state(item_data)
            
            # Determine status symbol
            if state["phase"] == "done":
                status = "✓ Done"
                status_style = "green"
            elif state["phase"] == "add":
                status = "→ Add"
                status_style = "yellow"
            elif state["phase"] == "convert_legacy":
                status = "○ None"
                status_style = "yellow"
            elif state["phase"] == "delete":
                status = "→ Delete"
                status_style = "yellow"
            else:
                status = "○ None"
                status_style = "dim"
            
            # Get OATH Name from appropriate source
            oath_name = state["old_oath_name"] or state["legacy_oath_name"] or "-"
            if state["new_tokens"]:
                first_token = state["new_tokens"][min(state["new_tokens"].keys())]
                oath_name = first_token.get("OATH Name", oath_name)
            
            token_count = len(state["new_tokens"]) or len(state["legacy_serials"]) or len(state["old_serials"])
            
            table.add_row(
                title[:40],
                uuid[:16] + "...",
                state["phase"],
                oath_name[:30],
                str(token_count),
                f"[{status_style}]{status}[/{status_style}]"
            )
        
        console.print(table)
    
    def save_migration_log(self, log_path: Path) -> None:
        """Save migration log to JSON file.
        
        Args:
            log_path: Path to save log file
        """
        with open(log_path, "w") as f:
            json.dump(self.migration_log, f, indent=2)
        
        console.print(f"\n[cyan]Migration log saved to {log_path}[/cyan]")


def main():
    """CLI entry point for migration tool."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Migrate YubiKey TOTP traceability fields to sections"
    )
    parser.add_argument(
        "--uuid",
        help="Migrate specific item by UUID"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Migrate all items (still interactive by default)"
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Skip confirmation prompts (use with caution)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show migration status table and exit"
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=Path("yubikey_migration.log.json"),
        help="Path to save migration log (default: yubikey_migration.log.json)"
    )
    
    args = parser.parse_args()
    
    migrator = YubiKeyFieldMigration(dry_run=args.dry_run)
    
    # Show status table
    if args.status:
        migrator.show_status_table()
        return 0
    
    # Migrate specific item
    if args.uuid:
        migrator.migrate_item(args.uuid, interactive=not args.non_interactive)
        migrator.save_migration_log(args.log)
        return 0
    
    # Migrate all items
    if args.all:
        stats = migrator.migrate_all(interactive=not args.non_interactive)
        
        console.print("\n[cyan]Migration Summary:[/cyan]")
        console.print(f"  Total items: {stats['total']}")
        console.print(f"  Migrated: {stats['migrated']}")
        console.print(f"  Skipped: {stats['skipped']}")
        console.print(f"  Failed: {stats['failed']}")
        
        migrator.save_migration_log(args.log)
        return 0
    
    # No action specified, show help
    console.print("[yellow]No action specified. Use --status, --uuid, or --all[/yellow]")
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
