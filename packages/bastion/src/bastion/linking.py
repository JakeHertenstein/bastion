"""Bidirectional item linking for 1Password.

This module provides bidirectional relationship management between 1Password items,
ensuring forward and reverse links are maintained consistently.

Relationship Types:
- derived_from / derives_to (e.g., username derived from entropy)
- generates / generated_by (e.g., entropy generates username)
- uses / used_by (e.g., item uses YubiKey)
- recovers / recovered_by (e.g., person recovers account)

CRITICAL: Items with Bastion/2FA/Passkey/Software tags have 1Password-stored passkeys.
JSON editing via stdin will PERMANENTLY DELETE the passkey's WebAuthn private key.
See: bastion/support/1PASSWORD-CLI-PASSKEY-BUG.md
"""

import json
import subprocess
from typing import Optional
from rich.console import Console

console = Console()

# Tag indicating 1Password-stored passkey (at risk during JSON editing)
PASSKEY_TAG = "Bastion/2FA/Passkey/Software"


class ItemLinker:
    """Manage bidirectional links between 1Password items."""
    
    # Supported item categories for linking (tested and verified)
    SUPPORTED_LINK_CATEGORIES = {
        "LOGIN",
        "SECURE_NOTE",
        "PASSWORD",
    }
    
    # Relationship pairs (forward, reverse)
    RELATIONSHIP_TYPES = {
        "derived_from": "derives_to",
        "generates": "generated_by",
        "uses": "used_by",
        "recovers": "recovered_by",
        "related_to": "related_to",  # Symmetric relationship
    }
    
    def __init__(self):
        """Initialize item linker."""
        pass
    
    def _get_reverse_relationship(self, relationship: str) -> str:
        """Get the reverse relationship type.
        
        Args:
            relationship: Forward relationship type
            
        Returns:
            Reverse relationship type
        """
        # Check if it's a forward relationship
        if relationship in self.RELATIONSHIP_TYPES:
            return self.RELATIONSHIP_TYPES[relationship]
        
        # Check if it's a reverse relationship
        for forward, reverse in self.RELATIONSHIP_TYPES.items():
            if relationship == reverse:
                return forward
        
        # Fallback for symmetric or unknown
        return relationship
    
    def has_passkey_risk(self, item_data: dict) -> bool:
        """Check if item has a 1Password-stored passkey that would be destroyed by JSON editing.
        
        CRITICAL: The 1Password CLI does not include passkey data in JSON output.
        Items tagged with Bastion/2FA/Passkey/Software have passkeys stored in 1Password
        that would be PERMANENTLY DELETED by JSON stdin editing.
        
        Hardware passkeys (FIDO2-Hardware) store keys on the device, not in 1Password,
        so they are not affected by this bug.
        
        See: bastion/support/1PASSWORD-CLI-PASSKEY-BUG.md
        
        Args:
            item_data: Item JSON data from 1Password
            
        Returns:
            True if item has Bastion/2FA/Passkey/Software tag
        """
        tags = item_data.get("tags", [])
        return PASSKEY_TAG in tags
    
    def can_edit_item(self, item_data: dict, allow_passkey_risk: bool = False) -> tuple[bool, str]:
        """Check if an item can be safely edited via JSON stdin.
        
        This validates that the item category is supported and that there are no
        known CLI bugs that would prevent editing.
        
        CRITICAL: Items with Bastion/2FA/Passkey/Software tags have 1Password-stored
        passkeys. JSON editing will PERMANENTLY DELETE the passkey's WebAuthn private key.
        
        Args:
            item_data: Item JSON data from 1Password
            allow_passkey_risk: If True, allow editing despite passkey deletion risk
            
        Returns:
            Tuple of (can_edit, reason_if_cannot)
        """
        category = item_data.get("category", "")
        
        # CRITICAL: Check for 1Password-stored passkey
        if self.has_passkey_risk(item_data) and not allow_passkey_risk:
            return False, (
                f"Item has tag: {PASSKEY_TAG}\n"
                "This indicates a 1Password-stored passkey. JSON editing would PERMANENTLY DELETE "
                "the passkey's WebAuthn private key (1Password CLI bug).\n"
                "Use field assignment syntax instead:\n"
                "  op item edit <uuid> 'Section.Field[type]=value' --tags 'tag'\n"
                "See: bastion/support/1PASSWORD-CLI-PASSKEY-BUG.md"
            )
        
        # Check if category is in the supported list
        if category in self.SUPPORTED_LINK_CATEGORIES:
            return True, ""
        
        # CUSTOM items with category_id cannot be edited due to CLI bug
        if category == "CUSTOM" and item_data.get("category_id"):
            return False, (
                "CUSTOM items with category_id cannot be edited via JSON stdin "
                "(1Password CLI limitation). Convert to SECURE_NOTE first using: "
                "bastion convert to-note <uuid>"
            )
        
        # CUSTOM items without category_id should work
        if category == "CUSTOM":
            return True, ""
        
        # Unknown/untested category
        return False, f"Untested item category: {category}"
    
    def get_item_details(self, item_uuid: str) -> Optional[dict]:
        """Get item details from 1Password.
        
        Args:
            item_uuid: Item UUID
            
        Returns:
            Item data dict or None if not found
        """
        try:
            result = subprocess.run(
                ["op", "item", "get", item_uuid, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            return json.loads(result.stdout)
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return None
    
    def create_link(
        self,
        source_uuid: str,
        target_uuid: str,
        bidirectional: bool = True,
    ) -> bool:
        """Create a native REFERENCE link between two items using JSON editing.
        
        Args:
            source_uuid: Source item UUID
            target_uuid: Target item UUID
            bidirectional: If True, also creates reverse link
            
        Returns:
            True if successful, False otherwise
        """
        # Get both items' details for vault validation
        source_item = self.get_item_details(source_uuid)
        target_item = self.get_item_details(target_uuid)
        
        if not source_item:
            console.print(f"[yellow]⚠ Source item not found (may be deleted/moved): {source_uuid}[/yellow]")
            return False
        if not target_item:
            console.print(f"[yellow]⚠ Target item not found (may be deleted/moved): {target_uuid}[/yellow]")
            return False
        
        # Validate both items are in the same vault
        source_vault_id = source_item.get("vault", {}).get("id", "")
        target_vault_id = target_item.get("vault", {}).get("id", "")
        source_vault_name = source_item.get("vault", {}).get("name", "Private")
        target_vault_name = target_item.get("vault", {}).get("name", "Private")
        
        if source_vault_id != target_vault_id:
            raise ValueError(
                f"Cannot link items in different vaults: '{source_vault_name}' ≠ '{target_vault_name}'. "
                f"1Password does not support cross-vault references."
            )
        
        target_title = target_item.get("title", "Unknown")
        
        # Create forward link
        try:
            if not self._add_reference_field(source_uuid, target_uuid, target_title, target_vault_name):
                return False
            console.print(f"[green]✓ Created forward link → {target_title}[/green]")
        except ValueError as e:
            console.print(f"[yellow]⚠ Skipped forward link: {e}[/yellow]")
        
        # Small delay to avoid conflicts when editing items in rapid succession
        import time
        time.sleep(0.5)
        
        # Create bidirectional reverse link
        if bidirectional:
            source_title = source_item.get("title", "Unknown")
            try:
                if self._add_reference_field(target_uuid, source_uuid, source_title, source_vault_name):
                    console.print(f"[green]✓ Created reverse link → {source_title}[/green]")
            except ValueError as e:
                console.print(f"[yellow]⚠ Skipped reverse link: {e}[/yellow]")
        
        return True
    
    def _add_reference_field(self, item_uuid: str, target_uuid: str, target_title: str, target_vault: str) -> bool:
        """Add a REFERENCE field to an item using JSON editing.
        
        Args:
            item_uuid: Item to add reference to
            target_uuid: UUID of target item
            target_title: Title of target item
            target_vault: Vault name of target item
            
        Returns:
            True if successful
        """
        try:
            # Get current item JSON
            result = subprocess.run(
                ["op", "item", "get", item_uuid, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            item_data = json.loads(result.stdout)
            
            # Validate item can be edited
            can_edit, reason = self.can_edit_item(item_data)
            if not can_edit:
                raise ValueError(reason)
            
            # Ensure fields array exists
            if "fields" not in item_data or item_data["fields"] is None:
                item_data["fields"] = []
            
            # Check if this reference already exists (check by value, ignore malformed fields)
            for field in item_data.get("fields", []):
                if (field.get("type") == "REFERENCE" and 
                    field.get("value") == target_uuid):
                    # Link already exists (in any section)
                    console.print("[dim]  (Link already exists)[/dim]")
                    return True
            
            # Ensure sections array exists
            if "sections" not in item_data or item_data["sections"] is None:
                item_data["sections"] = []
            
            # Ensure Related Items section exists
            section_id = None
            for section in item_data["sections"]:
                if section.get("label") == "Related Items":
                    section_id = section.get("id")
                    break
            
            if not section_id:
                section_id = "related_items"
                item_data["sections"].append({
                    "id": section_id,
                    "label": "Related Items"
                })
            
            # Clean up any malformed fields in Related Items section
            # Remove fields without proper ID or that might cause conflicts
            cleaned_fields = []
            for field in item_data["fields"]:
                field_section = field.get("section", {})
                field_section_label = field_section.get("label", "")
                
                # Keep all fields NOT in Related Items section
                if field_section_label != "Related Items":
                    cleaned_fields.append(field)
                # For Related Items section, only keep REFERENCE fields with proper structure
                elif (field.get("type") == "REFERENCE" and 
                      field.get("value") and 
                      field.get("id")):
                    cleaned_fields.append(field)
                # Skip malformed Related Items fields (will be implicit delete)
            
            item_data["fields"] = cleaned_fields
            
            # Add new REFERENCE field (1Password auto-generates label from target title)
            # Include an ID to ensure proper field structure
            import uuid
            new_field = {
                "id": str(uuid.uuid4()).replace("-", "")[:26],  # 1Password style ID
                "section": {
                    "id": section_id,
                    "label": "Related Items"
                },
                "type": "REFERENCE",
                "value": target_uuid
            }
            
            item_data["fields"].append(new_field)
            
            # Remove category_id if present (causes identity inconsistency errors for CUSTOM items)
            if "category_id" in item_data:
                del item_data["category_id"]
            
            # Write back to 1Password using op item edit with JSON stdin
            result = subprocess.run(
                ["op", "item", "edit", item_uuid, "-"],
                input=json.dumps(item_data),
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            return True
            
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr if e.stderr else str(e)
            # Log specific errors for troubleshooting while keeping output clean
            if "a field to edit must have either an ID or a Label" in error_msg:
                console.print("[dim]  (Note: Could not add reverse link - cleaning may have failed)[/dim]")
            elif "identity inconsistency" in error_msg.lower():
                console.print("[dim]  (Note: Item identity issue prevented link addition)[/dim]")
            else:
                console.print(f"[yellow]⚠ Could not add reference: {error_msg.strip()[:80]}[/yellow]")
            return False
        except (json.JSONDecodeError, KeyError) as e:
            console.print(f"[yellow]⚠ Could not add reference: JSON error - {e}[/yellow]")
            return False
    
    def get_links(self, item_uuid: str) -> dict[str, list[dict]]:
        """Get all links for an item.
        
        Args:
            item_uuid: Item UUID
            
        Returns:
            Dict of relationship types to list of linked items
        """
        item_data = self.get_item_details(item_uuid)
        if not item_data:
            return {}
        
        links = {"related_items": []}
        
        # Look for REFERENCE fields in Related Items section
        for field in item_data.get("fields", []):
            section = field.get("section", {})
            if section.get("label") == "Related Items":
                field_type = field.get("type", "")
                label = field.get("label", "")
                value = field.get("value", "")
                
                # REFERENCE type fields are native item-to-item links
                if field_type == "REFERENCE" and value:
                    links["related_items"].append({
                        "uuid": value,
                        "title": label,
                    })
        
        return links
    
    def verify_bidirectional_links(self, item_uuid: str) -> dict[str, list[dict]]:
        """Verify that all links have proper bidirectional pairs.
        
        Args:
            item_uuid: Item UUID to check
            
        Returns:
            Dict of issues found: {"missing_reverse": [...], "mismatched": [...]}
        """
        issues = {
            "missing_reverse": [],
            "mismatched": [],
        }
        
        links = self.get_links(item_uuid)
        
        for relationship, targets in links.items():
            reverse_rel = self._get_reverse_relationship(relationship)
            
            for target in targets:
                target_ref = target.get("reference", "")
                # Extract UUID from op:// reference
                if "op://" in target_ref:
                    target_uuid = target_ref.split("/")[-1]
                    
                    # Check if reverse link exists
                    target_links = self.get_links(target_uuid)
                    reverse_targets = target_links.get(reverse_rel, [])
                    
                    # Check if our item is in the reverse links
                    found = False
                    for reverse_target in reverse_targets:
                        reverse_ref = reverse_target.get("reference", "")
                        if item_uuid in reverse_ref:
                            found = True
                            break
                    
                    if not found:
                        issues["missing_reverse"].append({
                            "item": item_uuid,
                            "relationship": relationship,
                            "target": target_uuid,
                            "target_title": target.get("title", "Unknown"),
                            "expected_reverse": reverse_rel,
                        })
        
        return issues
    
    def list_all_links(self, item_uuid: str) -> None:
        """List all links for an item in a readable format.
        
        Args:
            item_uuid: Item UUID
        """
        item_data = self.get_item_details(item_uuid)
        if not item_data:
            console.print(f"[red]Item not found: {item_uuid}[/red]")
            return
        
        title = item_data.get("title", "Unknown")
        console.print(f"\n[bold]Links for: {title}[/bold]\n")
        
        links = self.get_links(item_uuid)
        
        if not links:
            console.print("[dim]No links found[/dim]")
            return
        
        for relationship, targets in sorted(links.items()):
            console.print(f"[cyan]{relationship}:[/cyan]")
            for target in targets:
                target_title = target.get("title", "Unknown")
                target_ref = target.get("reference", "")
                console.print(f"  • {target_title}")
                console.print(f"    [dim]{target_ref}[/dim]")
