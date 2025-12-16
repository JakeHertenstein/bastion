"""People and recovery tracking for 1Password items.

This module manages people (Identity items) and their recovery relationships
to other accounts and services.
"""

import json
import subprocess
from typing import Optional
from rich.console import Console

console = Console()


class PeopleManager:
    """Manages people (Identity items) and recovery relationships in 1Password."""
    
    def __init__(self):
        """Initialize the people manager."""
        pass
    
    def get_all_people(self) -> list[dict]:
        """Get all Identity items from 1Password.
        
        Returns:
            List of Identity items
        """
        try:
            result = subprocess.run(
                ["op", "item", "list", "--categories", "Identity", "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            return json.loads(result.stdout)
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            console.print(f"[red]Error fetching Identity items: {e}[/red]")
            return []
    
    def get_person_details(self, person_identifier: str) -> Optional[dict]:
        """Get detailed information about a person (Identity item).
        
        Args:
            person_identifier: Person's name or UUID
            
        Returns:
            Person details or None if not found
        """
        try:
            result = subprocess.run(
                ["op", "item", "get", person_identifier, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            return json.loads(result.stdout)
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return None
    
    def create_person(
        self,
        name: str,
        email: str | None = None,
        phone: str | None = None,
        relationship: str | None = None,
        notes: str | None = None,
    ) -> bool:
        """Create a new person (Identity item) in 1Password.
        
        Args:
            name: Person's full name
            email: Email address (optional)
            phone: Phone number (optional)
            relationship: Relationship description (e.g., "Spouse", "Emergency Contact")
            notes: Additional notes
            
        Returns:
            True if created successfully
        """
        cmd = ["op", "item", "create"]
        cmd.extend(["--category", "Identity"])
        cmd.extend(["--title", name])
        
        # Add name fields
        name_parts = name.split(maxsplit=1)
        if len(name_parts) == 2:
            cmd.extend([f"name.first={name_parts[0]}"])
            cmd.extend([f"name.last={name_parts[1]}"])
        else:
            cmd.extend([f"name.first={name}"])
        
        # Add contact info
        if email:
            cmd.extend([f"internet.email[email]={email}"])
        
        if phone:
            cmd.extend([f"phone[phone]={phone}"])
        
        # Add relationship as a custom field in Recovery section
        if relationship:
            cmd.extend([f"Recovery.Relationship[text]={relationship}"])
        
        if notes:
            cmd.extend([f"notesPlain={notes}"])
        
        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            return True
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Error creating person: {e.stderr}[/red]")
            return False
    
    def get_recovery_contacts(self) -> list[dict]:
        """Get all people who can provide account recovery.
        
        Returns:
            List of Identity items with recovery capabilities
        """
        all_people = self.get_all_people()
        recovery_contacts = []
        
        for person in all_people:
            details = self.get_person_details(person["id"])
            if details:
                # Check if person has any recovery relationships
                has_recovery = False
                for field in details.get("fields", []):
                    section = field.get("section", {})
                    if section.get("label") == "References":
                        field_label = field.get("label", "")
                        if "recovers" in field_label or "recovered_by" in field_label:
                            has_recovery = True
                            break
                
                if has_recovery:
                    recovery_contacts.append(person)
        
        return recovery_contacts
    
    def get_recovery_network(self, person_identifier: str) -> dict[str, list[dict]]:
        """Get the recovery network for a person.
        
        Shows what accounts this person can recover and who can recover their accounts.
        
        Args:
            person_identifier: Person's name or UUID
            
        Returns:
            Dict with "can_recover" and "recovered_by" lists
        """
        from .linking import ItemLinker
        
        linker = ItemLinker()
        links = linker.get_links(person_identifier)
        
        network = {
            "can_recover": [],
            "recovered_by": [],
        }
        
        # Parse relationships
        for rel_type, targets in links.items():
            if rel_type == "recovers":
                network["can_recover"].extend(targets)
            elif rel_type == "recovered_by":
                network["recovered_by"].extend(targets)
        
        return network
    
    def format_person_info(self, person_data: dict) -> str:
        """Format person information for display.
        
        Args:
            person_data: Person details from 1Password
            
        Returns:
            Formatted string
        """
        lines = []
        lines.append(f"[cyan]{person_data.get('title', 'Unknown')}[/cyan]")
        lines.append(f"UUID: {person_data.get('id', 'Unknown')}")
        
        # Extract fields
        for field in person_data.get("fields", []):
            label = field.get("label", "")
            value = field.get("value", "")
            field_type = field.get("type", "")
            section = field.get("section", {}).get("label", "")
            
            # Skip empty fields
            if not value:
                continue
            
            # Format known fields
            if label == "email" or field_type == "EMAIL":
                lines.append(f"Email: {value}")
            elif label == "phone" or field_type == "PHONE":
                lines.append(f"Phone: {value}")
            elif section == "Recovery" and label == "Relationship":
                lines.append(f"Relationship: {value}")
        
        # Add notes if present
        notes = person_data.get("notesPlain", "")
        if notes:
            lines.append(f"\nNotes:\n{notes}")
        
        return "\n".join(lines)
    
    def list_all_people(self, include_recovery: bool = False) -> str:
        """List all people with optional recovery info.
        
        Args:
            include_recovery: Include recovery relationship counts
            
        Returns:
            Formatted list of people
        """
        people = self.get_all_people()
        
        if not people:
            return "[dim]No Identity items found[/dim]"
        
        lines = []
        lines.append(f"[cyan]Found {len(people)} people:[/cyan]\n")
        
        for person in people:
            lines.append(f"• {person['title']}")
            
            if include_recovery:
                network = self.get_recovery_network(person["id"])
                can_recover = len(network["can_recover"])
                recovered_by = len(network["recovered_by"])
                
                if can_recover > 0 or recovered_by > 0:
                    recovery_info = []
                    if can_recover > 0:
                        recovery_info.append(f"can recover {can_recover} accounts")
                    if recovered_by > 0:
                        recovery_info.append(f"recovered by {recovered_by} contacts")
                    lines.append(f"  [dim]({', '.join(recovery_info)})[/dim]")
        
        return "\n".join(lines)
    
    def show_recovery_matrix(self) -> str:
        """Generate a recovery matrix showing who can recover what.
        
        Returns:
            Formatted recovery matrix
        """
        people = self.get_all_people()
        
        if not people:
            return "[dim]No people found[/dim]"
        
        lines = []
        lines.append("[cyan]Recovery Matrix:[/cyan]\n")
        
        for person in people:
            network = self.get_recovery_network(person["id"])
            
            if network["can_recover"] or network["recovered_by"]:
                lines.append(f"\n[yellow]{person['title']}[/yellow]")
                
                if network["can_recover"]:
                    lines.append("  Can recover:")
                    for target in network["can_recover"]:
                        title = target.get("title", target.get("reference", "Unknown"))
                        lines.append(f"    • {title}")
                
                if network["recovered_by"]:
                    lines.append("  Can be recovered by:")
                    for source in network["recovered_by"]:
                        title = source.get("title", source.get("reference", "Unknown"))
                        lines.append(f"    • {title}")
        
        if len(lines) == 2:  # Only header was added
            return "[dim]No recovery relationships found[/dim]"
        
        return "\n".join(lines)
