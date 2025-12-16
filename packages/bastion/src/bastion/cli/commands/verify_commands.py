"""Verify commands for Bastion CLI.

Provides verification of generated credentials.

Usage:
    bastion verify username github.com h7x2k9m4p8q3n1r5
    bastion verify username --label "Bastion/USER/SHA2/512:..." h7x2k9m4p8q3n1r5
"""

from __future__ import annotations

from typing import Annotated, Optional

import typer
from rich.console import Console

from ...username_generator import (
    UsernameGenerator,
    UsernameGeneratorConfig,
    LabelParser,
)
from ...label_spec import decode_params

console = Console()


def register_commands(app: typer.Typer) -> None:
    """Register verify-related commands with the app."""
    
    @app.command("verify")
    def verify_command(
        noun: Annotated[str, typer.Argument(help="Type to verify: 'username'")],
        identifier: Annotated[str, typer.Argument(help="Domain or full label to verify against")],
        value: Annotated[str, typer.Argument(help="Value to verify (e.g., username)")],
        label: Annotated[Optional[str], typer.Option("--label", "-l", help="Full label (if not inferring from domain)")] = None,
        salt_uuid: Annotated[Optional[str], typer.Option("--salt-uuid", help="Specific salt UUID to use")] = None,
        quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Only output exit code, no text")] = False,
    ) -> None:
        """Verify generated credentials match their source.
        
        Username verification:
          bastion verify username github.com h7x2k9m4p8q3n1r5
          bastion verify username --label "Bastion/USER/SHA2/512:github.com:2025-11-30#..." h7x2k9m4p8q3n1r5
        
        Exit codes:
          0 = Match verified
          1 = No match (mismatch or error)
        """
        if noun.lower() == "username":
            _verify_username(identifier, value, label, salt_uuid, quiet)
        else:
            if not quiet:
                console.print(f"[red]Error:[/red] Unknown verification type '{noun}'")
                console.print("Supported types: username")
            raise typer.Exit(1)


def _verify_username(
    identifier: str,
    username: str,
    full_label: Optional[str],
    salt_uuid: Optional[str],
    quiet: bool,
) -> None:
    """Verify a username against its label.
    
    Args:
        identifier: Domain name or ignored if full_label provided
        username: Username to verify
        full_label: Optional full label string
        salt_uuid: Optional specific salt UUID
        quiet: Suppress output, only use exit code
    """
    try:
        # Load config
        config = UsernameGeneratorConfig()
        generator = UsernameGenerator(config=config)
        
        # Determine the label to use
        if full_label:
            label = full_label
        else:
            # We need to look up the label from 1Password
            # For now, try to find an item with this domain
            if not quiet:
                console.print(f"[cyan]Looking up label for domain '{identifier}'...[/cyan]")
            
            # Search 1Password for items with this domain
            label = _lookup_label_for_domain(identifier)
            
            if not label:
                if not quiet:
                    console.print(f"[red]Error:[/red] No label found for domain '{identifier}'")
                    console.print("[dim]Use --label to provide the full label directly[/dim]")
                raise typer.Exit(1)
        
        # Parse label to extract nonce and encoding if present
        parser = LabelParser(label)
        if not parser.is_valid():
            if not quiet:
                console.print(f"[red]Error:[/red] Invalid label format: {label}")
            raise typer.Exit(1)
        
        # Extract nonce and encoding from params via internal BastionLabel
        nonce: Optional[str] = None
        encoding = 36
        
        if parser._bastion_label and parser._bastion_label.params:
            params = decode_params(parser._bastion_label.params)
            nonce_val = params.get('nonce')
            if isinstance(nonce_val, str):
                nonce = nonce_val
            if 'encoding' in params:
                try:
                    encoding = int(params['encoding'])
                except (ValueError, TypeError):
                    pass
        
        # Verify
        is_valid = generator.verify(label, username, salt_uuid, nonce, encoding)
        
        if is_valid:
            if not quiet:
                console.print("[green]✅ Verified:[/green] Username matches label")
                console.print(f"[dim]Username: {username}[/dim]")
                console.print(f"[dim]Label: {label}[/dim]")
            raise typer.Exit(0)
        else:
            if not quiet:
                console.print("[red]✗ Mismatch:[/red] Username does NOT match label")
                console.print(f"[dim]Username: {username}[/dim]")
                console.print(f"[dim]Label: {label}[/dim]")
                console.print("[dim]Check: correct domain? correct salt? correct date?[/dim]")
            raise typer.Exit(1)
            
    except RuntimeError as e:
        if not quiet:
            console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


def _lookup_label_for_domain(domain: str) -> Optional[str]:
    """Look up a label from 1Password for the given domain.
    
    Args:
        domain: Domain to search for
        
    Returns:
        Label string if found, None otherwise
    """
    import subprocess
    import json
    import re
    
    # Normalize domain
    clean_domain = re.sub(r'^https?://(www\.)?', '', domain)
    clean_domain = clean_domain.rstrip('/')
    
    try:
        # Search for items with Bastion/USER tag
        result = subprocess.run(
            ["op", "item", "list", "--tags", "Bastion/USER", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        
        items = json.loads(result.stdout)
        
        # Search for matching domain in titles or fields
        for item in items:
            # Check title
            title = item.get("title", "").lower()
            if clean_domain.lower() in title:
                # Get the full item to find the label
                return _get_label_from_item(item.get("id"))
        
        # If not found by title, check notes/fields
        for item in items:
            label = _get_label_from_item(item.get("id"))
            if label and f":{clean_domain}:" in label.lower():
                return label
        
        return None
        
    except subprocess.CalledProcessError:
        return None
    except json.JSONDecodeError:
        return None


def _get_label_from_item(item_id: str) -> Optional[str]:
    """Get the Bastion label from a 1Password item.
    
    Args:
        item_id: 1Password item UUID
        
    Returns:
        Label string if found, None otherwise
    """
    import subprocess
    import json
    
    if not item_id:
        return None
    
    try:
        result = subprocess.run(
            ["op", "item", "get", item_id, "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        
        item = json.loads(result.stdout)
        
        # Look for label in fields
        fields = item.get("fields", [])
        for field in fields:
            label = field.get("label", "")
            if label == "username_label" or label == "bastion_label":
                return field.get("value")
        
        # Check notes section
        notes_field = next((f for f in fields if f.get("id") == "notesPlain"), None)
        if notes_field:
            notes = notes_field.get("value", "")
            # Look for Bastion label format in notes
            import re
            match = re.search(r'(Bastion/USER/[^\s]+)', notes)
            if match:
                return match.group(1)
        
        return None
        
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return None
