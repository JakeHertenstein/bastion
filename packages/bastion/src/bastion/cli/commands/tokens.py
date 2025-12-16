"""Token management operations.

Functions for adding, removing, and renumbering authenticator tokens
(Phone App, SMS, YubiKey TOTP).
"""

from __future__ import annotations

from typing import Optional

import subprocess
import typer

from ..console import console


def token_add_app(
    uuid: str,
    item_title: str,
    analyzer,  # TokenAnalyzer - avoid circular import
    validator,  # TokenValidator
    op_client,  # OpClient
    app_name: Optional[str],
    identifier: Optional[str],
    oath_name: Optional[str],
    dry_run: bool,
    skip_confirm: bool,
) -> None:
    """Add Phone App token.
    
    Args:
        uuid: 1Password item UUID
        item_title: Display title of the item
        analyzer: TokenAnalyzer instance for the item
        validator: TokenValidator instance
        op_client: OpClient instance
        app_name: App name (e.g., 'Google Authenticator')
        identifier: Unique identifier for the token
        oath_name: OATH account name (Issuer:Account format)
        dry_run: If True, show what would be done without making changes
        skip_confirm: If True, skip confirmation prompts
    """
    from rich.prompt import Confirm
    
    # Validate required options
    if not app_name:
        console.print("[red]--app is required (e.g., 'Google Authenticator', 'Authy')[/red]")
        raise typer.Exit(1)
    
    if not identifier:
        console.print("[red]--identifier is required (e.g., 'Phone-App-Google-2025')[/red]")
        raise typer.Exit(1)
    
    # Get or validate OATH name
    if not oath_name:
        oath_name = analyzer.get_oath_name()
        if not oath_name:
            console.print("[red]No existing OATH name found. Use --oath-name to specify (format: Issuer:Account)[/red]")
            raise typer.Exit(1)
        console.print(f"[dim]Using existing OATH name: {oath_name}[/dim]")
    
    # Validate token data
    is_valid, messages = validator.validate_token_data(
        "Phone App",
        identifier,
        oath_name=oath_name,
        app_name=app_name
    )
    
    if messages:
        for msg in messages:
            level = "yellow" if is_valid else "red"
            console.print(f"[{level}]{msg}[/{level}]")
    
    if not is_valid:
        raise typer.Exit(1)
    
    # Check for serial conflict
    has_conflict, conflicts = analyzer.has_serial_conflict(identifier)
    if has_conflict:
        console.print(f"[red]Serial '{identifier}' conflicts with existing token(s): {conflicts}[/red]")
        raise typer.Exit(1)
    
    # Check token count
    current_count = analyzer.count_tokens()
    level, count_msg = validator.validate_token_count(current_count + 1)
    if count_msg:
        console.print(f"[yellow]{count_msg}[/yellow]")
    
    # Get next token number
    token_num = analyzer.get_next_token_number()
    
    # Show preview
    console.print(f"\n[cyan]Add Phone App Token to: {item_title}[/cyan]")
    console.print(f"  Token {token_num}:")
    console.print(f"    Serial: {identifier}")
    console.print("    Type: Phone App")
    console.print(f"    OATH Name: {oath_name}")
    console.print(f"    App Name: {app_name}")
    
    if dry_run:
        console.print("\n[yellow]DRY RUN: No changes made[/yellow]")
        return
    
    # Confirm
    if not skip_confirm:
        if not Confirm.ask("\nAdd this token?"):
            console.print("[dim]Cancelled[/dim]")
            return
    
    # Build op edit command
    section_name = f"Token {token_num}"
    edit_fields = [
        f"{section_name}.Serial[text]={identifier}",
        f"{section_name}.Type[text]=Phone App",
        f"{section_name}.OATH Name[text]={oath_name}",
        f"{section_name}.App Name[text]={app_name}",
    ]
    
    try:
        subprocess.run(
            ["op", "item", "edit", uuid] + edit_fields,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        console.print(f"\n[green]✓ Added {section_name}[/green]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Failed to add token: {e.stderr}[/red]")
        raise typer.Exit(1)
    
    # Update tags
    try:
        # Get current tags from 1Password
        current_tags = op_client.get_current_tags(uuid)
        
        # Add type-specific tag (Bastion base tag should already exist)
        type_tag = "Bastion/2FA/TOTP/Phone-App"
        tags_to_add = [type_tag] if type_tag not in current_tags else []
        
        if tags_to_add:
            # Use assignment syntax (tags=) for proper replacement
            new_tags = current_tags + tags_to_add
            subprocess.run(
                ["op", "item", "edit", uuid, f"tags={','.join(new_tags)}"],
                check=True,
                capture_output=True,
                timeout=30,
            )
            console.print(f"[green]✓ Added tags: {', '.join(tags_to_add)}[/green]")
    except Exception as e:
        console.print(f"[yellow]⚠ Could not update tags: {e}[/yellow]")


def token_add_sms(
    uuid: str,
    item_title: str,
    analyzer,  # TokenAnalyzer
    validator,  # TokenValidator
    op_client,  # OpClient
    phone_number: Optional[str],
    carrier_name: Optional[str],
    identifier: Optional[str],
    dry_run: bool,
    skip_confirm: bool,
) -> None:
    """Add SMS token.
    
    Args:
        uuid: 1Password item UUID
        item_title: Display title of the item
        analyzer: TokenAnalyzer instance for the item
        validator: TokenValidator instance
        op_client: OpClient instance
        phone_number: Phone number for SMS
        carrier_name: Carrier name (e.g., 'Verizon')
        identifier: Optional unique identifier (auto-generated if not provided)
        dry_run: If True, show what would be done without making changes
        skip_confirm: If True, skip confirmation prompts
    """
    from rich.prompt import Confirm
    
    # Validate required options
    if not phone_number:
        console.print("[red]--phone is required[/red]")
        raise typer.Exit(1)
    
    if not carrier_name:
        console.print("[red]--carrier is required (e.g., 'Verizon', 'AT&T')[/red]")
        raise typer.Exit(1)
    
    # Auto-generate identifier if not provided
    if not identifier:
        # Extract last 4 digits from phone number
        digits = ''.join(c for c in phone_number if c.isdigit())
        if len(digits) >= 4:
            identifier = f"SMS-{digits[-4:]}"
        else:
            identifier = f"SMS-{digits}"
        console.print(f"[dim]Auto-generated identifier: {identifier}[/dim]")
    
    # Validate token data
    is_valid, messages = validator.validate_token_data(
        "SMS",
        identifier,
        phone_number=phone_number,
        carrier_name=carrier_name
    )
    
    if messages:
        for msg in messages:
            level = "yellow" if is_valid else "red"
            console.print(f"[{level}]{msg}[/{level}]")
    
    if not is_valid:
        raise typer.Exit(1)
    
    # Check for serial conflict
    has_conflict, conflicts = analyzer.has_serial_conflict(identifier)
    if has_conflict:
        console.print(f"[red]Serial '{identifier}' conflicts with existing token(s): {conflicts}[/red]")
        console.print("[yellow]Use --identifier to specify a different identifier[/yellow]")
        raise typer.Exit(1)
    
    # Check token count
    current_count = analyzer.count_tokens()
    level, count_msg = validator.validate_token_count(current_count + 1)
    if count_msg:
        console.print(f"[yellow]{count_msg}[/yellow]")
    
    # Get next token number
    token_num = analyzer.get_next_token_number()
    
    # Show preview
    console.print(f"\n[cyan]Add SMS Token to: {item_title}[/cyan]")
    console.print(f"  Token {token_num}:")
    console.print(f"    Serial: {identifier}")
    console.print("    Type: SMS")
    console.print(f"    Phone Number: {phone_number}")
    console.print(f"    Carrier Name: {carrier_name}")
    
    if dry_run:
        console.print("\n[yellow]DRY RUN: No changes made[/yellow]")
        return
    
    # Confirm
    if not skip_confirm:
        if not Confirm.ask("\nAdd this token?"):
            console.print("[dim]Cancelled[/dim]")
            return
    
    # Build op edit command
    section_name = f"Token {token_num}"
    edit_fields = [
        f"{section_name}.Serial[text]={identifier}",
        f"{section_name}.Type[text]=SMS",
        f"{section_name}.Phone Number[phone]={phone_number}",
        f"{section_name}.Carrier Name[text]={carrier_name}",
    ]
    
    try:
        subprocess.run(
            ["op", "item", "edit", uuid] + edit_fields,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        console.print(f"\n[green]✓ Added {section_name}[/green]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Failed to add token: {e.stderr}[/red]")
        raise typer.Exit(1)
    
    # Update tags
    try:
        # Get current tags from 1Password
        current_tags = op_client.get_current_tags(uuid)
        
        # Add type-specific tag (Bastion base tag should already exist)
        type_tag = "Bastion/2FA/TOTP/SMS"
        tags_to_add = [type_tag] if type_tag not in current_tags else []
        
        if tags_to_add:
            # Use assignment syntax (tags=) for proper replacement
            new_tags = current_tags + tags_to_add
            subprocess.run(
                ["op", "item", "edit", uuid, f"tags={','.join(new_tags)}"],
                check=True,
                capture_output=True,
                timeout=30,
            )
            console.print(f"[green]✓ Added tags: {', '.join(tags_to_add)}[/green]")
    except Exception as e:
        console.print(f"[yellow]⚠ Could not update tags: {e}[/yellow]")


def token_remove(
    uuid: str,
    item_title: str,
    analyzer,  # TokenAnalyzer
    op_client,  # OpClient
    token_number: Optional[int],
    renumber: bool,
    dry_run: bool,
    skip_confirm: bool,
) -> None:
    """Remove token by number.
    
    Args:
        uuid: 1Password item UUID
        item_title: Display title of the item
        analyzer: TokenAnalyzer instance for the item
        op_client: OpClient instance
        token_number: Token number to remove
        renumber: If True, renumber remaining tokens after removal
        dry_run: If True, show what would be done without making changes
        skip_confirm: If True, skip confirmation prompts
    """
    from rich.prompt import Confirm
    from bastion.token_analyzer import TokenAnalyzer
    
    # Validate token number
    if token_number is None:
        console.print("[red]Token number is required[/red]")
        console.print("Example: bastion token remove <UUID> 2")
        raise typer.Exit(1)
    
    # Check if token exists
    if not analyzer.has_token_number(token_number):
        console.print(f"[red]Token {token_number} not found[/red]")
        console.print("\nAvailable tokens:")
        tokens = analyzer.get_tokens()
        for num in sorted(tokens.keys()):
            console.print(f"  {analyzer.format_token_summary(num, tokens[num])}")
        raise typer.Exit(1)
    
    # Get token data
    token_data = analyzer.get_token(token_number)
    token_type = token_data.get("Type", "Unknown")
    
    # Show preview
    console.print(f"\n[cyan]Remove Token from: {item_title}[/cyan]")
    console.print(f"  {analyzer.format_token_summary(token_number, token_data)}")
    
    # Check if last token of type
    token_counts = analyzer.count_tokens_by_type()
    if token_counts.get(token_type, 0) == 1:
        console.print(f"\n[yellow]⚠ This is the last {token_type} token[/yellow]")
    
    if dry_run:
        console.print("\n[yellow]DRY RUN: No changes made[/yellow]")
        if renumber and not analyzer.is_sequential():
            console.print("[dim]Would renumber tokens after removal[/dim]")
        return
    
    # Confirm
    if not skip_confirm:
        if not Confirm.ask("\nRemove this token?"):
            console.print("[dim]Cancelled[/dim]")
            return
    
    # Delete token fields
    section_name = f"Token {token_number}"
    all_possible_fields = [
        "Serial", "Type", "OATH Name", "TOTP Enabled", "PassKey Enabled",
        "App Name", "Phone Number", "Carrier Name", "Device Name",
        "Protocol", "Resident Keys", "Device Model", "Token ID",
        "Expiration Date", "Biometric Type"
    ]
    
    delete_fields = [f"{section_name}.{field}[delete]" for field in all_possible_fields]
    
    try:
        subprocess.run(
            ["op", "item", "edit", uuid] + delete_fields,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        console.print(f"\n[green]✓ Removed {section_name}[/green]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Failed to remove token: {e.stderr}[/red]")
        raise typer.Exit(1)
    
    # Update tags (check if we need to remove type-specific tag)
    try:
        # Re-fetch to get updated token list
        item_data_updated = op_client.get_item(uuid)
        if item_data_updated:
            analyzer_updated = TokenAnalyzer(item_data_updated)
            token_counts = analyzer_updated.count_tokens_by_type()
            
            # If no more tokens of this type, remove the type-specific tag
            if token_counts.get(token_type, 0) == 0:
                current_tags = op_client.get_current_tags(uuid)
                tag_map = {
                    "YubiKey": "Bastion/2FA/TOTP/YubiKey",
                    "Phone App": "Bastion/2FA/TOTP/Phone-App",
                    "SMS": "Bastion/2FA/TOTP/SMS",
                }
                tag_to_remove = tag_map.get(token_type)
                
                if tag_to_remove and tag_to_remove in current_tags:
                    new_tags = [t for t in current_tags if t != tag_to_remove]
                    # Use assignment syntax (tags=) for proper replacement
                    subprocess.run(
                        ["op", "item", "edit", uuid, f"tags={','.join(new_tags)}"],
                        check=True,
                        capture_output=True,
                        timeout=30,
                    )
                    console.print(f"[green]✓ Removed tag: {tag_to_remove}[/green]")
    except Exception as e:
        console.print(f"[yellow]⚠ Could not update tags: {e}[/yellow]")
    
    # Renumber if requested
    if renumber:
        # Re-fetch item and analyzer
        item_data = op_client.get_item(uuid)
        if item_data:
            new_analyzer = TokenAnalyzer(item_data)
            if not new_analyzer.is_sequential():
                console.print("\n[cyan]Renumbering tokens...[/cyan]")
                token_renumber(uuid, item_title, new_analyzer, op_client, dry_run=False, skip_confirm=True)


def token_renumber(
    uuid: str,
    item_title: str,
    analyzer,  # TokenAnalyzer
    op_client,  # OpClient
    dry_run: bool,
    skip_confirm: bool,
) -> None:
    """Renumber tokens to close gaps.
    
    Args:
        uuid: 1Password item UUID
        item_title: Display title of the item
        analyzer: TokenAnalyzer instance for the item
        op_client: OpClient instance
        dry_run: If True, show what would be done without making changes
        skip_confirm: If True, skip confirmation prompts
    """
    from rich.prompt import Confirm
    
    # Check if already sequential
    if analyzer.is_sequential():
        console.print("[green]Tokens are already numbered sequentially[/green]")
        return
    
    tokens = analyzer.get_tokens()
    if not tokens:
        console.print("[yellow]No tokens to renumber[/yellow]")
        return
    
    # Show preview
    console.print(f"\n[cyan]Renumber Tokens in: {item_title}[/cyan]")
    console.print(f"  Current: Token {', Token '.join(str(n) for n in sorted(tokens.keys()))}")
    console.print(f"  After:   Token {', Token '.join(str(n) for n in range(1, len(tokens) + 1))}")
    
    gaps = analyzer.detect_gaps()
    if gaps:
        console.print(f"  [dim]Closing gaps: {gaps}[/dim]")
    
    if dry_run:
        console.print("\n[yellow]DRY RUN: No changes made[/yellow]")
        return
    
    # Confirm
    if not skip_confirm:
        if not Confirm.ask("\nRenumber tokens?"):
            console.print("[dim]Cancelled[/dim]")
            return
    
    # Step 1: Read all token data
    token_data_list = [(num, tokens[num]) for num in sorted(tokens.keys())]
    
    # Step 2: Delete all existing tokens
    all_possible_fields = [
        "Serial", "Type", "OATH Name", "TOTP Enabled", "PassKey Enabled",
        "App Name", "Phone Number", "Carrier Name", "Device Name",
        "Protocol", "Resident Keys", "Device Model", "Token ID",
        "Expiration Date", "Biometric Type"
    ]
    
    delete_fields = []
    for old_num, _ in token_data_list:
        section_name = f"Token {old_num}"
        delete_fields.extend([f"{section_name}.{field}[delete]" for field in all_possible_fields])
    
    try:
        subprocess.run(
            ["op", "item", "edit", uuid] + delete_fields,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Failed to delete old tokens: {e.stderr}[/red]")
        console.print("[yellow]Manual recovery may be needed[/yellow]")
        raise typer.Exit(1)
    
    # Step 3: Create new sequential tokens
    for new_num, (old_num, token_data) in enumerate(token_data_list, start=1):
        section_name = f"Token {new_num}"
        edit_fields = []
        
        for field_name, field_value in token_data.items():
            if field_value:  # Only add non-empty fields
                # Determine field type
                field_type = "phone" if field_name == "Phone Number" else "text"
                edit_fields.append(f"{section_name}.{field_name}[{field_type}]={field_value}")
        
        if edit_fields:
            try:
                subprocess.run(
                    ["op", "item", "edit", uuid] + edit_fields,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
            except subprocess.CalledProcessError as e:
                console.print(f"[red]Failed to create {section_name}: {e.stderr}[/red]")
                console.print("[yellow]Manual recovery needed[/yellow]")
                raise typer.Exit(1)
    
    console.print(f"\n[green]✓ Renumbered {len(token_data_list)} tokens[/green]")


def add_token_to_account(
    uuid: str,
    token_type: str,  # "app" or "sms"
    app: str | None = None,
    identifier: str | None = None,
    oath_name: str | None = None,
    phone: str | None = None,
    carrier: str | None = None,
    dry_run: bool = False,
    yes: bool = False,
) -> None:
    """Add a token to an account.
    
    Args:
        uuid: Account UUID or title
        token_type: "app" or "sms"
        app: App name for Phone App tokens
        identifier: Unique identifier for token
        oath_name: OATH account name
        phone: Phone number for SMS tokens
        carrier: Carrier name for SMS tokens
        dry_run: Show what would be done
        yes: Skip confirmation
    """
    import typer
    from bastion.op_client import OpClient
    from bastion.token_analyzer import TokenAnalyzer
    from bastion.token_validator import TokenValidator
    from .tags import resolve_account_identifier
    
    # Initialize clients
    op_client = OpClient()
    validator = TokenValidator()
    
    # Resolve identifier to UUID
    uuid_resolved = resolve_account_identifier(uuid, op_client)
    
    # Fetch item
    item_data = op_client.get_item(uuid_resolved)
    if not item_data:
        console.print(f"[red]Account not found: {uuid_resolved}[/red]")
        raise typer.Exit(1)
    
    item_title = item_data.get("title", "Unknown")
    analyzer = TokenAnalyzer(item_data)
    
    # Route to token type handler
    if token_type == "app":
        token_add_app(uuid_resolved, item_title, analyzer, validator, op_client, app, identifier, oath_name, dry_run, yes)
    elif token_type == "sms":
        token_add_sms(uuid_resolved, item_title, analyzer, validator, op_client, phone, carrier, identifier, dry_run, yes)


def remove_token_from_account(
    uuid: str,
    token_number: int,
    renumber: bool = False,
    dry_run: bool = False,
    yes: bool = False,
) -> None:
    """Remove a token from an account.
    
    Args:
        uuid: Account UUID or title
        token_number: Token number to remove
        renumber: Renumber remaining tokens after removal
        dry_run: Show what would be done
        yes: Skip confirmation
    """
    import typer
    from bastion.op_client import OpClient
    from bastion.token_analyzer import TokenAnalyzer
    from .tags import resolve_account_identifier
    
    # Initialize clients
    op_client = OpClient()
    
    # Resolve identifier to UUID
    uuid_resolved = resolve_account_identifier(uuid, op_client)
    
    # Fetch item
    item_data = op_client.get_item(uuid_resolved)
    if not item_data:
        console.print(f"[red]Account not found: {uuid_resolved}[/red]")
        raise typer.Exit(1)
    
    item_title = item_data.get("title", "Unknown")
    analyzer = TokenAnalyzer(item_data)
    
    token_remove(uuid_resolved, item_title, analyzer, op_client, token_number, renumber, dry_run, yes)


def renumber_tokens_on_account(
    uuid: str,
    dry_run: bool = False,
    yes: bool = False,
) -> None:
    """Renumber tokens on an account to close gaps.
    
    Args:
        uuid: Account UUID or title
        dry_run: Show what would be done
        yes: Skip confirmation
    """
    import typer
    from bastion.op_client import OpClient
    from bastion.token_analyzer import TokenAnalyzer
    from .tags import resolve_account_identifier
    
    # Initialize clients
    op_client = OpClient()
    
    # Resolve identifier to UUID
    uuid_resolved = resolve_account_identifier(uuid, op_client)
    
    # Fetch item
    item_data = op_client.get_item(uuid_resolved)
    if not item_data:
        console.print(f"[red]Account not found: {uuid_resolved}[/red]")
        raise typer.Exit(1)
    
    item_title = item_data.get("title", "Unknown")
    analyzer = TokenAnalyzer(item_data)
    
    token_renumber(uuid_resolved, item_title, analyzer, op_client, dry_run, yes)
