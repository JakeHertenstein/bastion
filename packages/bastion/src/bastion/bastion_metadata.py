"""Bastion Metadata management for 1Password items.

This module provides structured metadata tracking for closed-loop risk management.
Adds a standardized "Bastion Metadata" section to login items with date/event tracking.
"""

import subprocess
import json
from dataclasses import dataclass
from datetime import date
from typing import Optional


@dataclass
class BastionMetadata:
    """Structured metadata for security analysis tracking."""
    
    # Password Management
    password_changed: Optional[str] = None  # YYYY-MM-DD
    password_expires: Optional[str] = None  # YYYY-MM-DD
    password_rotation_policy: Optional[str] = None  # "90d", "180d", "365d", "manual"
    
    # Username Management
    username_changed: Optional[str] = None  # YYYY-MM-DD
    username_type: Optional[str] = None  # "generated", "manual"
    
    # 2FA/TOTP Management
    totp_seed_issued: Optional[str] = None  # YYYY-MM-DD
    totp_seed_expires: Optional[str] = None  # YYYY-MM-DD
    totp_seed_changed: Optional[str] = None  # YYYY-MM-DD
    twofa_method_changed: Optional[str] = None  # YYYY-MM-DD
    
    # Security Events
    last_security_review: Optional[str] = None  # YYYY-MM-DD
    breach_detected: Optional[str] = None  # YYYY-MM-DD
    breach_remediated: Optional[str] = None  # YYYY-MM-DD
    
    # Account Lifecycle
    account_created: Optional[str] = None  # YYYY-MM-DD
    last_activity: Optional[str] = None  # YYYY-MM-DD
    
    # Recovery & Access
    recovery_email_changed: Optional[str] = None  # YYYY-MM-DD
    recovery_phone_changed: Optional[str] = None  # YYYY-MM-DD
    backup_codes_generated: Optional[str] = None  # YYYY-MM-DD
    
    # Risk Scoring
    risk_level: Optional[str] = None  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    risk_score: Optional[str] = None  # Numeric score as string
    risk_last_calculated: Optional[str] = None  # YYYY-MM-DD
    
    # Monitoring
    next_review_due: Optional[str] = None  # YYYY-MM-DD
    next_rotation_due: Optional[str] = None  # YYYY-MM-DD
    
    # Notes
    bastion_notes: Optional[str] = None  # Free-form security notes


def add_bastion_metadata(uuid: str, metadata: BastionMetadata) -> bool:
    """Add or update Bastion Metadata section in a 1Password item.
    
    Args:
        uuid: 1Password item UUID
        metadata: BastionMetadata object with fields to set
        
    Returns:
        True if successful, False otherwise
    """
    edit_fields = []
    
    # Build edit command fields for non-None values
    if metadata.password_changed:
        edit_fields.append(f"Bastion Metadata.Password Changed[date]={metadata.password_changed}")
    if metadata.password_expires:
        edit_fields.append(f"Bastion Metadata.Password Expires[date]={metadata.password_expires}")
    if metadata.password_rotation_policy:
        edit_fields.append(f"Bastion Metadata.Password Rotation Policy[text]={metadata.password_rotation_policy}")
    
    if metadata.username_changed:
        edit_fields.append(f"Bastion Metadata.Username Changed[date]={metadata.username_changed}")
    if metadata.username_type:
        edit_fields.append(f"Bastion Metadata.Username Type[text]={metadata.username_type}")
    
    if metadata.totp_seed_issued:
        edit_fields.append(f"Bastion Metadata.TOTP Seed Issued[date]={metadata.totp_seed_issued}")
    if metadata.totp_seed_expires:
        edit_fields.append(f"Bastion Metadata.TOTP Seed Expires[date]={metadata.totp_seed_expires}")
    if metadata.totp_seed_changed:
        edit_fields.append(f"Bastion Metadata.TOTP Seed Changed[date]={metadata.totp_seed_changed}")
    if metadata.twofa_method_changed:
        edit_fields.append(f"Bastion Metadata.2FA Method Changed[date]={metadata.twofa_method_changed}")
    
    if metadata.last_security_review:
        edit_fields.append(f"Bastion Metadata.Last Security Review[date]={metadata.last_security_review}")
    if metadata.breach_detected:
        edit_fields.append(f"Bastion Metadata.Breach Detected[date]={metadata.breach_detected}")
    if metadata.breach_remediated:
        edit_fields.append(f"Bastion Metadata.Breach Remediated[date]={metadata.breach_remediated}")
    
    if metadata.account_created:
        edit_fields.append(f"Bastion Metadata.Account Created[date]={metadata.account_created}")
    if metadata.last_activity:
        edit_fields.append(f"Bastion Metadata.Last Activity[date]={metadata.last_activity}")
    
    if metadata.recovery_email_changed:
        edit_fields.append(f"Bastion Metadata.Recovery Email Changed[date]={metadata.recovery_email_changed}")
    if metadata.recovery_phone_changed:
        edit_fields.append(f"Bastion Metadata.Recovery Phone Changed[date]={metadata.recovery_phone_changed}")
    if metadata.backup_codes_generated:
        edit_fields.append(f"Bastion Metadata.Backup Codes Generated[date]={metadata.backup_codes_generated}")
    
    if metadata.risk_level:
        edit_fields.append(f"Bastion Metadata.Risk Level[text]={metadata.risk_level}")
    if metadata.risk_score:
        edit_fields.append(f"Bastion Metadata.Risk Score[text]={metadata.risk_score}")
    if metadata.risk_last_calculated:
        edit_fields.append(f"Bastion Metadata.Risk Last Calculated[date]={metadata.risk_last_calculated}")
    
    if metadata.next_review_due:
        edit_fields.append(f"Bastion Metadata.Next Review Due[date]={metadata.next_review_due}")
    if metadata.next_rotation_due:
        edit_fields.append(f"Bastion Metadata.Next Rotation Due[date]={metadata.next_rotation_due}")
    
    if metadata.bastion_notes:
        # Escape special characters in notes
        notes_escaped = metadata.bastion_notes.replace('"', '\\"')
        edit_fields.append(f'Bastion Metadata.Bastion Notes[text]={notes_escaped}')
    
    if not edit_fields:
        return False  # Nothing to update
    
    try:
        subprocess.run(
            ["op", "item", "edit", uuid] + edit_fields,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def get_bastion_metadata(uuid: str) -> Optional[BastionMetadata]:
    """Retrieve Bastion Metadata from a 1Password item.
    
    Args:
        uuid: 1Password item UUID
        
    Returns:
        BastionMetadata object if found, None otherwise
    """
    try:
        result = subprocess.run(
            ["op", "item", "get", uuid, "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        
        item_data = json.loads(result.stdout)
        fields = item_data.get("fields", [])
        
        # Extract Bastion Metadata section fields
        metadata = BastionMetadata()
        
        for field in fields:
            section = field.get("section", {})
            if section.get("label") != "Bastion Metadata":
                continue
            
            label = field.get("label", "")
            value = field.get("value", "")
            
            # Map field labels to metadata attributes
            if label == "Password Changed":
                metadata.password_changed = value
            elif label == "Password Expires":
                metadata.password_expires = value
            elif label == "Password Rotation Policy":
                metadata.password_rotation_policy = value
            elif label == "Username Changed":
                metadata.username_changed = value
            elif label == "Username Type":
                metadata.username_type = value
            elif label == "TOTP Seed Issued":
                metadata.totp_seed_issued = value
            elif label == "TOTP Seed Expires":
                metadata.totp_seed_expires = value
            elif label == "TOTP Seed Changed":
                metadata.totp_seed_changed = value
            elif label == "2FA Method Changed":
                metadata.twofa_method_changed = value
            elif label == "Last Security Review":
                metadata.last_security_review = value
            elif label == "Breach Detected":
                metadata.breach_detected = value
            elif label == "Breach Remediated":
                metadata.breach_remediated = value
            elif label == "Account Created":
                metadata.account_created = value
            elif label == "Last Activity":
                metadata.last_activity = value
            elif label == "Recovery Email Changed":
                metadata.recovery_email_changed = value
            elif label == "Recovery Phone Changed":
                metadata.recovery_phone_changed = value
            elif label == "Backup Codes Generated":
                metadata.backup_codes_generated = value
            elif label == "Risk Level":
                metadata.risk_level = value
            elif label == "Risk Score":
                metadata.risk_score = value
            elif label == "Risk Last Calculated":
                metadata.risk_last_calculated = value
            elif label == "Next Review Due":
                metadata.next_review_due = value
            elif label == "Next Rotation Due":
                metadata.next_rotation_due = value
            elif label == "Bastion Notes":
                metadata.bastion_notes = value
        
        return metadata
        
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return None


def update_bastion_metadata(uuid: str, **kwargs) -> bool:
    """Update specific Bastion Metadata fields.
    
    Args:
        uuid: 1Password item UUID
        **kwargs: Field names and values to update
        
    Returns:
        True if successful, False otherwise
        
    Example:
        update_bastion_metadata(uuid, password_changed="2025-11-27", risk_level="MEDIUM")
    """
    # Get existing metadata
    existing = get_bastion_metadata(uuid) or BastionMetadata()
    
    # Update with provided kwargs
    for key, value in kwargs.items():
        if hasattr(existing, key):
            setattr(existing, key, value)
    
    return add_bastion_metadata(uuid, existing)


def today() -> str:
    """Get today's date in YYYY-MM-DD format."""
    return date.today().isoformat()
