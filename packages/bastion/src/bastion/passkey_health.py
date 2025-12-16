"""Passkey health detection and cleanup utilities.

This module provides functions to detect orphaned passkeys (where the private key
has been deleted by the 1Password CLI bug) and clean them up via JSON editing.

The orphaned passkey state occurs when:
- overview.passkey exists (public metadata: credentialId, rpId, userHandle)
- details.passkey is missing (no privateKey)

This state is caused by using `op item edit` with JSON stdin on items with passkeys.
See: bastion/support/1PASSWORD-CLI-PASSKEY-BUG.md

Detection requires the UI export JSON (not CLI JSON) because the CLI doesn't
expose passkey data at all.
"""

from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from typing import Any


def get_clipboard_json() -> dict | None:
    """Read JSON from clipboard (macOS only via pbpaste).
    
    Returns:
        Parsed JSON dict, or None if clipboard doesn't contain valid JSON
    """
    try:
        result = subprocess.run(
            ["pbpaste"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return None
        
        content = result.stdout.strip()
        if not content:
            return None
            
        return json.loads(content)
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return None


def is_passkey_healthy(export_json: dict) -> bool:
    """Check if a passkey is healthy (has both public and private key).
    
    A healthy passkey has:
    - overview.passkey (public metadata)
    - details.passkey.privateKey (the actual WebAuthn private key)
    
    Args:
        export_json: Full item export from 1Password UI (overview/details format)
        
    Returns:
        True if passkey is healthy, False if missing or orphaned
    """
    overview = export_json.get("overview", {})
    details = export_json.get("details", {})
    
    has_overview_passkey = "passkey" in overview
    has_details_passkey = "passkey" in details
    has_private_key = details.get("passkey", {}).get("privateKey") is not None
    
    # Healthy = has all three
    return has_overview_passkey and has_details_passkey and has_private_key


def is_passkey_orphaned(export_json: dict) -> bool:
    """Check if a passkey is orphaned (public key exists but private key deleted).
    
    An orphaned passkey has:
    - overview.passkey (public metadata still present)
    - details.passkey missing OR details.passkey.privateKey missing
    
    This state is created by the 1Password CLI bug where JSON editing
    deletes the passkey private key.
    
    Args:
        export_json: Full item export from 1Password UI (overview/details format)
        
    Returns:
        True if passkey is orphaned (overview exists, private key missing)
    """
    overview = export_json.get("overview", {})
    details = export_json.get("details", {})
    
    has_overview_passkey = "passkey" in overview
    has_details_passkey = "passkey" in details
    has_private_key = details.get("passkey", {}).get("privateKey") is not None
    
    # Orphaned = has overview passkey but missing private key
    return has_overview_passkey and (not has_details_passkey or not has_private_key)


def has_any_passkey(export_json: dict) -> bool:
    """Check if item has any passkey data (healthy or orphaned).
    
    Args:
        export_json: Full item export from 1Password UI (overview/details format)
        
    Returns:
        True if overview.passkey exists
    """
    overview = export_json.get("overview", {})
    return "passkey" in overview


def get_passkey_status(export_json: dict) -> str:
    """Get human-readable passkey status.
    
    Args:
        export_json: Full item export from 1Password UI (overview/details format)
        
    Returns:
        Status string: "healthy", "orphaned", or "none"
    """
    if not has_any_passkey(export_json):
        return "none"
    elif is_passkey_healthy(export_json):
        return "healthy"
    else:
        return "orphaned"


def transform_to_cli_format(export_json: dict) -> dict[str, Any]:
    """Transform UI export JSON to CLI-compatible format for editing.
    
    This transforms the 1Password UI export format (overview/details structure)
    to the CLI format (flat structure with fields array).
    
    The transformed JSON intentionally excludes passkey data, which will
    cause the passkey to be deleted when used with `op item edit`.
    
    Args:
        export_json: Full item export from 1Password UI
        
    Returns:
        CLI-compatible JSON dict ready for `op item edit` stdin
    """
    overview = export_json.get("overview", {})
    details = export_json.get("details", {})
    
    # Build CLI format
    cli_json: dict[str, Any] = {
        "title": overview.get("title", ""),
        "category": "LOGIN",
        "created_at": export_json.get("createdAt", ""),
        "updated_at": export_json.get("updatedAt", ""),
    }
    
    # Preserve tags
    if "tags" in overview:
        cli_json["tags"] = overview["tags"]
    
    # Build URLs
    url = overview.get("url")
    if url:
        cli_json["urls"] = [{
            "label": "website",
            "primary": True,
            "href": url,
        }]
    
    # Build fields from details.fields
    fields = []
    for field in details.get("fields", []):
        designation = field.get("designation", "")
        field_type = field.get("type", "T")
        value = field.get("value", "")
        
        if designation == "username":
            fields.append({
                "id": "username",
                "type": "STRING",
                "purpose": "USERNAME",
                "label": "username",
                "value": value,
            })
        elif designation == "password":
            fields.append({
                "id": "password",
                "type": "CONCEALED",
                "purpose": "PASSWORD",
                "label": "password",
                "value": value,
            })
    
    # Add notes if present
    notes = details.get("notesPlain", "")
    if notes:
        fields.append({
            "id": "notesPlain",
            "type": "STRING",
            "purpose": "NOTES",
            "label": "notesPlain",
            "value": notes,
        })
    
    if fields:
        cli_json["fields"] = fields
    
    return cli_json


def clean_orphaned_passkey_json(export_json: dict) -> dict:
    """Remove orphaned passkey structure from UI export JSON.
    
    This removes overview.passkey from the export JSON, preparing it
    for transformation and editing.
    
    Note: This modifies a copy, not the original.
    
    Args:
        export_json: Full item export from 1Password UI
        
    Returns:
        Copy of export_json with overview.passkey removed
    """
    cleaned = deepcopy(export_json)
    if "overview" in cleaned and "passkey" in cleaned["overview"]:
        del cleaned["overview"]["passkey"]
    return cleaned


def get_item_info_from_export(export_json: dict) -> dict[str, str]:
    """Extract basic item info from UI export JSON.
    
    Args:
        export_json: Full item export from 1Password UI
        
    Returns:
        Dict with uuid, title, url keys
    """
    overview = export_json.get("overview", {})
    return {
        "uuid": export_json.get("uuid", ""),
        "title": overview.get("title", "Unknown"),
        "url": overview.get("url", ""),
    }
