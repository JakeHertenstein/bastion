"""YubiKey-related pure utility functions.

These functions handle token field parsing and OATH name generation
without any CLI dependencies (no console output, no typer).
"""

from __future__ import annotations

from urllib.parse import urlparse


def generate_unique_oath_name(
    title: str,
    username: str | None,
    vault: str,
    website: str | None,
    uuid: str,
    existing_names: list[str],
) -> tuple[str, str]:
    """
    Generate unique OATH name optimized for Yubico Authenticator icon matching.
    
    Character limits: issuer=20 (clean title for icon matching), account=54
    
    Issuer: Clean title only (e.g., "1Password", "Google") - kept short for icon matching
    Account: "username (https://domain)" format for disambiguation
    
    Tries in order:
    1. Title:username (https://domain)
    2. Title:username (domain)
    3. Title:username
    4. Title:username [UUID-short]
    
    Returns: (issuer, account) tuple
    """
    # Helper to truncate with limit
    def truncate(s: str, limit: int) -> str:
        return s[:limit] if s else ""
    
    # Issuer: Clean title only (20 char limit for icon matching)
    issuer = truncate(title, 20)
    
    # Account base: username
    username_part = username if username else "user"
    
    # Try 1: username (https://domain) - full URL for best disambiguation
    if website:
        try:
            # Clean URL: remove trailing slashes, fragments
            clean_url = website.rstrip('/').split('#')[0].split('?')[0]
            full_account = f"{username_part} ({clean_url})"
            
            if len(full_account) <= 54:
                candidate = f"{issuer}:{full_account}"
                if candidate not in existing_names:
                    return issuer, full_account
            else:
                # URL too long, try truncating protocol and path
                parsed = urlparse(clean_url)
                simple_url = f"https://{parsed.netloc}"
                full_account = f"{username_part} ({simple_url})"
                
                if len(full_account) <= 54:
                    candidate = f"{issuer}:{full_account}"
                    if candidate not in existing_names:
                        return issuer, full_account
        except Exception:
            pass
    
    # Try 2: username (domain) - domain only if URL didn't fit
    if website:
        try:
            domain = urlparse(website).netloc.replace("www.", "")
            account_with_domain = f"{username_part} ({domain})"
            
            if len(account_with_domain) <= 54:
                candidate = f"{issuer}:{account_with_domain}"
                if candidate not in existing_names:
                    return issuer, account_with_domain
            else:
                # Domain still too long, truncate username intelligently
                domain_space = len(domain) + 3  # 3 for " ()"
                username_max = 54 - domain_space
                if username_max > 5:
                    truncated_username = username_part[:username_max]
                    account_with_domain = f"{truncated_username} ({domain})"
                    candidate = f"{issuer}:{account_with_domain}"
                    if candidate not in existing_names:
                        return issuer, account_with_domain
        except Exception:
            pass
    
    # Try 3: username only (simple fallback)
    account_simple = truncate(username_part, 54)
    candidate = f"{issuer}:{account_simple}"
    if candidate not in existing_names:
        return issuer, account_simple
    
    # Try 4: username [UUID-short] (guaranteed unique)
    uuid_short = uuid[:6]
    account_with_uuid = truncate(f"{username_part} [{uuid_short}]", 54)
    return issuer, account_with_uuid


def get_yubikey_field(item_data: dict, field_name: str, section_name: str | None = None) -> str | None:
    """Get authenticator token field value from Token sections or old flat format.
    
    Supports three formats for backward compatibility:
    1. New Token N sections (e.g., "Token 1", "Token 2") with type-specific fields
    2. Legacy Tokens section with token_N fields
    3. Old flat custom fields (yubikey_oath_name, yubikey_serials)
    
    Args:
        item_data: Full 1Password item data
        field_name: Field name to retrieve (e.g., "oath_name", "serials", "tokens")
        section_name: Deprecated - kept for backward compatibility
        
    Returns:
        Field value string or None if not found
        For "serials"/"tokens", returns comma-separated list from Token sections
    """
    fields = item_data.get("fields", [])
    
    # Special handling for "serials" or "tokens" - aggregate from Token N sections
    if field_name in ["serials", "tokens"]:
        # Try new Token N sections first
        token_serials = {}
        for field in fields:
            section = field.get("section", {})
            section_label = section.get("label", "") if section else ""
            field_label = field.get("label", "")
            
            if section_label.startswith("Token "):
                try:
                    token_num = int(section_label.split(" ")[1])
                    if field_label == "Serial":
                        token_serials[token_num] = field.get("value", "")
                except (IndexError, ValueError):
                    pass
        
        if token_serials:
            # Return serials in order
            return ",".join([token_serials[i] for i in sorted(token_serials.keys())])
        
        # Fall back to legacy Tokens section with token_N fields
        legacy_tokens = {}
        for field in fields:
            section = field.get("section", {})
            section_label = section.get("label", "") if section else ""
            field_label = field.get("label", "")
            
            if section_label == "Tokens" and field_label.startswith("token_"):
                try:
                    token_num = int(field_label.split("_")[1])
                    legacy_tokens[token_num] = field.get("value", "")
                except (IndexError, ValueError):
                    pass
        
        if legacy_tokens:
            return ",".join([legacy_tokens[i] for i in sorted(legacy_tokens.keys())])
        
        # Fall back to old yubikey_serials CSV field
        field_name = "serials"
    
    # Special handling for "oath_name" - get from first Token section with OATH Name
    if field_name == "oath_name":
        # Try Token N sections (YubiKey or Phone App types have OATH Name)
        token_sections = {}
        for field in fields:
            section = field.get("section", {})
            section_label = section.get("label", "") if section else ""
            field_label = field.get("label", "")
            
            if section_label.startswith("Token "):
                try:
                    token_num = int(section_label.split(" ")[1])
                    if token_num not in token_sections:
                        token_sections[token_num] = {}
                    if field_label in ["OATH Name", "Type"]:
                        token_sections[token_num][field_label] = field.get("value", "")
                except (IndexError, ValueError):
                    pass
        
        # Return OATH Name from first YubiKey or Phone App token
        for token_num in sorted(token_sections.keys()):
            token_data = token_sections[token_num]
            token_type = token_data.get("Type", "")
            if token_type in ["YubiKey", "Phone App"] and "OATH Name" in token_data:
                return token_data["OATH Name"]
        
        # Fall back to old yubikey_oath_name field
        # (will be handled by code below)
    
    # Try legacy section-based format (YubiKey TOTP section)
    if section_name:
        for field in fields:
            section = field.get("section", {})
            section_label = section.get("label", "") if section else ""
            field_label = field.get("label", "")
            
            if section_label == section_name and field_label == field_name:
                return field.get("value")
    
    # Fall back to old flat format
    old_field_map = {
        "oath_name": "yubikey_oath_name",
        "serials": "yubikey_serials"
    }
    
    old_field_name = old_field_map.get(field_name, field_name)
    
    for field in fields:
        section = field.get("section", {})
        section_label = section.get("label", "") if section else ""
        field_label = field.get("label", "")
        
        # Only match if it's NOT in a section (flat field)
        if not section_label and field_label == old_field_name:
            return field.get("value")
    
    return None


def get_all_oath_names_from_tokens(item_data: dict) -> list[str]:
    """Get all OATH names from all Token sections in a 1Password item.
    
    This returns ALL OATH names found across all Token N sections,
    which is useful for finding duplicates or stale entries on YubiKeys.
    
    Args:
        item_data: Full 1Password item data
        
    Returns:
        List of OATH names (may be empty if none found)
    """
    oath_names = []
    fields = item_data.get("fields", [])
    
    for field in fields:
        section = field.get("section", {})
        section_label = section.get("label", "") if section else ""
        field_label = field.get("label", "")
        
        # Check Token N sections for OATH Name fields
        if section_label.startswith("Token ") and field_label == "OATH Name":
            oath_name = field.get("value", "")
            if oath_name:
                oath_names.append(oath_name)
    
    return oath_names
