"""Token analyzer for parsing and analyzing authenticator token structure in 1Password items."""

from typing import Dict, List, Optional, Tuple


class TokenAnalyzer:
    """Analyze token structure in 1Password items."""
    
    TOKEN_SECTION_PREFIX = "Token"
    
    # Canonical token types
    TOKEN_TYPES = {
        "YubiKey",
        "Phone App",
        "SMS",
        "WebAuthn Device",
        "Hardware Token",
        "Biometric Key",
    }
    
    # Type-specific field names
    TYPE_FIELDS = {
        "YubiKey": {"Serial", "Type", "OATH Name", "TOTP Enabled", "PassKey Enabled"},
        "Phone App": {"Serial", "Type", "OATH Name", "App Name"},
        "SMS": {"Serial", "Type", "Phone Number", "Carrier Name"},
        "WebAuthn Device": {"Serial", "Type", "Device Name", "Protocol", "PassKey Enabled", "Resident Keys"},
        "Hardware Token": {"Serial", "Type", "Device Model", "Token ID", "Expiration Date"},
        "Biometric Key": {"Serial", "Type", "Device Name", "Biometric Type", "Protocol"},
    }
    
    def __init__(self, item_data: dict):
        """
        Initialize analyzer with 1Password item data.
        
        Args:
            item_data: Item data from op item get --format json
        """
        self.item_data = item_data
        self._tokens: Optional[Dict[int, dict]] = None
    
    def get_tokens(self) -> Dict[int, dict]:
        """
        Parse and return all Token N sections from item.
        
        Returns:
            Dict mapping token number to token data
            Example: {1: {"Serial": "123", "Type": "YubiKey", ...}, 2: {...}}
        """
        if self._tokens is not None:
            return self._tokens
        
        tokens = {}
        
        for field in self.item_data.get("fields", []):
            section = field.get("section", {})
            if not section:
                continue
            
            section_label = section.get("label", "")
            if not section_label.startswith(self.TOKEN_SECTION_PREFIX + " "):
                continue
            
            # Extract token number (e.g., "Token 5" -> 5)
            try:
                token_num = int(section_label.split()[1])
            except (IndexError, ValueError):
                continue
            
            # Initialize token dict if needed
            if token_num not in tokens:
                tokens[token_num] = {}
            
            # Add field to token
            field_label = field.get("label", "")
            field_value = field.get("value", "")
            tokens[token_num][field_label] = field_value
        
        self._tokens = tokens
        return tokens
    
    def count_tokens(self) -> int:
        """Return total count of tokens."""
        return len(self.get_tokens())
    
    def count_tokens_by_type(self) -> Dict[str, int]:
        """
        Count tokens grouped by type.
        
        Returns:
            Dict mapping token type to count
            Example: {"YubiKey": 3, "Phone App": 1, "SMS": 1}
        """
        tokens = self.get_tokens()
        counts = {}
        
        for token_data in tokens.values():
            token_type = token_data.get("Type", "Unknown")
            counts[token_type] = counts.get(token_type, 0) + 1
        
        return counts
    
    def get_next_token_number(self) -> int:
        """
        Get next sequential token number.
        
        Returns:
            Next available token number (max + 1, or 1 if no tokens exist)
        """
        tokens = self.get_tokens()
        if not tokens:
            return 1
        return max(tokens.keys()) + 1
    
    def has_token_number(self, token_num: int) -> bool:
        """Check if token number exists."""
        return token_num in self.get_tokens()
    
    def get_token(self, token_num: int) -> Optional[dict]:
        """
        Get token data by number.
        
        Args:
            token_num: Token number (e.g., 1 for "Token 1")
            
        Returns:
            Token field data or None if not found
        """
        return self.get_tokens().get(token_num)
    
    def detect_gaps(self) -> List[int]:
        """
        Detect gaps in token numbering.
        
        Returns:
            List of missing token numbers
            Example: [3, 4] if tokens are 1, 2, 5, 6
        """
        tokens = self.get_tokens()
        if not tokens:
            return []
        
        min_num = min(tokens.keys())
        max_num = max(tokens.keys())
        
        expected = set(range(min_num, max_num + 1))
        actual = set(tokens.keys())
        
        return sorted(expected - actual)
    
    def is_sequential(self) -> bool:
        """Check if token numbering is sequential with no gaps."""
        tokens = self.get_tokens()
        if not tokens:
            return True
        
        expected = list(range(1, len(tokens) + 1))
        actual = sorted(tokens.keys())
        
        return expected == actual
    
    def has_serial_conflict(self, serial: str, exclude_token_num: Optional[int] = None) -> Tuple[bool, List[int]]:
        """
        Check if serial conflicts with existing tokens.
        
        Args:
            serial: Serial to check
            exclude_token_num: Token number to exclude from check (for updates)
            
        Returns:
            (has_conflict, list of conflicting token numbers)
        """
        tokens = self.get_tokens()
        conflicts = []
        
        for token_num, token_data in tokens.items():
            if exclude_token_num and token_num == exclude_token_num:
                continue
            
            if token_data.get("Serial") == serial:
                conflicts.append(token_num)
        
        return (len(conflicts) > 0, conflicts)
    
    def get_oath_name(self) -> Optional[str]:
        """
        Get OATH Name from first YubiKey or Phone App token.
        
        Returns:
            OATH Name or None if no OATH-based tokens exist
        """
        tokens = self.get_tokens()
        
        for token_data in tokens.values():
            token_type = token_data.get("Type", "")
            if token_type in ("YubiKey", "Phone App"):
                oath_name = token_data.get("OATH Name", "")
                if oath_name:
                    return oath_name
        
        return None
    
    def validate_token_type(self, token_type: str) -> Tuple[bool, str]:
        """
        Validate token type against canonical types.
        
        Args:
            token_type: Type to validate
            
        Returns:
            (is_valid, error_message)
        """
        if token_type in self.TOKEN_TYPES:
            return (True, "")
        
        return (
            False,
            f"Invalid token type '{token_type}'. "
            f"Valid types: {', '.join(sorted(self.TOKEN_TYPES))}"
        )
    
    def get_required_fields_for_type(self, token_type: str) -> set:
        """
        Get required fields for a token type.
        
        Args:
            token_type: Token type
            
        Returns:
            Set of required field names
        """
        return self.TYPE_FIELDS.get(token_type, {"Serial", "Type"})
    
    def validate_token_fields(self, token_data: dict) -> Tuple[bool, List[str]]:
        """
        Validate that token has required fields for its type.
        
        Args:
            token_data: Token field data
            
        Returns:
            (is_valid, list of error messages)
        """
        errors = []
        
        token_type = token_data.get("Type")
        if not token_type:
            errors.append("Missing required field: Type")
            return (False, errors)
        
        # Validate type
        is_valid_type, type_error = self.validate_token_type(token_type)
        if not is_valid_type:
            errors.append(type_error)
        
        # Check required fields
        required_fields = self.get_required_fields_for_type(token_type)
        for field_name in required_fields:
            if field_name not in token_data or not token_data[field_name]:
                errors.append(f"Missing required field for {token_type}: {field_name}")
        
        return (len(errors) == 0, errors)
    
    def format_token_summary(self, token_num: int, token_data: dict) -> str:
        """
        Format token data as human-readable summary.
        
        Args:
            token_num: Token number
            token_data: Token field data
            
        Returns:
            Formatted string (e.g., "Token 1 (YubiKey): Serial 123, OATH Name Google:user")
        """
        token_type = token_data.get("Type", "Unknown")
        serial = token_data.get("Serial", "Unknown")
        
        # Type-specific details
        details = []
        if token_type in ("YubiKey", "Phone App"):
            oath_name = token_data.get("OATH Name", "")
            if oath_name:
                details.append(f"OATH Name {oath_name}")
        
        if token_type == "Phone App":
            app_name = token_data.get("App Name", "")
            if app_name:
                details.append(f"App {app_name}")
        
        if token_type == "SMS":
            phone = token_data.get("Phone Number", "")
            carrier = token_data.get("Carrier Name", "")
            if phone:
                details.append(f"Phone {phone}")
            if carrier:
                details.append(f"Carrier {carrier}")
        
        details_str = ", ".join(details) if details else ""
        
        return f"Token {token_num} ({token_type}): Serial {serial}" + (f", {details_str}" if details_str else "")
