"""Token validators for authenticator token fields."""

import re
from typing import List, Tuple


class PhoneNumberValidator:
    """Validate and lint phone number formats."""
    
    # Common patterns (for linting suggestions, not enforcement)
    E164_PATTERN = r'^\+\d{1,15}$'  # +1234567890
    US_FORMATTED = r'^\(\d{3}\)\s\d{3}-\d{4}$'  # (555) 123-4567
    DOTTED = r'^\d{3}\.\d{3}\.\d{4}$'  # 555.123.4567
    DASHED = r'^\d{3}-\d{3}-\d{4}$'  # 555-123-4567
    PLAIN = r'^\d{10,15}$'  # 5551234567
    
    def validate(self, phone: str) -> Tuple[bool, str, List[str]]:
        """
        Validate phone number.
        
        Args:
            phone: Phone number to validate
            
        Returns:
            (is_valid, normalized, warnings)
        """
        warnings = []
        
        # Basic checks
        if not phone or not phone.strip():
            return (False, "", ["Phone number cannot be empty"])
        
        # Strip whitespace
        phone = phone.strip()
        
        # Extract digits only for length check
        digits = ''.join(c for c in phone if c.isdigit())
        
        if len(digits) < 10:
            warnings.append("Phone number has fewer than 10 digits (may be invalid)")
        elif len(digits) > 15:
            warnings.append("Phone number has more than 15 digits (may be invalid)")
        
        # Check for recognized formats
        formats_matched = []
        if re.match(self.E164_PATTERN, phone):
            formats_matched.append("E.164")
        if re.match(self.US_FORMATTED, phone):
            formats_matched.append("US Formatted")
        if re.match(self.DOTTED, phone):
            formats_matched.append("Dotted")
        if re.match(self.DASHED, phone):
            formats_matched.append("Dashed")
        if re.match(self.PLAIN, phone):
            formats_matched.append("Plain")
        
        if not formats_matched:
            warnings.append(f"Unusual phone format: '{phone}' (consider E.164: +1234567890)")
        
        # Store as-is (no normalization)
        return (True, phone, warnings)


class OATHNameValidator:
    """Validate and lint OATH name formats."""
    
    STANDARD_PATTERN = r'^[^:]+:[^:]+$'  # Issuer:Account
    
    def validate(self, oath_name: str) -> Tuple[bool, List[str]]:
        """
        Validate OATH name format.
        
        Args:
            oath_name: OATH name to validate
            
        Returns:
            (is_valid, warnings)
        """
        warnings = []
        
        # Basic checks
        if not oath_name or not oath_name.strip():
            return (False, ["OATH name cannot be empty"])
        
        oath_name = oath_name.strip()
        
        # Check for standard format
        if ':' not in oath_name:
            warnings.append(
                f"OATH name '{oath_name}' missing colon separator. "
                "Standard format: Issuer:Account (e.g., 'GitHub:username')"
            )
        elif oath_name.count(':') > 1:
            warnings.append(
                f"OATH name '{oath_name}' has multiple colons. "
                "Standard format uses single colon: Issuer:Account"
            )
        elif oath_name.startswith(':') or oath_name.endswith(':'):
            warnings.append(
                f"OATH name '{oath_name}' has empty issuer or account. "
                "Both parts should be non-empty: Issuer:Account"
            )
        
        # Check for common mistakes
        if '@' in oath_name and ':' not in oath_name:
            warnings.append(
                f"OATH name looks like email only. "
                f"Consider adding issuer: 'Google:{oath_name}'"
            )
        
        return (True, warnings)


class TokenCountValidator:
    """Validate token counts and provide warnings."""
    
    WARNING_THRESHOLD = 10
    ERROR_THRESHOLD = 50
    
    def validate_count(self, token_count: int) -> Tuple[str, str]:
        """
        Validate token count.
        
        Args:
            token_count: Number of tokens
            
        Returns:
            (level, message) where level is "ok", "warning", or "error"
        """
        if token_count <= self.WARNING_THRESHOLD:
            return ("ok", "")
        elif token_count <= self.ERROR_THRESHOLD:
            return (
                "warning",
                f"This item has {token_count} tokens. "
                "Consider reviewing for duplicates or stale entries."
            )
        else:
            return (
                "error",
                f"This item has {token_count} tokens (limit: {self.ERROR_THRESHOLD}). "
                "This likely indicates a data issue. Review and clean up tokens."
            )


class SerialValidator:
    """Validate serial/identifier formats."""
    
    def validate(self, serial: str, token_type: str) -> Tuple[bool, List[str]]:
        """
        Validate serial format.
        
        Args:
            serial: Serial/identifier to validate
            token_type: Token type
            
        Returns:
            (is_valid, warnings)
        """
        warnings = []
        
        # Basic checks
        if not serial or not serial.strip():
            return (False, ["Serial cannot be empty"])
        
        serial = serial.strip()
        
        # Type-specific validation
        if token_type == "YubiKey":
            # YubiKey serials are typically 8-digit numbers
            if not serial.isdigit():
                warnings.append(
                    f"YubiKey serial '{serial}' is not numeric. "
                    "YubiKey serials are typically 8-digit numbers."
                )
            elif len(serial) != 8:
                warnings.append(
                    f"YubiKey serial '{serial}' is not 8 digits. "
                    "Standard YubiKey serials are 8 digits."
                )
        
        return (True, warnings)


class TokenValidator:
    """Main token validator combining all validation rules."""
    
    def __init__(self):
        self.phone_validator = PhoneNumberValidator()
        self.oath_validator = OATHNameValidator()
        self.count_validator = TokenCountValidator()
        self.serial_validator = SerialValidator()
    
    def validate_phone_number(self, phone: str) -> Tuple[bool, str, List[str]]:
        """Validate phone number."""
        return self.phone_validator.validate(phone)
    
    def validate_oath_name(self, oath_name: str) -> Tuple[bool, List[str]]:
        """Validate OATH name."""
        return self.oath_validator.validate(oath_name)
    
    def validate_token_count(self, count: int) -> Tuple[str, str]:
        """Validate token count."""
        return self.count_validator.validate_count(count)
    
    def validate_serial(self, serial: str, token_type: str) -> Tuple[bool, List[str]]:
        """Validate serial."""
        return self.serial_validator.validate(serial, token_type)
    
    def validate_token_data(
        self,
        token_type: str,
        serial: str,
        **kwargs
    ) -> Tuple[bool, List[str]]:
        """
        Validate complete token data.
        
        Args:
            token_type: Token type
            serial: Serial/identifier
            **kwargs: Type-specific fields
            
        Returns:
            (is_valid, list of error/warning messages)
        """
        messages = []
        is_valid = True
        
        # Validate serial
        serial_valid, serial_warnings = self.validate_serial(serial, token_type)
        if not serial_valid:
            is_valid = False
        messages.extend(serial_warnings)
        
        # Type-specific validation
        if token_type in ("YubiKey", "Phone App"):
            oath_name = kwargs.get("oath_name")
            if oath_name:
                oath_valid, oath_warnings = self.validate_oath_name(oath_name)
                if not oath_valid:
                    is_valid = False
                messages.extend(oath_warnings)
            else:
                is_valid = False
                messages.append(f"{token_type} requires OATH Name")
        
        if token_type == "Phone App":
            app_name = kwargs.get("app_name")
            if not app_name:
                is_valid = False
                messages.append("Phone App requires App Name")
        
        if token_type == "SMS":
            phone = kwargs.get("phone_number")
            if phone:
                phone_valid, _, phone_warnings = self.validate_phone_number(phone)
                if not phone_valid:
                    is_valid = False
                messages.extend(phone_warnings)
            else:
                is_valid = False
                messages.append("SMS requires Phone Number")
            
            carrier = kwargs.get("carrier_name")
            if not carrier:
                is_valid = False
                messages.append("SMS requires Carrier Name")
        
        return (is_valid, messages)
