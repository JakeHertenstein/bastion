"""Bastion Label Specification v1 — Unified label format for credential generators.

SPECIFICATION
=============

This module defines the Bastion Label format used across all credential generation
tools (usernames, cards, keys). Labels are deterministic identifiers that enable
reproducible generation of credentials from a secret salt.

The format is designed for compatibility with 1Password tag hierarchy — the
HIERARCHY portion (before first ":") becomes a browsable folder structure.

GRAMMAR
-------
    LABEL     = HIERARCHY ":" IDENT ":" DATE "#" PARAMS [ "|" CHECK ]
    HIERARCHY = TOOL "/" TYPE "/" ALGO
    ALGO      = ALGO_PART ( "/" ALGO_PART )*
    PARAMS    = "VERSION=" VERSION_NUM ( "&" ATTR "=" VALUE )*
    CHECK     = <single Luhn mod-36 character>

FIELD DEFINITIONS
-----------------
    TOOL      Tool name. Currently "Bastion".
              Case: PascalCase
              
    TYPE      Generator type identifier.
              Values: USER, CARD, KEY
              Case: UPPERCASE
              
    ALGO      Cryptographic algorithm(s) used, hierarchical with "/".
              Values: SHA2/512, SHA3/512, SLIP39/ARGON2ID, X25519, RSA/4096, etc.
              Case: UPPERCASE
              
    IDENT     Service/purpose identifier.
              Case: lowercase
              Examples: github.com, aws-prod, banking.a0, ssh-primary
              
    DATE      Generation date or user-defined descriptor.
              Recommended: ISO 8601 (YYYY-MM-DD)
              Examples: 2025-11-30, initial, recovery-1
              
    PARAMS    Generation parameters in URL query-string notation.
              VERSION always required.
              Format: ATTR=value joined with "&" (canonical order required)
              Values must be non-empty, matching [A-Za-z0-9._-]+
              Examples:
                BASTION=0.3.0&VERSION=1&LENGTH=16
                BASTION=0.3.0&VERSION=1&TIME=3&MEMORY=65536&PARALLELISM=4&ENCODING=90
              Case: UPPERCASE for attribute names

PARAMETER ORDERING
------------------
Parameters must appear in this fixed order (include only relevant ones):

    BASTION={semver}  Tool version (optional)        BASTION=0.3.0, BASTION=1.0.0
    VERSION={n}       Format version (required)      VERSION=1, VERSION=1.1
    TIME={n}          Argon2 time cost               TIME=3, TIME=10
    MEMORY={n}        Argon2 memory (KB)             MEMORY=65536, MEMORY=2048
    PARALLELISM={n}   Argon2 parallelism             PARALLELISM=4, PARALLELISM=8
    NONCE={value}     Generation nonce               NONCE=Kx7mQ9bL
    LENGTH={n}        Output length (chars)          LENGTH=16, LENGTH=24
    ENCODING={n}      Output encoding size           ENCODING=36, ENCODING=90

CHARACTER SET
-------------
    TOOL:  [A-Za-z][A-Za-z0-9]* (PascalCase)
    TYPE:  [A-Z]+
    ALGO:  [A-Z0-9/]+
    IDENT: [a-z0-9._-]+
    DATE:  [A-Za-z0-9-]+
    CHECK: [0-9A-Z] (single character)

DELIMITERS
----------
    "/"  Hierarchy separator (creates 1P folders)
    ":"  Metadata field separator
    "#"  Params section marker
    "&"  Param attribute separator (URL-style)
    "="  Attribute name/value separator (URL-style)
    "|"  Check digit separator

ALGORITHM NAMING
----------------
    SHA-256 (SHA-2):    SHA2/256
    SHA-512 (SHA-2):    SHA2/512
    SHA3-512:           SHA3/512
    Argon2id:           ARGON2ID
    SLIP39 + Argon2id:  SLIP39/ARGON2ID
    X25519:             X25519
    Ed25519:            ED25519
    RSA 2048-bit:       RSA/2048
    RSA 4096-bit:       RSA/4096

EXAMPLES
--------
    Username (16 char, with tool version):
        Bastion/USER/SHA2/512:github.com:2025-11-30#BASTION=0.3.0&VERSION=1&LENGTH=16|K
        
    Username (custom length, SHA3):
        Bastion/USER/SHA3/512:aws.amazon.com:2025-11-30#BASTION=0.3.0&VERSION=1.1&LENGTH=24|M
        
    Card token with KDF params:
        Bastion/CARD/SLIP39/ARGON2ID:banking.a0:2025-11-30#BASTION=0.3.0&VERSION=1&TIME=3&MEMORY=2048&PARALLELISM=8&NONCE=Kx7mQ9bL&ENCODING=90|X
        
    Key (minimal params):
        Bastion/KEY/X25519:ssh-primary:2025-11-30#VERSION=1|J

1PASSWORD TAG EXTRACTION
------------------------
To extract the 1Password tag from a label:

    TAG = everything before the first ":"

Examples:
    Bastion/USER/SHA2/512:...|K  →  Bastion/USER/SHA2/512
    Bastion/CARD/SLIP39/ARGON2ID:...|X  →  Bastion/CARD/SLIP39/ARGON2ID

LUHN MOD-36 CHECK DIGIT
-----------------------
The optional check digit detects single-character errors and adjacent
transpositions in human-transcribed labels. It uses the Luhn mod N algorithm
with N=36, alphabet [0-9A-Z].

The check digit is:
- Computed over everything before "|" (the BODY)
- Appended after "|" when building labels
- Validated on input; stripped before processing
- Optional: labels without "|" are valid but unverified

TYPE-SPECIFIC DEFAULTS
----------------------
    USER:  ALGO=SHA2/512, PARAMS=VERSION=1&LENGTH=16
    CARD:  ALGO=SLIP39/ARGON2ID, PARAMS=VERSION=1&TIME=3&MEMORY=65536&PARALLELISM=4&ENCODING=90
    KEY:   ALGO=X25519, PARAMS=VERSION=1
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# =============================================================================
# Constants
# =============================================================================

# URL-safe Base64 character set (excluding padding '=')
FIELD_CHARSET = re.compile(r'^[A-Za-z0-9_-]*$')

# Extended charset for IDENT field (allows period for domain names)
IDENT_CHARSET = re.compile(r'^[A-Za-z0-9_.-]*$')

# Algo charset (UPPERCASE with / for hierarchy)
ALGO_CHARSET = re.compile(r'^[A-Z0-9/]+$')

# Default tool name
DEFAULT_TOOL = 'Bastion'

# Valid generator types
VALID_TYPES = frozenset({'USER', 'CARD', 'KEY'})

# Valid algorithms by type (using hierarchical naming)
VALID_ALGOS = {
    'USER': frozenset({'SHA2/256', 'SHA2/512', 'SHA3/256', 'SHA3/512'}),
    'CARD': frozenset({'SLIP39/ARGON2ID', 'ARGON2ID', 'PBKDF2/SHA2/256'}),
    'KEY': frozenset({'X25519', 'ED25519', 'RSA/2048', 'RSA/4096'}),
}

# Default algorithms by type
DEFAULT_ALGO = {
    'USER': 'SHA2/512',
    'CARD': 'SLIP39/ARGON2ID',
    'KEY': 'X25519',
}

# Default params by type (URL query-string notation: ATTR=value&ATTR=value)
DEFAULT_PARAMS = {
    'USER': 'VERSION=1&LENGTH=16',
    'CARD': 'VERSION=0.3.0&TIME=3&MEMORY=65536&PARALLELISM=4&ENCODING=90',
    'KEY': 'VERSION=0.3.0',
}

# Parameter ordering (for canonical form)
# VERSION = Bastion tool version (SemVer) that generated the credential
PARAM_ORDER = ['VERSION', 'TIME', 'MEMORY', 'PARALLELISM', 'NONCE', 'LENGTH', 'ENCODING']

# Luhn mod-36 alphabet (0-9, A-Z uppercase)
LUHN_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
LUHN_BASE = 36


# =============================================================================
# Luhn Mod-36 Implementation
# =============================================================================

def luhn_mod36_char_to_int(char: str) -> int:
    """Convert character to Luhn mod-36 value.
    
    Args:
        char: Single character [0-9A-Za-z]
        
    Returns:
        Integer value 0-35
        
    Raises:
        ValueError: If character not in alphabet
    """
    c = char.upper()
    if c in LUHN_ALPHABET:
        return LUHN_ALPHABET.index(c)
    raise ValueError(f"Invalid Luhn character: {char!r}")


def luhn_mod36_int_to_char(value: int) -> str:
    """Convert integer to Luhn mod-36 character.
    
    Args:
        value: Integer 0-35
        
    Returns:
        Uppercase character [0-9A-Z]
        
    Raises:
        ValueError: If value out of range
    """
    if 0 <= value < LUHN_BASE:
        return LUHN_ALPHABET[value]
    raise ValueError(f"Value out of range: {value}")


def luhn_mod36_generate(s: str) -> str:
    """Generate Luhn mod-36 check character for a string.
    
    Uses the standard Luhn algorithm adapted for base-36:
    1. Process characters right-to-left
    2. Double every second digit (from the right)
    3. If doubled value >= 36, subtract 36 (equivalently, sum digits in base-36)
    4. Sum all values
    5. Check digit = (36 - (sum mod 36)) mod 36
    
    Args:
        s: Input string (alphanumeric, case-insensitive)
        
    Returns:
        Single uppercase check character [0-9A-Z]
        
    Raises:
        ValueError: If string contains invalid characters
        
    Example:
        >>> luhn_mod36_generate("v1:USER:SHA512:L16:github.com:2025-11-30")
        '1'
    """
    if not s:
        return '0'
    
    # Filter to alphanumeric only (ignore delimiters for checksum)
    chars = [c for c in s if c.isalnum()]
    
    total = 0
    for i, char in enumerate(reversed(chars)):
        value = luhn_mod36_char_to_int(char)
        
        # Double every second digit (odd indices in reversed list)
        if i % 2 == 0:
            value *= 2
            if value >= LUHN_BASE:
                value -= LUHN_BASE
        
        total += value
    
    check_value = (LUHN_BASE - (total % LUHN_BASE)) % LUHN_BASE
    return luhn_mod36_int_to_char(check_value)


def luhn_mod36_validate(s: str) -> bool:
    """Validate a string with Luhn mod-36 check character.
    
    The check character should be the last alphanumeric character.
    
    Args:
        s: String ending with check character
        
    Returns:
        True if check digit is valid, False otherwise
        
    Example:
        >>> luhn_mod36_validate("v1:USER:SHA512:L16:github.com:2025-11-30|K")
        True
    """
    if not s:
        return False
    
    # Filter to alphanumeric only
    chars = [c for c in s if c.isalnum()]
    
    if len(chars) < 2:
        return False
    
    total = 0
    for i, char in enumerate(reversed(chars)):
        value = luhn_mod36_char_to_int(char)
        
        # Double every second digit (odd indices, which is the payload)
        if i % 2 == 1:
            value *= 2
            if value >= LUHN_BASE:
                value -= LUHN_BASE
        
        total += value
    
    return total % LUHN_BASE == 0


# =============================================================================
# Parameter Encoding/Decoding
# =============================================================================

# Allowed characters in parameter values (non-empty, URL-safe subset)
PARAM_VALUE_PATTERN = re.compile(r'^[A-Za-z0-9._-]+$')


def validate_param_value(value: str, param_name: str) -> None:
    """Validate a parameter value.
    
    Args:
        value: Parameter value to validate
        param_name: Parameter name (for error messages)
        
    Raises:
        ValueError: If value is empty or contains invalid characters
    """
    if not value:
        raise ValueError(f"Parameter '{param_name}' cannot have empty value")
    if not PARAM_VALUE_PATTERN.match(str(value)):
        raise ValueError(
            f"Parameter '{param_name}' value contains invalid characters: {value!r}. "
            f"Allowed: A-Z, a-z, 0-9, '.', '_', '-'"
        )


def encode_params(params: dict[str, int | str]) -> str:
    """Encode parameter dictionary to URL query-string format.
    
    Uses '&' as parameter separator and '=' as key-value separator.
    Parameters are output in canonical order (BASTION, VERSION first).
    
    Args:
        params: Dictionary of parameter key-value pairs
                Keys: 'bastion', 'version', 'time', 'memory', 'parallelism', 
                      'nonce', 'length', 'encoding'
                
    Returns:
        Parameter string (e.g., "BASTION=0.3.0&VERSION=1&LENGTH=16")
        
    Raises:
        ValueError: If any value is empty or contains invalid characters
        
    Example:
        >>> encode_params({'bastion': '0.3.0', 'version': 1, 'length': 16})
        'BASTION=0.3.0&VERSION=1&LENGTH=16'
    """
    parts = []
    
    # Fixed order: BASTION, VERSION, TIME, MEMORY, PARALLELISM, NONCE, LENGTH, ENCODING
    if 'bastion' in params:
        validate_param_value(str(params['bastion']), 'BASTION')
        parts.append(f"BASTION={params['bastion']}")
    if 'version' in params:
        validate_param_value(str(params['version']), 'VERSION')
        parts.append(f"VERSION={params['version']}")
    if 'time' in params:
        validate_param_value(str(params['time']), 'TIME')
        parts.append(f"TIME={params['time']}")
    if 'memory' in params:
        validate_param_value(str(params['memory']), 'MEMORY')
        parts.append(f"MEMORY={params['memory']}")
    if 'parallelism' in params:
        validate_param_value(str(params['parallelism']), 'PARALLELISM')
        parts.append(f"PARALLELISM={params['parallelism']}")
    if 'nonce' in params:
        validate_param_value(str(params['nonce']), 'NONCE')
        parts.append(f"NONCE={params['nonce']}")
    if 'length' in params:
        validate_param_value(str(params['length']), 'LENGTH')
        parts.append(f"LENGTH={params['length']}")
    if 'encoding' in params:
        validate_param_value(str(params['encoding']), 'ENCODING')
        parts.append(f"ENCODING={params['encoding']}")
    
    return '&'.join(parts)


def decode_params(params_str: str) -> dict[str, int | str]:
    """Decode URL query-string parameter format to dictionary.
    
    Uses '&' as parameter separator and '=' as key-value separator.
    Validates canonical ordering and rejects empty values.
    
    Args:
        params_str: Parameter string (e.g., "VERSION=1&LENGTH=16")
        
    Returns:
        Dictionary of parameter key-value pairs
        
    Raises:
        ValueError: If parameters are out of order, empty, or malformed
        
    Example:
        >>> decode_params('VERSION=1&LENGTH=16')
        {'version': '1', 'length': 16}
    """
    if not params_str:
        return {}
    
    result: dict[str, int | str] = {}
    last_order_index = -1
    
    for part in params_str.split('&'):
        if not part:
            raise ValueError("Empty parameter segment (consecutive '&' or trailing '&')")
        
        if '=' not in part:
            raise ValueError(f"Parameter missing '=' separator: {part!r}")
        
        attr, value = part.split('=', 1)
        attr_upper = attr.upper()
        attr_lower = attr.lower()
        
        # Validate non-empty value
        if not value:
            raise ValueError(f"Parameter '{attr_upper}' has empty value")
        
        # Validate value characters
        if not PARAM_VALUE_PATTERN.match(value):
            raise ValueError(
                f"Parameter '{attr_upper}' value contains invalid characters: {value!r}"
            )
        
        # Validate canonical ordering
        if attr_upper in PARAM_ORDER:
            current_index = PARAM_ORDER.index(attr_upper)
            if current_index <= last_order_index:
                raise ValueError(
                    f"Parameters out of canonical order: '{attr_upper}' must come before "
                    f"previous parameter. Required order: {', '.join(PARAM_ORDER)}"
                )
            last_order_index = current_index
        
        # Convert numeric values
        if attr_lower in ('time', 'memory', 'parallelism', 'length', 'encoding'):
            try:
                result[attr_lower] = int(value)
            except ValueError:
                result[attr_lower] = value
        else:
            # Keep bastion, version and nonce as strings
            result[attr_lower] = value
    
    return result


# =============================================================================
# Field Validation
# =============================================================================

def validate_field_charset(value: str, field_name: str) -> list[str]:
    """Validate that a field contains only URL-safe Base64 characters.
    
    Args:
        value: Field value to validate
        field_name: Name of field (for error messages)
        
    Returns:
        List of error messages (empty if valid)
    """
    if not FIELD_CHARSET.match(value):
        invalid = set(c for c in value if not re.match(r'[A-Za-z0-9_-]', c))
        return [f"{field_name}: invalid characters {invalid!r}"]
    return []


def validate_ident_charset(value: str) -> list[str]:
    """Validate that ident field contains valid characters (including period).
    
    Args:
        value: Ident field value to validate
        
    Returns:
        List of error messages (empty if valid)
    """
    if not IDENT_CHARSET.match(value):
        invalid = set(c for c in value if not re.match(r'[A-Za-z0-9_.-]', c))
        return [f"ident: invalid characters {invalid!r}"]
    return []


def validate_type(type_: str) -> list[str]:
    """Validate type field.
    
    Args:
        type_: Type string (e.g., "USER")
        
    Returns:
        List of error messages (empty if valid)
    """
    if type_ not in VALID_TYPES:
        return [f"type: must be one of {sorted(VALID_TYPES)}, got {type_!r}"]
    return []


def validate_algo(algo: str, type_: str) -> list[str]:
    """Validate algorithm field for given type.
    
    Args:
        algo: Algorithm string with / hierarchy (e.g., "SHA2/512")
        type_: Generator type for context
        
    Returns:
        List of error messages (empty if valid)
    """
    errors = []
    
    # Check charset (now allows /)
    if not re.match(r'^[A-Z0-9/]+$', algo):
        invalid = set(c for c in algo if not re.match(r'[A-Z0-9/]', c))
        errors.append(f"algo: invalid characters {invalid!r}")
    
    # Check against valid algorithms for type (warning only, allow extension)
    if type_ in VALID_ALGOS and algo not in VALID_ALGOS[type_]:
        # Not an error, just unusual - algorithms can be extended
        pass
    
    return errors


# =============================================================================
# BastionLabel Dataclass
# =============================================================================

@dataclass
class BastionLabel:
    """Parsed Bastion label with validation and building capabilities.
    
    New format: TOOL/TYPE/ALGO:IDENT:DATE#PARAMS|CHECK
    
    Attributes:
        tool: Tool name (e.g., "Bastion")
        type: Generator type (USER, CARD, KEY)
        algo: Algorithm name with "/" hierarchy (SHA2/512, SLIP39/ARGON2ID, etc.)
        ident: Service/purpose identifier (github.com, banking.a0)
        date: Date or descriptor (2025-11-30, initial)
        params: Parameter string (VERSION=1&LENGTH=16, etc.)
        check: Luhn check character or None if not present
        
    Example:
        >>> label = BastionLabel.parse("Bastion/USER/SHA2/512:github.com:2025-11-30#VERSION=1&LENGTH=16|K")
        >>> label.type
        'USER'
        >>> label.get_param('length')
        16
        >>> label.build()
        'Bastion/USER/SHA2/512:github.com:2025-11-30#VERSION=1&LENGTH=16|K'
    """
    
    tool: str
    type: str
    algo: str
    ident: str
    date: str
    params: str
    check: Optional[str] = None
    
    # Cached decoded params
    _decoded_params: dict = field(default_factory=dict, repr=False, compare=False)
    
    def __post_init__(self):
        """Decode params on initialization."""
        if self.params and not self._decoded_params:
            object.__setattr__(self, '_decoded_params', decode_params(self.params))
    
    @classmethod
    def parse(cls, label: str) -> BastionLabel:
        """Parse a label string into BastionLabel.
        
        Format: TOOL/TYPE/ALGO:IDENT:DATE#PARAMS|CHECK
        
        Args:
            label: Full label string, with or without check digit
            
        Returns:
            Parsed BastionLabel instance
            
        Raises:
            ValueError: If label format is invalid
            
        Example:
            >>> BastionLabel.parse("Bastion/USER/SHA2/512:github.com:2025-11-30#VERSION=1&LENGTH=16|K")
            BastionLabel(tool='Bastion', type='USER', algo='SHA2/512', ...)
        """
        if not label:
            raise ValueError("Label cannot be empty")
        
        # Split off check digit if present
        check: Optional[str] = None
        body = label
        
        if '|' in label:
            body, check_part = label.rsplit('|', 1)
            if len(check_part) == 1:
                check = check_part.upper()
            else:
                raise ValueError(f"Check digit must be single character, got {check_part!r}")
        
        # Split off params if present
        params = ''
        if '#' in body:
            body, params = body.rsplit('#', 1)
        
        # Parse HIERARCHY:IDENT:DATE
        colon_parts = body.split(':')
        
        if len(colon_parts) != 3:
            raise ValueError(
                f"Label must have format HIERARCHY:IDENT:DATE, got {len(colon_parts)} colon-separated parts: {body!r}"
            )
        
        hierarchy, ident, date = colon_parts
        
        # Parse TOOL/TYPE/ALGO from hierarchy
        slash_parts = hierarchy.split('/')
        
        if len(slash_parts) < 3:
            raise ValueError(
                f"Hierarchy must have at least TOOL/TYPE/ALGO, got: {hierarchy!r}"
            )
        
        tool = slash_parts[0]
        type_ = slash_parts[1].upper()
        algo = '/'.join(slash_parts[2:]).upper()  # Rejoin remaining parts as algo
        
        return cls(
            tool=tool,
            type=type_,
            algo=algo,
            ident=ident,
            date=date,
            params=params,
            check=check,
        )
    
    @classmethod
    def build_new(
        cls,
        type: str,
        ident: str,
        date: str,
        algo: Optional[str] = None,
        params: Optional[str] = None,
        tool: str = DEFAULT_TOOL,
        with_check: bool = True,
    ) -> BastionLabel:
        """Build a new label with defaults for missing fields.
        
        Args:
            type: Generator type (USER, CARD, KEY)
            ident: Service/purpose identifier
            date: Date or descriptor
            algo: Algorithm (defaults based on type)
            params: Parameters (defaults based on type)
            tool: Tool name (default "Bastion")
            with_check: Whether to compute check digit
            
        Returns:
            New BastionLabel instance
            
        Example:
            >>> label = BastionLabel.build_new("USER", "github.com", "2025-11-30")
            >>> label.algo
            'SHA2/512'
            >>> label.params
            'VERSION=1&LENGTH=16'
        """
        type_upper = type.upper()
        
        if algo is None:
            algo = DEFAULT_ALGO.get(type_upper, 'SHA2/512')
        
        if params is None:
            params = DEFAULT_PARAMS.get(type_upper, 'VERSION=1')
        
        label = cls(
            tool=tool,
            type=type_upper,
            algo=algo.upper(),
            ident=ident,
            date=date,
            params=params,
            check=None,
        )
        
        if with_check:
            label = label.with_check()
        
        return label
    
    def hierarchy(self) -> str:
        """Get hierarchy portion (1Password tag).
        
        Returns:
            Hierarchy string: TOOL/TYPE/ALGO
        """
        return f"{self.tool}/{self.type}/{self.algo}"
    
    def tag(self) -> str:
        """Get 1Password tag (alias for hierarchy).
        
        Returns:
            1Password-compatible tag string
        """
        return self.hierarchy()
    
    def body(self) -> str:
        """Get label body (without check digit).
        
        Returns:
            Label string without "|CHECK" suffix
        """
        return f"{self.hierarchy()}:{self.ident}:{self.date}#{self.params}"
    
    def build(self, with_check: bool = True) -> str:
        """Build complete label string.
        
        Args:
            with_check: Whether to include check digit
            
        Returns:
            Complete label string
            
        Example:
            >>> label.build()
            'Bastion/USER/SHA2/512:github.com:2025-11-30#VERSION=1&LENGTH=16|K'
            >>> label.build(with_check=False)
            'Bastion/USER/SHA2/512:github.com:2025-11-30#VERSION=1&LENGTH=16'
        """
        body = self.body()
        
        if with_check:
            check = self.check or luhn_mod36_generate(body)
            return f"{body}|{check}"
        
        return body
    
    def with_check(self) -> BastionLabel:
        """Return copy with computed check digit.
        
        Returns:
            New BastionLabel with check digit set
        """
        check = luhn_mod36_generate(self.body())
        return BastionLabel(
            tool=self.tool,
            type=self.type,
            algo=self.algo,
            ident=self.ident,
            date=self.date,
            params=self.params,
            check=check,
        )
    
    def without_check(self) -> BastionLabel:
        """Return copy without check digit.
        
        Returns:
            New BastionLabel with check=None
        """
        return BastionLabel(
            tool=self.tool,
            type=self.type,
            algo=self.algo,
            ident=self.ident,
            date=self.date,
            params=self.params,
            check=None,
        )
    
    def validate(self) -> list[str]:
        """Validate all fields.
        
        Returns:
            List of error messages (empty if valid)
            
        Example:
            >>> label = BastionLabel.parse("Bastion/USER/SHA2/512:github.com:2025-11-30#VERSION=1&LENGTH=16|K")
            >>> label.validate()
            []
        """
        errors = []
        
        # Tool (must be PascalCase, start with letter)
        if not self.tool or not self.tool[0].isupper():
            errors.append(f"tool: must be PascalCase, got {self.tool!r}")
        
        # Type
        errors.extend(validate_type(self.type))
        
        # Algorithm (now allows /)
        if not re.match(r'^[A-Z0-9/]+$', self.algo):
            errors.append(f"algo: must be UPPERCASE with / separators, got {self.algo!r}")
        
        # Params must start with VERSION=
        if not self.params.startswith('VERSION='):
            errors.append(f"params: must start with VERSION=n, got {self.params!r}")
        
        # Ident charset (allows period for domain names)
        errors.extend(validate_ident_charset(self.ident))
        
        # Date charset
        if not re.match(r'^[A-Za-z0-9-]+$', self.date):
            errors.append(f"date: invalid characters in {self.date!r}")
        
        # Check digit (if present)
        if self.check is not None:
            if not luhn_mod36_validate(self.build(with_check=True)):
                errors.append(f"check: invalid Luhn check digit '{self.check}'")
        
        return errors
    
    def is_valid(self) -> bool:
        """Check if label is valid.
        
        Returns:
            True if no validation errors
        """
        return len(self.validate()) == 0
    
    def verify_check(self) -> bool:
        """Verify the check digit is correct.
        
        Returns:
            True if check digit matches, False if missing or incorrect
        """
        if self.check is None:
            return False
        return luhn_mod36_validate(self.build(with_check=True))
    
    def get_param(self, key: str, default: int | str | None = None) -> int | str | None:
        """Get a decoded parameter value.
        
        Args:
            key: Parameter key (length, time, memory, parallelism, encoding)
            default: Default value if not present
            
        Returns:
            Parameter value or default
            
        Example:
            >>> label.get_param('length')
            16
            >>> label.get_param('encoding', 'BASE36')
            'BASE36'
        """
        if not self._decoded_params:
            object.__setattr__(self, '_decoded_params', decode_params(self.params))
        return self._decoded_params.get(key, default)
    
    def get_length(self, default: int = 16) -> int:
        """Get length parameter.
        
        Args:
            default: Default length if not specified
            
        Returns:
            Length value
        """
        value = self.get_param('length', default)
        return int(value) if value is not None else default


# =============================================================================
# Convenience Functions
# =============================================================================

def parse_label(label: str) -> BastionLabel:
    """Parse a label string (convenience function).
    
    Args:
        label: Full label string
        
    Returns:
        Parsed BastionLabel
        
    Example:
        >>> parse_label("Bastion/USER/SHA2/512:github.com:2025-11-30#VERSION=1&LENGTH=16|K")
        BastionLabel(...)
    """
    return BastionLabel.parse(label)


def build_label(
    type: str,
    ident: str,
    date: str,
    algo: Optional[str] = None,
    params: Optional[str] = None,
    tool: str = DEFAULT_TOOL,
    with_check: bool = True,
) -> str:
    """Build a label string (convenience function).
    
    Args:
        type: Generator type (USER, CARD, KEY)
        ident: Service/purpose identifier
        date: Date or descriptor
        algo: Algorithm (defaults based on type)
        params: Parameters (defaults based on type)
        tool: Tool name (default "Bastion")
        with_check: Whether to include check digit
        
    Returns:
        Complete label string
        
    Example:
        >>> build_label("USER", "github.com", "2025-11-30")
        'Bastion/USER/SHA2/512:github.com:2025-11-30#VERSION=1&LENGTH=16|K'
    """
    label = BastionLabel.build_new(
        type=type,
        ident=ident,
        date=date,
        algo=algo,
        params=params,
        tool=tool,
        with_check=with_check,
    )
    return label.build(with_check=with_check)


def validate_label(label: str) -> tuple[bool, list[str]]:
    """Validate a label string (convenience function).
    
    Args:
        label: Label string to validate
        
    Returns:
        Tuple of (is_valid, error_messages)
        
    Example:
        >>> validate_label("Bastion/USER/SHA2/512:github.com:2025-11-30#VERSION=1&LENGTH=16|K")
        (True, [])
    """
    try:
        parsed = BastionLabel.parse(label)
        errors = parsed.validate()
        return len(errors) == 0, errors
    except ValueError as e:
        return False, [str(e)]
