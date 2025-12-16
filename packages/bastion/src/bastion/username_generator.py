"""Deterministic username generator using HMAC-SHA512 and Base36 encoding.

This module provides a secure, deterministic username generation system that:
- Uses HMAC-SHA512 (default v1) for high compatibility and hardware acceleration
- Supports SHA256, SHA512, SHA3-512 algorithms with version labels
- Encodes to Base36 for wide compatibility (a-z0-9)
- Produces traceable usernames by recomputing with same label
- Requires secure storage of the secret salt in 1Password
- Stores configuration in 1Password Secure Note
- Links generated usernames to specific salt items via UUID

Label Format (Bastion Label Specification v1):
    v1:USER:ALGO:PARAMS:IDENT:DATE[|CHECK]
    
    Example: v1:USER:SHA512:L16:github.com:2025-11-30|K
    
    See label_spec.py for full specification.

Security Design: HMAC vs Key Derivation Functions (Argon2id, PBKDF2, scrypt)
-----------------------------------------------------------------------------
We use HMAC-SHA512 rather than a password-based KDF because:

1. THREAT MODEL: Security depends on salt secrecy, not brute-force resistance.
   The salt is 256-bit high-entropy random data (from YubiKey HMAC + dice),
   not a user-memorable password that needs stretching.

2. NO BRUTE-FORCE ATTACK: An attacker with the salt can regenerate ALL usernames
   instantly regardless of algorithm. An attacker without the salt gains nothing
   from Argon2id's computational hardness—there's no low-entropy secret to crack.

3. PERFORMANCE: Username generation for 100+ services should be fast (~μs).
   Argon2id's intentional slowness (~500ms) provides no security benefit here
   but would make bulk operations impractical.

4. QUANTUM RESISTANCE: HMAC-SHA512 provides 128-bit security against quantum
   attacks (Grover's algorithm halves effective bits from 256 to 128). This is
   sufficient for usernames—256-bit quantum resistance (SHA3-512) is available
   if desired but provides no practical benefit for non-secret identifiers.

5. CORRECT PRIMITIVE: HMAC is designed for keyed message authentication and
   deterministic derivation. KDFs are designed to slow down attacks on
   low-entropy passwords—a problem we don't have.

The security guarantee: If the 256-bit salt remains secret in 1Password,
usernames cannot be correlated across services or predicted by attackers.
"""

import hmac
import hashlib
import secrets
import subprocess
import json
import re
import base64 as base64_module
from typing import Optional

from .label_spec import BastionLabel, decode_params


# =============================================================================
# Encoding Functions
# =============================================================================

# Valid encoding values (alphabet size)
VALID_ENCODINGS = {10, 36, 64}


def base10_encode(number: int) -> str:
    """Encode a number to base10 string (0-9 only).
    
    Args:
        number: Integer to encode
        
    Returns:
        Base10 encoded string (numeric only)
    """
    return str(number)


def base36_encode(number: int) -> str:
    """Encode a number to base36 string (0-9, a-z).
    
    Args:
        number: Integer to encode
        
    Returns:
        Base36 encoded string (lowercase)
    """
    if number == 0:
        return '0'
    
    alphabet = '0123456789abcdefghijklmnopqrstuvwxyz'
    result = []
    
    while number:
        number, remainder = divmod(number, 36)
        result.append(alphabet[remainder])
    
    return ''.join(reversed(result))


def base64_encode(data: bytes) -> str:
    """Encode bytes to URL-safe base64 string (without padding).
    
    Uses URL-safe alphabet (- and _ instead of + and /) for
    compatibility with usernames and URLs.
    
    Args:
        data: Bytes to encode
        
    Returns:
        URL-safe base64 encoded string (no padding)
    """
    return base64_module.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def encode_hash(raw_hash: bytes, encoding: int = 36) -> str:
    """Encode hash bytes using specified encoding.
    
    Args:
        raw_hash: Raw hash bytes
        encoding: Alphabet size (10, 36, or 64)
        
    Returns:
        Encoded string
        
    Raises:
        ValueError: If encoding is not supported
    """
    if encoding == 10:
        hash_int = int.from_bytes(raw_hash, byteorder='big')
        return base10_encode(hash_int)
    elif encoding == 36:
        hash_int = int.from_bytes(raw_hash, byteorder='big')
        return base36_encode(hash_int)
    elif encoding == 64:
        return base64_encode(raw_hash)
    else:
        raise ValueError(f"Unsupported encoding: {encoding}. Use 10, 36, or 64.")


def generate_nonce(length: int = 8) -> str:
    """Generate a URL-safe random nonce for non-recoverable usernames.
    
    Nonce mode provides protection against stolen seeds:
    - If seed is compromised, attacker cannot regenerate usernames
    - Nonce must be stored alongside the generated username
    - Cannot recover username from label + salt alone (requires nonce)
    
    Args:
        length: Desired nonce length in characters (default 8)
        
    Returns:
        URL-safe random string
    """
    # secrets.token_urlsafe returns ~1.3 chars per byte
    # Use 6 bytes to get at least 8 characters
    byte_length = max(1, (length * 3) // 4 + 1)
    nonce = secrets.token_urlsafe(byte_length)
    return nonce[:length]


def generate_username_v1_sha256(
    label: str,
    secret_salt: str,
    length: int = 16,
    encoding: int = 36,
    nonce: Optional[str] = None,
) -> str:
    """Generate username using HMAC-SHA256.
    
    Args:
        label: Full label (e.g., "v1:USER:SHA256:L16:github.com:2025-11-30")
        secret_salt: High-entropy secret key
        length: Desired username length (default 16, max 51 for base36)
        encoding: Output encoding (10=numeric, 36=alphanumeric, 64=base64)
        nonce: Optional random nonce for non-recoverable usernames
        
    Returns:
        Deterministic username string
    """
    key_bytes = secret_salt.encode('utf-8')
    # Include nonce in message if provided (makes username non-recoverable without nonce)
    message = f"{label}:{nonce}" if nonce else label
    message_bytes = message.encode('utf-8')
    raw_hash = hmac.new(key_bytes, message_bytes, hashlib.sha256).digest()
    username = encode_hash(raw_hash, encoding)
    return username[:length]


def generate_username_v1_sha512(
    label: str,
    secret_salt: str,
    length: int = 16,
    encoding: int = 36,
    nonce: Optional[str] = None,
) -> str:
    """Generate username using HMAC-SHA512 (default algorithm).
    
    Args:
        label: Full label (e.g., "v1:USER:SHA512:L16:github.com:2025-11-30")
        secret_salt: High-entropy secret key
        length: Desired username length (default 16, max 100 for base36)
        encoding: Output encoding (10=numeric, 36=alphanumeric, 64=base64)
        nonce: Optional random nonce for non-recoverable usernames
        
    Returns:
        Deterministic username string
    """
    key_bytes = secret_salt.encode('utf-8')
    # Include nonce in message if provided (makes username non-recoverable without nonce)
    message = f"{label}:{nonce}" if nonce else label
    message_bytes = message.encode('utf-8')
    raw_hash = hmac.new(key_bytes, message_bytes, hashlib.sha512).digest()
    username = encode_hash(raw_hash, encoding)
    return username[:length]


def generate_username_v1_sha3_512(
    label: str,
    secret_salt: str,
    length: int = 16,
    encoding: int = 36,
    nonce: Optional[str] = None,
) -> str:
    """Generate username using HMAC-SHA3-512 (quantum-resistant option).
    
    Args:
        label: Full label (e.g., "v1:USER:SHA3-512:L16:github.com:2025-11-30")
        secret_salt: High-entropy secret key
        length: Desired username length (default 16, max 100 for base36)
        encoding: Output encoding (10=numeric, 36=alphanumeric, 64=base64)
        nonce: Optional random nonce for non-recoverable usernames
        
    Returns:
        Deterministic username string
    """
    key_bytes = secret_salt.encode('utf-8')
    # Include nonce in message if provided (makes username non-recoverable without nonce)
    message = f"{label}:{nonce}" if nonce else label
    message_bytes = message.encode('utf-8')
    raw_hash = hmac.new(key_bytes, message_bytes, hashlib.sha3_512).digest()
    username = encode_hash(raw_hash, encoding)
    return username[:length]


def generate_username(
    label: str,
    secret_salt: str,
    length: int = 16,
    encoding: int = 36,
    nonce: Optional[str] = None,
) -> str:
    """Generate username (legacy SHA256 wrapper for backward compatibility).
    
    This function is deprecated. Use generate_username_v1_sha512() or parse
    the label to determine the correct algorithm.
    
    Args:
        label: Service identifier or full label
        secret_salt: High-entropy secret key
        length: Desired username length (default 16)
        encoding: Output encoding (10=numeric, 36=alphanumeric, 64=base64)
        nonce: Optional random nonce for non-recoverable usernames
        
    Returns:
        Deterministic username string
    """
    return generate_username_v1_sha256(label, secret_salt, length, encoding, nonce)


def verify_username(
    label: str,
    username: str,
    secret_salt: str,
    encoding: int = 36,
    nonce: Optional[str] = None,
) -> bool:
    """Verify a username was generated from the given label and salt.
    
    Uses constant-time comparison to prevent timing attacks.
    
    Args:
        label: Original service identifier or full label
        username: Username to verify
        secret_salt: Secret salt used for generation
        encoding: Output encoding (10=numeric, 36=alphanumeric, 64=base64)
        nonce: Optional nonce if username was generated with nonce mode
        
    Returns:
        True if username matches, False otherwise
    """
    expected = generate_username(label, secret_salt, len(username), encoding, nonce)
    return secrets.compare_digest(username, expected)


class LabelParser:
    """Compatibility wrapper for BastionLabel.
    
    New Label Format: v1:USER:SHA512:L16:github.com:2025-11-30|K
    
    This class provides backward compatibility while using the new
    BastionLabel specification under the hood.
    
    NOTE: Owner is no longer stored in labels. Store owner in 1Password
    metadata section instead.
    """
    
    # Algorithm normalization map
    ALGORITHM_MAP = {
        'sha256': 'SHA256',
        'sha512': 'SHA512',
        'sha3': 'SHA3-512',
        'sha3-512': 'SHA3-512',
    }
    
    # Reverse map for compatibility
    ALGORITHM_REVERSE = {
        'SHA256': 'sha256',
        'SHA512': 'sha512',
        'SHA3-512': 'sha3-512',
    }
    
    def __init__(self, label: str):
        """Parse a label string.
        
        Accepts both new format (v1:USER:SHA512:L16:github.com:2025-11-30)
        and legacy format (v1:sha512:owner:domain:date) for compatibility.
        
        Args:
            label: Full label string
        """
        self.raw_label = label
        self._bastion_label: Optional[BastionLabel] = None
        self.version: Optional[str] = None
        self.algorithm: Optional[str] = None
        self.owner: Optional[str] = None  # Deprecated: always empty for new labels
        self.domain: Optional[str] = None
        self.date: Optional[str] = None
        self.length: int = 16  # Default length
        self._parse()
    
    def _parse(self) -> None:
        """Parse label components."""
        # Try parsing as new hierarchical BastionLabel format (Bastion/TYPE/ALGO:...)
        if self.raw_label.startswith('Bastion/'):
            try:
                self._bastion_label = BastionLabel.parse(self.raw_label)
                self.version = self._bastion_label.get_param('version', '1')
                # Map hierarchical algo back to simple name
                algo_reverse = {
                    'SHA2/256': 'sha256',
                    'SHA2/512': 'sha512',
                    'SHA3/256': 'sha3-256',
                    'SHA3/512': 'sha3-512',
                }
                self.algorithm = algo_reverse.get(
                    self._bastion_label.algo, 
                    self._bastion_label.algo.lower().replace('/', '-')
                )
                self.owner = ''  # Owner not in new format
                self.domain = self._bastion_label.ident
                self.date = self._bastion_label.date
                # Extract length from params
                length_val = self._bastion_label.get_param('length', 16)
                self.length = int(length_val) if length_val else 16
                return
            except ValueError:
                pass
        
        # Try old BastionLabel format (v1:USER:ALGO:PARAMS:IDENT:DATE)
        parts = self.raw_label.split(':')
        if len(parts) >= 6 and parts[1] == 'USER':
            try:
                # Old format - convert to new for parsing
                self.version = parts[0].lstrip('v') or '1'
                self.algorithm = self.ALGORITHM_REVERSE.get(parts[2], parts[2].lower())
                self.owner = ''
                self.domain = parts[4]
                self.date = parts[5].split('|')[0]  # Strip check digit
                # Extract length from old params format (L16)
                if parts[3]:
                    params = decode_params(parts[3])
                    self.length = int(params.get('length', 16))
                return
            except (ValueError, IndexError):
                pass
        
        # Legacy format: v1:sha512:owner:domain:date
        if len(parts) >= 5:
            self.version = parts[0]
            algo_raw = parts[1].lower()
            self.algorithm = algo_raw if algo_raw in ('sha256', 'sha512', 'sha3-512') else 'sha512'
            self.owner = parts[2]
            self.domain = parts[3]
            self.date = parts[4]
        elif len(parts) == 1:
            # Very legacy: simple label (no version/algorithm)
            self.version = 'legacy'
            self.algorithm = 'sha256'
            self.domain = parts[0]
    
    def is_valid(self) -> bool:
        """Check if label is valid.
        
        Returns:
            True if label has all required components
        """
        if self._bastion_label:
            return len(self._bastion_label.validate()) == 0
        return all([self.version, self.algorithm, self.domain, self.date])
    
    def get_generation_function(self):
        """Get the appropriate generation function for this label's algorithm.
        
        Returns:
            Callable generation function
            
        Raises:
            ValueError: If algorithm is unknown
        """
        algo = self.algorithm.lower() if self.algorithm else 'sha512'
        if algo == 'sha256':
            return generate_username_v1_sha256
        elif algo == 'sha512':
            return generate_username_v1_sha512
        elif algo in ('sha3-512', 'sha3'):
            return generate_username_v1_sha3_512
        else:
            raise ValueError(f"Unknown algorithm: {self.algorithm}")
    
    def get_max_length(self) -> int:
        """Get maximum username length for this algorithm.
        
        Returns:
            Maximum length (51 for SHA256, 100 for SHA512/SHA3-512)
        """
        algo = self.algorithm.lower() if self.algorithm else 'sha512'
        if algo == 'sha256':
            return 51
        else:
            return 100
    
    @staticmethod
    def build_label(
        version: str,
        algorithm: str,
        domain: str,
        date: str,
        length: int = 16,
        owner: str = '',  # Deprecated: ignored, kept for compatibility
        with_check: bool = True,
        nonce: Optional[str] = None,
        encoding: int = 36,
        bastion_version: Optional[str] = None,
    ) -> str:
        """Build a label from components using new BastionLabel format.
        
        New format: Bastion/USER/ALGO:IDENT:DATE#PARAMS|CHECK
        
        Args:
            version: Version (ignored - bastion_version used instead)
            algorithm: Algorithm name (sha256, sha512, sha3-512)
            domain: Domain/URL (e.g., "github.com")
            date: Date in ISO format (YYYY-MM-DD)
            length: Username length (default 16)
            owner: DEPRECATED - ignored, kept for API compatibility
            with_check: Include Luhn check digit (default True)
            nonce: Optional random nonce for non-recoverable usernames (stolen seed protection)
            encoding: Output encoding (10, 36, 64)
            bastion_version: Bastion tool version (e.g., "0.3.0") - stored as VERSION param
            
        Returns:
            Formatted label string in new BastionLabel format
        """
        # Map algorithm to new hierarchical format
        algo_map = {
            'sha256': 'SHA2/256',
            'sha512': 'SHA2/512',
            'sha3-512': 'SHA3/512',
            'sha3-256': 'SHA3/256',
        }
        algo_hier = algo_map.get(algorithm.lower(), algorithm.upper())
        
        # Build params string (URL query-string format, canonical order)
        # VERSION = Bastion tool SemVer (required)
        params_parts = []
        from . import __version__
        version_str = bastion_version or __version__
        params_parts.append(f'VERSION={version_str}')
        if nonce:
            params_parts.append(f'NONCE={nonce}')
        params_parts.append(f'LENGTH={length}')
        if encoding != 36:
            params_parts.append(f'ENCODING={encoding}')
        params = '&'.join(params_parts)
        
        # Create BastionLabel with new format
        label = BastionLabel(
            tool='Bastion',
            type='USER',
            algo=algo_hier,
            ident=domain,
            date=date,
            params=params,
        )
        
        return label.build(with_check=with_check)


class UsernameGeneratorConfig:
    """Configuration manager for username generator stored in 1Password Secure Note.
    
    Config is stored in a Secure Note titled "Bastion Username Generator Config"
    with JSON content containing default_owner, default_algorithm, default_length,
    and service_rules.
    """
    
    CONFIG_ITEM_TITLE = "Bastion Username Generator Config"
    DEFAULT_CONFIG = {
        "default_owner": "",
        "default_algorithm": "sha512",  # SHA-512: hardware acceleration, universal support
        "default_length": 16,
        "service_rules": {
            "github": {"max": 39},
            "twitter": {"max": 15},
            "instagram": {"max": 30},
            "aws": {"min": 1, "max": 64},
        }
    }
    
    def __init__(self):
        """Initialize config manager."""
        self._cached_config: Optional[dict] = None
    
    def load_config_from_1password(self) -> dict:
        """Load configuration from 1Password Secure Note.
        
        Returns:
            Configuration dictionary
            
        Raises:
            RuntimeError: If load fails
        """
        if self._cached_config:
            return self._cached_config
        
        try:
            result = subprocess.run(
                ["op", "item", "get", self.CONFIG_ITEM_TITLE, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            item_data = json.loads(result.stdout)
            
            # Extract config from section fields
            config = {
                "default_owner": "",
                "default_algorithm": "sha512",
                "default_length": 16,
                "service_rules": {}
            }
            
            for field in item_data.get("fields", []):
                section = field.get("section", {})
                section_label = section.get("label", "") if section else ""
                field_label = field.get("label", "")
                field_value = field.get("value")
                
                if section_label == "Defaults":
                    if field_label == "owner":
                        config["default_owner"] = field_value or ""
                    elif field_label == "algorithm":
                        config["default_algorithm"] = field_value or "sha512"
                    elif field_label == "length":
                        config["default_length"] = int(field_value) if field_value else 16
                
                elif section_label.startswith("Service Rules: "):
                    service = section_label.replace("Service Rules: ", "")
                    if service not in config["service_rules"]:
                        config["service_rules"][service] = {}
                    if field_label in ["min", "max"]:
                        config["service_rules"][service][field_label] = int(field_value) if field_value else 0
            
            self._cached_config = config
            return config
            
        except subprocess.CalledProcessError:
            # Item doesn't exist, create it
            return self._create_default_config()
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise RuntimeError(f"Failed to parse config: {e}") from e
    
    def _create_default_config(self) -> dict:
        """Create default config in 1Password.
        
        Returns:
            Default configuration dictionary
        """
        # Auto-detect owner from 1Password account
        owner = self._detect_owner()
        config = self.DEFAULT_CONFIG.copy()
        config["default_owner"] = owner
        
        # Build field list using native 1Password sections
        fields = [
            "--category", "Secure Note",
            "--title", self.CONFIG_ITEM_TITLE,
            "--tags", "Bastion/CONFIG",
            # Defaults section
            f"Defaults.owner[text]={owner}",
            f"Defaults.algorithm[text]={config['default_algorithm']}",
            f"Defaults.length[text]={config['default_length']}",
        ]
        
        # Add service rules as separate sections
        for service, rules in config.get("service_rules", {}).items():
            section_name = f"Service Rules: {service}"
            if "max" in rules:
                fields.append(f"{section_name}.max[text]={rules['max']}")
            if "min" in rules:
                fields.append(f"{section_name}.min[text]={rules['min']}")
        
        fields.extend(["--format", "json"])
        
        try:
            subprocess.run(
                ["op", "item", "create"] + fields,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            self._cached_config = config
            return config
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to create config: {e.stderr}") from e
    
    def _detect_owner(self) -> str:
        """Detect owner email from 1Password account.
        
        Returns:
            Email address or empty string if detection fails
        """
        try:
            result = subprocess.run(
                ["op", "account", "get", "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            account_data = json.loads(result.stdout)
            return account_data.get("email", "")
            
        except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError):
            return ""
    
    def save_config_to_1password(self, config: dict) -> None:
        """Save configuration to 1Password Secure Note.
        
        Args:
            config: Configuration dictionary to save
            
        Raises:
            RuntimeError: If save fails
        """
        # Build edit fields using sections
        fields = [
            f"Defaults.owner[text]={config.get('default_owner', '')}",
            f"Defaults.algorithm[text]={config.get('default_algorithm', 'sha512')}",
            f"Defaults.length[text]={config.get('default_length', 16)}",
        ]
        
        # Add service rules
        for service, rules in config.get("service_rules", {}).items():
            section_name = f"Service Rules: {service}"
            if "max" in rules:
                fields.append(f"{section_name}.max[text]={rules['max']}")
            if "min" in rules:
                fields.append(f"{section_name}.min[text]={rules['min']}")
        
        try:
            subprocess.run(
                ["op", "item", "edit", self.CONFIG_ITEM_TITLE] + fields,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            self._cached_config = config
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to save config: {e.stderr}") from e
    
    def get_default_owner(self) -> str:
        """Get default owner from config.
        
        Returns:
            Owner email address
        """
        config = self.load_config_from_1password()
        return config.get("default_owner", "")
    
    def get_default_algorithm(self) -> str:
        """Get default algorithm from config.
        
        Returns:
            Algorithm name (e.g., "sha512")
        """
        config = self.load_config_from_1password()
        return config.get("default_algorithm", "sha512")
    
    def get_default_length(self) -> int:
        """Get default length from config.
        
        Returns:
            Default username length
        """
        config = self.load_config_from_1password()
        return config.get("default_length", 16)
    
    def get_service_rules(self) -> dict:
        """Get service-specific rules from config.
        
        Returns:
            Dictionary of service_name -> constraints
        """
        config = self.load_config_from_1password()
        return config.get("service_rules", {})
    
    def set_default_owner(self, owner: str) -> None:
        """Set default owner in config.
        
        Args:
            owner: Owner email address
        """
        config = self.load_config_from_1password()
        config["default_owner"] = owner
        self.save_config_to_1password(config)
    
    def set_default_algorithm(self, algorithm: str) -> None:
        """Set default algorithm in config.
        
        Args:
            algorithm: Algorithm name (sha256, sha512, sha3-512)
        """
        config = self.load_config_from_1password()
        config["default_algorithm"] = algorithm
        self.save_config_to_1password(config)
    
    def set_default_length(self, length: int) -> None:
        """Set default length in config.
        
        Args:
            length: Default username length
        """
        config = self.load_config_from_1password()
        config["default_length"] = length
        self.save_config_to_1password(config)
    
    def get_service_max_length(self, service: str) -> Optional[int]:
        """Get maximum length for a specific service.
        
        Args:
            service: Service name (e.g., 'github', 'twitter')
            
        Returns:
            Maximum length, or None if not defined
        """
        service_rules = self.get_service_rules()
        service_config = service_rules.get(service, {})
        return service_config.get("max")


class UsernameGenerator:
    """Username generator with 1Password integration."""
    
    SALT_ITEM_PREFIX = "Bastion Salt"
    SALT_TAG = "Bastion/SALT"
    
    def __init__(self, op_client=None, config: Optional[UsernameGeneratorConfig] = None):
        """Initialize generator.
        
        Args:
            op_client: Optional OpClient instance. If None, uses subprocess directly.
            config: Optional config instance. If None, creates new one.
        """
        self.op_client = op_client
        self.config = config or UsernameGeneratorConfig()
        self._cached_salt: Optional[tuple[str, str]] = None  # (salt_value, salt_uuid)
    
    def find_highest_serial_number(self, version: str = "v1") -> int:
        """Find the highest serial number for salt items of a given version.
        
        Args:
            version: Version string (e.g., "v1")
            
        Returns:
            Highest serial number found, or 0 if none exist
        """
        try:
            # List all items with salt tag
            result = subprocess.run(
                ["op", "item", "list", "--tags", self.SALT_TAG, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            items = json.loads(result.stdout)
            
            # Parse serial numbers from titles - format: "Bastion Username Generator Salt #123"
            serial_pattern = re.compile(rf'{re.escape(self.SALT_ITEM_PREFIX)} #(\d+)')
            max_serial = 0
            
            for item in items:
                title = item.get("title", "")
                match = serial_pattern.search(title)
                if match:
                    serial = int(match.group(1))
                    max_serial = max(max_serial, serial)
            
            return max_serial
            
        except (subprocess.CalledProcessError, json.JSONDecodeError, ValueError):
            return 0
    
    def get_latest_salt_by_serial(
        self,
        version: str = "v1",
        algorithm: str = "sha512"
    ) -> Optional[tuple[str, str, int]]:
        """Get the latest salt item by highest serial number.
        
        Args:
            version: Version string (e.g., "v1")
            algorithm: Algorithm name for filtering
            
        Returns:
            Tuple of (salt_value, salt_uuid, serial_number) or None if not found
        """
        if self._cached_salt:
            return (self._cached_salt[0], self._cached_salt[1], 0)  # Return cached (serial unknown)
        
        try:
            highest_serial = self.find_highest_serial_number(version)
            
            if highest_serial == 0:
                return None
            
            # Get the item with highest serial
            title = f"{self.SALT_ITEM_PREFIX} #{highest_serial}"
            
            result = subprocess.run(
                ["op", "item", "get", title, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            item_data = json.loads(result.stdout)
            salt_uuid = item_data.get("id", "")
            
            # Extract password field (salt value)
            for field in item_data.get("fields", []):
                if field.get("id") == "password" and field.get("value"):
                    salt_value = field["value"]
                    self._cached_salt = (salt_value, salt_uuid)
                    return (salt_value, salt_uuid, highest_serial)
            
            return None
            
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return None
    
    def get_salt_from_1password(
        self,
        salt_uuid: Optional[str] = None
    ) -> Optional[tuple[str, str]]:
        """Retrieve salt from 1Password by UUID or get latest.
        
        Args:
            salt_uuid: Optional specific salt UUID to retrieve
            
        Returns:
            Tuple of (salt_value, salt_uuid) or None if not found
        """
        if salt_uuid:
            # Get specific salt by UUID
            try:
                result = subprocess.run(
                    ["op", "item", "get", salt_uuid, "--format", "json"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
                
                item_data = json.loads(result.stdout)
                
                for field in item_data.get("fields", []):
                    if field.get("id") == "password" and field.get("value"):
                        return (field["value"], salt_uuid)
                
                return None
                
            except (subprocess.CalledProcessError, json.JSONDecodeError):
                return None
        else:
            # Get latest salt by serial number
            result = self.get_latest_salt_by_serial()
            if result:
                return (result[0], result[1])
            return None
    
    def create_salt_item(
        self,
        salt: Optional[str] = None,
        vault: str = "Private",
        version: str = "v1",
        algorithm: str = "sha512",
        entropy_pool_uuid: Optional[str] = None,
    ) -> tuple[str, str, int]:
        """Create a new salt item in 1Password with serial number.
        
        The salt can be provided directly, derived from an entropy pool stored
        in 1Password, or generated using Python's cryptographically secure RNG.
        
        Args:
            salt: Secret salt to store (hex string). If None, derives from
                  entropy_pool_uuid or generates a secure random value.
            vault: Vault name to store in (default: "Private")
            version: Version string (default: "v1")
            algorithm: Algorithm name (default: "sha512")
            entropy_pool_uuid: UUID of entropy pool to derive salt from.
                              If provided, salt is derived using HKDF-SHA512
                              and the entropy pool is marked as consumed.
            
        Returns:
            Tuple of (salt_value, salt_uuid, serial_number)
            
        Raises:
            RuntimeError: If creation fails or entropy pool is invalid
        """
        import secrets
        from .entropy import derive_salt_from_entropy_pool
        
        # Track derivation metadata
        entropy_source_uuid = None
        derivation_label = None
        
        if salt is None:
            if entropy_pool_uuid:
                # Derive salt from entropy pool using HKDF-SHA512
                salt_bytes, entropy_source_uuid, derivation_label = derive_salt_from_entropy_pool(
                    entropy_pool_uuid=entropy_pool_uuid,
                    ident="username-generator",
                )
                salt = salt_bytes.hex()
            else:
                # Generate 512-bit (64 byte) random salt using system RNG
                salt = secrets.token_hex(64)
        
        # Find next serial number (simple increment, no padding, no limit)
        highest_serial = self.find_highest_serial_number(version)
        next_serial = highest_serial + 1
        
        # Build title (version in metadata, not title)
        title = f"{self.SALT_ITEM_PREFIX} #{next_serial}"
        
        # Build field list
        fields = [
            "op", "item", "create",
            "--category", "password",
            "--title", title,
            "--vault", vault,
            f"password={salt}",
            "--tags", self.SALT_TAG,
            # Salt Info section (Title Case field names)
            f"Salt Info.Version[text]={version}",
            f"Salt Info.Serial Number[text]={next_serial}",
            f"Salt Info.Algorithm[text]={algorithm}",
        ]
        
        # Add derivation metadata if derived from entropy pool
        if entropy_source_uuid:
            fields.extend([
                f"Derivation.Entropy Source UUID[text]={entropy_source_uuid}",
                f"Derivation.Label[text]={derivation_label}",
                "Derivation.Method[text]=HKDF-SHA512",
                "Derivation.Output Length[text]=512 bits",
            ])
        else:
            fields.append("Derivation.Source[text]=system RNG (secrets.token_hex)")
        
        fields.extend(["--format", "json"])
        
        try:
            # Create password item with salt using sections
            result = subprocess.run(
                fields,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            item_data = json.loads(result.stdout)
            salt_uuid = item_data.get("id", "")
            
            self._cached_salt = (salt, salt_uuid)
            return (salt, salt_uuid, next_serial)
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to create salt item: {e.stderr}") from e
    
    def generate(
        self,
        label: str,
        length: int = 16,
        salt_uuid: Optional[str] = None,
        nonce: Optional[str] = None,
        encoding: int = 36,
    ) -> str:
        """Generate a username for the given service label.
        
        Retrieves the salt from 1Password and generates a deterministic username
        using the algorithm specified in the label.
        
        Args:
            label: Full label (e.g., "Bastion/USER/SHA2/512:domain:date#PARAMS")
            length: Desired username length (default 16)
            salt_uuid: Optional specific salt UUID to use
            nonce: Optional nonce for non-recoverable usernames (stolen seed protection)
            encoding: Output encoding (10=numeric, 36=alphanumeric, 64=base64)
            
        Returns:
            Generated username
            
        Raises:
            RuntimeError: If salt is not found in 1Password
            ValueError: If label is invalid or algorithm unknown
        """
        # Parse label
        parser = LabelParser(label)
        
        if not parser.is_valid():
            raise ValueError(f"Invalid label format: {label}")
        
        # Get salt
        salt_result = self.get_salt_from_1password(salt_uuid)
        
        if not salt_result:
            raise RuntimeError(
                "Salt item not found in 1Password. "
                "Run 'bastion generate username --init' to create it."
            )
        
        salt_value, _ = salt_result
        
        # Get generation function for algorithm
        gen_func = parser.get_generation_function()
        
        # Validate length
        max_length = parser.get_max_length()
        if length > max_length:
            raise ValueError(f"Length {length} exceeds maximum {max_length} for {parser.algorithm}")
        
        return gen_func(label, salt_value, length, encoding, nonce)
    
    def verify(
        self,
        label: str,
        username: str,
        salt_uuid: Optional[str] = None,
        nonce: Optional[str] = None,
        encoding: int = 36,
    ) -> bool:
        """Verify a username was generated from the given label.
        
        Args:
            label: Full label string
            username: Username to verify
            salt_uuid: Optional specific salt UUID to use
            nonce: Optional nonce if username was generated with nonce mode
            encoding: Output encoding used (10, 36, or 64)
            
        Returns:
            True if username matches, False otherwise
            
        Raises:
            RuntimeError: If salt is not found in 1Password
        """
        salt_result = self.get_salt_from_1password(salt_uuid)
        
        if not salt_result:
            raise RuntimeError("Salt item not found in 1Password")
        
        salt_value, _ = salt_result
        
        expected = self.generate(label, len(username), salt_uuid, nonce, encoding)
        return username == expected
    
    def check_label_collision(self, label: str) -> Optional[dict]:
        """Check if a label already exists in 1Password.
        
        Args:
            label: Full label to check for duplicates
            
        Returns:
            Dictionary with collision info (title, uuid) or None if no collision
        """
        try:
            # Search for items with Bastion/USER tag (all generated usernames)
            result = subprocess.run(
                ["op", "item", "list", "--tags", "Bastion/USER", "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            items = json.loads(result.stdout)
            
            # Check each item for matching label
            for item in items:
                item_uuid = item.get("id", "")
                item_title = item.get("title", "")
                
                # Get full item details to check custom fields
                detail_result = subprocess.run(
                    ["op", "item", "get", item_uuid, "--format", "json"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
                
                detail_data = json.loads(detail_result.stdout)
                
                # Check username_label field
                for field in detail_data.get("fields", []):
                    if field.get("label") == "username_label" and field.get("value") == label:
                        return {
                            "title": item_title,
                            "uuid": item_uuid,
                            "label": label
                        }
            
            return None
            
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return None
    
    def suggest_collision_suffix(self, label: str) -> list[str]:
        """Suggest alternative labels for collision resolution.
        
        Args:
            label: Original colliding label
            
        Returns:
            List of suggested alternative labels with suffix variations
        """
        parser = LabelParser(label)
        if not parser.is_valid():
            return []
        
        suggestions = []
        
        # Try suffixes on the date: 2025-11-21-b, 2025-11-21-c, etc.
        for letter in "bcdefghij":  # First 10 suggestions
            new_label = LabelParser.build_label(
                version=parser.version,
                algorithm=parser.algorithm,
                domain=parser.domain,
                date=f"{parser.date}-{letter}",
                length=parser.length,
            )
            suggestions.append(new_label)
        
        return suggestions
    
    def create_login_with_username(
        self,
        title: str,
        label: str,
        website: str = "",
        vault: str = "Private",
        length: int = 16,
        tags: list[str] | None = None,
        salt_uuid: Optional[str] = None,
    ) -> dict:
        """Create a 1Password login item with generated username and full metadata.
        
        Args:
            title: Display title for the login item
            label: Full label for username generation (e.g., "v1:sha3-512:owner:service:date")
            website: Optional website URL
            vault: Vault name (default: "Private")
            length: Username length (default: 16)
            tags: Optional list of tags to add
            salt_uuid: Optional specific salt UUID to use
            
        Returns:
            Dictionary with item details including 'uuid', 'username', 'label', 'salt_uuid', etc.
            
        Raises:
            RuntimeError: If creation fails or salt not found
            ValueError: If label is invalid
        """
        # Parse label for algorithm info
        parser = LabelParser(label)
        
        if not parser.is_valid():
            raise ValueError(f"Invalid label format: {label}")
        
        # Get salt and UUID
        salt_result = self.get_salt_from_1password(salt_uuid)
        
        if not salt_result:
            raise RuntimeError("Salt item not found in 1Password")
        
        _, used_salt_uuid = salt_result
        
        # Generate username
        username = self.generate(label, length, salt_uuid)
        
        # Build tags list from parsed label hierarchy
        # Tag format: Bastion/USER/SHA2/512 (algorithm hierarchy)
        # Build tags list from parsed label hierarchy
        # Tag format: Bastion/USER/SHA2/512 (algorithm hierarchy)
        bl = parser._bastion_label  # Access internal BastionLabel
        generated_tag = bl.tag() if bl else "Bastion/USER"
        all_tags = [generated_tag]
        if tags:
            all_tags.extend(tags)
        
        # Build op item create command
        cmd = [
            "op", "item", "create",
            "--category", "login",
            "--title", title,
            "--vault", vault,
            f"username={username}",
            f"url={website}" if website else "",
            "--tags", ",".join(all_tags),
            "--format", "json",
        ]
        
        # Remove empty url if not provided
        cmd = [arg for arg in cmd if arg]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            item_data = json.loads(result.stdout)
            uuid = item_data.get("id")
            
            # Build metadata edit command with unified Bastion Label section
            # and separate Salt section (fields in label order)
            edit_args = [
                "op", "item", "edit", uuid,
                # Bastion Label section - all label components in order
                f"Bastion Label.Label[text]={label}",
                f"Bastion Label.Type[text]={bl.type if bl else 'USER'}",
                f"Bastion Label.Algorithm[text]={bl.algo if bl else ''}",
                f"Bastion Label.Identifier[text]={bl.ident if bl else ''}",
                f"Bastion Label.Date[text]={bl.date if bl else ''}",
                f"Bastion Label.Version[text]={bl.get_param('version', '1') if bl else '1'}",
                f"Bastion Label.Length[text]={bl.get_param('length', length) if bl else length}",
                # Salt section - reference to salt item
                f"Salt.UUID[text]={used_salt_uuid}",
            ]
            
            subprocess.run(
                edit_args,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            return {
                "uuid": uuid,
                "title": title,
                "username": username,
                "label": label,
                "salt_uuid": used_salt_uuid,
                "vault": vault,
                "tag": bl.tag() if bl else generated_tag,
                "algorithm": bl.algo if bl else "SHA2/512",
                "length": bl.get_param('length', length) if bl else length,
            }
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to create login item: {e.stderr}") from e
