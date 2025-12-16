#!/usr/bin/env python3
"""
Core cryptographic functions for Seeder system.
Handles HMAC stream generation, Base90 conversion, and unbiased sampling.
"""

import base64
import hashlib
import hmac
import math
import os
import re
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

from .config import (
    ALPHABET,
    ALPHABET_SIZE,
    ARGON2_MEMORY_COST_MB,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    CHARS_PER_TOKEN,
    HMAC_LABEL_TOKENS,
    LABEL_VERSION,
    NONCE_BYTES,
    STREAM_BUFFER_SIZE,
    decode_argon2_params,
    encode_argon2_params,
)

# === LUHN MOD-36 CHECK DIGIT ===

# Luhn mod-36 alphabet: 0-9, A-Z (uppercase)
LUHN_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LUHN_BASE = 36


def luhn_mod36_check(body: str) -> str:
    """
    Compute Luhn mod-36 check digit for a label body.
    
    Uses the Luhn mod N algorithm with N=36 and alphabet [0-9A-Z].
    The check digit detects single-character errors and adjacent transpositions.
    
    Args:
        body: Label string to compute check digit for
        
    Returns:
        Single character check digit from LUHN_ALPHABET
    """
    # Convert body to uppercase for consistent mapping
    body_upper = body.upper()
    
    # Map each character to its position in the alphabet
    # Characters not in alphabet are mapped by their Unicode codepoint mod 36
    def char_to_value(c: str) -> int:
        idx = LUHN_ALPHABET.find(c)
        if idx >= 0:
            return idx
        return ord(c) % LUHN_BASE
    
    total = 0
    # Process from right to left, doubling every second digit
    for i, c in enumerate(reversed(body_upper)):
        value = char_to_value(c)
        if i % 2 == 1:
            # Double and sum digits if >= base
            value *= 2
            if value >= LUHN_BASE:
                value = (value // LUHN_BASE) + (value % LUHN_BASE)
        total += value
    
    # Check digit makes total divisible by base
    check_value = (LUHN_BASE - (total % LUHN_BASE)) % LUHN_BASE
    return LUHN_ALPHABET[check_value]


def luhn_mod36_validate(label: str) -> tuple[bool, str]:
    """
    Validate and strip Luhn mod-36 check digit from a label.
    
    Labels with check digit have format: BODY|CHECK
    Labels without check digit are returned as-is (valid but unverified).
    
    Args:
        label: Full label string, optionally with |CHECK suffix
        
    Returns:
        Tuple of (is_valid, body_without_check)
        - If label has check digit: validates it, returns (valid, body)
        - If label has no check digit: returns (True, label)
    """
    if "|" not in label:
        # No check digit, return as-is (unverified but valid format)
        return True, label
    
    # Find the last | which separates body from check digit
    last_pipe = label.rfind("|")
    body = label[:last_pipe]
    check = label[last_pipe + 1:]
    
    # Check digit should be single character
    if len(check) != 1:
        return False, body
    
    expected = luhn_mod36_check(body)
    return check.upper() == expected, body


def build_label_with_check(body: str) -> str:
    """
    Append Luhn mod-36 check digit to a label body.
    
    Args:
        body: Label body (colon-separated fields)
        
    Returns:
        Complete label with |CHECK suffix
    """
    check = luhn_mod36_check(body)
    return f"{body}|{check}"


# === NONCE AND LABEL UTILITIES ===

def generate_nonce(num_bytes: int = NONCE_BYTES) -> str:
    """
    Generate a cryptographically random nonce encoded as URL-safe Base64.
    
    Args:
        num_bytes: Number of random bytes (default 6 = 48 bits)
        
    Returns:
        URL-safe Base64 encoded string (no padding, no +/)
    """
    random_bytes = os.urandom(num_bytes)
    # Use URL-safe Base64, strip padding
    return base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')


def build_label(
    seed_type: str,
    kdf: str = "ARGON2ID",
    kdf_params: Optional[str] = None,
    base: str = "BASE90",
    date: Optional[str] = None,
    nonce: Optional[str] = None,
    card_id: Optional[str] = None,
    card_index: str = "A0",
) -> str:
    """
    Build a complete v1 label string for deterministic derivation (Argon2 salt).
    
    Bastion Label Format: Bastion/TOKEN/ALGO:IDENT:DATE#PARAMS|CHECK
    
    Uses URL-style parameter encoding with & separator and = assignment.
    Parameter order is canonical: VERSION, TIME, MEMORY, PARALLELISM, NONCE, ENCODING
    
    Example: Bastion/TOKEN/SIMPLE-ARGON2ID:banking.A0:2025-11-28#VERSION=1&TIME=3&MEMORY=2048&PARALLELISM=8&NONCE=Kx7mQ9bL&ENCODING=90|X
    
    Args:
        seed_type: SIMPLE, BIP39, or SLIP39
        kdf: KDF algorithm (ARGON2ID, PBKDF2, SHA512)
        kdf_params: Encoded KDF params in Bastion format (TIME=3&MEMORY=2048&PARALLELISM=4)
        base: BASE10, BASE62, or BASE90
        date: Full date YYYY-MM-DD (optional)
        nonce: URL-safe Base64 nonce (optional, auto-generated if None)
        card_id: User-defined card identifier (lowercase recommended)
        card_index: Card index as grid coordinate A0-J9 (default "A0")
        
    Returns:
        Complete label string with Luhn check digit
    """
    if kdf_params is None:
        kdf_params = encode_argon2_params()
    
    if nonce is None:
        nonce = generate_nonce()
    
    # Parse params (Bastion format only)
    time_cost, memory_mb, parallelism = decode_argon2_params(kdf_params)
    
    # Build ALGO: SEED_TYPE-KDF (e.g., SIMPLE-ARGON2ID)
    algo = f"{seed_type.upper()}-{kdf.upper()}"
    
    # Build IDENT: {card_id}.{card_index} (lowercase card_id recommended)
    ident = f"{(card_id or 'card').lower()}.{card_index or 'A0'}"
    
    # Extract encoding number from base (BASE90 -> 90)
    encoding = base.upper().replace("BASE", "")
    
    # Build PARAMS in Bastion canonical order using URL-style format
    # Order: VERSION, TIME, MEMORY, PARALLELISM, NONCE, ENCODING
    params = f"VERSION=1&TIME={time_cost}&MEMORY={memory_mb}&PARALLELISM={parallelism}&NONCE={nonce}&ENCODING={encoding}"
    
    # Build body: Bastion/TOKEN/ALGO:IDENT:DATE#PARAMS
    body = f"Bastion/TOKEN/{algo}:{ident}:{date or ''}#{params}"
    
    # Append Luhn check digit
    return build_label_with_check(body)


def build_hmac_label(card_index: str, token_coord: str) -> str:
    """
    Build HMAC info label for per-token domain separation.
    
    Bastion Format: Bastion/TOKEN/HMAC:{card_index}.{token_coord}#VERSION=1|CHECK
    
    Example: Bastion/TOKEN/HMAC:A0.B3#VERSION=1|Y
    
    This ensures each token position derives unique bytes even with same seed.
    
    Args:
        card_index: Card index as grid coordinate (A0-J9)
        token_coord: Token coordinate within the card (A0-J9)
        
    Returns:
        HMAC info label string with Luhn check digit
    """
    # Build IDENT: {card_index}.{token_coord}
    ident = f"{card_index or 'A0'}.{token_coord}"
    
    # Build body: Bastion/TOKEN/HMAC:IDENT:#VERSION=1
    # Note: DATE field is empty for HMAC labels
    body = f"Bastion/TOKEN/HMAC:{ident}:#VERSION=1"
    
    return build_label_with_check(body)


def parse_hmac_label(label: str) -> Dict[str, str]:
    """
    Parse an HMAC info label.
    
    Bastion format only: Bastion/TOKEN/HMAC:A0.B3:#VERSION=1|Y
    
    Args:
        label: HMAC label string
        
    Returns:
        Dictionary with version, card_index, token_coord
        
    Raises:
        ValueError: If label format is invalid
    """
    # Bastion format (starts with Bastion/)
    if not label.startswith("Bastion/"):
        raise ValueError(f"Invalid HMAC label format: expected 'Bastion/' prefix, got: {label}")
    
    # Validate and strip Luhn check digit
    is_valid, body = luhn_mod36_validate(label)
    if not is_valid:
        raise ValueError(f"Invalid Luhn check digit in label: {label}")
    
    # Parse: Bastion/TOKEN/HMAC:IDENT:#VERSION=1
    if "#" not in body:
        raise ValueError(f"Invalid Bastion HMAC label format: missing # params")
    
    metadata, params_str = body.split("#", 1)
    
    # Parse metadata: Bastion/TOKEN/HMAC:IDENT:
    slash_parts = metadata.split("/")
    if len(slash_parts) < 3:
        raise ValueError(f"Invalid Bastion HMAC label: missing Tool/TYPE/ALGO")
    
    # Get algo and rest after second slash
    algo_and_rest = "/".join(slash_parts[2:])
    colon_parts = algo_and_rest.split(":")
    
    if len(colon_parts) < 2 or colon_parts[0] != "HMAC":
        raise ValueError(f"Invalid HMAC label format: {label}")
    
    ident = colon_parts[1]
    ident_parts = ident.split(".")
    if len(ident_parts) != 2:
        raise ValueError(f"Invalid HMAC label IDENT: {ident}")
    
    # Parse version from params
    params_dict = _parse_url_params(params_str)
    
    return {
        "version": str(params_dict.get("version", "1")),
        "card_index": ident_parts[0],
        "token_coord": ident_parts[1],
    }


def parse_label(label: str) -> Dict[str, Any]:
    """
    Parse a label string into its components.
    
    Bastion format only: Bastion/TOKEN/ALGO:IDENT:DATE#PARAMS|CHECK
    
    Args:
        label: Complete label string
        
    Returns:
        Dictionary with parsed components
        
    Raises:
        ValueError: If label format is invalid
    """
    if not label.startswith("Bastion/"):
        raise ValueError(f"Invalid label format: expected 'Bastion/' prefix, got: {label}")
    
    return _parse_new_bastion_label(label)


def _parse_new_bastion_label(label: str) -> Dict[str, Any]:
    """
    Parse the Bastion format label.
    
    Format: Bastion/TOKEN/ALGO:IDENT:DATE#PARAMS|CHECK
    - ALGO: SEED_TYPE-KDF (e.g., SIMPLE-ARGON2ID)
    - IDENT: {card_id}.{card_index}
    - PARAMS: URL-style VERSION=1&TIME=3&MEMORY=2048&PARALLELISM=8&NONCE=Kx7mQ9bL&ENCODING=90
    
    Example: Bastion/TOKEN/SIMPLE-ARGON2ID:banking.A0:2025-11-28#VERSION=1&TIME=3&MEMORY=2048&PARALLELISM=8&NONCE=Kx7mQ9bL&ENCODING=90|X
    """
    # Validate and strip Luhn check digit
    is_valid, body = luhn_mod36_validate(label)
    if not is_valid:
        raise ValueError(f"Invalid Luhn check digit in label: {label}")
    
    # Split on # to separate metadata from params
    if "#" not in body:
        raise ValueError(f"Invalid Bastion label format: missing # params separator")
    
    metadata, params_str = body.split("#", 1)
    
    # Parse metadata: Seeder/TOKEN/ALGO:IDENT:DATE
    # Split by "/" first to get tool/type/algo, then by ":" for the rest
    slash_parts = metadata.split("/")
    if len(slash_parts) < 3:
        raise ValueError(f"Invalid Bastion label format: expected Tool/TYPE/ALGO prefix")
    
    tool = slash_parts[0]
    label_type = slash_parts[1]
    
    # Everything after second "/" contains ALGO:IDENT:DATE
    algo_and_rest = "/".join(slash_parts[2:])
    colon_parts = algo_and_rest.split(":")
    
    if len(colon_parts) != 3:
        raise ValueError(f"Invalid Bastion label format: expected ALGO:IDENT:DATE, got {len(colon_parts)} parts")
    
    algo = colon_parts[0]
    ident = colon_parts[1]
    date = colon_parts[2] if colon_parts[2] else None
    
    # Parse ALGO: SEED_TYPE-KDF
    algo_parts = algo.split("-", 1)
    if len(algo_parts) != 2:
        raise ValueError(f"Invalid ALGO format: {algo}")
    seed_type, kdf = algo_parts
    
    # Parse IDENT: {card_id}.{card_index}
    ident_parts = ident.rsplit(".", 1)
    if len(ident_parts) != 2:
        raise ValueError(f"Invalid IDENT format: {ident}")
    card_id, card_index = ident_parts
    
    # Parse PARAMS (URL-style)
    params_dict = _parse_url_params(params_str)
    
    # Build base from encoding
    encoding = params_dict.get("encoding", "90")
    base = f"BASE{encoding}"
    
    result = {
        "version": str(params_dict.get("version", "1")),
        "type": label_type,
        "tool": tool,
        "seed_type": seed_type.upper(),
        "kdf": kdf.upper(),
        "kdf_params": f"TIME={params_dict.get('time', 3)}&MEMORY={params_dict.get('memory', 2048)}&PARALLELISM={params_dict.get('parallelism', 4)}",
        "base": base,
        "date": date,
        "nonce": params_dict.get("nonce", ""),
        "card_id": card_id.upper() if card_id else "CARD",
        "card_index": card_index.upper() if card_index else "A0",
    }
    
    # Add parsed Argon2 params
    if kdf.upper() in ("ARGON2", "ARGON2ID"):
        result["argon2_time"] = params_dict.get("time", 3)
        result["argon2_memory_mb"] = params_dict.get("memory", 2048)
        result["argon2_parallelism"] = params_dict.get("parallelism", 4)
    
    return result


def _parse_url_params(params_str: str) -> Dict[str, Any]:
    """
    Parse URL-style parameters.
    
    Format: KEY=value&KEY=value&...
    Example: VERSION=1&TIME=3&MEMORY=2048&PARALLELISM=8&NONCE=Kx7mQ9bL&ENCODING=90
    
    Returns dict with lowercase keys and appropriate value types.
    """
    result: Dict[str, Any] = {}
    
    for part in params_str.split("&"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key_lower = key.lower()
        
        # Convert numeric values
        if key_lower in ("version", "time", "memory", "parallelism", "encoding"):
            try:
                result[key_lower] = int(value)
            except ValueError:
                result[key_lower] = value
        else:
            result[key_lower] = value
    
    return result


class SeedCardCrypto:
    """Core cryptographic operations for deterministic token generation."""
    
    @staticmethod
    def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
        """
        HKDF-Expand function per RFC 5869.
        
        Expands a pseudorandom key (PRK) into output keying material using
        HMAC-SHA512. This is the standard HKDF expand phase with chained blocks.
        
        Args:
            prk: Pseudorandom key (should be at least hash_len bytes)
            info: Context/application-specific info (can be empty)
            length: Desired output length in bytes
            
        Returns:
            Output keying material of specified length
            
        Raises:
            ValueError: If length exceeds maximum (255 * hash_len)
        """
        hash_len = 64  # SHA-512 output size
        max_length = 255 * hash_len
        
        if length > max_length:
            raise ValueError(f"HKDF-Expand length {length} exceeds maximum {max_length}")
        
        # Number of blocks needed
        n = (length + hash_len - 1) // hash_len
        
        okm = b""
        t = b""
        
        for i in range(1, n + 1):
            # T(i) = HMAC(PRK, T(i-1) || info || i)
            # Each block chains the previous block's output
            t = hmac.new(prk, t + info + bytes([i]), hashlib.sha512).digest()
            okm += t
        
        return okm[:length]
    
    @staticmethod
    def hkdf_stream(seed_bytes: bytes, info_label: bytes, needed_bytes: int, card_id: Optional[str] = None) -> bytes:
        """
        Generate deterministic byte stream using standard HKDF-Expand (RFC 5869).
        
        Note: We skip HKDF-Extract because our seed is already a uniformly random
        64-byte value from Argon2id (which produces indistinguishable-from-random output).
        Using the Argon2 output directly as PRK is cryptographically safe.
        
        Args:
            seed_bytes: 64-byte seed from Argon2id (used directly as PRK)
            info_label: Context label for domain separation
            needed_bytes: Number of bytes to generate
            card_id: Optional card ID to incorporate into info_label
            
        Returns:
            Deterministic byte stream of requested length
        """
        if len(seed_bytes) != 64:
            raise ValueError(f"Expected 64-byte seed, got {len(seed_bytes)} bytes")
        
        # Incorporate card_id into info_label for domain separation
        working_info = info_label
        if card_id:
            working_info = info_label + b"-" + card_id.encode('utf-8')
        
        return SeedCardCrypto.hkdf_expand(seed_bytes, working_info, needed_bytes)
    
    # Backward compatibility alias
    @staticmethod
    def hkdf_like_stream(seed_bytes: bytes, info_label: bytes, needed_bytes: int, card_id: Optional[str] = None) -> bytes:
        """
        Generate deterministic byte stream using standard HKDF-Expand (RFC 5869).
        
        This method is an alias for hkdf_stream() maintained for backward compatibility.
        The implementation now uses standard HKDF-Expand with chained HMAC-SHA512.
        
        Args:
            seed_bytes: 64-byte seed from Argon2id
            info_label: Context label (e.g., b"v1|A0|TOKEN|B3")
            needed_bytes: Number of bytes to generate
            card_id: Optional card ID for domain separation
            
        Returns:
            Deterministic byte stream of requested length
        """
        return SeedCardCrypto.hkdf_stream(seed_bytes, info_label, needed_bytes, card_id)
    
    @staticmethod
    def byte_to_symbol(byte_value: int, alphabet_size: int) -> Optional[int]:
        """
        Map byte value to alphabet index using rejection sampling.
        
        Args:
            byte_value: Single byte value (0-255)
            alphabet_size: Size of target alphabet
            
        Returns:
            Alphabet index if byte is usable, None if rejected
        """
        if not (0 <= byte_value <= 255):
            raise ValueError(f"Byte value must be 0-255, got {byte_value}")
        
        # Calculate maximum usable value to avoid modulo bias
        max_usable = (256 // alphabet_size) * alphabet_size
        
        if byte_value < max_usable:
            return byte_value % alphabet_size
        else:
            return None  # Reject this byte
    
    @classmethod
    def generate_token_from_stream(cls, byte_stream_iter: Iterator[int], 
                                   alphabet: Optional[List[str]] = None) -> str:
        """
        Generate a single token from byte stream using rejection sampling.
        
        Args:
            byte_stream_iter: Iterator over byte values
            alphabet: List of characters to map to (defaults to BASE90 ALPHABET)
            
        Returns:
            Token string of length CHARS_PER_TOKEN
            
        Raises:
            RuntimeError: If insufficient entropy bytes available
        """
        if alphabet is None:
            alphabet = ALPHABET
            
        token_chars: List[str] = []
        alphabet_size = len(alphabet)
        
        while len(token_chars) < CHARS_PER_TOKEN:
            try:
                byte_val = next(byte_stream_iter)
            except StopIteration as exc:
                raise RuntimeError("Out of entropy bytes unexpectedly") from exc
            
            symbol_index = cls.byte_to_symbol(byte_val, alphabet_size)
            if symbol_index is not None:
                token_chars.append(alphabet[symbol_index])
        
        return "".join(token_chars)
    
    @classmethod
    def generate_token_stream(cls, seed_bytes: bytes, num_tokens: int, 
                            card_id: Optional[str] = None, 
                            alphabet: Optional[List[str]] = None,
                            card_index: str = "A0") -> List[str]:
        """
        Generate a stream of tokens from seed material using per-token HMAC labels.
        
        Each token is generated with a unique HMAC info label for domain separation:
        - Format: v1|{card_index}|TOKEN|{token_coord}
        - This matches the web app's token generation for cross-platform compatibility
        
        Args:
            seed_bytes: 64-byte seed material
            num_tokens: Number of tokens to generate (typically 100 for 10x10 grid)
            card_id: Optional card ID (unused, kept for backward compatibility)
            alphabet: List of characters to use (defaults to BASE90 ALPHABET)
            card_index: Card index for batch generation (A0-J9), default "A0"
            
        Returns:
            List of generated tokens in row-major order (A0, B0, ..., J0, A1, ..., J9)
        """
        if alphabet is None:
            alphabet = ALPHABET
        
        from .config import TOKENS_TALL, TOKENS_WIDE
        
        tokens = []
        token_count = 0
        
        # Generate each token with unique HMAC label matching web app format
        for row in range(TOKENS_TALL):
            for col in range(TOKENS_WIDE):
                if token_count >= num_tokens:
                    return tokens
                    
                # Spreadsheet convention: letter=column (A-J), number=row (0-9)
                token_coord = f"{chr(ord('A') + col)}{row}"
                
                # Build per-token HMAC label: v1|{card_index}|TOKEN|{token_coord}
                hmac_label = build_hmac_label(card_index, token_coord)
                
                # Generate byte stream for this specific token
                # 64 bytes is plenty for ~20 bytes needed per token with rejection sampling
                byte_stream = cls.hkdf_like_stream(
                    seed_bytes, 
                    hmac_label.encode('utf-8'),
                    64
                )
                byte_iter = iter(byte_stream)
                
                token = cls.generate_token_from_stream(byte_iter, alphabet)
                tokens.append(token)
                token_count += 1
        
        return tokens


class SeedCardDigest:
    """Generate integrity digests and verification hashes."""
    
    @staticmethod
    def generate_sha512_hash(seed_bytes: bytes) -> str:
        """Generate SHA-512 hex digest of seed bytes for integrity verification."""
        return hashlib.sha512(seed_bytes).hexdigest()
    
    @staticmethod
    def generate_hmac_digest(seed_bytes: bytes, label: bytes) -> str:
        """Generate HMAC-SHA512 digest for specific label."""
        digest = hmac.new(seed_bytes, label, hashlib.sha512).digest()
        return digest.hex()


class PasswordEntropyAnalyzer:
    """Analyze entropy and security properties of passwords generated from coordinate patterns."""
    
    @staticmethod
    def calculate_token_entropy(alphabet_size: Optional[int] = None) -> float:
        """
        Calculate bits of entropy per token.
        
        Args:
            alphabet_size: Size of alphabet (defaults to BASE90)
            
        Returns:
            Bits of entropy per 4-character token
        """
        if alphabet_size is None:
            alphabet_size = ALPHABET_SIZE
        return math.log2(alphabet_size ** CHARS_PER_TOKEN)
    
    @staticmethod
    def calculate_password_entropy(num_tokens: int, alphabet_size: Optional[int] = None) -> float:
        """
        Calculate total entropy for a password with given number of tokens.
        
        Args:
            num_tokens: Number of tokens in password
            alphabet_size: Size of alphabet (defaults to BASE90)
            
        Returns:
            Total bits of entropy
        """
        token_entropy = PasswordEntropyAnalyzer.calculate_token_entropy(alphabet_size)
        return token_entropy * num_tokens
    
    @staticmethod
    def calculate_memorized_word_entropy(word_length: int, charset_size: int = 26) -> float:
        """Calculate entropy for a memorized word component."""
        return math.log2(charset_size ** word_length)
    
    @staticmethod
    def calculate_punctuation_entropy(num_punctuation: int, charset_size: int = 32) -> float:
        """Calculate entropy for punctuation separators."""
        return math.log2(charset_size ** num_punctuation)
    
    @staticmethod
    def calculate_rolling_token_entropy(rotation_period_days: int = 90) -> float:
        """
        Calculate additional entropy from rolling/rotating tokens.
        
        Args:
            rotation_period_days: How often the rolling component changes
        """
        # This represents the timing uncertainty for an attacker
        # Conservative estimate: attacker knows approximate time period
        time_uncertainty_bits = math.log2(rotation_period_days / 7)  # Weekly uncertainty
        return max(1.0, time_uncertainty_bits)  # Minimum 1 bit
    
    @staticmethod
    def analyze_composite_password(
        num_fixed_tokens: int = 2,
        num_rolling_tokens: int = 1, 
        memorized_word_length: int = 6,
        num_separators: int = 4,
        rotation_days: int = 90,
        include_order_entropy: bool = True
    ) -> Dict[str, Union[str, int, bool]]:
        """
        Analyze composite password formats like: TokenA-TokenB-TokenC-MemWord!
        
        Args:
            num_fixed_tokens: Number of static tokens from grid
            num_rolling_tokens: Number of tokens that change periodically
            memorized_word_length: Length of memorized word component
            num_separators: Number of punctuation/separator characters
            rotation_days: How often rolling tokens change
            include_order_entropy: Whether to include component ordering entropy
        """
        # Calculate individual components
        fixed_token_entropy = PasswordEntropyAnalyzer.calculate_password_entropy(num_fixed_tokens)
        rolling_token_entropy = PasswordEntropyAnalyzer.calculate_password_entropy(num_rolling_tokens)
        rolling_time_entropy = PasswordEntropyAnalyzer.calculate_rolling_token_entropy(rotation_days)
        memorized_entropy = PasswordEntropyAnalyzer.calculate_memorized_word_entropy(memorized_word_length)
        separator_entropy = PasswordEntropyAnalyzer.calculate_punctuation_entropy(num_separators)
        
        # Component ordering entropy (if components can be rearranged)
        total_components = 3 + (1 if memorized_word_length > 0 else 0)  # tokens + rolling + memorized + separators
        order_entropy = math.log2(math.factorial(total_components)) if include_order_entropy else 0
        
        # Total entropy is sum of independent components
        total_entropy = (
            fixed_token_entropy + 
            rolling_token_entropy + 
            rolling_time_entropy +
            memorized_entropy + 
            separator_entropy +
            order_entropy
        )
        
        # Security classification (RFC 4086 compliant thresholds)
        # RFC 4086: "29 bits for online attacks, up to 96 bits for cryptographic keys"
        if total_entropy < 29:
            security_level = "INSUFFICIENT"
            security_color = "bright_red"
        elif total_entropy < 48:  # Online attack protection
            security_level = "BASIC"
            security_color = "yellow"
        elif total_entropy < 64:  # Strong offline protection  
            security_level = "GOOD"
            security_color = "green"
        elif total_entropy < 80:  # Very strong protection
            security_level = "STRONG"
            security_color = "bright_green"
        else:  # Approaching cryptographic key strength (96+ bits)
            security_level = "EXCELLENT"
            security_color = "bright_cyan"
        
        # Example password format
        example_format = []
        if num_fixed_tokens > 0:
            example_format.extend([f"Token{i+1}" for i in range(num_fixed_tokens)])
        if num_rolling_tokens > 0:
            example_format.extend([f"Roll{i+1}" for i in range(num_rolling_tokens)])
        if memorized_word_length > 0:
            example_format.append("MemWord")
        
        format_string = "-".join(example_format) if num_separators > 0 else "".join(example_format)
        
        return {
            "format_example": format_string,
            "total_components": total_components,
            "fixed_token_entropy": f"{fixed_token_entropy:.1f}",
            "rolling_token_entropy": f"{rolling_token_entropy:.1f}", 
            "rolling_time_entropy": f"{rolling_time_entropy:.1f}",
            "memorized_word_entropy": f"{memorized_entropy:.1f}",
            "separator_entropy": f"{separator_entropy:.1f}",
            "order_entropy": f"{order_entropy:.1f}",
            "total_entropy": f"{total_entropy:.1f}",
            "security_level": security_level,
            "security_color": security_color,
            "num_fixed_tokens": num_fixed_tokens,
            "num_rolling_tokens": num_rolling_tokens,
            "memorized_word_length": memorized_word_length,
            "num_separators": num_separators,
            "rotation_days": rotation_days,
            "include_order_entropy": include_order_entropy
        }
    
    @staticmethod
    def analyze_compromised_card_scenario(
        num_fixed_tokens: int = 2,
        num_rolling_tokens: int = 1, 
        memorized_word_length: int = 6,
        num_separators: int = 4,
        rotation_days: int = 90,
        include_order_entropy: bool = True
    ) -> Dict[str, Union[str, float]]:
        """
        Analyze security when the physical card is compromised but secrets remain.
        
        This models the threat scenario where an attacker has:
        - COMPROMISED: Physical card with all token values visible
        - SECRET: Memorized word, component order, rotation schedule, coordinate selection
        
        Args:
            Same as analyze_composite_password
            
        Returns:
            Dictionary with both total entropy and "card compromised" entropy
        """
        # Get full analysis first
        full_analysis = PasswordEntropyAnalyzer.analyze_composite_password(
            num_fixed_tokens, num_rolling_tokens, memorized_word_length,
            num_separators, rotation_days, include_order_entropy
        )
        
        # Calculate what remains secret if card is compromised
        # COMPROMISED: All token values are visible (entropy = 0 for tokens themselves)
        # SECRET: Which coordinates to use, memorized word, separators, order, timing
        
        # Coordinate selection entropy (which tokens to pick from 100 available)
        total_tokens = num_fixed_tokens + num_rolling_tokens
        if total_tokens > 0:
            coordinate_selection_entropy = math.log2(math.comb(100, total_tokens)) if total_tokens <= 100 else 0
        else:
            coordinate_selection_entropy = 0
        
        # Rolling schedule uncertainty (when to rotate)
        rolling_schedule_entropy = PasswordEntropyAnalyzer.calculate_rolling_token_entropy(rotation_days)
        
        # Memorized components remain fully secret
        memorized_entropy = PasswordEntropyAnalyzer.calculate_memorized_word_entropy(memorized_word_length)
        
        # Separator choice remains secret
        separator_entropy = PasswordEntropyAnalyzer.calculate_punctuation_entropy(num_separators)
        
        # Component ordering remains secret
        total_components = 2 + (1 if memorized_word_length > 0 else 0)  # tokens + memorized + separators
        order_entropy = math.log2(math.factorial(total_components)) if include_order_entropy else 0
        
        # Total "card compromised" entropy
        card_compromised_entropy = (
            coordinate_selection_entropy +
            rolling_schedule_entropy + 
            memorized_entropy +
            separator_entropy +
            order_entropy
        )
        
        # Security assessment for compromised scenario (RFC 4086 compliant)
        if card_compromised_entropy < 20:
            compromised_security_level = "CRITICAL"
            compromised_security_color = "bright_red"
        elif card_compromised_entropy < 29:  # Below RFC 4086 minimum
            compromised_security_level = "INSUFFICIENT" 
            compromised_security_color = "red"
        elif card_compromised_entropy < 48:  # Online attack protection
            compromised_security_level = "BASIC"
            compromised_security_color = "yellow"
        elif card_compromised_entropy < 64:  # Strong offline protection
            compromised_security_level = "GOOD"
            compromised_security_color = "green"
        else:  # Strong protection even when compromised
            compromised_security_level = "STRONG"
            compromised_security_color = "bright_green"
        
        # Calculate the vulnerability ratio
        total_entropy = float(full_analysis["total_entropy"])
        vulnerability_ratio = (total_entropy - card_compromised_entropy) / total_entropy
        
        return {
            # Full scenario (no compromise)
            "full_entropy": full_analysis["total_entropy"],
            "full_security_level": full_analysis["security_level"],
            "full_security_color": full_analysis["security_color"],
            
            # Card compromised scenario
            "compromised_entropy": f"{card_compromised_entropy:.1f}",
            "compromised_security_level": compromised_security_level,
            "compromised_security_color": compromised_security_color,
            
            # Breakdown of what remains secret
            "coordinate_selection_entropy": f"{coordinate_selection_entropy:.1f}",
            "rolling_schedule_entropy": f"{rolling_schedule_entropy:.1f}",
            "memorized_entropy": f"{memorized_entropy:.1f}",
            "separator_entropy": f"{separator_entropy:.1f}",
            "order_entropy": f"{order_entropy:.1f}",
            
            # Vulnerability analysis
            "vulnerability_ratio": f"{vulnerability_ratio:.1%}",
            "entropy_loss": f"{total_entropy - card_compromised_entropy:.1f}",
            
            # Component details
            "num_fixed_tokens": num_fixed_tokens,
            "num_rolling_tokens": num_rolling_tokens,
            "memorized_word_length": memorized_word_length,
            "num_separators": num_separators,
            "total_tokens": total_tokens,
            "format_example": full_analysis["format_example"]
        }
    
    @staticmethod
    def estimate_crack_time(entropy_bits: float, guesses_per_second: int = 1000) -> Dict[str, str]:
        """
        Estimate time to crack password given entropy and attack rate.
        
        Args:
            entropy_bits: Password entropy in bits
            guesses_per_second: Attack rate (default: 1000 for rate-limited online attacks)
                               Modern hardware: 7B+ guesses/sec (GPU), 100K+ guesses/sec (CPU)
            
        Returns:
            Dictionary with time estimates for 50% and 99% probability of cracking
        """
        total_combinations = 2 ** entropy_bits
        
        # Time to crack with 50% probability (half the keyspace)
        avg_time_seconds = (total_combinations / 2) / guesses_per_second
        
        # Time to crack with 99% probability (nearly full keyspace)
        worst_time_seconds = (total_combinations * 0.99) / guesses_per_second
        
        def format_time(seconds: float) -> str:
            """Format seconds into human-readable time."""
            if seconds < 60:
                return f"{seconds:.1f} seconds"
            elif seconds < 3600:
                return f"{seconds/60:.1f} minutes"
            elif seconds < 86400:
                return f"{seconds/3600:.1f} hours"
            elif seconds < 31536000:
                return f"{seconds/86400:.1f} days"
            else:
                years = seconds / 31536000
                if years < 1000:
                    return f"{years:.1f} years"
                elif years < 1000000:
                    return f"{years/1000:.1f} thousand years"
                elif years < 1000000000:
                    return f"{years/1000000:.1f} million years"
                else:
                    return f"{years/1000000000:.1f} billion years"
        
        return {
            "entropy_bits": f"{entropy_bits:.1f}",
            "total_combinations": f"{total_combinations:.2e}",
            "avg_crack_time": format_time(avg_time_seconds),
            "worst_crack_time": format_time(worst_time_seconds),
            "guesses_per_second": f"{guesses_per_second:,}"
        }
    
    @staticmethod
    def analyze_coordinate_pattern(coordinates: List[str]) -> Dict[str, Any]:
        """
        Analyze the entropy and security properties of a coordinate pattern.
        
        Args:
            coordinates: List of coordinate strings like ["A0", "B1", "C2", "D3"]
            
        Returns:
            Dictionary with comprehensive analysis
        """
        num_tokens = len(coordinates)
        token_entropy = PasswordEntropyAnalyzer.calculate_token_entropy()
        total_entropy = PasswordEntropyAnalyzer.calculate_password_entropy(num_tokens)
        
        # Calculate pattern entropy (predictability of coordinate selection)
        total_grid_positions = 100  # 10x10 grid
        pattern_combinations = math.comb(total_grid_positions, num_tokens) if num_tokens <= total_grid_positions else 0
        pattern_entropy = math.log2(pattern_combinations) if pattern_combinations > 0 else 0
        
        # Effective entropy is limited by the weaker of token or pattern entropy
        effective_entropy = min(total_entropy, pattern_entropy)
        
        # Security levels based on RFC 4086 entropy thresholds
        if effective_entropy < 29:
            security_level = "INSUFFICIENT" 
            security_color = "bright_red"
        elif effective_entropy < 48:
            security_level = "BASIC"
            security_color = "yellow"
        elif effective_entropy < 64:
            security_level = "GOOD"
            security_color = "green"
        elif effective_entropy < 80:
            security_level = "STRONG"
            security_color = "bright_green"
        else:
            security_level = "EXCELLENT"
            security_color = "bright_cyan"
        
        # Attack scenarios (2025 threat model)
        # Note: Modern GPU attacks can achieve 7B+ guesses/sec for simple hashes
        # We use conservative rates assuming proper key stretching/salting
        online_attack = PasswordEntropyAnalyzer.estimate_crack_time(effective_entropy, 1000)  # Rate-limited online
        offline_attack = PasswordEntropyAnalyzer.estimate_crack_time(effective_entropy, 1000000)  # Conservative offline
        
        return {
            "coordinates": coordinates,
            "num_tokens": num_tokens,
            "token_entropy_bits": f"{token_entropy:.1f}",
            "total_token_entropy": f"{total_entropy:.1f}",
            "pattern_entropy_bits": f"{pattern_entropy:.1f}",
            "effective_entropy_bits": f"{effective_entropy:.1f}",
            "security_level": security_level,
            "security_color": security_color,
            "pattern_combinations": f"{pattern_combinations:,}" if pattern_combinations > 0 else "Invalid",
            "online_attack": online_attack,
            "offline_attack": offline_attack,
            "alphabet_size": ALPHABET_SIZE,
            "chars_per_token": CHARS_PER_TOKEN
        }


# === REJECTION SAMPLING ANALYSIS ===
def analyze_rejection_rate(alphabet_size: int = ALPHABET_SIZE) -> Dict[str, Union[int, float, str]]:
    """
    Analyze rejection sampling statistics for given alphabet size.
    
    Returns:
        Dictionary with rejection rate analysis
    """
    max_usable = (256 // alphabet_size) * alphabet_size
    rejected_count = 256 - max_usable
    rejection_rate = (rejected_count / 256) * 100
    
    return {
        "alphabet_size": alphabet_size,
        "max_usable_byte": max_usable - 1,
        "rejected_bytes": rejected_count,
        "rejection_rate_percent": round(rejection_rate, 1),
        "accepted_range": f"0-{max_usable - 1}",
        "rejected_range": f"{max_usable}-255" if rejected_count > 0 else "None"
    }


if __name__ == "__main__":
    # Demonstration of rejection sampling
    analysis = analyze_rejection_rate()
    print("Base90 Rejection Sampling Analysis:")
    print(f"Alphabet size: {analysis['alphabet_size']}")
    print(f"Rejection rate: {analysis['rejection_rate_percent']}%")
    print(f"Accepted bytes: {analysis['accepted_range']}")
    print(f"Rejected bytes: {analysis['rejected_range']}")
