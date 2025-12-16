#!/usr/bin/env python3
"""
Configuration constants for Seeder system.
Centralized configuration to support easy modification and testing.
"""

from typing import List

# === CRYPTOGRAPHIC CONSTANTS ===
DEFAULT_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"  # BIP-39 test vector
DEFAULT_PASSPHRASE = ""
DEFAULT_PBKDF2_ITERATIONS = 2048

# === GRID CONFIGURATION ===
TOKENS_WIDE = 10        # A-J columns
TOKENS_TALL = 10        # 0-9 rows  
CHARS_PER_TOKEN = 4     # 4 characters per token

# === BASE90 ALPHABET ===
# Excludes problematic characters: space, quotes, backslash, backtick
ALPHABET: List[str] = list(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz" 
    "0123456789"
    "!#$%&()*+,-./:;<=>?@[]^_{|}~"
)
ALPHABET_SIZE = len(ALPHABET)  # 90

# === HMAC LABELS ===
HMAC_LABEL_TOKENS = b"SEEDER-TOKENS"
HMAC_LABEL_DIGEST = b"SEEDER-DIGEST" 
HMAC_LABEL_SLIP39 = b"SEEDER-SLIP39"

# === ARGON2 KDF CONFIGURATION ===
# Default parameters for Argon2id key derivation
# 2GB memory = maximum protection against GPU/ASIC attacks
ARGON2_TIME_COST = 3           # Iterations (t)
ARGON2_MEMORY_COST_MB = 2048   # Memory in MB (2GB default)
ARGON2_MEMORY_COST_KB = ARGON2_MEMORY_COST_MB * 1024  # Memory in KB for argon2-cffi
ARGON2_PARALLELISM = 4         # Threads (p) - fallback if auto-detection fails
ARGON2_HASH_LENGTH = 64        # Output bytes (matches current 64-byte seed)
ARGON2_TYPE = "argon2id"       # Recommended variant (hybrid of argon2i/argon2d)
ARGON2_MAX_PARALLELISM = 16    # Cap auto-detected parallelism

def get_auto_parallelism() -> int:
    """Auto-detect optimal parallelism based on CPU cores, capped at 16.
    
    This matches the web app's behavior for cross-platform consistency.
    More lanes = more memory-hard, but slower if lanes > cores.
    
    Returns:
        Number of parallel lanes (1-16)
    """
    import os
    cores = os.cpu_count()
    if cores is None:
        return ARGON2_PARALLELISM  # Fallback to default
    return min(cores, ARGON2_MAX_PARALLELISM)

# Nonce configuration for unique card derivation
NONCE_BYTES = 6                # 6 bytes = 48 bits entropy (Base64 = 8 chars)

# Test constants for cross-platform verification
# These use 64MB memory for browser compatibility (production uses 2GB)
TEST_NONCE = "TESTNONC"        # 8-char deterministic nonce for test vectors
TEST_ARGON2_TIME = 3
TEST_ARGON2_MEMORY_MB = 64     # 64MB for browser compatibility
TEST_ARGON2_PARALLELISM = 4
TEST_ARGON2_PARAMS = f"TIME={TEST_ARGON2_TIME}&MEMORY={TEST_ARGON2_MEMORY_MB}&PARALLELISM={TEST_ARGON2_PARALLELISM}"

# Label format version
LABEL_VERSION = "v1"

# Bastion-style Argon2 parameter encoding using URL query-string format
# Format: TIME=3&MEMORY=2048&PARALLELISM=4
# Canonical order: TIME, MEMORY, PARALLELISM (alphabetical within Argon2 params)
def encode_argon2_params(time_cost: int = ARGON2_TIME_COST, 
                         memory_mb: int = ARGON2_MEMORY_COST_MB,
                         parallelism: int = ARGON2_PARALLELISM) -> str:
    """Encode Argon2 parameters in Bastion URL-style format: TIME=3&MEMORY=2048&PARALLELISM=4"""
    return f"TIME={time_cost}&MEMORY={memory_mb}&PARALLELISM={parallelism}"

def decode_argon2_params(encoded: str) -> tuple[int, int, int]:
    """Decode Argon2 params from Bastion URL-style format.
    
    Format: TIME=3&MEMORY=2048&PARALLELISM=4
    
    Returns (time_cost, memory_mb, parallelism).
    
    Raises:
        ValueError: If format is invalid or missing required params
    """
    if '=' not in encoded:
        raise ValueError(f"Invalid Argon2 params format (expected URL-style): {encoded}")
    
    params = {}
    for part in encoded.split('&'):
        if '=' in part:
            key, value = part.split('=', 1)
            params[key.upper()] = value
    
    if 'TIME' in params and 'MEMORY' in params and 'PARALLELISM' in params:
        return int(params['TIME']), int(params['MEMORY']), int(params['PARALLELISM'])
    raise ValueError(f"Missing required Argon2 params (TIME, MEMORY, PARALLELISM) in: {encoded}")

# === BASE CONFIGURATIONS ===
# Define multiple base systems for token generation
BASE_CONFIGS = {
    "base10": {
        "alphabet": list("0123456789"),
        "name": "Base10 (Digits)",
        "description": "PIN codes using digits 0-9",
    },
    "base62": {
        "alphabet": list(
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
        ),
        "name": "Base62 (Alphanumeric)",
        "description": "Tokens using digits and letters (case-sensitive)",
    },
    "base90": {
        "alphabet": ALPHABET,
        "name": "Base90 (Mixed)",
        "description": "Full 90-character alphabet including special characters",
    },
}

# Default base (for backward compatibility)
DEFAULT_BASE = "base90"

# Calculate stream buffer size based on alphabet for rejection sampling
# Formula: (alphabet_size / 256) * chars_per_token * chars_per_token * grid_width * grid_tall * overhead_factor
def get_stream_buffer_size(alphabet_size: int) -> int:
    """Calculate required stream buffer size for given alphabet size."""
    # For rejection sampling: max_usable = floor(256 / alphabet_size) * alphabet_size
    # Expected rejection rate increases as alphabet_size decreases
    # Conservative estimate: 4096 bytes handles even Base10 comfortably
    return 4096

STREAM_BUFFER_SIZE = 4096  # Conservative byte buffer for token generation

# === CSV FORMAT ===
CSV_DEFAULT_FILENAME = "token_matrices.csv"
CSV_HEADERS = ["ID", "DATE", "SHORT_HASH", "SHA512", "TOKENS", "ENCODING"]

# === COORDINATE SYSTEM ===
# Spreadsheet convention: letter=column (A-J), number=row (0-9)
# A0=top-left, J0=top-right, A9=bottom-left, J9=bottom-right
def coordinate_to_indices(coord: str) -> tuple[int, int]:
    """Convert A0-J9 coordinate to (row, col) indices.
    
    Spreadsheet convention: letter=column (A-J), number=row (0-9)
    Returns (row, col) for matrix[row][col] access.
    """
    if len(coord) != 2:
        raise ValueError(f"Invalid coordinate format: {coord}")
    
    col_char = coord[0].upper()  # Letter = column
    row_char = coord[1]          # Number = row
    
    if col_char < 'A' or col_char > 'J':
        raise ValueError(f"Invalid column: {col_char}")
    if not row_char.isdigit() or int(row_char) > 9:
        raise ValueError(f"Invalid row: {row_char}")
        
    col = ord(col_char) - ord('A')
    row = int(row_char)
    
    return (row, col)

def indices_to_coordinate(row: int, col: int) -> str:
    """Convert (row, col) indices to A0-J9 coordinate.
    
    Spreadsheet convention: letter=column (A-J), number=row (0-9)
    """
    if row < 0 or row >= TOKENS_TALL:
        raise ValueError(f"Invalid row index: {row}")
    if col < 0 or col >= TOKENS_WIDE:
        raise ValueError(f"Invalid column index: {col}")
        
    col_char = chr(ord('A') + col)
    return f"{col_char}{row}"

# === VALIDATION ===
def validate_config() -> None:
    """Validate configuration constants for consistency."""
    assert ALPHABET_SIZE == 90, f"Expected ALPHABET_SIZE=90, got {ALPHABET_SIZE}"
    assert TOKENS_WIDE == 10, f"Expected TOKENS_WIDE=10, got {TOKENS_WIDE}"
    assert TOKENS_TALL == 10, f"Expected TOKENS_TALL=10, got {TOKENS_TALL}"
    assert CHARS_PER_TOKEN == 4, f"Expected CHARS_PER_TOKEN=4, got {CHARS_PER_TOKEN}"
    assert len(set(ALPHABET)) == ALPHABET_SIZE, "Alphabet contains duplicates"
    
    # Verify problematic characters are excluded
    excluded_chars = [' ', '"', "'", '\\', '`']
    for char in excluded_chars:
        assert char not in ALPHABET, f"Problematic character '{char}' found in alphabet"

if __name__ == "__main__":
    validate_config()
    print("✓ Configuration validation passed")
