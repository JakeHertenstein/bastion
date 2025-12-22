"""SLIP-39 Shamir secret sharing implementation.

This module provides SLIP-39 share generation and recovery with:
- 256-bit master secrets (24-word Cryptosteel-compatible mnemonics)
- Configurable threshold schemes (default: 3-of-5 single group)
- Mandatory re-entry verification workflow
- Display-only shares (never written to disk)
- Sigchain audit events

Uses the Trezor shamir-mnemonic library for SLIP-39 operations.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from shamir_mnemonic import combine_mnemonics, generate_mnemonics
from shamir_mnemonic.share import Share

if TYPE_CHECKING:
    from .crypto import EntropyCollection


# =============================================================================
# CONFIGURATION
# =============================================================================


@dataclass
class SLIP39Config:
    """Configuration for SLIP-39 share generation.

    Defaults are optimized for Cryptosteel Capsule compatibility
    and estate planning use cases.

    Word counts (SLIP-39 standard):
    - 128 bits → 20 words per share (fits Cryptosteel's 24 slots) ← DEFAULT
    - 256 bits → 33 words per share (requires larger storage)
    """

    # Number of shares to generate
    total_shares: int = 5

    # Minimum shares required for recovery
    threshold: int = 3

    # Master secret size in bits (128 = 20 words, 256 = 33 words)
    # Default 128 bits for Cryptosteel Capsule compatibility
    secret_bits: int = 128

    # Optional passphrase (NOT recoverable from shares!)
    passphrase: str = ""

    # Group configuration (single group by default)
    # Format: list of (group_threshold, group_count) tuples
    # For single group 3-of-5: [(3, 5)]
    groups: list[tuple[int, int]] = field(default_factory=lambda: [(3, 5)])

    def __post_init__(self) -> None:
        """Validate configuration."""
        if self.threshold > self.total_shares:
            raise ValueError(
                f"Threshold ({self.threshold}) cannot exceed total shares ({self.total_shares})"
            )
        if self.threshold < 1:
            raise ValueError("Threshold must be at least 1")
        if self.total_shares < 2:
            raise ValueError("Must generate at least 2 shares")
        if self.secret_bits not in (128, 256):
            raise ValueError("Secret bits must be 128 (20 words) or 256 (33 words)")

        # Update groups based on threshold/total if using defaults
        if self.groups == [(3, 5)]:
            self.groups = [(self.threshold, self.total_shares)]

    @property
    def secret_bytes(self) -> int:
        """Number of bytes in master secret."""
        return self.secret_bits // 8

    @property
    def words_per_share(self) -> int:
        """Number of words in each mnemonic share.

        SLIP-39 formula: 20 words for 128-bit, 33 words for 256-bit.
        Each share includes checksum and metadata.
        """
        # 128 bits = 20 words, 256 bits = 33 words
        return 20 if self.secret_bits == 128 else 33


# =============================================================================
# SHARE DATA STRUCTURES
# =============================================================================


@dataclass
class SLIP39Share:
    """A single SLIP-39 share with metadata."""

    # The mnemonic words (space-separated)
    mnemonic: str

    # Share index (1-based for display)
    index: int

    # Total shares in set
    total: int

    # Threshold required
    threshold: int

    # Fingerprint for verification (truncated hash)
    fingerprint: str = ""

    # Creation timestamp
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        """Compute fingerprint if not provided."""
        if not self.fingerprint:
            self.fingerprint = compute_share_fingerprint(self.mnemonic)

    @property
    def words(self) -> list[str]:
        """Get mnemonic as word list."""
        return self.mnemonic.split()

    @property
    def word_count(self) -> int:
        """Number of words in mnemonic."""
        return len(self.words)


@dataclass
class SLIP39ShareSet:
    """Complete set of SLIP-39 shares from a single generation."""

    # All generated shares
    shares: list[SLIP39Share]

    # Configuration used
    config: SLIP39Config

    # Master secret fingerprint (for verification without revealing secret)
    master_fingerprint: str = ""

    # Generation timestamp
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def share_count(self) -> int:
        """Number of shares in set."""
        return len(self.shares)


# =============================================================================
# CORE OPERATIONS
# =============================================================================


def compute_share_fingerprint(mnemonic: str) -> str:
    """Compute a truncated fingerprint for share verification.

    Uses first 8 characters of SHA-256 hash.
    This allows verification without revealing the full share.

    Args:
        mnemonic: Space-separated mnemonic words

    Returns:
        8-character hex fingerprint
    """
    normalized = normalize_mnemonic(mnemonic)
    hash_bytes = hashlib.sha256(normalized.encode()).digest()
    return hash_bytes.hex()[:8]


def compute_master_fingerprint(master_secret: bytes) -> str:
    """Compute fingerprint for master secret.

    Args:
        master_secret: Raw master secret bytes

    Returns:
        8-character hex fingerprint
    """
    hash_bytes = hashlib.sha256(master_secret).digest()
    return hash_bytes.hex()[:8]


def normalize_mnemonic(mnemonic: str) -> str:
    """Normalize mnemonic for comparison.

    - Converts to lowercase
    - Collapses multiple spaces to single space
    - Strips leading/trailing whitespace

    Args:
        mnemonic: Input mnemonic string

    Returns:
        Normalized mnemonic
    """
    return " ".join(mnemonic.lower().split())


def verify_share_reentry(original: str, user_input: str) -> bool:
    """Verify user's re-entry matches original share.

    Performs exact match after normalization.

    Args:
        original: Original mnemonic from generation
        user_input: User's re-entered mnemonic

    Returns:
        True if exact match after normalization
    """
    return normalize_mnemonic(original) == normalize_mnemonic(user_input)


def validate_share(mnemonic: str) -> tuple[bool, str]:
    """Validate a SLIP-39 share mnemonic.

    Checks:
    - Word count (20 or 33 words)
    - All words in SLIP-39 wordlist
    - Checksum validity

    Args:
        mnemonic: Space-separated mnemonic words

    Returns:
        Tuple of (is_valid, error_message)
    """
    normalized = normalize_mnemonic(mnemonic)
    words = normalized.split()

    # Check word count
    if len(words) not in (20, 33):
        return False, f"Invalid word count: {len(words)} (expected 20 or 33)"

    # Try to parse as SLIP-39 share
    try:
        Share.from_mnemonic(normalized)
        return True, ""
    except Exception as e:
        return False, str(e)


def generate_shares(
    config: SLIP39Config | None = None,
    master_secret: bytes | None = None,
    entropy_source: EntropyCollection | None = None,
) -> SLIP39ShareSet:
    """Generate SLIP-39 Shamir shares.

    If master_secret is not provided, generates cryptographically
    random bytes using either the provided entropy source or
    system randomness.

    Args:
        config: Share configuration (uses defaults if None)
        master_secret: Optional pre-generated master secret
        entropy_source: Optional verified entropy for secret generation

    Returns:
        SLIP39ShareSet with all generated shares

    Raises:
        ValueError: If configuration is invalid
    """
    if config is None:
        config = SLIP39Config()

    # Generate or use provided master secret
    if master_secret is None:
        if entropy_source is not None:
            # Use verified entropy
            if len(entropy_source.data) < config.secret_bytes:
                raise ValueError(
                    f"Entropy source has {len(entropy_source.data)} bytes, "
                    f"need {config.secret_bytes} bytes"
                )
            master_secret = entropy_source.data[:config.secret_bytes]
        else:
            # Use system randomness
            master_secret = secrets.token_bytes(config.secret_bytes)

    # Validate master secret size
    if len(master_secret) != config.secret_bytes:
        raise ValueError(
            f"Master secret is {len(master_secret)} bytes, "
            f"expected {config.secret_bytes} bytes"
        )

    # Generate shares using shamir-mnemonic library
    # generate_mnemonics returns list of groups, each group is list of mnemonics
    passphrase_bytes = config.passphrase.encode() if config.passphrase else b""

    group_mnemonics = generate_mnemonics(
        group_threshold=1,  # Single group
        groups=config.groups,
        master_secret=master_secret,
        passphrase=passphrase_bytes,
    )

    # Flatten groups (we use single group)
    all_mnemonics = group_mnemonics[0] if group_mnemonics else []

    # Create share objects
    shares = []
    for i, mnemonic in enumerate(all_mnemonics):
        share = SLIP39Share(
            mnemonic=mnemonic,
            index=i + 1,
            total=config.total_shares,
            threshold=config.threshold,
        )
        shares.append(share)

    # Create share set
    share_set = SLIP39ShareSet(
        shares=shares,
        config=config,
        master_fingerprint=compute_master_fingerprint(master_secret),
    )

    return share_set


def recover_secret(
    mnemonics: list[str],
    passphrase: str = "",
) -> bytes:
    """Recover master secret from SLIP-39 shares.

    Requires at least threshold number of valid shares.

    Args:
        mnemonics: List of share mnemonics (threshold or more required)
        passphrase: Optional passphrase used during generation

    Returns:
        Recovered master secret bytes

    Raises:
        ValueError: If shares are invalid or insufficient
    """
    # Normalize all mnemonics
    normalized = [normalize_mnemonic(m) for m in mnemonics]

    # Validate all shares first
    for i, mnemonic in enumerate(normalized):
        is_valid, error = validate_share(mnemonic)
        if not is_valid:
            raise ValueError(f"Share {i + 1} is invalid: {error}")

    # Recover using shamir-mnemonic library
    passphrase_bytes = passphrase.encode() if passphrase else b""

    try:
        master_secret = combine_mnemonics(normalized, passphrase_bytes)
        return master_secret
    except Exception as e:
        raise ValueError(f"Recovery failed: {e}") from e


def verify_shares(share_set: SLIP39ShareSet) -> tuple[bool, str]:
    """Verify shares can reconstruct the original secret.

    Tests recovery using exactly threshold shares.

    Args:
        share_set: Share set to verify

    Returns:
        Tuple of (success, message)
    """
    config = share_set.config

    # Select threshold shares
    test_shares = share_set.shares[:config.threshold]
    mnemonics = [s.mnemonic for s in test_shares]

    try:
        recovered = recover_secret(mnemonics, config.passphrase)
        recovered_fingerprint = compute_master_fingerprint(recovered)

        if recovered_fingerprint == share_set.master_fingerprint:
            return True, "Verification successful: shares reconstruct correctly"
        else:
            return False, "Verification failed: recovered secret doesn't match"
    except Exception as e:
        return False, f"Verification failed: {e}"


# =============================================================================
# DISPLAY HELPERS
# =============================================================================


def format_share_for_display(share: SLIP39Share, show_mnemonic: bool = True) -> str:
    """Format a share for terminal display.

    Args:
        share: Share to format
        show_mnemonic: Whether to include the actual mnemonic

    Returns:
        Formatted string for display
    """
    lines = [
        f"Share {share.index} of {share.total} ({share.threshold} required for recovery)",
        f"Fingerprint: {share.fingerprint}",
        f"Words: {share.word_count}",
    ]

    if show_mnemonic:
        lines.append("")
        # Format mnemonic in rows of 4 words for readability
        words = share.words
        for i in range(0, len(words), 4):
            row_words = words[i:i + 4]
            numbered = [f"{i + j + 1:2}. {w}" for j, w in enumerate(row_words)]
            lines.append("  ".join(numbered))

    return "\n".join(lines)


def format_share_summary(share_set: SLIP39ShareSet) -> str:
    """Format a summary of all shares (fingerprints only).

    Args:
        share_set: Share set to summarize

    Returns:
        Formatted summary string
    """
    lines = [
        f"SLIP-39 Share Set ({share_set.config.threshold}-of-{share_set.config.total_shares})",
        f"Master Fingerprint: {share_set.master_fingerprint}",
        f"Generated: {share_set.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "Share Fingerprints:",
    ]

    for share in share_set.shares:
        lines.append(f"  {share.index}. {share.fingerprint}")

    return "\n".join(lines)
