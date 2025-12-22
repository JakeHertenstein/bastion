#!/usr/bin/env python3
"""
Seed source implementations for different mnemonic and input types.
Extracted from monolithic seed.py for better modularity.
"""

import hashlib

from argon2.low_level import Type, hash_secret_raw
from mnemonic import Mnemonic
from shamir_mnemonic import combine_mnemonics, generate_mnemonics

from .config import (
    ARGON2_HASH_LENGTH,
    ARGON2_MEMORY_COST_KB,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    DEFAULT_PBKDF2_ITERATIONS,
)
from .exceptions import SeedDerivationError, SLIP39Error

# Remove logging for now


class SeedSources:
    """Collection of seed derivation methods for different input types."""

    @staticmethod
    def argon2_to_seed(
        seed_phrase: str,
        salt: bytes,
        time_cost: int = ARGON2_TIME_COST,
        memory_cost_kb: int = ARGON2_MEMORY_COST_KB,
        parallelism: int = ARGON2_PARALLELISM,
        hash_length: int = ARGON2_HASH_LENGTH,
    ) -> bytes:
        """
        Derive 64-byte seed using Argon2id (memory-hard KDF).

        This provides strong protection against GPU/ASIC brute-force attacks,
        making even weak passphrases more resistant to offline attacks.

        Args:
            seed_phrase: Input phrase to derive from
            salt: Salt bytes (typically derived from label)
            time_cost: Number of iterations (default 3)
            memory_cost_kb: Memory in KB (default 1GB = 1048576 KB)
            parallelism: Number of threads (default 4)
            hash_length: Output length in bytes (default 64)

        Returns:
            64-byte seed

        Raises:
            SeedDerivationError: If derivation fails
        """
        try:
            seed = hash_secret_raw(
                secret=seed_phrase.encode('utf-8'),
                salt=salt,
                time_cost=time_cost,
                memory_cost=memory_cost_kb,
                parallelism=parallelism,
                hash_len=hash_length,
                type=Type.ID,  # Argon2id - recommended variant
            )
            return seed

        except Exception as e:
            raise SeedDerivationError(f"Argon2 seed derivation failed: {e}") from e

    @staticmethod
    def bip39_to_seed(mnemonic: str, passphrase: str = "", iterations: int = DEFAULT_PBKDF2_ITERATIONS, validate: bool = True) -> bytes:
        """
        Convert BIP-39 mnemonic to 64-byte seed using PBKDF2-HMAC-SHA512.

        Args:
            mnemonic: BIP-39 mnemonic words (space-separated)
            passphrase: Optional passphrase for additional security
            iterations: PBKDF2 iteration count
            validate: Whether to validate mnemonic against BIP-39 standard (recommended: True)

        Returns:
            64-byte seed

        Raises:
            SeedDerivationError: If derivation fails or mnemonic is invalid
        """
        try:
            # Use official BIP-39 library for validation and seed generation
            mnemo = Mnemonic("english")

            if validate:
                # Proper BIP-39 validation: word list + checksum verification
                if not mnemo.check(mnemonic):
                    raise ValueError("Invalid BIP-39 mnemonic: failed word list or checksum validation")

            # Use official BIP-39 seed generation
            seed = mnemo.to_seed(mnemonic, passphrase)

            # logger.log_seed_derivation("BIP-39", True, words=len(mnemonic.split()), iterations=iterations, validated=validate)
            return seed

        except Exception as e:
            raise SeedDerivationError(f"BIP-39 seed derivation failed: {e}") from e

    @staticmethod
    def simple_to_seed(seed_phrase: str) -> bytes:
        """
        Convert simple phrase to 64-byte seed using SHA-512.

        Args:
            seed_phrase: Simple text phrase

        Returns:
            64-byte seed

        Raises:
            SeedDerivationError: If derivation fails
        """
        try:
            seed = hashlib.sha512(seed_phrase.encode('utf-8')).digest()
            # TODO: Add proper logging
            # logger.log_seed_derivation("Simple", True, words=len(seed_phrase.split()))
            return seed

        except Exception as e:
            raise SeedDerivationError(f"Simple seed derivation failed: {e}")

    @staticmethod
    def slip39_to_seed(shares: list[str]) -> bytes:
        """
        Reconstruct seed from SLIP-39 shares using Shamir's Secret Sharing.

        Args:
            shares: List of SLIP-39 share strings

        Returns:
            64-byte seed

        Raises:
            SLIP39Error: If share reconstruction fails
        """
        try:
            if len(shares) < 2:
                raise SLIP39Error("At least 2 shares required for reconstruction")

            # Validate share format (each should be 20 or 33 words)
            for i, share in enumerate(shares):
                word_count = len(share.split())
                if word_count not in [20, 33]:
                    raise SLIP39Error(f"Share {i+1} has {word_count} words, expected 20 or 33")

            # Use official Trezor implementation for reconstruction
            master_secret = combine_mnemonics(shares)

            if len(master_secret) < 16:
                raise SLIP39Error(f"Reconstructed secret too short: {len(master_secret)} bytes")

            # Expand to 64 bytes using PBKDF2-HMAC-SHA512
            seed = hashlib.pbkdf2_hmac(
                'sha512',
                master_secret,
                b'SLIP39',  # Standard salt
                1  # Single iteration for speed
            )

            # TODO: Add proper logging
            # logger.log_seed_derivation("SLIP-39", True, shares=len(shares))
            return seed

        except Exception as e:
            if isinstance(e, SLIP39Error):
                raise
            raise SLIP39Error(f"SLIP-39 reconstruction failed: {e}")

    @staticmethod
    def create_test_slip39_shares(secret_phrase: str, threshold: int = 2, total_shares: int = 3) -> list[str]:
        """
        Generate real SLIP-39 test shares using the official library.

        Args:
            secret_phrase: Source phrase to split
            threshold: Minimum shares needed for reconstruction
            total_shares: Total shares to generate

        Returns:
            List of real SLIP-39 share strings

        Raises:
            SLIP39Error: If share generation fails
        """
        try:
            if threshold > total_shares:
                raise SLIP39Error("Threshold cannot exceed total shares")

            if threshold < 2:
                raise SLIP39Error("Threshold must be at least 2")

            # Convert phrase to 128-bit secret (minimum for SLIP-39)
            secret_bytes = hashlib.sha512(secret_phrase.encode()).digest()[:16]

            # Generate real SLIP-39 shares using official library
            # Format: groups = [(threshold, total_shares)]
            share_groups = generate_mnemonics(
                group_threshold=1,  # Only one group needed
                groups=[(threshold, total_shares)],
                master_secret=secret_bytes,
                passphrase=b"",
                iteration_exponent=1
            )

            # Extract shares from the first (and only) group
            shares = share_groups[0]

            # TODO: Add proper logging
            # logger.log_operation("SLIP-39", True, shares_generated=total_shares)
            return shares

        except Exception as e:
            raise SLIP39Error(f"Test share generation failed: {e}") from e


class SeedValidator:
    """Validation utilities for different seed types."""

    @staticmethod
    def validate_bip39_mnemonic(mnemonic: str) -> tuple[bool, str]:
        """
        Basic validation of BIP-39 mnemonic format.

        Args:
            mnemonic: Space-separated mnemonic words

        Returns:
            Tuple of (is_valid, error_message)
        """
        words = mnemonic.strip().split()

        if len(words) not in [12, 15, 18, 21, 24]:
            return False, f"Invalid word count: {len(words)} (expected 12, 15, 18, 21, or 24)"

        # Check for obvious issues
        if any(not word.isalpha() for word in words):
            return False, "Mnemonic contains non-alphabetic characters"

        if len(set(words)) != len(words):
            return False, "Mnemonic contains duplicate words"

        return True, "Mnemonic format appears valid"

    @staticmethod
    def validate_slip39_shares(shares: list[str]) -> tuple[bool, str]:
        """
        Basic validation of SLIP-39 share format.

        Args:
            shares: List of SLIP-39 share strings

        Returns:
            Tuple of (is_valid, error_message)
        """
        if len(shares) < 2:
            return False, "At least 2 shares required"

        for i, share in enumerate(shares):
            words = share.strip().split()
            if len(words) not in [20, 33]:
                return False, f"Share {i+1} has {len(words)} words (expected 20 or 33)"

        return True, "Share format appears valid"

    @staticmethod
    def estimate_entropy(seed_phrase: str) -> float:
        """
        Estimate entropy of a simple seed phrase.

        Args:
            seed_phrase: Input phrase

        Returns:
            Estimated entropy in bits
        """
        # Simple character-based entropy estimation
        char_counts = {}
        for char in seed_phrase:
            char_counts[char] = char_counts.get(char, 0) + 1

        entropy = 0.0
        total_chars = len(seed_phrase)

        for count in char_counts.values():
            probability = count / total_chars
            if probability > 0:
                entropy -= probability * (probability * total_chars).bit_length()

        return entropy * total_chars


# Example usage and testing
if __name__ == "__main__":
    print("Seed Sources Demo")
    print("=" * 30)

    # Test simple seed
    simple_phrase = "test phrase for demonstration"
    simple_seed = SeedSources.simple_to_seed(simple_phrase)
    print(f"Simple seed length: {len(simple_seed)} bytes")

    # Test BIP-39 (using test vector)
    test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    bip39_seed = SeedSources.bip39_to_seed(test_mnemonic)
    print(f"BIP-39 seed length: {len(bip39_seed)} bytes")

    # Test SLIP-39 share generation
    test_shares = SeedSources.create_test_slip39_shares("TestSecret")
    print(f"Generated {len(test_shares)} test shares")

    # Validation tests
    is_valid, msg = SeedValidator.validate_bip39_mnemonic(test_mnemonic)
    print(f"BIP-39 validation: {is_valid} - {msg}")

    is_valid, msg = SeedValidator.validate_slip39_shares(test_shares)
    print(f"SLIP-39 validation: {is_valid} - {msg}")

    entropy = SeedValidator.estimate_entropy(simple_phrase)
    print(f"Phrase entropy: {entropy:.2f} bits")
