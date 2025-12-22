#!/usr/bin/env python3
"""
Custom exceptions for Seeder system.
Provides specific error types for better error handling and user experience.
"""

class SeedCardError(Exception):
    """Base exception for Seeder system."""
    pass


class SeedDerivationError(SeedCardError):
    """Raised when seed derivation fails."""
    pass


class InvalidSeedFormatError(SeedDerivationError):
    """Raised when seed format is invalid."""
    pass


class SLIP39Error(SeedDerivationError):
    """Raised when SLIP-39 operations fail."""
    pass


class InsufficientSharesError(SLIP39Error):
    """Raised when insufficient SLIP-39 shares provided."""
    def __init__(self, provided: int, required: int):
        self.provided = provided
        self.required = required
        super().__init__(f"Insufficient shares: got {provided}, need at least {required}")


class InvalidShareFormatError(SLIP39Error):
    """Raised when SLIP-39 share format is invalid."""
    def __init__(self, share_num: int, word_count: int, expected: list[int]):
        self.share_num = share_num
        self.word_count = word_count
        self.expected = expected
        super().__init__(f"Share {share_num} has {word_count} words, expected {expected}")


class CryptoError(SeedCardError):
    """Raised when cryptographic operations fail."""
    pass


class InsufficientEntropyError(CryptoError):
    """Raised when insufficient entropy for token generation."""
    pass


class GridGenerationError(SeedCardError):
    """Raised when token grid generation fails."""
    pass


class CoordinateError(SeedCardError):
    """Raised when coordinate operations fail."""
    pass


class CSVError(SeedCardError):
    """Raised when CSV operations fail."""
    pass


class VerificationError(SeedCardError):
    """Raised when token verification fails."""
    pass


# === ERROR CONTEXT HELPERS ===
def format_bip39_error(e: Exception) -> str:
    """Format BIP-39 related errors with helpful context."""
    error_msg = str(e).lower()

    if "invalid" in error_msg and "word" in error_msg:
        return (
            "Invalid BIP-39 mnemonic word detected. "
            "Ensure all words are from the official BIP-39 wordlist."
        )
    elif "checksum" in error_msg:
        return (
            "BIP-39 mnemonic checksum validation failed. "
            "The mnemonic phrase may be corrupted or incomplete."
        )
    else:
        return f"BIP-39 processing failed: {e}"


def format_slip39_error(e: Exception) -> str:
    """Format SLIP-39 related errors with helpful context."""
    error_msg = str(e).lower()

    if "share" in error_msg and "invalid" in error_msg:
        return (
            "Invalid SLIP-39 share format. "
            "Ensure shares are complete mnemonic phrases (20 or 33 words each)."
        )
    elif "threshold" in error_msg:
        return (
            "Insufficient SLIP-39 shares for reconstruction. "
            "Provide at least the threshold number of shares."
        )
    else:
        return f"SLIP-39 processing failed: {e}"


def format_crypto_error(e: Exception) -> str:
    """Format cryptographic errors with helpful context."""
    error_msg = str(e).lower()

    if "entropy" in error_msg:
        return (
            "Insufficient entropy for token generation. "
            "This indicates a bug in the byte stream calculation."
        )
    elif "seed" in error_msg and "64" in error_msg:
        return (
            "Invalid seed length. Expected 64 bytes from seed derivation function."
        )
    else:
        return f"Cryptographic operation failed: {e}"
