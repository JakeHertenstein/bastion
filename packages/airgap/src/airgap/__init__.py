"""Bastion Airgap - Air-gapped cryptographic key generation system.

This module provides tools for secure key generation and SLIP-39 secret
sharing on air-gapped systems.

Features:
- SLIP-39 (Shamir's Secret Sharing) for 5-share, 3-of-5 recovery
- Hardware entropy collection from Infinite Noise TRNG
- QR code data transfer for air-gapped input/output
- MicroSD card domain management
- Integration with 1Password via Bastion labels
- Sigchain audit trail with QR export for Manager import
"""

__version__ = "0.1.0"

from airgap.sigchain import (
    EnclaveEvent,
    EnclaveEventType,
    EnclaveBatch,
    EnclaveSession,
)

__all__ = [
    "EnclaveEvent",
    "EnclaveEventType",
    "EnclaveBatch",
    "EnclaveSession",
]
