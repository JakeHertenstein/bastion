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

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def _read_root_version() -> str:
    try:
        p = Path(__file__).resolve()
        for parent in [p.parent, *p.parents]:
            vf = (parent / "VERSION")
            if vf.exists():
                return vf.read_text(encoding="utf-8").strip()
    except Exception:
        pass
    return "0.0.0"

try:
    __version__ = version("bastion-airgap")
except PackageNotFoundError:
    __version__ = _read_root_version()

from airgap.sigchain import (
    EnclaveBatch,
    EnclaveEvent,
    EnclaveEventType,
    EnclaveSession,
)

__all__ = [
    "EnclaveEvent",
    "EnclaveEventType",
    "EnclaveBatch",
    "EnclaveSession",
]
