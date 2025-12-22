"""OpenTimestamps integration for Bastion sigchain.

This module provides Bitcoin-anchored timestamps for audit trail integrity.
It uses the OpenTimestamps protocol to create and verify proofs.

Components:
    - anchor: Merkle root anchoring and proof management
    - client: Calendar server communication (CLI and HTTP)
"""

from bastion.ots.anchor import (
    AnchorStatus,
    CompletedAnchor,
    MerkleTree,
    OTSAnchor,
    PendingAnchor,
)
from bastion.ots.client import (
    DEFAULT_CALENDARS,
    CalendarResponse,
    CalendarServer,
    OTSCalendar,
    OTSHttpClient,
    OTSProof,
    check_ots_available,
)

__all__ = [
    # Anchor
    "OTSAnchor",
    "AnchorStatus",
    "PendingAnchor",
    "CompletedAnchor",
    "MerkleTree",
    # Client
    "OTSCalendar",
    "OTSHttpClient",
    "CalendarServer",
    "CalendarResponse",
    "DEFAULT_CALENDARS",
    "OTSProof",
    "check_ots_available",
]
