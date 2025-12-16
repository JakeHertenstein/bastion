"""Sigchain data models.

Defines the core structures for the cryptographic audit chain:
- SigchainLink: Individual chain entry with hash linking
- ChainHead: Current chain state for persistence
- EnclaveImportBatch: Batch of events from air-gapped Enclave
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class DeviceType(str, Enum):
    """Device that generated the sigchain event."""
    
    MANAGER = "manager"  # Daily connected machine (Bastion Manager)
    ENCLAVE = "enclave"  # Air-gapped machine (Bastion Enclave)


class SigchainLink(BaseModel):
    """Individual link in the sigchain.
    
    Each link contains:
    - Sequence number for ordering
    - Hash of previous link (chain integrity)
    - Event type and payload hash
    - Dual timestamps (source creation + chain append)
    - Device provenance
    
    The payload itself is stored separately; only its hash is in the link
    to keep the chain compact and enable selective disclosure.
    """
    
    seqno: int = Field(..., ge=1, description="Sequence number (1-indexed)")
    prev_hash: str | None = Field(
        None, 
        description="SHA-256 hash of previous link JSON, None for genesis"
    )
    event_type: str = Field(..., description="Event type identifier")
    payload_hash: str = Field(..., description="SHA-256 hash of event payload JSON")
    source_timestamp: datetime = Field(
        ..., 
        description="When the event was created on source device"
    )
    append_timestamp: datetime = Field(
        ..., 
        description="When the event was appended to this chain"
    )
    device: DeviceType = Field(..., description="Device that created the event")
    
    # Optional fields for cross-chain references
    enclave_seqno: int | None = Field(
        None, 
        description="Original seqno from Enclave chain (for imported events)"
    )
    
    def compute_hash(self) -> str:
        """Compute SHA-256 hash of this link for chaining.
        
        Uses canonical JSON serialization (sorted keys, no extra whitespace)
        to ensure deterministic hashing.
        
        Returns:
            Hex-encoded SHA-256 hash
        """
        import hashlib
        import json
        
        # Canonical JSON: sorted keys, no indent, separators without spaces
        canonical = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ChainHead(BaseModel):
    """Current state of the sigchain for persistence.
    
    Stored in 1Password as a Secure Note for quick access to chain state
    without loading the full chain from git.
    """
    
    head_hash: str = Field(..., description="Hash of the latest link")
    seqno: int = Field(..., ge=0, description="Sequence number of latest link")
    last_anchor_block: int | None = Field(
        None, 
        description="Bitcoin block height of last OTS anchor"
    )
    last_anchor_time: datetime | None = Field(
        None, 
        description="Timestamp when last OTS anchor was confirmed"
    )
    device: DeviceType = Field(
        DeviceType.MANAGER, 
        description="Device that owns this chain"
    )
    
    # For display in 1Password UI
    last_events_summary: str = Field(
        "", 
        description="Human-readable summary of last 5 events"
    )


class EnclaveImportBatch(BaseModel):
    """Batch of events imported from Bastion Enclave.
    
    When events are transferred from the air-gapped Enclave to Manager
    via QR codes, they're wrapped in this batch structure that preserves
    the original timestamps and Enclave chain state.
    """
    
    source_head_hash: str = Field(
        ..., 
        description="Hash of Enclave chain head at export time"
    )
    source_seqno: int = Field(
        ..., 
        description="Enclave chain seqno at export time"
    )
    links: list[SigchainLink] = Field(
        default_factory=list, 
        description="Events to import, in Enclave chain order"
    )
    export_timestamp: datetime = Field(
        ..., 
        description="When the batch was exported from Enclave"
    )
    import_timestamp: datetime | None = Field(
        None, 
        description="When the batch was imported to Manager (set on import)"
    )
    
    # QR transfer metadata
    qr_sequence_count: int = Field(
        1, 
        description="Number of QR codes used for transfer"
    )
    checksum: str | None = Field(
        None, 
        description="SHA-256 checksum of batch for transfer verification"
    )
    
    def compute_checksum(self) -> str:
        """Compute checksum for transfer verification.
        
        Returns:
            Hex-encoded SHA-256 hash of batch data (excluding checksum field)
        """
        import hashlib
        import json
        
        data = self.model_dump(mode="json", exclude={"checksum", "import_timestamp"})
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    
    def verify_checksum(self) -> bool:
        """Verify the batch checksum.
        
        Returns:
            True if checksum matches, False otherwise
        """
        if not self.checksum:
            return False
        return self.compute_checksum() == self.checksum


class EventSummary(BaseModel):
    """Compact event summary for 1Password UI display."""
    
    seqno: int
    event_type: str
    timestamp: datetime
    device: DeviceType
    description: str = Field(..., max_length=100)
    
    def format_line(self) -> str:
        """Format as single line for Notes field.
        
        Returns:
            Formatted string like: "#42 [manager] password_rotation: Updated github.com"
        """
        ts = self.timestamp.strftime("%Y-%m-%d %H:%M")
        return f"#{self.seqno} [{self.device.value}] {self.event_type}: {self.description} ({ts})"
