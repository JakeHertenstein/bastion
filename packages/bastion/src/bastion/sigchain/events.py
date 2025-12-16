"""Sigchain event types and payloads.

Defines all auditable events that can be recorded in the sigchain.
Each event type has a corresponding payload model with the specific
data relevant to that operation.

Event Categories:
- Credential operations: PasswordRotation, UsernameGenerated
- Security infrastructure: EntropyPoolCreated, TagOperation
- Configuration: ConfigChange
- Cross-device: EnclaveImport
- Anchoring: OTSAnchor
"""

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class AuditEventType(str, Enum):
    """Types of auditable events in the sigchain."""
    
    # Credential operations
    PASSWORD_ROTATION = "password_rotation"
    USERNAME_GENERATED = "username_generated"
    
    # Security infrastructure
    ENTROPY_POOL_CREATED = "entropy_pool_created"
    ENTROPY_POOL_CONSUMED = "entropy_pool_consumed"
    TAG_OPERATION = "tag_operation"
    
    # Configuration
    CONFIG_CHANGE = "config_change"
    SALT_INITIALIZED = "salt_initialized"
    
    # Cross-device
    ENCLAVE_IMPORT = "enclave_import"
    
    # Anchoring
    OTS_ANCHOR = "ots_anchor"
    OTS_UPGRADED = "ots_upgraded"
    
    # Enclave-specific (generated on air-gapped machine)
    KEY_GENERATED = "key_generated"
    SHARE_CREATED = "share_created"
    BACKUP_VERIFIED = "backup_verified"
    ENCLAVE_ENTROPY_COLLECTED = "enclave_entropy_collected"


# =============================================================================
# Event Payload Models
# =============================================================================

class EventPayload(BaseModel):
    """Base class for event payloads.
    
    All payloads must be JSON-serializable and should contain only
    the data necessary to describe the event (no secrets).
    """
    
    event_type: AuditEventType
    
    def compute_hash(self) -> str:
        """Compute SHA-256 hash of this payload.
        
        Returns:
            Hex-encoded SHA-256 hash
        """
        import hashlib
        import json
        
        canonical = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    
    def get_summary(self) -> str:
        """Get human-readable summary for 1Password display.
        
        Returns:
            Short description (max 100 chars)
        """
        return f"{self.event_type.value}"


class PasswordRotationPayload(EventPayload):
    """Password rotation event data."""
    
    event_type: Literal[AuditEventType.PASSWORD_ROTATION] = AuditEventType.PASSWORD_ROTATION
    
    account_uuid: str = Field(..., description="1Password item UUID")
    account_title: str = Field(..., description="Account title for display")
    domain: str = Field("", description="Primary domain/URL")
    previous_change_date: str | None = Field(
        None, 
        description="Previous password change date (YYYY-MM-DD)"
    )
    new_change_date: str = Field(..., description="New password change date (YYYY-MM-DD)")
    rotation_interval_days: int = Field(90, description="Days until next rotation")
    tier: str = Field("Tier 2", description="Account tier")
    
    def get_summary(self) -> str:
        return f"Rotated {self.account_title}"


class UsernameGeneratedPayload(EventPayload):
    """Username generation event data."""
    
    event_type: Literal[AuditEventType.USERNAME_GENERATED] = AuditEventType.USERNAME_GENERATED
    
    domain: str = Field(..., description="Domain for username")
    algorithm: str = Field(..., description="Hash algorithm used (sha512, sha3-512)")
    label: str = Field(..., description="Full Bastion label")
    username_hash: str = Field(
        ..., 
        description="SHA-256 hash of generated username (not the username itself)"
    )
    length: int = Field(..., description="Username length")
    saved_to_1password: bool = Field(False, description="Whether saved to 1Password")
    account_uuid: str | None = Field(None, description="1Password item UUID if saved")
    
    def get_summary(self) -> str:
        saved = "→ 1P" if self.saved_to_1password else ""
        return f"Generated for {self.domain} {saved}"


class EntropyPoolCreatedPayload(EventPayload):
    """Entropy pool creation event data."""
    
    event_type: Literal[AuditEventType.ENTROPY_POOL_CREATED] = AuditEventType.ENTROPY_POOL_CREATED
    
    pool_uuid: str = Field(..., description="1Password item UUID for entropy pool")
    serial_number: int = Field(..., description="Pool serial number")
    source: str = Field(..., description="Entropy source (yubikey, dice, infnoise, combined)")
    bits: int = Field(..., description="Entropy size in bits")
    quality_rating: str = Field(..., description="ENT analysis rating (EXCELLENT/GOOD/FAIR/POOR)")
    entropy_per_byte: float = Field(..., description="Measured entropy per byte")
    device_serial: str | None = Field(None, description="Hardware device serial if applicable")
    
    def get_summary(self) -> str:
        return f"Pool #{self.serial_number} ({self.source}, {self.bits} bits, {self.quality_rating})"


class TagOperationPayload(EventPayload):
    """Tag operation event data."""
    
    event_type: Literal[AuditEventType.TAG_OPERATION] = AuditEventType.TAG_OPERATION
    
    account_uuid: str = Field(..., description="1Password item UUID")
    account_title: str = Field(..., description="Account title")
    action: Literal["add", "remove", "replace"] = Field(..., description="Tag action")
    tags_before: list[str] = Field(default_factory=list, description="Tags before operation")
    tags_after: list[str] = Field(default_factory=list, description="Tags after operation")
    
    def get_summary(self) -> str:
        return f"{self.action.title()} tags on {self.account_title}"


class ConfigChangePayload(EventPayload):
    """Configuration change event data."""
    
    event_type: Literal[AuditEventType.CONFIG_CHANGE] = AuditEventType.CONFIG_CHANGE
    
    config_section: str = Field(..., description="Config section changed")
    config_key: str = Field(..., description="Config key changed")
    old_value: str | None = Field(None, description="Previous value (redacted if sensitive)")
    new_value: str | None = Field(None, description="New value (redacted if sensitive)")
    source: str = Field("cli", description="Change source (cli, config_file, api)")
    
    def get_summary(self) -> str:
        return f"Changed {self.config_section}.{self.config_key}"


class EnclaveImportPayload(EventPayload):
    """Enclave batch import event data."""
    
    event_type: Literal[AuditEventType.ENCLAVE_IMPORT] = AuditEventType.ENCLAVE_IMPORT
    
    source_head_hash: str = Field(..., description="Enclave chain head at export")
    source_seqno: int = Field(..., description="Enclave seqno at export")
    events_imported: int = Field(..., description="Number of events in batch")
    event_types: list[str] = Field(
        default_factory=list, 
        description="Types of events imported"
    )
    export_timestamp: datetime = Field(..., description="When batch was exported")
    qr_sequence_count: int = Field(1, description="QR codes used for transfer")
    
    def get_summary(self) -> str:
        return f"Imported {self.events_imported} events from Enclave"


class OTSAnchorPayload(EventPayload):
    """OpenTimestamps anchor event data."""
    
    event_type: Literal[AuditEventType.OTS_ANCHOR] = AuditEventType.OTS_ANCHOR
    
    merkle_root: str = Field(..., description="Merkle root of anchored events")
    events_start_seqno: int = Field(..., description="First event seqno in anchor")
    events_end_seqno: int = Field(..., description="Last event seqno in anchor")
    calendars: list[str] = Field(
        default_factory=list, 
        description="OTS calendars submitted to"
    )
    pending_proof_hash: str = Field(
        ..., 
        description="SHA-256 of pending .ots proof bytes"
    )
    # Filled in when upgraded
    bitcoin_block: int | None = Field(None, description="Bitcoin block height when confirmed")
    attestation_time: datetime | None = Field(None, description="Bitcoin block timestamp")
    
    def get_summary(self) -> str:
        if self.bitcoin_block:
            return f"Anchored #{self.events_start_seqno}-{self.events_end_seqno} @ block {self.bitcoin_block}"
        return f"Pending anchor #{self.events_start_seqno}-{self.events_end_seqno}"


# =============================================================================
# Enclave-Specific Events (generated on air-gapped machine)
# =============================================================================

class KeyGeneratedPayload(EventPayload):
    """Key generation event (Enclave)."""
    
    event_type: Literal[AuditEventType.KEY_GENERATED] = AuditEventType.KEY_GENERATED
    
    key_type: str = Field(..., description="Key type (gpg, ssh, slip39)")
    key_id: str = Field(..., description="Key identifier (fingerprint or ID)")
    algorithm: str = Field(..., description="Key algorithm")
    bits: int | None = Field(None, description="Key size in bits")
    purpose: str = Field("", description="Intended use")
    
    def get_summary(self) -> str:
        return f"Generated {self.key_type} key {self.key_id[:16]}..."


class ShareCreatedPayload(EventPayload):
    """SLIP-39 share creation event (Enclave)."""
    
    event_type: Literal[AuditEventType.SHARE_CREATED] = AuditEventType.SHARE_CREATED
    
    share_index: int = Field(..., description="Share index (1-5)")
    group_threshold: int = Field(3, description="Shares needed to recover")
    group_total: int = Field(5, description="Total shares in group")
    share_hash: str = Field(..., description="SHA-256 hash of share words")
    destination: str = Field("", description="Intended storage location")
    
    def get_summary(self) -> str:
        return f"Created SLIP-39 share {self.share_index}/{self.group_total}"


class BackupVerifiedPayload(EventPayload):
    """Backup verification event (Enclave)."""
    
    event_type: Literal[AuditEventType.BACKUP_VERIFIED] = AuditEventType.BACKUP_VERIFIED
    
    backup_type: str = Field(..., description="Type of backup (card, share, seed)")
    backup_id: str = Field(..., description="Backup identifier")
    verification_hash: str = Field(..., description="Hash used for verification")
    result: Literal["pass", "fail"] = Field(..., description="Verification result")
    location: str = Field("", description="Backup storage location")
    
    def get_summary(self) -> str:
        status = "✓" if self.result == "pass" else "✗"
        return f"Verified {self.backup_type} {self.backup_id}: {status}"


class EnclaveEntropyCollectedPayload(EventPayload):
    """Entropy collection event (Enclave)."""
    
    event_type: Literal[AuditEventType.ENCLAVE_ENTROPY_COLLECTED] = AuditEventType.ENCLAVE_ENTROPY_COLLECTED
    
    source: str = Field(..., description="Entropy source (infnoise, dice)")
    bits: int = Field(..., description="Bits collected")
    device_serial: str | None = Field(None, description="Device serial if hardware")
    quality_rating: str = Field(..., description="Quality assessment")
    purpose: str = Field("", description="Intended use")
    
    def get_summary(self) -> str:
        return f"Collected {self.bits} bits from {self.source}"


# Type alias for all payload types
AnyEventPayload = (
    PasswordRotationPayload
    | UsernameGeneratedPayload
    | EntropyPoolCreatedPayload
    | TagOperationPayload
    | ConfigChangePayload
    | EnclaveImportPayload
    | OTSAnchorPayload
    | KeyGeneratedPayload
    | ShareCreatedPayload
    | BackupVerifiedPayload
    | EnclaveEntropyCollectedPayload
)

# Mapping from event type to payload class
EVENT_PAYLOAD_CLASSES: dict[AuditEventType, type[EventPayload]] = {
    AuditEventType.PASSWORD_ROTATION: PasswordRotationPayload,
    AuditEventType.USERNAME_GENERATED: UsernameGeneratedPayload,
    AuditEventType.ENTROPY_POOL_CREATED: EntropyPoolCreatedPayload,
    AuditEventType.TAG_OPERATION: TagOperationPayload,
    AuditEventType.CONFIG_CHANGE: ConfigChangePayload,
    AuditEventType.ENCLAVE_IMPORT: EnclaveImportPayload,
    AuditEventType.OTS_ANCHOR: OTSAnchorPayload,
    AuditEventType.KEY_GENERATED: KeyGeneratedPayload,
    AuditEventType.SHARE_CREATED: ShareCreatedPayload,
    AuditEventType.BACKUP_VERIFIED: BackupVerifiedPayload,
    AuditEventType.ENCLAVE_ENTROPY_COLLECTED: EnclaveEntropyCollectedPayload,
}
