"""Sigchain support for Bastion Enclave (airgap).

This module provides a minimal sigchain implementation for the air-gapped
Enclave machine. It supports:

- Creating audit events for enclave operations
- Building batches for QR transfer to Manager
- Minimal offline chain management

The Enclave sigchain is designed to work without:
- Network connectivity
- Git (events stored in simple JSONL)
- OpenTimestamps (Manager handles anchoring after import)

Events are batched by session and exported as QR codes for the Manager
to import and anchor.
"""

from __future__ import annotations

import base64
import hashlib
import json
import zlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class EnclaveEventType(str):
    """Event types that can occur on the Enclave."""

    KEY_GENERATED = "KEY_GENERATED"
    SHARE_CREATED = "SHARE_CREATED"
    BACKUP_VERIFIED = "BACKUP_VERIFIED"
    ENTROPY_COLLECTED = "ENTROPY_COLLECTED"
    SESSION_STARTED = "SESSION_STARTED"
    SESSION_ENDED = "SESSION_ENDED"


class EnclaveEvent(BaseModel):
    """An audit event from the Enclave.

    These events are created offline and later imported to the
    Manager's sigchain via QR code transfer.
    """

    event_type: str = Field(description="Type of event")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    payload: dict[str, Any] = Field(default_factory=dict)
    payload_hash: str = Field(default="")

    # Enclave-local sequence number (reset per session)
    local_seqno: int = Field(default=0)

    # Session this event belongs to
    session_id: str = Field(default="")

    model_config = {"frozen": False}

    def model_post_init(self, __context: Any) -> None:
        """Compute payload hash after initialization."""
        if not self.payload_hash:
            payload_json = json.dumps(self.payload, sort_keys=True)
            self.payload_hash = hashlib.sha256(payload_json.encode()).hexdigest()

    def get_summary(self) -> str:
        """Get human-readable summary of event."""
        if self.event_type == EnclaveEventType.KEY_GENERATED:
            key_type = self.payload.get("key_type", "unknown")
            return f"Generated {key_type} key"
        elif self.event_type == EnclaveEventType.SHARE_CREATED:
            share_idx = self.payload.get("share_index", "?")
            total = self.payload.get("total_shares", "?")
            return f"Created share {share_idx}/{total}"
        elif self.event_type == EnclaveEventType.BACKUP_VERIFIED:
            return "Backup verification completed"
        elif self.event_type == EnclaveEventType.ENTROPY_COLLECTED:
            bits = self.payload.get("bits", 0)
            source = self.payload.get("source", "unknown")
            return f"Collected {bits} bits from {source}"
        elif self.event_type == EnclaveEventType.SESSION_STARTED:
            return "Enclave session started"
        elif self.event_type == EnclaveEventType.SESSION_ENDED:
            events = self.payload.get("event_count", 0)
            return f"Session ended ({events} events)"
        else:
            return self.event_type


class EnclaveBatch(BaseModel):
    """A batch of events for QR transfer to Manager.

    Batches are compressed and encoded for efficient QR code transfer.
    The Manager imports these and appends to its sigchain.
    """

    batch_id: str = Field(default_factory=lambda: uuid4().hex[:12])
    session_id: str = Field(description="Enclave session ID")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    events: list[EnclaveEvent] = Field(default_factory=list)
    event_count: int = Field(default=0)

    # For chain continuity
    first_local_seqno: int = Field(default=1)
    last_local_seqno: int = Field(default=0)

    # Batch merkle root (for Manager to anchor)
    merkle_root: str = Field(default="")

    model_config = {"frozen": False}

    def add_event(self, event: EnclaveEvent) -> None:
        """Add an event to the batch."""
        self.events.append(event)
        self.event_count = len(self.events)
        self.last_local_seqno = event.local_seqno
        if self.event_count == 1:
            self.first_local_seqno = event.local_seqno

    def compute_merkle_root(self) -> str:
        """Compute merkle root of event hashes."""
        if not self.events:
            return hashlib.sha256(b"").hexdigest()

        # Simple merkle tree
        hashes = [bytes.fromhex(e.payload_hash) for e in self.events]

        while len(hashes) > 1:
            new_level = []
            for i in range(0, len(hashes), 2):
                if i + 1 < len(hashes):
                    # Sort for determinism
                    pair = sorted([hashes[i], hashes[i + 1]])
                    combined = hashlib.sha256(pair[0] + pair[1]).digest()
                else:
                    combined = hashes[i]
                new_level.append(combined)
            hashes = new_level

        self.merkle_root = hashes[0].hex()
        return self.merkle_root

    def to_qr_data(self) -> str:
        """Serialize batch for QR code transfer.

        Uses compression and base64 encoding to fit in QR capacity.

        Returns:
            Base64-encoded compressed JSON
        """
        self.compute_merkle_root()

        # Minimal JSON representation
        data = {
            "b": self.batch_id,
            "s": self.session_id,
            "t": self.created_at.isoformat(),
            "m": self.merkle_root,
            "e": [
                {
                    "y": e.event_type,
                    "t": e.timestamp.isoformat(),
                    "p": e.payload,
                    "h": e.payload_hash,
                    "n": e.local_seqno,
                }
                for e in self.events
            ],
        }

        json_bytes = json.dumps(data, separators=(",", ":")).encode()
        compressed = zlib.compress(json_bytes, level=9)
        return base64.b64encode(compressed).decode()

    @classmethod
    def from_qr_data(cls, qr_data: str) -> EnclaveBatch:
        """Deserialize batch from QR code data.

        Args:
            qr_data: Base64-encoded compressed JSON

        Returns:
            Reconstructed EnclaveBatch
        """
        compressed = base64.b64decode(qr_data)
        json_bytes = zlib.decompress(compressed)
        data = json.loads(json_bytes)

        events = [
            EnclaveEvent(
                event_type=e["y"],
                timestamp=datetime.fromisoformat(e["t"]),
                payload=e["p"],
                payload_hash=e["h"],
                local_seqno=e["n"],
                session_id=data["s"],
            )
            for e in data["e"]
        ]

        batch = cls(
            batch_id=data["b"],
            session_id=data["s"],
            created_at=datetime.fromisoformat(data["t"]),
            events=events,
            event_count=len(events),
            merkle_root=data["m"],
        )

        if events:
            batch.first_local_seqno = events[0].local_seqno
            batch.last_local_seqno = events[-1].local_seqno

        return batch

    def estimate_qr_size(self) -> int:
        """Estimate size of QR data in bytes."""
        return len(self.to_qr_data())

    def can_fit_in_qr(self, max_bytes: int = 2048) -> bool:
        """Check if batch fits in a single QR code.

        Args:
            max_bytes: Maximum bytes for QR (Level H, ~2KB practical limit)

        Returns:
            True if batch fits
        """
        return self.estimate_qr_size() <= max_bytes


class EnclaveSession:
    """Manages an Enclave session with event logging.

    This is a simplified session manager for offline use.
    Events are logged to a local file and can be exported
    as a batch for QR transfer.

    Example:
        >>> session = EnclaveSession()
        >>> session.start()
        >>> session.log_event(EnclaveEventType.ENTROPY_COLLECTED, {"bits": 8192})
        >>> batch = session.export_batch()
        >>> qr_data = batch.to_qr_data()
    """

    def __init__(self, storage_path: Path | None = None):
        """Initialize session manager.

        Args:
            storage_path: Path to store session data (default: ~/.enclave/sessions/)
        """
        self.storage_path = storage_path or Path.home() / ".enclave" / "sessions"
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self.session_id: str = ""
        self.events: list[EnclaveEvent] = []
        self.local_seqno: int = 0
        self.started_at: datetime | None = None
        self.active: bool = False

    def start(self) -> str:
        """Start a new session.

        Returns:
            Session ID
        """
        self.session_id = uuid4().hex[:16]
        self.events = []
        self.local_seqno = 0
        self.started_at = datetime.now(UTC)
        self.active = True

        # Log session start event
        self.log_event(EnclaveEventType.SESSION_STARTED, {
            "started_at": self.started_at.isoformat(),
        })

        return self.session_id

    def log_event(self, event_type: str, payload: dict[str, Any]) -> EnclaveEvent:
        """Log an event to the session.

        Args:
            event_type: Type of event
            payload: Event payload data

        Returns:
            The created event
        """
        if not self.active:
            raise RuntimeError("Session not active. Call start() first.")

        self.local_seqno += 1

        event = EnclaveEvent(
            event_type=event_type,
            payload=payload,
            local_seqno=self.local_seqno,
            session_id=self.session_id,
        )

        self.events.append(event)

        # Also append to session log file
        log_path = self.storage_path / f"{self.session_id}.jsonl"
        with open(log_path, "a") as f:
            f.write(event.model_dump_json() + "\n")

        return event

    def end(self) -> EnclaveBatch:
        """End the session and create export batch.

        Returns:
            Batch ready for QR export
        """
        if not self.active:
            raise RuntimeError("Session not active.")

        # Log session end event
        self.log_event(EnclaveEventType.SESSION_ENDED, {
            "event_count": len(self.events),
            "ended_at": datetime.now(UTC).isoformat(),
        })

        self.active = False

        return self.export_batch()

    def export_batch(self) -> EnclaveBatch:
        """Export current events as a batch.

        Returns:
            EnclaveBatch ready for QR encoding
        """
        batch = EnclaveBatch(session_id=self.session_id)
        for event in self.events:
            batch.add_event(event)
        batch.compute_merkle_root()
        return batch

    def split_into_qr_batches(self, max_bytes: int = 2048) -> list[EnclaveBatch]:
        """Split events into multiple batches if needed.

        If the full batch is too large for a single QR code,
        split into multiple smaller batches.

        Args:
            max_bytes: Maximum bytes per QR code

        Returns:
            List of batches, each fitting in one QR
        """
        full_batch = self.export_batch()

        if full_batch.can_fit_in_qr(max_bytes):
            return [full_batch]

        # Split into smaller batches
        batches = []
        current_events: list[EnclaveEvent] = []

        for event in self.events:
            test_batch = EnclaveBatch(session_id=self.session_id)
            for e in current_events + [event]:
                test_batch.add_event(e)

            if test_batch.can_fit_in_qr(max_bytes):
                current_events.append(event)
            else:
                # Current batch is full, start new one
                if current_events:
                    batch = EnclaveBatch(session_id=self.session_id)
                    for e in current_events:
                        batch.add_event(e)
                    batch.compute_merkle_root()
                    batches.append(batch)
                current_events = [event]

        # Add remaining events
        if current_events:
            batch = EnclaveBatch(session_id=self.session_id)
            for e in current_events:
                batch.add_event(e)
            batch.compute_merkle_root()
            batches.append(batch)

        return batches

    @staticmethod
    def list_sessions(storage_path: Path | None = None) -> list[dict[str, Any]]:
        """List available sessions.

        Args:
            storage_path: Path to session storage

        Returns:
            List of session info dicts
        """
        path = storage_path or Path.home() / ".enclave" / "sessions"
        if not path.exists():
            return []

        sessions = []
        for log_file in path.glob("*.jsonl"):
            session_id = log_file.stem
            events = []
            for line in log_file.read_text().strip().split("\n"):
                if line:
                    events.append(json.loads(line))

            sessions.append({
                "session_id": session_id,
                "event_count": len(events),
                "log_path": str(log_file),
            })

        return sessions
