"""Sigchain management — append, verify, and query the audit chain.

The Sigchain class manages the append-only log of audit events.
It handles:
- Appending new events with proper hash linking
- Importing batches from Enclave
- Computing Merkle roots for OTS anchoring
- Verification of chain integrity
- Export/import for persistence
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from .models import (
    ChainHead,
    DeviceType,
    EnclaveImportBatch,
    EventSummary,
    SigchainLink,
)
from .events import (
    AuditEventType,
    EnclaveImportPayload,
    EventPayload,
)

if TYPE_CHECKING:
    from typing import Iterator


class SigchainError(Exception):
    """Base exception for sigchain operations."""
    pass


class ChainIntegrityError(SigchainError):
    """Raised when chain verification fails."""
    pass


class Sigchain:
    """Manages the cryptographic audit chain.
    
    The sigchain is an append-only log where each entry (link) contains
    the hash of the previous entry, forming an immutable chain. The chain
    can be verified by recomputing hashes from genesis.
    
    Attributes:
        device: The device type (manager or enclave)
        links: Ordered list of chain links
        payloads: Mapping from payload_hash to payload data
    """
    
    def __init__(
        self,
        device: DeviceType = DeviceType.MANAGER,
        links: list[SigchainLink] | None = None,
        payloads: dict[str, dict] | None = None,
    ) -> None:
        """Initialize the sigchain.
        
        Args:
            device: Device type that owns this chain
            links: Existing chain links (for loading)
            payloads: Existing payload data (for loading)
        """
        self.device = device
        self.links: list[SigchainLink] = links or []
        self.payloads: dict[str, dict] = payloads or {}
    
    @property
    def head(self) -> SigchainLink | None:
        """Get the current head (latest link) of the chain."""
        return self.links[-1] if self.links else None
    
    @property
    def seqno(self) -> int:
        """Get the current sequence number (0 if empty)."""
        return self.links[-1].seqno if self.links else 0
    
    @property
    def head_hash(self) -> str | None:
        """Get the hash of the current head."""
        return self.head.compute_hash() if self.head else None
    
    def append(
        self,
        payload: EventPayload,
        source_timestamp: datetime | None = None,
    ) -> SigchainLink:
        """Append a new event to the chain.
        
        Args:
            payload: Event payload to record
            source_timestamp: When the event occurred (defaults to now)
            
        Returns:
            The newly created link
        """
        now = datetime.now(timezone.utc)
        source_ts = source_timestamp or now
        
        # Compute payload hash
        payload_hash = payload.compute_hash()
        
        # Store payload
        self.payloads[payload_hash] = payload.model_dump(mode="json")
        
        # Create new link
        link = SigchainLink(
            seqno=self.seqno + 1,
            prev_hash=self.head_hash,
            event_type=payload.event_type.value,
            payload_hash=payload_hash,
            source_timestamp=source_ts,
            append_timestamp=now,
            device=self.device,
        )
        
        self.links.append(link)
        return link
    
    def import_enclave_batch(
        self,
        batch: EnclaveImportBatch,
    ) -> SigchainLink:
        """Import a batch of events from Bastion Enclave.
        
        Creates individual links for each Enclave event, preserving their
        original timestamps, then creates an EnclaveImport wrapper event.
        
        Args:
            batch: Batch of events from Enclave
            
        Returns:
            The EnclaveImport wrapper link
            
        Raises:
            SigchainError: If batch verification fails
        """
        if not batch.verify_checksum():
            raise SigchainError("Enclave batch checksum verification failed")
        
        now = datetime.now(timezone.utc)
        batch.import_timestamp = now
        
        # Track imported event types for summary
        event_types: list[str] = []
        
        # Import each link from the batch
        for enclave_link in batch.links:
            # Create new link preserving source timestamp
            link = SigchainLink(
                seqno=self.seqno + 1,
                prev_hash=self.head_hash,
                event_type=enclave_link.event_type,
                payload_hash=enclave_link.payload_hash,
                source_timestamp=enclave_link.source_timestamp,
                append_timestamp=now,
                device=DeviceType.ENCLAVE,
                enclave_seqno=enclave_link.seqno,
            )
            self.links.append(link)
            event_types.append(enclave_link.event_type)
        
        # Create wrapper event
        import_payload = EnclaveImportPayload(
            source_head_hash=batch.source_head_hash,
            source_seqno=batch.source_seqno,
            events_imported=len(batch.links),
            event_types=event_types,
            export_timestamp=batch.export_timestamp,
            qr_sequence_count=batch.qr_sequence_count,
        )
        
        return self.append(import_payload, source_timestamp=now)
    
    def verify(self, full: bool = True) -> bool:
        """Verify chain integrity.
        
        Walks the chain from genesis, verifying that each link's prev_hash
        matches the computed hash of the previous link.
        
        Args:
            full: If True, verify entire chain; if False, only check last 100 links
            
        Returns:
            True if chain is valid
            
        Raises:
            ChainIntegrityError: If verification fails (with details)
        """
        if not self.links:
            return True
        
        # Determine starting point
        start_idx = 0 if full else max(0, len(self.links) - 100)
        
        for i in range(start_idx, len(self.links)):
            link = self.links[i]
            
            # Check sequence number
            expected_seqno = i + 1
            if link.seqno != expected_seqno:
                raise ChainIntegrityError(
                    f"Seqno mismatch at index {i}: expected {expected_seqno}, got {link.seqno}"
                )
            
            # Check prev_hash
            if i == 0:
                if link.prev_hash is not None:
                    raise ChainIntegrityError("Genesis link has non-null prev_hash")
            else:
                prev_link = self.links[i - 1]
                expected_prev = prev_link.compute_hash()
                if link.prev_hash != expected_prev:
                    raise ChainIntegrityError(
                        f"Hash mismatch at seqno {link.seqno}: "
                        f"expected {expected_prev[:16]}..., got {link.prev_hash[:16] if link.prev_hash else 'None'}..."
                    )
        
        return True
    
    def get_merkle_root(
        self,
        start_seqno: int | None = None,
        end_seqno: int | None = None,
    ) -> str:
        """Compute Merkle root of a range of events.
        
        Used for OTS anchoring — the Merkle root commits to all events
        in the range without revealing their contents.
        
        Args:
            start_seqno: First event to include (default: 1)
            end_seqno: Last event to include (default: current head)
            
        Returns:
            Hex-encoded SHA-256 Merkle root
        """
        start = start_seqno or 1
        end = end_seqno or self.seqno
        
        # Gather hashes for the range
        hashes: list[bytes] = []
        for link in self.links:
            if start <= link.seqno <= end:
                hashes.append(bytes.fromhex(link.compute_hash()))
        
        if not hashes:
            # Empty range — return hash of empty string
            return hashlib.sha256(b"").hexdigest()
        
        # Build Merkle tree
        while len(hashes) > 1:
            # Pad to even number if needed
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])
            
            # Combine pairs
            new_level: list[bytes] = []
            for i in range(0, len(hashes), 2):
                combined = hashlib.sha256(hashes[i] + hashes[i + 1]).digest()
                new_level.append(combined)
            hashes = new_level
        
        return hashes[0].hex()
    
    def get_chain_head(self) -> ChainHead:
        """Get current chain state for persistence.
        
        Returns:
            ChainHead with current state and event summaries
        """
        if not self.links:
            return ChainHead(
                head_hash="",
                seqno=0,
                device=self.device,
                last_events_summary="(empty chain)",
            )
        
        # Build summary of last 5 events
        summaries: list[str] = []
        for link in self.links[-5:]:
            payload_data = self.payloads.get(link.payload_hash, {})
            description = payload_data.get("account_title", "") or payload_data.get("domain", "") or ""
            if len(description) > 30:
                description = description[:27] + "..."
            
            summary = EventSummary(
                seqno=link.seqno,
                event_type=link.event_type,
                timestamp=link.source_timestamp,
                device=link.device,
                description=description or link.event_type,
            )
            summaries.append(summary.format_line())
        
        return ChainHead(
            head_hash=self.head_hash or "",
            seqno=self.seqno,
            device=self.device,
            last_events_summary="\n".join(summaries),
        )
    
    def export_for_git(self) -> dict:
        """Export chain state for git storage.
        
        Returns:
            Dictionary with chain data suitable for JSON serialization
        """
        return {
            "version": "1.0",
            "device": self.device.value,
            "head_hash": self.head_hash,
            "seqno": self.seqno,
            "links": [link.model_dump(mode="json") for link in self.links],
            "payloads": self.payloads,
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }
    
    def export_events_jsonl(
        self,
        start_seqno: int | None = None,
        end_seqno: int | None = None,
    ) -> Iterator[str]:
        """Export events as JSON Lines for append-only log.
        
        Args:
            start_seqno: First event (default: 1)
            end_seqno: Last event (default: head)
            
        Yields:
            JSON strings, one per event
        """
        start = start_seqno or 1
        end = end_seqno or self.seqno
        
        for link in self.links:
            if start <= link.seqno <= end:
                entry = {
                    "link": link.model_dump(mode="json"),
                    "payload": self.payloads.get(link.payload_hash),
                }
                yield json.dumps(entry, sort_keys=True, separators=(",", ":"))
    
    @classmethod
    def load_from_git(cls, data: dict) -> Sigchain:
        """Load chain from git export format.
        
        Args:
            data: Dictionary from export_for_git()
            
        Returns:
            Reconstructed Sigchain
        """
        device = DeviceType(data.get("device", "manager"))
        links = [SigchainLink.model_validate(ld) for ld in data.get("links", [])]
        payloads = data.get("payloads", {})
        
        chain = cls(device=device, links=links, payloads=payloads)
        
        # Verify on load
        chain.verify()
        
        return chain
    
    @classmethod
    def load_from_file(cls, path: Path) -> Sigchain:
        """Load chain from JSON file.
        
        Args:
            path: Path to chain.json
            
        Returns:
            Loaded Sigchain
        """
        with open(path) as f:
            data = json.load(f)
        return cls.load_from_git(data)
    
    def save_to_file(self, path: Path) -> None:
        """Save chain to JSON file.
        
        Args:
            path: Destination path
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.export_for_git(), f, indent=2)
    
    def __len__(self) -> int:
        """Return number of links in chain."""
        return len(self.links)
    
    def __iter__(self) -> Iterator[SigchainLink]:
        """Iterate over links."""
        return iter(self.links)
    
    def __getitem__(self, seqno: int) -> SigchainLink:
        """Get link by sequence number (1-indexed)."""
        if seqno < 1 or seqno > len(self.links):
            raise IndexError(f"Seqno {seqno} out of range [1, {len(self.links)}]")
        return self.links[seqno - 1]
