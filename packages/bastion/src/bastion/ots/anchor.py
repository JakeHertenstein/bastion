"""OpenTimestamps anchor management.

This module handles:
- Creating merkle roots from session events
- Submitting anchors to calendar servers
- Managing pending anchors until Bitcoin confirmation
- Storing and retrieving completed proofs
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class AnchorStatus(str, Enum):
    """Status of an OTS anchor."""
    
    PENDING = "pending"  # Submitted, awaiting Bitcoin confirmation
    CONFIRMED = "confirmed"  # Bitcoin block confirmation received
    FAILED = "failed"  # Submission or upgrade failed
    UPGRADED = "upgraded"  # Proof upgraded with attestation


class PendingAnchor(BaseModel):
    """A timestamp anchor awaiting Bitcoin confirmation.
    
    Pending anchors are stored locally until the OTS proof can be
    upgraded with a Bitcoin attestation (typically 1-24 hours).
    """
    
    merkle_root: str = Field(description="Hex-encoded merkle root hash")
    session_id: str = Field(description="Session that created this anchor")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    seqno_range: tuple[int, int] = Field(description="Range of sigchain seqnos included")
    event_count: int = Field(description="Number of events in this anchor")
    
    # OTS proof data (incomplete until upgraded)
    ots_proof_pending: str | None = Field(
        default=None,
        description="Base64-encoded pending .ots proof"
    )
    
    # Calendar responses
    calendar_responses: dict[str, str] = Field(
        default_factory=dict,
        description="Responses from each calendar server"
    )
    
    status: AnchorStatus = Field(default=AnchorStatus.PENDING)
    last_upgrade_attempt: datetime | None = Field(default=None)
    upgrade_attempts: int = Field(default=0)
    
    model_config = {"frozen": False}


class CompletedAnchor(BaseModel):
    """A fully confirmed OTS timestamp proof.
    
    Once the Bitcoin attestation is available, the pending anchor
    is upgraded to a completed anchor with the full proof.
    """
    
    merkle_root: str = Field(description="Hex-encoded merkle root hash")
    session_id: str = Field(description="Session that created this anchor")
    created_at: datetime
    confirmed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    seqno_range: tuple[int, int]
    event_count: int
    
    # Full OTS proof
    ots_proof: str = Field(description="Base64-encoded complete .ots proof")
    
    # Bitcoin attestation details
    bitcoin_block_height: int | None = Field(default=None)
    bitcoin_block_hash: str | None = Field(default=None)
    bitcoin_timestamp: datetime | None = Field(default=None)
    
    status: AnchorStatus = Field(default=AnchorStatus.CONFIRMED)
    
    model_config = {"frozen": True}


@dataclass
class MerkleTree:
    """Merkle tree for batching event hashes.
    
    Builds a binary merkle tree from event payload hashes,
    producing a single root that can be timestamped.
    """
    
    leaves: list[bytes] = field(default_factory=list)
    _levels: list[list[bytes]] = field(default_factory=list)
    
    def add_leaf(self, data: bytes | str) -> None:
        """Add a leaf to the tree.
        
        Args:
            data: Raw bytes or hex string to add as leaf
        """
        if isinstance(data, str):
            data = bytes.fromhex(data)
        self.leaves.append(data)
        self._levels = []  # Invalidate cached levels
    
    def _hash_pair(self, left: bytes, right: bytes) -> bytes:
        """Hash two nodes together."""
        # Sort to ensure deterministic ordering
        if left > right:
            left, right = right, left
        return hashlib.sha256(left + right).digest()
    
    def _build(self) -> None:
        """Build the merkle tree from leaves."""
        if not self.leaves:
            self._levels = []
            return
        
        # First level is the leaf hashes
        current_level = [hashlib.sha256(leaf).digest() for leaf in self.leaves]
        self._levels = [current_level]
        
        # Build up the tree
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    next_level.append(
                        self._hash_pair(current_level[i], current_level[i + 1])
                    )
                else:
                    # Odd number of nodes - promote the last one
                    next_level.append(current_level[i])
            current_level = next_level
            self._levels.append(current_level)
    
    def get_root(self) -> bytes:
        """Get the merkle root.
        
        Returns:
            The root hash, or empty hash if no leaves
        """
        if not self.leaves:
            return hashlib.sha256(b"").digest()
        
        if not self._levels:
            self._build()
        
        return self._levels[-1][0]
    
    def get_root_hex(self) -> str:
        """Get the merkle root as hex string."""
        return self.get_root().hex()
    
    def get_proof(self, leaf_index: int) -> list[tuple[bytes, str]]:
        """Get merkle proof for a specific leaf.
        
        Args:
            leaf_index: Index of the leaf to prove
            
        Returns:
            List of (hash, direction) tuples for verification
        """
        if not self.leaves or leaf_index >= len(self.leaves):
            return []
        
        if not self._levels:
            self._build()
        
        proof = []
        idx = leaf_index
        
        for level in self._levels[:-1]:  # Exclude root level
            if idx % 2 == 0:
                # We're on the left, sibling is on right
                if idx + 1 < len(level):
                    proof.append((level[idx + 1], "right"))
            else:
                # We're on the right, sibling is on left
                proof.append((level[idx - 1], "left"))
            idx //= 2
        
        return proof
    
    @staticmethod
    def verify_proof(
        leaf: bytes,
        proof: list[tuple[bytes, str]],
        root: bytes
    ) -> bool:
        """Verify a merkle proof.
        
        Args:
            leaf: The original leaf data
            proof: Proof from get_proof()
            root: Expected merkle root
            
        Returns:
            True if proof is valid
        """
        current = hashlib.sha256(leaf).digest()
        
        for sibling, direction in proof:
            # Sort to match _hash_pair behavior
            if direction == "left":
                left, right = sibling, current
            else:
                left, right = current, sibling
            
            # Apply same sorting as _hash_pair
            if left > right:
                left, right = right, left
            
            current = hashlib.sha256(left + right).digest()
        
        return current == root


class OTSAnchor:
    """Manages OTS anchoring for sigchain events.
    
    This class handles the full lifecycle of timestamp proofs:
    1. Building merkle trees from session events
    2. Submitting roots to calendar servers
    3. Storing pending anchors
    4. Upgrading proofs once Bitcoin confirmation arrives
    5. Storing completed proofs
    
    Example:
        >>> anchor = OTSAnchor(storage_path)
        >>> anchor.create_anchor(session_id, event_hashes, seqno_range)
        >>> # Later, upgrade pending anchors
        >>> anchor.upgrade_pending()
    """
    
    def __init__(self, storage_path: Path):
        """Initialize the anchor manager.
        
        Args:
            storage_path: Path to store anchor data
        """
        self.storage_path = Path(storage_path)
        self.pending_path = self.storage_path / "pending"
        self.completed_path = self.storage_path / "completed"
        
        # Ensure directories exist
        self.pending_path.mkdir(parents=True, exist_ok=True)
        self.completed_path.mkdir(parents=True, exist_ok=True)
    
    def create_anchor(
        self,
        session_id: str,
        event_hashes: list[str],
        seqno_range: tuple[int, int],
    ) -> PendingAnchor:
        """Create a new anchor from event hashes.
        
        Builds a merkle tree and prepares for submission to calendars.
        
        Args:
            session_id: ID of the session creating this anchor
            event_hashes: List of hex-encoded event payload hashes
            seqno_range: (start, end) seqno range of events
            
        Returns:
            PendingAnchor ready for submission
        """
        # Build merkle tree
        tree = MerkleTree()
        for hash_hex in event_hashes:
            tree.add_leaf(hash_hex)
        
        merkle_root = tree.get_root_hex()
        
        # Create pending anchor
        anchor = PendingAnchor(
            merkle_root=merkle_root,
            session_id=session_id,
            seqno_range=seqno_range,
            event_count=len(event_hashes),
        )
        
        return anchor
    
    def save_pending(self, anchor: PendingAnchor) -> Path:
        """Save a pending anchor to disk.
        
        Args:
            anchor: The anchor to save
            
        Returns:
            Path to saved file
        """
        filename = f"{anchor.session_id}_{anchor.merkle_root[:16]}.json"
        filepath = self.pending_path / filename
        
        filepath.write_text(anchor.model_dump_json(indent=2))
        return filepath
    
    def load_pending(self) -> list[PendingAnchor]:
        """Load all pending anchors.
        
        Returns:
            List of pending anchors
        """
        anchors = []
        for filepath in self.pending_path.glob("*.json"):
            try:
                data = json.loads(filepath.read_text())
                anchors.append(PendingAnchor.model_validate(data))
            except Exception:
                continue
        return anchors
    
    def save_completed(self, anchor: CompletedAnchor) -> Path:
        """Save a completed anchor to disk.
        
        Args:
            anchor: The completed anchor to save
            
        Returns:
            Path to saved file
        """
        filename = f"{anchor.session_id}_{anchor.merkle_root[:16]}.json"
        filepath = self.completed_path / filename
        
        filepath.write_text(anchor.model_dump_json(indent=2))
        
        # Remove from pending
        pending_filepath = self.pending_path / filename
        if pending_filepath.exists():
            pending_filepath.unlink()
        
        return filepath
    
    def load_completed(self, merkle_root: str | None = None) -> list[CompletedAnchor]:
        """Load completed anchors.
        
        Args:
            merkle_root: Optional filter by merkle root
            
        Returns:
            List of completed anchors
        """
        anchors = []
        for filepath in self.completed_path.glob("*.json"):
            try:
                data = json.loads(filepath.read_text())
                anchor = CompletedAnchor.model_validate(data)
                if merkle_root is None or anchor.merkle_root == merkle_root:
                    anchors.append(anchor)
            except Exception:
                continue
        return anchors
    
    def get_anchor_for_seqno(self, seqno: int) -> CompletedAnchor | PendingAnchor | None:
        """Find the anchor containing a specific seqno.
        
        Args:
            seqno: The sigchain sequence number
            
        Returns:
            The anchor containing this seqno, or None
        """
        # Check completed first
        for anchor in self.load_completed():
            start, end = anchor.seqno_range
            if start <= seqno <= end:
                return anchor
        
        # Check pending
        for anchor in self.load_pending():
            start, end = anchor.seqno_range
            if start <= seqno <= end:
                return anchor
        
        return None
    
    def get_stats(self) -> dict[str, Any]:
        """Get anchor statistics.
        
        Returns:
            Dict with pending/completed counts and ranges
        """
        pending = self.load_pending()
        completed = self.load_completed()
        
        all_seqnos: list[int] = []
        for a in pending + completed:  # type: ignore
            all_seqnos.extend(range(a.seqno_range[0], a.seqno_range[1] + 1))
        
        return {
            "pending_count": len(pending),
            "completed_count": len(completed),
            "total_events_anchored": sum(a.event_count for a in completed),
            "total_events_pending": sum(a.event_count for a in pending),
            "seqno_coverage": sorted(set(all_seqnos)) if all_seqnos else [],
        }
