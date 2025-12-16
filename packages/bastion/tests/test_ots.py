"""Tests for the OTS (OpenTimestamps) module."""

import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from bastion.ots import (
    OTSAnchor,
    AnchorStatus,
    PendingAnchor,
    CompletedAnchor,
    MerkleTree,
    OTSCalendar,
    CalendarServer,
    DEFAULT_CALENDARS,
    check_ots_available,
)


class TestMerkleTree:
    """Tests for MerkleTree implementation."""

    def test_empty_tree(self):
        """Test empty merkle tree."""
        tree = MerkleTree()
        root = tree.get_root_hex()
        # Empty tree should return hash of empty string
        assert len(root) == 64

    def test_single_leaf(self):
        """Test tree with single leaf."""
        tree = MerkleTree()
        tree.add_leaf(b"test data")
        root = tree.get_root_hex()
        assert len(root) == 64

    def test_two_leaves(self):
        """Test tree with two leaves."""
        tree = MerkleTree()
        tree.add_leaf(b"leaf1")
        tree.add_leaf(b"leaf2")
        root = tree.get_root_hex()
        assert len(root) == 64

    def test_multiple_leaves(self):
        """Test tree with multiple leaves."""
        tree = MerkleTree()
        for i in range(8):
            tree.add_leaf(f"leaf{i}".encode())
        root = tree.get_root_hex()
        assert len(root) == 64

    def test_deterministic_root(self):
        """Test that same leaves produce same root."""
        tree1 = MerkleTree()
        tree2 = MerkleTree()
        
        for i in range(4):
            tree1.add_leaf(f"data{i}".encode())
            tree2.add_leaf(f"data{i}".encode())
        
        assert tree1.get_root_hex() == tree2.get_root_hex()

    def test_different_leaves_different_root(self):
        """Test that different leaves produce different roots."""
        tree1 = MerkleTree()
        tree2 = MerkleTree()
        
        tree1.add_leaf(b"data1")
        tree2.add_leaf(b"data2")
        
        assert tree1.get_root_hex() != tree2.get_root_hex()

    def test_add_leaf_hex_string(self):
        """Test adding leaf as hex string."""
        tree = MerkleTree()
        tree.add_leaf("abcd1234")
        root = tree.get_root_hex()
        assert len(root) == 64

    def test_get_proof(self):
        """Test merkle proof generation."""
        tree = MerkleTree()
        for i in range(4):
            tree.add_leaf(f"leaf{i}".encode())
        
        proof = tree.get_proof(0)
        assert len(proof) > 0

    def test_verify_proof(self):
        """Test merkle proof verification."""
        tree = MerkleTree()
        leaves = [f"leaf{i}".encode() for i in range(4)]
        for leaf in leaves:
            tree.add_leaf(leaf)
        
        root = tree.get_root()
        proof = tree.get_proof(0)
        
        assert MerkleTree.verify_proof(leaves[0], proof, root)


class TestPendingAnchor:
    """Tests for PendingAnchor model."""

    def test_create_pending_anchor(self):
        """Test creating a pending anchor."""
        anchor = PendingAnchor(
            merkle_root="abc123def456",
            session_id="session-001",
            seqno_range=(1, 10),
            event_count=10,
        )
        assert anchor.status == AnchorStatus.PENDING
        assert anchor.merkle_root == "abc123def456"
        assert anchor.event_count == 10

    def test_pending_anchor_defaults(self):
        """Test default values for pending anchor."""
        anchor = PendingAnchor(
            merkle_root="abc123",
            session_id="test",
            seqno_range=(1, 5),
            event_count=5,
        )
        assert anchor.ots_proof_pending is None
        assert anchor.upgrade_attempts == 0
        assert anchor.status == AnchorStatus.PENDING


class TestCompletedAnchor:
    """Tests for CompletedAnchor model."""

    def test_create_completed_anchor(self):
        """Test creating a completed anchor."""
        anchor = CompletedAnchor(
            merkle_root="abc123def456",
            session_id="session-001",
            created_at=datetime.now(timezone.utc),
            seqno_range=(1, 10),
            event_count=10,
            ots_proof="base64encodedproof",
            bitcoin_block_height=800000,
        )
        assert anchor.status == AnchorStatus.CONFIRMED
        assert anchor.bitcoin_block_height == 800000


class TestOTSAnchor:
    """Tests for OTSAnchor manager."""

    def test_create_anchor(self):
        """Test creating an anchor from event hashes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            anchor_mgr = OTSAnchor(Path(tmpdir))
            
            # Use valid SHA-256 hex hashes
            event_hashes = [
                "abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
                "def456abc123def456abc123def456abc123def456abc123def456abc123def4",
                "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
            ]
            
            pending = anchor_mgr.create_anchor(
                session_id="test-session",
                event_hashes=event_hashes,
                seqno_range=(1, 3),
            )
            
            assert pending.event_count == 3
            assert pending.session_id == "test-session"
            assert len(pending.merkle_root) == 64

    def test_save_and_load_pending(self):
        """Test saving and loading pending anchors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            anchor_mgr = OTSAnchor(Path(tmpdir))
            
            pending = anchor_mgr.create_anchor(
                session_id="test-session",
                event_hashes=[
                    "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
                    "efef5678efef5678efef5678efef5678efef5678efef5678efef5678efef5678",
                ],
                seqno_range=(1, 2),
            )
            
            anchor_mgr.save_pending(pending)
            
            loaded = anchor_mgr.load_pending()
            assert len(loaded) == 1
            assert loaded[0].session_id == "test-session"

    def test_get_anchor_for_seqno(self):
        """Test finding anchor by seqno."""
        with tempfile.TemporaryDirectory() as tmpdir:
            anchor_mgr = OTSAnchor(Path(tmpdir))
            
            pending = anchor_mgr.create_anchor(
                session_id="test-session",
                event_hashes=[
                    "0000111100001111000011110000111100001111000011110000111100001111",
                    "0000222200002222000022220000222200002222000022220000222200002222",
                    "0000333300003333000033330000333300003333000033330000333300003333",
                    "0000444400004444000044440000444400004444000044440000444400004444",
                    "0000555500005555000055550000555500005555000055550000555500005555",
                ],
                seqno_range=(10, 14),
            )
            anchor_mgr.save_pending(pending)
            
            # Should find anchor for seqno 12
            found = anchor_mgr.get_anchor_for_seqno(12)
            assert found is not None
            assert found.session_id == "test-session"
            
            # Should not find anchor for seqno 5
            not_found = anchor_mgr.get_anchor_for_seqno(5)
            assert not_found is None

    def test_get_stats(self):
        """Test getting anchor statistics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            anchor_mgr = OTSAnchor(Path(tmpdir))
            
            # Create some pending anchors with valid hex hashes
            for i in range(3):
                hashes = [
                    f"aaaa{j:04d}aaaa{j:04d}aaaa{j:04d}aaaa{j:04d}aaaa{j:04d}aaaa{j:04d}aaaa{j:04d}aaaa{j:04d}"
                    for j in range(5)
                ]
                pending = anchor_mgr.create_anchor(
                    session_id=f"session-{i}",
                    event_hashes=hashes,
                    seqno_range=(i * 5 + 1, i * 5 + 5),
                )
                anchor_mgr.save_pending(pending)
            
            stats = anchor_mgr.get_stats()
            assert stats["pending_count"] == 3
            assert stats["completed_count"] == 0
            assert stats["total_events_pending"] == 15


class TestCalendarServer:
    """Tests for CalendarServer enum."""

    def test_calendar_servers(self):
        """Test calendar server values."""
        assert "alice" in CalendarServer.ALICE.value
        assert "bob" in CalendarServer.BOB.value
        assert "finney" in CalendarServer.FINNEY.value

    def test_default_calendars(self):
        """Test default calendar list."""
        assert len(DEFAULT_CALENDARS) >= 2
        assert CalendarServer.ALICE in DEFAULT_CALENDARS


class TestOTSCalendar:
    """Tests for OTSCalendar client."""

    def test_create_client(self):
        """Test creating calendar client."""
        client = OTSCalendar()
        assert len(client.calendars) > 0

    def test_check_ots_available(self):
        """Test checking OTS availability."""
        available, message = check_ots_available()
        # Either available or not, should return tuple
        assert isinstance(available, bool)
        assert isinstance(message, str)
