"""Tests for the sigchain module."""

from datetime import datetime, timezone
from pathlib import Path
import json
import tempfile

import pytest

from bastion.sigchain import (
    Sigchain,
    SigchainLink,
    ChainHead,
    DeviceType,
    AuditEventType,
    PasswordRotationPayload,
    UsernameGeneratedPayload,
    EntropyPoolCreatedPayload,
    TagOperationPayload,
    ConfigChangePayload,
)
from bastion.sigchain.chain import SigchainError, ChainIntegrityError


class TestSigchainLink:
    """Tests for SigchainLink model."""

    def test_create_link(self):
        """Test creating a sigchain link."""
        link = SigchainLink(
            seqno=1,
            prev_hash=None,
            event_type="PASSWORD_ROTATION",
            payload_hash="abc123",
            source_timestamp=datetime.now(timezone.utc),
            append_timestamp=datetime.now(timezone.utc),
            device=DeviceType.MANAGER,
        )
        assert link.seqno == 1
        assert link.prev_hash is None
        assert link.device == DeviceType.MANAGER

    def test_compute_hash(self):
        """Test that hash computation is deterministic."""
        ts = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        link = SigchainLink(
            seqno=1,
            prev_hash=None,
            event_type="TEST",
            payload_hash="abc123",
            source_timestamp=ts,
            append_timestamp=ts,
            device=DeviceType.MANAGER,
        )
        hash1 = link.compute_hash()
        hash2 = link.compute_hash()
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex

    def test_hash_changes_with_data(self):
        """Test that different data produces different hashes."""
        ts = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        link1 = SigchainLink(
            seqno=1,
            prev_hash=None,
            event_type="TEST",
            payload_hash="abc123",
            source_timestamp=ts,
            append_timestamp=ts,
            device=DeviceType.MANAGER,
        )
        link2 = SigchainLink(
            seqno=2,
            prev_hash=None,
            event_type="TEST",
            payload_hash="abc123",
            source_timestamp=ts,
            append_timestamp=ts,
            device=DeviceType.MANAGER,
        )
        assert link1.compute_hash() != link2.compute_hash()


class TestEventPayloads:
    """Tests for event payload models."""

    def test_password_rotation_payload(self):
        """Test PasswordRotationPayload creation and hashing."""
        payload = PasswordRotationPayload(
            account_uuid="uuid-123",
            account_title="Test Account",
            domain="example.com",
            new_change_date="2025-01-15",
            rotation_interval_days=90,
            tier="Tier 1",
        )
        assert payload.event_type == AuditEventType.PASSWORD_ROTATION
        hash1 = payload.compute_hash()
        assert len(hash1) == 64
        
    def test_username_generated_payload(self):
        """Test UsernameGeneratedPayload."""
        payload = UsernameGeneratedPayload(
            domain="github.com",
            algorithm="sha512",
            label="Bastion/USER/SHA2/512:github.com:2025-01-15#VERSION=1&LENGTH=16",
            username_hash="abc123def456",
            length=16,
        )
        assert payload.event_type == AuditEventType.USERNAME_GENERATED
        summary = payload.get_summary()
        assert "github.com" in summary

    def test_entropy_pool_payload(self):
        """Test EntropyPoolCreatedPayload."""
        payload = EntropyPoolCreatedPayload(
            pool_uuid="pool-uuid-123",
            serial_number=42,
            source="yubikey",
            bits=8192,
            quality_rating="EXCELLENT",
            entropy_per_byte=7.99,
        )
        assert payload.event_type == AuditEventType.ENTROPY_POOL_CREATED
        summary = payload.get_summary()
        assert "8192" in summary

    def test_tag_operation_payload(self):
        """Test TagOperationPayload."""
        payload = TagOperationPayload(
            account_uuid="uuid-456",
            account_title="Test",
            action="add",
            tags_before=[],
            tags_after=["Bastion/Tier/1"],
        )
        assert payload.event_type == AuditEventType.TAG_OPERATION

    def test_config_change_payload(self):
        """Test ConfigChangePayload."""
        payload = ConfigChangePayload(
            config_section="entropy",
            config_key="default_bits",
            old_value="4096",
            new_value="8192",
            source="cli",
        )
        assert payload.event_type == AuditEventType.CONFIG_CHANGE

    def test_payload_hash_determinism(self):
        """Test that payload hashing is deterministic."""
        payload1 = PasswordRotationPayload(
            account_uuid="uuid-123",
            account_title="Test",
            domain="example.com",
            new_change_date="2025-01-15",
        )
        payload2 = PasswordRotationPayload(
            account_uuid="uuid-123",
            account_title="Test",
            domain="example.com",
            new_change_date="2025-01-15",
        )
        assert payload1.compute_hash() == payload2.compute_hash()


class TestSigchain:
    """Tests for the Sigchain class."""

    def test_create_empty_chain(self):
        """Test creating an empty sigchain."""
        chain = Sigchain(device=DeviceType.MANAGER)
        assert chain.seqno == 0
        assert chain.head_hash is None
        assert len(chain.links) == 0

    def test_append_event(self):
        """Test appending an event to the chain."""
        chain = Sigchain(device=DeviceType.MANAGER)
        payload = PasswordRotationPayload(
            account_uuid="uuid-123",
            account_title="Test Account",
            domain="example.com",
            new_change_date="2025-01-15",
        )
        link = chain.append(payload)
        
        assert chain.seqno == 1
        assert link.seqno == 1
        assert link.prev_hash is None  # Genesis
        assert chain.head_hash == link.compute_hash()

    def test_append_multiple_events(self):
        """Test appending multiple events creates proper chain."""
        chain = Sigchain(device=DeviceType.MANAGER)
        
        # First event
        payload1 = PasswordRotationPayload(
            account_uuid="uuid-1",
            account_title="Account 1",
            domain="example.com",
            new_change_date="2025-01-15",
        )
        link1 = chain.append(payload1)
        
        # Second event
        payload2 = UsernameGeneratedPayload(
            domain="example.com",
            algorithm="sha512",
            label="Bastion/USER/SHA2/512:example.com:2025-01-15#VERSION=1&LENGTH=16",
            username_hash="abc123",
            length=16,
        )
        link2 = chain.append(payload2)
        
        assert chain.seqno == 2
        assert link2.prev_hash == link1.compute_hash()
        assert link1.prev_hash is None

    def test_verify_chain(self):
        """Test chain verification succeeds for valid chain."""
        chain = Sigchain(device=DeviceType.MANAGER)
        
        for i in range(5):
            payload = PasswordRotationPayload(
                account_uuid=f"uuid-{i}",
                account_title=f"Account {i}",
                domain="example.com",
                new_change_date="2025-01-15",
            )
            chain.append(payload)
        
        assert chain.verify() is True

    def test_verify_detects_tampering(self):
        """Test that verification fails if chain is tampered."""
        chain = Sigchain(device=DeviceType.MANAGER)
        
        for i in range(3):
            payload = PasswordRotationPayload(
                account_uuid=f"uuid-{i}",
                account_title=f"Account {i}",
                domain="example.com",
                new_change_date="2025-01-15",
            )
            chain.append(payload)
        
        # Tamper with middle link
        chain.links[1] = SigchainLink(
            seqno=2,
            prev_hash="tampered_hash",
            event_type="PASSWORD_ROTATION",
            payload_hash="fake",
            source_timestamp=datetime.now(timezone.utc),
            append_timestamp=datetime.now(timezone.utc),
            device=DeviceType.MANAGER,
        )
        
        with pytest.raises(ChainIntegrityError):
            chain.verify()

    def test_get_merkle_root(self):
        """Test merkle root computation."""
        chain = Sigchain(device=DeviceType.MANAGER)
        
        for i in range(4):
            payload = PasswordRotationPayload(
                account_uuid=f"uuid-{i}",
                account_title=f"Account {i}",
                domain="example.com",
                new_change_date="2025-01-15",
            )
            chain.append(payload)
        
        root = chain.get_merkle_root()
        assert len(root) == 64
        
        # Same chain should produce same root
        root2 = chain.get_merkle_root()
        assert root == root2

    def test_get_chain_head(self):
        """Test getting chain head state."""
        chain = Sigchain(device=DeviceType.MANAGER)
        
        payload = PasswordRotationPayload(
            account_uuid="uuid-1",
            account_title="Test Account",
            domain="example.com",
            new_change_date="2025-01-15",
        )
        chain.append(payload)
        
        head = chain.get_chain_head()
        assert isinstance(head, ChainHead)
        assert head.seqno == 1
        assert head.device == DeviceType.MANAGER

    def test_export_events_jsonl(self):
        """Test exporting events as JSONL."""
        chain = Sigchain(device=DeviceType.MANAGER)
        
        for i in range(3):
            payload = PasswordRotationPayload(
                account_uuid=f"uuid-{i}",
                account_title=f"Account {i}",
                domain="example.com",
                new_change_date="2025-01-15",
            )
            chain.append(payload)
        
        lines = list(chain.export_events_jsonl())
        assert len(lines) == 3
        
        # Each line should be valid JSON
        for line in lines:
            data = json.loads(line)
            assert "link" in data
            assert "payload" in data

    def test_save_and_load(self):
        """Test saving and loading chain from file."""
        chain = Sigchain(device=DeviceType.MANAGER)
        
        for i in range(3):
            payload = PasswordRotationPayload(
                account_uuid=f"uuid-{i}",
                account_title=f"Account {i}",
                domain="example.com",
                new_change_date="2025-01-15",
            )
            chain.append(payload)
        
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)
        
        try:
            chain.save_to_file(path)
            loaded = Sigchain.load_from_file(path)
            
            assert loaded.seqno == chain.seqno
            assert loaded.head_hash == chain.head_hash
            assert len(loaded.links) == len(chain.links)
        finally:
            path.unlink()


class TestDeviceType:
    """Tests for DeviceType enum."""

    def test_device_types(self):
        """Test device type values."""
        assert DeviceType.MANAGER.value == "manager"
        assert DeviceType.ENCLAVE.value == "enclave"

    def test_device_from_string(self):
        """Test creating device type from string."""
        assert DeviceType("manager") == DeviceType.MANAGER
        assert DeviceType("enclave") == DeviceType.ENCLAVE


class TestChainHead:
    """Tests for ChainHead model."""

    def test_create_chain_head(self):
        """Test creating a chain head."""
        head = ChainHead(
            head_hash="abc123",
            seqno=42,
            device=DeviceType.MANAGER,
        )
        assert head.seqno == 42
        assert head.device == DeviceType.MANAGER

    def test_chain_head_serialization(self):
        """Test serializing and deserializing chain head."""
        head = ChainHead(
            head_hash="abc123",
            seqno=42,
            device=DeviceType.MANAGER,
            last_events_summary="Test summary",
        )
        
        json_str = head.model_dump_json()
        loaded = ChainHead.model_validate_json(json_str)
        
        assert loaded.seqno == head.seqno
        assert loaded.head_hash == head.head_hash
