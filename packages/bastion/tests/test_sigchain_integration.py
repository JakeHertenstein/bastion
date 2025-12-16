"""Tests for sigchain integration helpers."""

import pytest

from bastion.sigchain.integration import (
    get_active_session,
    set_active_session,
    is_sigchain_enabled,
)
from bastion.sigchain.events import (
    PasswordRotationPayload,
    UsernameGeneratedPayload,
    EntropyPoolCreatedPayload,
    TagOperationPayload,
    ConfigChangePayload,
)


class TestSessionState:
    """Tests for session state management."""

    def test_initial_state_is_none(self):
        """Test that initial session state is None."""
        # Clear any existing state
        set_active_session(None)
        assert get_active_session() is None

    def test_set_and_get_session(self):
        """Test setting and getting session."""
        # Create a mock session-like object
        class MockSession:
            active = True
        
        mock = MockSession()
        set_active_session(mock)
        
        assert get_active_session() is mock
        
        # Clean up
        set_active_session(None)

    def test_clear_session(self):
        """Test clearing session state."""
        class MockSession:
            active = True
        
        set_active_session(MockSession())
        set_active_session(None)
        
        assert get_active_session() is None


class TestSigchainEnabled:
    """Tests for sigchain enabled check."""

    def test_default_enabled(self):
        """Test that sigchain is enabled by default."""
        # This may fail if config module isn't available
        # In that case, it should default to True
        result = is_sigchain_enabled()
        assert result is True


class TestEventPayloadHelpers:
    """Tests for event creation via helper functions.
    
    These tests verify that the payloads created by integration helpers
    have the correct structure and field names.
    """

    def test_password_rotation_payload_structure(self):
        """Test PasswordRotationPayload has expected fields."""
        payload = PasswordRotationPayload(
            account_uuid="test-uuid",
            account_title="Test Account",
            domain="example.com",
            new_change_date="2025-01-15",
        )
        
        assert payload.account_uuid == "test-uuid"
        assert payload.domain == "example.com"
        assert payload.new_change_date == "2025-01-15"
        assert payload.compute_hash()  # Should not raise

    def test_username_generated_payload_structure(self):
        """Test UsernameGeneratedPayload has expected fields."""
        payload = UsernameGeneratedPayload(
            domain="github.com",
            algorithm="sha3-512",
            label="test-label",
            username_hash="abc123",
            length=16,
        )
        
        assert payload.domain == "github.com"
        assert payload.algorithm == "sha3-512"
        assert payload.length == 16
        assert payload.compute_hash()

    def test_entropy_pool_payload_structure(self):
        """Test EntropyPoolCreatedPayload has expected fields."""
        payload = EntropyPoolCreatedPayload(
            pool_uuid="pool-123",
            serial_number=42,
            source="yubikey",
            bits=8192,
            quality_rating="EXCELLENT",
            entropy_per_byte=7.99,
        )
        
        assert payload.serial_number == 42
        assert payload.source == "yubikey"
        assert payload.bits == 8192
        assert payload.compute_hash()

    def test_tag_operation_payload_structure(self):
        """Test TagOperationPayload has expected fields."""
        payload = TagOperationPayload(
            account_uuid="acc-uuid",
            account_title="Test",
            action="add",
            tags_before=[],
            tags_after=["Bastion/Tier/1"],
        )
        
        assert payload.action == "add"
        assert payload.tags_after == ["Bastion/Tier/1"]
        assert payload.compute_hash()

    def test_config_change_payload_structure(self):
        """Test ConfigChangePayload has expected fields."""
        payload = ConfigChangePayload(
            config_section="sigchain",
            config_key="enabled",
            old_value="true",
            new_value="false",
        )
        
        assert payload.config_section == "sigchain"
        assert payload.config_key == "enabled"
        assert payload.compute_hash()
