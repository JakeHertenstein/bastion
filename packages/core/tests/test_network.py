"""Tests for bastion_core.network module."""

import pytest

from bastion_core.network import (
    AirgapStatus,
    can_reach_dns,
    can_reach_host,
    check_airgap_status,
    has_internet_connectivity,
    has_network_interfaces,
    is_airgapped,
)


class TestAirgapDetection:
    """Tests for air-gap detection."""

    def test_is_airgapped_returns_bool(self):
        """is_airgapped() should return a boolean."""
        result = is_airgapped()
        assert isinstance(result, bool)

    def test_has_network_interfaces_returns_bool(self):
        """has_network_interfaces() should return a boolean."""
        result = has_network_interfaces()
        assert isinstance(result, bool)

    def test_is_airgapped_inverse_of_has_interfaces(self):
        """is_airgapped() should be inverse of has_network_interfaces()."""
        assert is_airgapped() == (not has_network_interfaces())


class TestAirgapStatus:
    """Tests for detailed air-gap status check."""

    def test_check_airgap_status_returns_status(self):
        """check_airgap_status() should return AirgapStatus."""
        result = check_airgap_status()
        assert isinstance(result, AirgapStatus)

    def test_airgap_status_fields(self):
        """AirgapStatus should have all expected fields."""
        status = check_airgap_status()
        assert hasattr(status, "is_airgapped")
        assert hasattr(status, "has_wifi")
        assert hasattr(status, "has_ethernet")
        assert hasattr(status, "has_bluetooth")
        assert hasattr(status, "active_interfaces")
        assert hasattr(status, "warnings")

    def test_airgap_status_types(self):
        """AirgapStatus fields should have correct types."""
        status = check_airgap_status()
        assert isinstance(status.is_airgapped, bool)
        assert isinstance(status.has_wifi, bool)
        assert isinstance(status.has_ethernet, bool)
        assert isinstance(status.has_bluetooth, bool)
        assert isinstance(status.active_interfaces, list)
        assert isinstance(status.warnings, list)


class TestConnectivity:
    """Tests for connectivity checking."""

    def test_has_internet_connectivity_returns_bool(self):
        """has_internet_connectivity() should return a boolean."""
        result = has_internet_connectivity()
        assert isinstance(result, bool)

    def test_can_reach_host_localhost(self):
        """can_reach_host() should work with localhost."""
        # This might fail if nothing is listening on 80
        # but the function should return a boolean either way
        result = can_reach_host("127.0.0.1", port=80, timeout=0.5)
        assert isinstance(result, bool)

    def test_can_reach_host_invalid(self):
        """can_reach_host() should return False for invalid hosts."""
        result = can_reach_host("192.0.2.1", port=80, timeout=0.5)  # TEST-NET-1
        assert result is False

    def test_can_reach_dns_returns_bool(self):
        """can_reach_dns() should return a boolean."""
        result = can_reach_dns(timeout=1.0)
        assert isinstance(result, bool)


class TestConnectivityConsistency:
    """Tests for consistency between connectivity functions."""

    @pytest.mark.integration
    def test_connectivity_matches_dns_reach(self):
        """If we have connectivity, we should reach DNS."""
        # This is an integration test as it requires network
        if has_internet_connectivity():
            assert can_reach_dns()
