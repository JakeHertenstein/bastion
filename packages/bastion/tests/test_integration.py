"""Integration tests for Bastion CLI.

These tests require:
- 1Password CLI (`op`) installed and authenticated
- Access to test vault

Run with: pytest -m integration tests/test_integration.py

Skip with: pytest -m "not integration"
"""

import json
import subprocess
from unittest.mock import patch

import pytest


def is_1password_authenticated() -> bool:
    """Check if 1Password CLI is available and authenticated."""
    try:
        result = subprocess.run(
            ["op", "whoami"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


# Skip all tests in this module if 1Password is not authenticated
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not is_1password_authenticated(),
        reason="1Password CLI not available or not signed in"
    ),
]


class TestOPClientIntegration:
    """Integration tests for 1Password CLI wrapper."""
    
    def test_op_whoami(self):
        """Test that op whoami works (basic auth check)."""
        result = subprocess.run(
            ["op", "whoami", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "email" in data or "user_uuid" in data
    
    def test_op_vault_list(self):
        """Test that vault listing works."""
        result = subprocess.run(
            ["op", "vault", "list", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        assert result.returncode == 0
        vaults = json.loads(result.stdout)
        assert isinstance(vaults, list)
        # Should have at least one vault
        assert len(vaults) >= 1
    
    def test_op_item_list(self):
        """Test that item listing works."""
        result = subprocess.run(
            ["op", "item", "list", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        assert result.returncode == 0
        # Should return valid JSON (empty list or items)
        items = json.loads(result.stdout)
        assert isinstance(items, list)


class TestBastionCLIIntegration:
    """Integration tests for Bastion CLI commands."""
    
    def test_bastion_help(self):
        """Test bastion --help works."""
        result = subprocess.run(
            ["bastion", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        assert result.returncode == 0
        assert "bastion" in result.stdout.lower()
    
    def test_bastion_show_config(self):
        """Test bastion show config works."""
        result = subprocess.run(
            ["bastion", "show", "config"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        # Should succeed even without config file (uses defaults)
        assert result.returncode == 0
        assert "Settings" in result.stdout or "Default" in result.stdout
    
    def test_bastion_sync_help(self):
        """Test bastion sync --help works."""
        result = subprocess.run(
            ["bastion", "sync", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        assert result.returncode == 0


class TestEntropyPoolIntegration:
    """Integration tests for entropy pool operations."""
    
    def test_list_entropy_pools(self):
        """Test listing entropy pools (may be empty)."""
        result = subprocess.run(
            ["bastion", "show", "entropy"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        
        # Should succeed (may show "no pools" message)
        assert result.returncode == 0


class TestDatabaseIntegration:
    """Integration tests for database operations."""
    
    def test_cache_key_check(self):
        """Test that cache key infrastructure exists or can be created."""
        from bastion.db import BastionCacheManager
        
        manager = BastionCacheManager()
        
        # Either key exists, or we get a helpful error
        try:
            key_exists = manager.key_exists()
            assert isinstance(key_exists, bool)
        except Exception as e:
            # Should be a known error type
            assert "1Password" in str(e) or "key" in str(e).lower()


class TestTagOperationsIntegration:
    """Integration tests for tag operations."""
    
    def test_list_bastion_tags(self):
        """Test listing items with Bastion tags."""
        result = subprocess.run(
            ["op", "item", "list", "--tags", "Bastion", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        
        # Should succeed (may return empty list)
        assert result.returncode == 0
        items = json.loads(result.stdout)
        assert isinstance(items, list)
