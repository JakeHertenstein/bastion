"""Pytest configuration and shared fixtures for Bastion tests.

Markers:
    @pytest.mark.unit - Fast tests without external dependencies
    @pytest.mark.integration - Tests requiring 1Password CLI
    @pytest.mark.slow - Tests taking > 1 second
    @pytest.mark.crypto - Cryptographic operation tests

Run markers:
    pytest -m unit           # Run only unit tests
    pytest -m "not integration"  # Skip integration tests
    pytest -m crypto         # Run only crypto tests
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# Auto-mark tests based on fixtures they use
def pytest_collection_modifyitems(config, items):
    """Automatically apply markers based on test characteristics."""
    for item in items:
        # Mark tests using mock_op_cli as unit tests
        if "mock_op_cli" in item.fixturenames:
            item.add_marker(pytest.mark.unit)
        
        # Mark tests in certain modules
        if "test_entropy" in str(item.fspath) or "test_db_encryption" in str(item.fspath):
            item.add_marker(pytest.mark.crypto)


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_op_cli():
    """Mock 1Password CLI subprocess calls.
    
    Use this fixture to avoid actual 1Password API calls during tests.
    """
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout="{}",
            stderr="",
            returncode=0,
        )
        yield mock_run


@pytest.fixture
def sample_entropy_bytes():
    """Generate sample entropy bytes for testing.
    
    Returns 1024 bytes of pseudo-random data (NOT cryptographically secure,
    only for testing entropy processing logic).
    """
    import hashlib
    # Deterministic "random" bytes for reproducible tests
    seed = b"bastion-test-seed-do-not-use-in-production"
    result = b""
    for i in range(64):  # 64 * 16 = 1024 bytes
        result += hashlib.md5(seed + i.to_bytes(4, 'big')).digest()
    return result


@pytest.fixture
def sample_salt():
    """Generate a sample salt for username generation tests."""
    return bytes.fromhex(
        "0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef"
    )


@pytest.fixture
def mock_fernet_key():
    """Generate a valid Fernet key for encryption tests."""
    from cryptography.fernet import Fernet
    return Fernet.generate_key()
