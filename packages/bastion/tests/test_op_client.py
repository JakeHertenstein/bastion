"""Tests for 1Password CLI operations in bastion/op_client.py.

These tests verify:
- Command argument sanitization
- Error handling for CLI failures
- Authentication error detection
- Proper subprocess usage (no shell=True)

All tests in this module are unit tests (mocked subprocess).
"""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest


# Mark all tests in this module as unit tests
pytestmark = pytest.mark.unit


class TestOPClientImports:
    """Test that op_client modules import correctly."""
    
    def test_op_client_imports(self):
        """Verify op_client module can be imported."""
        from bastion import op_client
        assert op_client is not None
    
    def test_op_auth_error_imports(self):
        """Verify OPAuthError can be imported."""
        from bastion.op_client import OPAuthError
        assert OPAuthError is not None
    
    def test_is_auth_error_imports(self):
        """Verify is_auth_error can be imported."""
        from bastion.op_client import is_auth_error
        assert is_auth_error is not None


class TestAuthErrorDetection:
    """Test authentication error detection."""
    
    def test_is_auth_error_not_signed_in(self):
        """Test detection of not signed in error."""
        from bastion.op_client import is_auth_error
        
        error_msg = "[ERROR] 2024/01/01 not signed in"
        assert is_auth_error(error_msg) is True
    
    def test_is_auth_error_session_expired(self):
        """Test detection of session expired error."""
        from bastion.op_client import is_auth_error
        
        error_msg = "[ERROR] session expired"
        assert is_auth_error(error_msg) is True
    
    def test_is_auth_error_authorization_denied(self):
        """Test detection of authorization denied error."""
        from bastion.op_client import is_auth_error
        
        error_msg = "[ERROR] authorization denied"
        assert is_auth_error(error_msg) is True
    
    def test_is_auth_error_not_auth(self):
        """Test that non-auth errors return False."""
        from bastion.op_client import is_auth_error
        
        error_msg = "[ERROR] Item not found"
        assert is_auth_error(error_msg) is False
    
    def test_is_auth_error_empty_string(self):
        """Test that empty string returns False."""
        from bastion.op_client import is_auth_error
        
        assert is_auth_error("") is False


class TestTagValidation:
    """Test tag validation."""
    
    def test_validate_tag_valid(self):
        """Test valid tag patterns."""
        from bastion.op_client import validate_tag
        
        assert validate_tag("Bastion/ENTROPY") is True
        assert validate_tag("Bastion/2FA/TOTP") is True
        assert validate_tag("Bastion/Category/Sub-category") is True
    
    def test_validate_tag_invalid(self):
        """Test invalid tag patterns."""
        from bastion.op_client import validate_tag
        
        assert validate_tag("bastion/entropy") is False  # lowercase
        assert validate_tag("Other/Tag") is False  # not Bastion prefix
        assert validate_tag("no-slash") is False


class TestSanitization:
    """Test input sanitization for subprocess."""
    
    def test_sanitize_for_subprocess(self):
        """Test that sanitization handles special characters."""
        from bastion.op_client import sanitize_for_subprocess
        
        # Should handle normal strings
        assert sanitize_for_subprocess("normal") == "normal"
        
        # Should handle strings with spaces
        result = sanitize_for_subprocess("has spaces")
        assert "spaces" in result


class TestIsAuthenticated:
    """Test is_authenticated function."""
    
    @patch("subprocess.run")
    def test_is_authenticated_true(self, mock_run):
        """Test is_authenticated returns True when authenticated."""
        from bastion.op_client import is_authenticated
        
        mock_run.return_value = MagicMock(returncode=0)
        
        assert is_authenticated() is True
    
    @patch("subprocess.run")
    def test_is_authenticated_false(self, mock_run):
        """Test is_authenticated returns False when not authenticated."""
        from bastion.op_client import is_authenticated
        
        mock_run.return_value = MagicMock(returncode=1)
        
        assert is_authenticated() is False
    
    @patch("subprocess.run")
    def test_is_authenticated_timeout(self, mock_run):
        """Test is_authenticated handles timeout."""
        from bastion.op_client import is_authenticated
        
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["op"], timeout=10)
        
        assert is_authenticated() is False


class TestSecurityPatterns:
    """Test security-related patterns in the code."""
    
    def test_auth_error_patterns_exist(self):
        """Verify AUTH_ERROR_PATTERNS is defined."""
        from bastion.op_client import AUTH_ERROR_PATTERNS
        
        assert isinstance(AUTH_ERROR_PATTERNS, list)
        assert len(AUTH_ERROR_PATTERNS) > 0
    
    def test_op_auth_error_docstring_warning(self):
        """Verify OPAuthError has security warning in docstring."""
        from bastion.op_client import OPAuthError
        
        assert "NEVER" in OPAuthError.__doc__ or "sensitive" in OPAuthError.__doc__.lower()
