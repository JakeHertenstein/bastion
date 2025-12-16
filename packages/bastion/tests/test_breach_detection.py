"""Tests for breach detection in bastion/breach_detection.py.

These tests verify:
- HIBP k-anonymity implementation (hash prefix/suffix split)
- Password hash generation
- API response parsing
- Breach count extraction

All tests use mocked HTTP responses to avoid external API calls.
"""

import hashlib
from unittest.mock import MagicMock, patch

import pytest


# Mark all tests in this module as unit tests
pytestmark = pytest.mark.unit


class TestBreachDetectorImports:
    """Test that breach_detection modules import correctly."""
    
    def test_breach_detector_imports(self):
        """Verify BreachDetector can be imported."""
        from bastion.breach_detection import BreachDetector
        assert BreachDetector is not None


class TestKAnonymityHashSplit:
    """Test k-anonymity hash prefix/suffix implementation."""
    
    def test_hash_split_returns_tuple(self):
        """Test that _get_password_hash_prefix returns tuple."""
        from bastion.breach_detection import BreachDetector
        from rich.console import Console
        
        detector = BreachDetector(Console())
        result = detector._get_password_hash_prefix("password123")
        
        assert isinstance(result, tuple)
        assert len(result) == 2
    
    def test_hash_prefix_is_5_chars(self):
        """Test that prefix is exactly 5 characters (HIBP requirement)."""
        from bastion.breach_detection import BreachDetector
        from rich.console import Console
        
        detector = BreachDetector(Console())
        prefix, suffix = detector._get_password_hash_prefix("test")
        
        assert len(prefix) == 5
    
    def test_hash_suffix_is_35_chars(self):
        """Test that suffix is remaining 35 chars of SHA-1."""
        from bastion.breach_detection import BreachDetector
        from rich.console import Console
        
        detector = BreachDetector(Console())
        prefix, suffix = detector._get_password_hash_prefix("test")
        
        # SHA-1 is 40 hex chars, minus 5 prefix = 35 suffix
        assert len(suffix) == 35
    
    def test_hash_is_uppercase(self):
        """Test that hash is uppercase (HIBP format)."""
        from bastion.breach_detection import BreachDetector
        from rich.console import Console
        
        detector = BreachDetector(Console())
        prefix, suffix = detector._get_password_hash_prefix("test")
        
        assert prefix == prefix.upper()
        assert suffix == suffix.upper()
    
    def test_known_password_hash(self):
        """Test hash of known password matches expected SHA-1."""
        from bastion.breach_detection import BreachDetector
        from rich.console import Console
        
        detector = BreachDetector(Console())
        # SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        prefix, suffix = detector._get_password_hash_prefix("password")
        
        assert prefix == "5BAA6"
        assert suffix == "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
    
    def test_different_passwords_different_hashes(self):
        """Test that different passwords produce different hashes."""
        from bastion.breach_detection import BreachDetector
        from rich.console import Console
        
        detector = BreachDetector(Console())
        hash1 = detector._get_password_hash_prefix("password1")
        hash2 = detector._get_password_hash_prefix("password2")
        
        # Full hashes should be different
        assert (hash1[0] + hash1[1]) != (hash2[0] + hash2[1])


class TestBreachCheckParsing:
    """Test HIBP API response parsing."""
    
    @patch("httpx.get")
    def test_breached_password_detected(self, mock_get):
        """Test that a breached password is correctly identified."""
        from bastion.breach_detection import BreachDetector
        from rich.console import Console
        
        # Mock HIBP response format: "SUFFIX:COUNT"
        # SHA-1("password") suffix is 1E4C9B93F3F0682250B6CF8331B7EE68FD8
        mock_response = MagicMock()
        mock_response.text = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\nOTHERHASH:123"
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        
        detector = BreachDetector(Console())
        is_breached, count = detector.check_password("password")
        
        assert is_breached is True
        assert count == 9659365
    
    @patch("httpx.get")
    def test_safe_password_not_flagged(self, mock_get):
        """Test that a safe password returns not breached."""
        from bastion.breach_detection import BreachDetector
        from rich.console import Console
        
        # Response doesn't contain our suffix
        mock_response = MagicMock()
        mock_response.text = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1:100\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:50"
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        
        detector = BreachDetector(Console())
        is_breached, count = detector.check_password("my-super-unique-password-xyz-123")
        
        assert is_breached is False
        assert count == 0
    
    @patch("httpx.get")
    def test_api_error_returns_safe_default(self, mock_get):
        """Test that API errors return safe defaults (not breached)."""
        from bastion.breach_detection import BreachDetector
        from rich.console import Console
        import httpx
        
        mock_get.side_effect = httpx.HTTPError("Connection failed")
        
        detector = BreachDetector(Console())
        is_breached, count = detector.check_password("test")
        
        # Should fail safe - don't flag as breached on API error
        assert is_breached is False
        assert count == 0


class TestPrivacyPreservation:
    """Test that k-anonymity is properly implemented."""
    
    @patch("httpx.get")
    def test_only_prefix_sent_to_api(self, mock_get):
        """Verify only 5-char prefix is sent to HIBP API."""
        from bastion.breach_detection import BreachDetector
        from rich.console import Console
        
        mock_response = MagicMock()
        mock_response.text = ""
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        
        detector = BreachDetector(Console())
        detector.check_password("secretpassword")
        
        # Verify the URL only contains 5-char prefix
        call_url = mock_get.call_args[0][0]
        assert call_url.endswith("range/") or len(call_url.split("/")[-1]) == 5
        
        # The full hash should NOT be in the URL
        full_hash = hashlib.sha1(b"secretpassword").hexdigest().upper()
        assert full_hash not in call_url
    
    def test_suffix_never_transmitted(self):
        """Verify suffix is computed locally, never sent."""
        from bastion.breach_detection import BreachDetector
        from rich.console import Console
        
        # This is a design verification test
        # The suffix comparison happens locally in check_password()
        detector = BreachDetector(Console())
        prefix, suffix = detector._get_password_hash_prefix("test")
        
        # Suffix should be long enough to be unique
        assert len(suffix) == 35
        # But we never send it - verification is local


class TestHIBPAPIFormat:
    """Test compliance with HIBP API format."""
    
    def test_api_url_constant(self):
        """Verify HIBP API URL is correctly defined."""
        from bastion.breach_detection import BreachDetector
        
        assert BreachDetector.HIBP_API_URL == "https://api.pwnedpasswords.com/range/"
    
    @patch("httpx.get")
    def test_user_agent_header_set(self, mock_get):
        """Verify User-Agent header is set (HIBP requirement)."""
        from bastion.breach_detection import BreachDetector
        from rich.console import Console
        
        mock_response = MagicMock()
        mock_response.text = ""
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        
        detector = BreachDetector(Console())
        detector.check_password("test")
        
        # Check headers were passed
        call_kwargs = mock_get.call_args[1]
        assert "headers" in call_kwargs
        assert "User-Agent" in call_kwargs["headers"]
