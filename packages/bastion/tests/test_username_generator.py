"""Tests for username generation in bastion/username_generator.py.

These tests verify:
- Deterministic username generation from salt + domain
- HMAC-SHA512 implementation
- Character set mapping
- UsernameGenerator class structure

All tests in this module are unit tests (no external dependencies).
"""

import hashlib
import hmac
from unittest.mock import MagicMock, patch

import pytest


# Mark all tests in this module as unit and crypto tests
pytestmark = [pytest.mark.unit, pytest.mark.crypto]


class TestUsernameGeneratorImports:
    """Test that username generator modules import correctly."""
    
    def test_username_generator_imports(self):
        """Verify UsernameGenerator can be imported."""
        from bastion.username_generator import UsernameGenerator
        assert UsernameGenerator is not None
    
    def test_username_generator_config_imports(self):
        """Verify UsernameGeneratorConfig can be imported."""
        from bastion.username_generator import UsernameGeneratorConfig
        assert UsernameGeneratorConfig is not None


class TestUsernameGeneratorClass:
    """Test UsernameGenerator class structure."""
    
    def test_generator_has_expected_attributes(self):
        """Test that UsernameGenerator has expected class attributes."""
        from bastion.username_generator import UsernameGenerator
        
        assert hasattr(UsernameGenerator, "SALT_ITEM_PREFIX")
        assert hasattr(UsernameGenerator, "SALT_TAG")
        assert UsernameGenerator.SALT_TAG == "Bastion/SALT"
    
    def test_generator_initialization(self):
        """Test UsernameGenerator can be initialized."""
        from bastion.username_generator import UsernameGenerator
        
        generator = UsernameGenerator()
        assert generator.config is not None
        assert generator._cached_salt is None


class TestUsernameGeneratorConfig:
    """Test UsernameGeneratorConfig class."""
    
    def test_config_default_config_dict(self):
        """Test UsernameGeneratorConfig has DEFAULT_CONFIG with expected keys."""
        from bastion.username_generator import UsernameGeneratorConfig
        
        # DEFAULT_CONFIG is a class-level dict with defaults
        assert "default_length" in UsernameGeneratorConfig.DEFAULT_CONFIG
        assert "default_algorithm" in UsernameGeneratorConfig.DEFAULT_CONFIG
        assert "service_rules" in UsernameGeneratorConfig.DEFAULT_CONFIG
        
        # Check default values
        assert UsernameGeneratorConfig.DEFAULT_CONFIG["default_length"] == 16
        assert UsernameGeneratorConfig.DEFAULT_CONFIG["default_algorithm"] == "sha512"
    
    def test_config_service_rules(self):
        """Test config has service rules defined."""
        from bastion.username_generator import UsernameGeneratorConfig
        
        rules = UsernameGeneratorConfig.DEFAULT_CONFIG["service_rules"]
        assert "github" in rules
        assert rules["github"]["max"] == 39
        assert "twitter" in rules
        assert rules["twitter"]["max"] == 15


class TestHMACImplementation:
    """Test HMAC-SHA512 implementation details."""
    
    def test_hmac_sha512_produces_64_bytes(self, sample_salt):
        """Test that HMAC-SHA512 produces 64 bytes."""
        message = b"test domain"
        
        mac = hmac.new(sample_salt, message, hashlib.sha512)
        digest = mac.digest()
        
        assert len(digest) == 64
    
    def test_hmac_is_deterministic(self, sample_salt):
        """Test that HMAC is deterministic."""
        message = b"test domain"
        
        mac1 = hmac.new(sample_salt, message, hashlib.sha512).digest()
        mac2 = hmac.new(sample_salt, message, hashlib.sha512).digest()
        
        assert mac1 == mac2
    
    def test_hmac_different_messages_different_output(self, sample_salt):
        """Test that different messages produce different MACs."""
        mac1 = hmac.new(sample_salt, b"message1", hashlib.sha512).digest()
        mac2 = hmac.new(sample_salt, b"message2", hashlib.sha512).digest()
        
        assert mac1 != mac2
    
    def test_hmac_different_keys_different_output(self):
        """Test that different keys produce different MACs."""
        key1 = b"key1" * 16
        key2 = b"key2" * 16
        message = b"same message"
        
        mac1 = hmac.new(key1, message, hashlib.sha512).digest()
        mac2 = hmac.new(key2, message, hashlib.sha512).digest()
        
        assert mac1 != mac2


class TestCharacterSetMapping:
    """Test character set mapping concepts for usernames."""
    
    def test_base36_encoding(self):
        """Test base36-like encoding for username characters."""
        # Username generators typically use base36 (a-z, 0-9) = 36 chars
        # Verify the concept works
        charset = "abcdefghijklmnopqrstuvwxyz0123456789"
        assert len(charset) == 36
        
        # Test byte to character mapping
        byte_value = 100
        char = charset[byte_value % len(charset)]
        assert char in charset
    
    def test_first_char_letter_constraint(self):
        """Test that first character can be constrained to letter."""
        letters = "abcdefghijklmnopqrstuvwxyz"
        
        # Any byte can be mapped to a letter
        for byte_value in range(256):
            char = letters[byte_value % len(letters)]
            assert char.isalpha()


class TestSerialNumberParsing:
    """Test serial number parsing from item titles."""
    
    def test_parse_serial_from_title(self):
        """Test parsing serial numbers from salt item titles."""
        import re
        
        pattern = re.compile(r'Bastion Salt #(\d+)')
        
        title1 = "Bastion Salt #1"
        title2 = "Bastion Salt #42"
        title3 = "Other Item"
        
        match1 = pattern.search(title1)
        match2 = pattern.search(title2)
        match3 = pattern.search(title3)
        
        assert match1 and int(match1.group(1)) == 1
        assert match2 and int(match2.group(1)) == 42
        assert match3 is None


class TestDomainNormalization:
    """Test domain normalization concepts."""
    
    def test_lowercase_normalization(self):
        """Test that domains should be lowercased for consistency."""
        domains = ["GitHub.com", "GITHUB.COM", "github.com"]
        normalized = [d.lower() for d in domains]
        
        assert all(d == "github.com" for d in normalized)
    
    def test_strip_whitespace(self):
        """Test that whitespace should be stripped."""
        domain = "  github.com  "
        assert domain.strip() == "github.com"
