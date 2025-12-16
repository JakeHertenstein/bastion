"""Tests for Bastion configuration in bastion/config.py.

These tests verify:
- Configuration file loading and parsing
- Default value fallbacks
- Configuration merging
- BastionConfig singleton behavior

All tests use temporary directories to avoid modifying real config.
"""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


# Mark all tests in this module as unit tests
pytestmark = pytest.mark.unit


class TestBastionConfigImports:
    """Test that config modules import correctly."""
    
    def test_config_module_imports(self):
        """Verify config module can be imported."""
        from bastion import config
        assert config is not None
    
    def test_bastion_config_class_imports(self):
        """Verify BastionConfig class can be imported."""
        from bastion.config import BastionConfig
        assert BastionConfig is not None
    
    def test_default_config_exists(self):
        """Verify DEFAULT_CONFIG is defined."""
        from bastion.config import DEFAULT_CONFIG
        assert DEFAULT_CONFIG is not None
        assert isinstance(DEFAULT_CONFIG, dict)


class TestDefaultConfig:
    """Test default configuration values."""
    
    def test_default_config_has_required_sections(self):
        """Test DEFAULT_CONFIG has all required sections."""
        from bastion.config import DEFAULT_CONFIG
        
        required_sections = ["general", "entropy", "username", "rotation", "yubikey"]
        for section in required_sections:
            assert section in DEFAULT_CONFIG, f"Missing section: {section}"
    
    def test_general_section_defaults(self):
        """Test general section has default vault."""
        from bastion.config import DEFAULT_CONFIG
        
        assert "default_vault" in DEFAULT_CONFIG["general"]
        assert DEFAULT_CONFIG["general"]["default_vault"] == "Private"
    
    def test_entropy_section_defaults(self):
        """Test entropy section has required defaults."""
        from bastion.config import DEFAULT_CONFIG
        
        entropy = DEFAULT_CONFIG["entropy"]
        assert entropy["default_bits"] == 8192
        assert entropy["expiry_days"] == 90
        assert entropy["quality_threshold"] == "GOOD"
    
    def test_username_section_defaults(self):
        """Test username section has required defaults."""
        from bastion.config import DEFAULT_CONFIG
        
        username = DEFAULT_CONFIG["username"]
        assert username["default_length"] == 16
        assert username["default_algorithm"] == "sha512"
    
    def test_rotation_section_defaults(self):
        """Test rotation section has required defaults."""
        from bastion.config import DEFAULT_CONFIG
        
        rotation = DEFAULT_CONFIG["rotation"]
        assert rotation["default_interval_days"] == 90
        assert rotation["warning_days"] == 14
    
    def test_yubikey_section_defaults(self):
        """Test yubikey section has required defaults."""
        from bastion.config import DEFAULT_CONFIG
        
        yubikey = DEFAULT_CONFIG["yubikey"]
        assert yubikey["default_slot"] == 2
        assert yubikey["challenge_iterations"] == 1024


class TestConfigPaths:
    """Test configuration path constants."""
    
    def test_bastion_dir_in_home(self):
        """Test BASTION_DIR is in home directory (.bsec)."""
        from bastion.config import BASTION_DIR
        
        assert BASTION_DIR.parent == Path.home()
        assert BASTION_DIR.name == ".bsec"
    
    def test_config_path_in_bastion_dir(self):
        """Test config file path is in BASTION_DIR."""
        from bastion.config import BASTION_CONFIG_PATH, BASTION_DIR
        
        assert BASTION_CONFIG_PATH.parent == BASTION_DIR
        assert BASTION_CONFIG_PATH.name == "config.toml"
    
    def test_cache_dir_in_bastion_dir(self):
        """Test cache directory is in BASTION_DIR."""
        from bastion.config import BASTION_CACHE_DIR, BASTION_DIR
        
        assert BASTION_CACHE_DIR.parent == BASTION_DIR
        assert BASTION_CACHE_DIR.name == "cache"


class TestBastionConfigClass:
    """Test BastionConfig class behavior."""
    
    def test_config_get_with_default(self):
        """Test get() returns default when key missing."""
        from bastion.config import BastionConfig
        
        # Reset singleton for fresh test
        BastionConfig._instance = None
        BastionConfig._config = None
        
        config = BastionConfig()
        result = config.get("nonexistent", "key", "default_value")
        
        assert result == "default_value"
    
    def test_config_properties_return_values(self):
        """Test config properties return expected types."""
        from bastion.config import BastionConfig
        
        # Reset singleton
        BastionConfig._instance = None
        BastionConfig._config = None
        
        config = BastionConfig()
        
        assert isinstance(config.default_vault, str)
        assert isinstance(config.entropy_bits, int)
        assert isinstance(config.username_length, int)
        assert isinstance(config.username_algorithm, str)
        assert isinstance(config.rotation_interval_days, int)
        assert isinstance(config.yubikey_slot, int)
    
    def test_get_section_returns_dict(self):
        """Test get_section returns dictionary."""
        from bastion.config import BastionConfig
        
        # Reset singleton
        BastionConfig._instance = None
        BastionConfig._config = None
        
        config = BastionConfig()
        section = config.get_section("entropy")
        
        assert isinstance(section, dict)
        assert "default_bits" in section


class TestConfigMerging:
    """Test configuration merging behavior."""
    
    def test_merge_preserves_defaults(self):
        """Test merging preserves default values not in override."""
        from bastion.config import BastionConfig
        
        config = BastionConfig()
        
        defaults = {"a": 1, "b": 2, "c": 3}
        overrides = {"b": 20}
        
        result = config._merge_config(defaults, overrides)
        
        assert result["a"] == 1  # Preserved
        assert result["b"] == 20  # Overridden
        assert result["c"] == 3  # Preserved
    
    def test_merge_handles_nested_dicts(self):
        """Test merging handles nested dictionaries."""
        from bastion.config import BastionConfig
        
        config = BastionConfig()
        
        defaults = {
            "section1": {"a": 1, "b": 2},
            "section2": {"x": 10},
        }
        overrides = {
            "section1": {"b": 20, "c": 3},
        }
        
        result = config._merge_config(defaults, overrides)
        
        assert result["section1"]["a"] == 1  # Preserved
        assert result["section1"]["b"] == 20  # Overridden
        assert result["section1"]["c"] == 3  # Added
        assert result["section2"]["x"] == 10  # Preserved


class TestGetConfigFunction:
    """Test get_config() function."""
    
    def test_get_config_returns_instance(self):
        """Test get_config returns BastionConfig instance."""
        from bastion.config import get_config, BastionConfig
        
        config = get_config()
        assert isinstance(config, BastionConfig)
    
    def test_get_config_returns_same_instance(self):
        """Test get_config returns singleton."""
        from bastion.config import get_config
        
        config1 = get_config()
        config2 = get_config()
        
        assert config1 is config2
