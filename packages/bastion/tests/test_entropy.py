"""Tests for entropy operations in bastion/entropy.py.

These tests verify:
- Entropy pool creation and retrieval
- HKDF salt derivation
- Entropy combination (XOR + SHAKE256)
- ENT analysis parsing
- Quality threshold calculations

All tests in this module are unit tests (no external dependencies).
"""

import base64
import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest


# Mark all tests in this module as unit and crypto tests
pytestmark = [pytest.mark.unit, pytest.mark.crypto]


class TestEntropyAnalysis:
    """Test EntropyAnalysis class."""
    
    def test_entropy_analysis_imports(self):
        """Verify EntropyAnalysis can be imported."""
        from bastion.entropy import EntropyAnalysis
        assert EntropyAnalysis is not None
    
    def test_entropy_analysis_initialization(self):
        """Test EntropyAnalysis with typical values."""
        from bastion.entropy import EntropyAnalysis
        
        analysis = EntropyAnalysis(
            entropy_bits_per_byte=7.988,
            chi_square=250.0,
            chi_square_pvalue=0.5,
            arithmetic_mean=127.5,
            monte_carlo_pi=3.14159,
            monte_carlo_error=0.01,
            serial_correlation=0.001,
        )
        
        assert analysis.entropy_bits_per_byte == 7.988
        assert analysis.chi_square_pvalue == 0.5
    
    def test_quality_rating_excellent(self):
        """Test EXCELLENT quality rating for ideal entropy."""
        from bastion.entropy import EntropyAnalysis
        
        analysis = EntropyAnalysis(
            entropy_bits_per_byte=7.988,
            chi_square=250.0,
            chi_square_pvalue=0.5,  # Middle of acceptable range
            arithmetic_mean=127.5,
            monte_carlo_pi=3.14159,
            monte_carlo_error=0.01,
            serial_correlation=0.001,
        )
        
        assert analysis.quality_rating() == "EXCELLENT"
    
    def test_quality_rating_good(self):
        """Test GOOD quality rating."""
        from bastion.entropy import EntropyAnalysis
        
        analysis = EntropyAnalysis(
            entropy_bits_per_byte=7.95,  # Slightly lower
            chi_square=250.0,
            chi_square_pvalue=0.02,  # Near edge of acceptable
            arithmetic_mean=127.5,
            monte_carlo_pi=3.14159,
            monte_carlo_error=0.01,
            serial_correlation=0.001,
        )
        
        assert analysis.quality_rating() == "GOOD"
    
    def test_quality_rating_poor(self):
        """Test POOR quality rating for bad entropy."""
        from bastion.entropy import EntropyAnalysis
        
        analysis = EntropyAnalysis(
            entropy_bits_per_byte=6.0,  # Very low
            chi_square=1000.0,
            chi_square_pvalue=0.0001,  # Highly non-uniform
            arithmetic_mean=100.0,
            monte_carlo_pi=3.5,
            monte_carlo_error=10.0,
            serial_correlation=0.5,
        )
        
        assert analysis.quality_rating() == "POOR"
    
    def test_is_acceptable_true(self):
        """Test is_acceptable returns True for good entropy."""
        from bastion.entropy import EntropyAnalysis
        
        analysis = EntropyAnalysis(
            entropy_bits_per_byte=7.9,
            chi_square=250.0,
            chi_square_pvalue=0.5,
            arithmetic_mean=127.5,
            monte_carlo_pi=3.14159,
            monte_carlo_error=0.01,
            serial_correlation=0.01,
        )
        
        assert analysis.is_acceptable() is True
    
    def test_is_acceptable_false_low_entropy(self):
        """Test is_acceptable returns False for low entropy."""
        from bastion.entropy import EntropyAnalysis
        
        analysis = EntropyAnalysis(
            entropy_bits_per_byte=7.0,  # Below 7.5 threshold
            chi_square=250.0,
            chi_square_pvalue=0.5,
            arithmetic_mean=127.5,
            monte_carlo_pi=3.14159,
            monte_carlo_error=0.01,
            serial_correlation=0.01,
        )
        
        assert analysis.is_acceptable() is False
    
    def test_to_dict_roundtrip(self):
        """Test to_dict and from_dict preserve values."""
        from bastion.entropy import EntropyAnalysis
        
        original = EntropyAnalysis(
            entropy_bits_per_byte=7.988,
            chi_square=271.84,
            chi_square_pvalue=0.2238,
            arithmetic_mean=127.0284,
            monte_carlo_pi=3.16044,
            monte_carlo_error=0.6,
            serial_correlation=-0.006846,
        )
        
        data = original.to_dict()
        restored = EntropyAnalysis.from_dict(data)
        
        assert restored.entropy_bits_per_byte == original.entropy_bits_per_byte
        assert restored.chi_square == original.chi_square
        assert restored.serial_correlation == original.serial_correlation


class TestQualityThreshold:
    """Test QualityThreshold enum."""
    
    def test_quality_threshold_imports(self):
        """Verify QualityThreshold can be imported."""
        from bastion.entropy import QualityThreshold
        assert QualityThreshold is not None
    
    def test_meets_threshold_exact_match(self):
        """Test meets_threshold with exact match."""
        from bastion.entropy import QualityThreshold
        
        assert QualityThreshold.meets_threshold("GOOD", QualityThreshold.GOOD) is True
    
    def test_meets_threshold_exceeds(self):
        """Test meets_threshold when rating exceeds minimum."""
        from bastion.entropy import QualityThreshold
        
        assert QualityThreshold.meets_threshold("EXCELLENT", QualityThreshold.GOOD) is True
    
    def test_meets_threshold_below(self):
        """Test meets_threshold when rating is below minimum."""
        from bastion.entropy import QualityThreshold
        
        assert QualityThreshold.meets_threshold("FAIR", QualityThreshold.GOOD) is False


class TestEntropyCombination:
    """Test entropy combination functions."""
    
    def test_combine_entropy_sources_imports(self):
        """Verify combine_entropy_sources can be imported."""
        from bastion.entropy import combine_entropy_sources
        assert combine_entropy_sources is not None
    
    def test_combine_single_source_returns_unchanged(self):
        """Test that single source returns unchanged."""
        from bastion.entropy import combine_entropy_sources
        
        source = b"\x01\x02\x03\x04\x05"
        result = combine_entropy_sources(source)
        
        assert result == source
    
    def test_combine_two_equal_length_sources(self):
        """Test combining two sources of equal length."""
        from bastion.entropy import combine_entropy_sources
        
        source1 = b"\xff\x00\xff\x00"
        source2 = b"\x00\xff\x00\xff"
        
        result = combine_entropy_sources(source1, source2)
        
        # XOR of these should be all 0xff
        assert result == b"\xff\xff\xff\xff"
    
    def test_combine_different_length_sources(self):
        """Test combining sources of different lengths."""
        from bastion.entropy import combine_entropy_sources
        
        short = b"\x01\x02"
        long = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        
        result = combine_entropy_sources(short, long)
        
        # Result should be length of longest source
        assert len(result) == len(long)
    
    def test_combine_empty_raises_error(self):
        """Test that empty input raises ValueError."""
        from bastion.entropy import combine_entropy_sources
        
        with pytest.raises(ValueError):
            combine_entropy_sources()
    
    def test_combine_is_deterministic(self):
        """Test that combination is deterministic."""
        from bastion.entropy import combine_entropy_sources
        
        source1 = b"entropy source one"
        source2 = b"entropy source two - longer"
        
        result1 = combine_entropy_sources(source1, source2)
        result2 = combine_entropy_sources(source1, source2)
        
        assert result1 == result2


class TestEntropyPool:
    """Test EntropyPool class."""
    
    def test_entropy_pool_imports(self):
        """Verify EntropyPool can be imported."""
        from bastion.entropy import EntropyPool
        assert EntropyPool is not None
    
    def test_entropy_pool_initialization(self):
        """Test EntropyPool initializes without errors."""
        from bastion.entropy import EntropyPool
        
        pool = EntropyPool()
        assert pool._cached_pools == {}
        assert pool._cached_max_serial is None
    
    def test_entropy_pool_constants(self):
        """Test EntropyPool has expected constants."""
        from bastion.entropy import EntropyPool
        
        pool = EntropyPool()
        assert pool.SOURCE_ITEM_PREFIX == "Bastion Entropy Source"
        assert pool.DERIVED_ITEM_PREFIX == "Bastion Entropy Derived"
        assert pool.POOL_TAG == "Bastion/ENTROPY"
    
    @patch("subprocess.run")
    def test_find_highest_serial_empty(self, mock_run):
        """Test find_highest_serial_number with no existing pools."""
        from bastion.entropy import EntropyPool
        
        mock_run.return_value = MagicMock(stdout="[]", returncode=0)
        
        pool = EntropyPool()
        result = pool.find_highest_serial_number()
        
        assert result == 0
    
    @patch("subprocess.run")
    def test_find_highest_serial_with_pools(self, mock_run):
        """Test find_highest_serial_number with existing pools."""
        from bastion.entropy import EntropyPool
        
        mock_items = [
            {"id": "uuid1", "title": "Bastion Entropy Source #5"},
            {"id": "uuid2", "title": "Bastion Entropy Source #10"},
            {"id": "uuid3", "title": "Bastion Entropy Source #3"},
        ]
        mock_run.return_value = MagicMock(stdout=json.dumps(mock_items), returncode=0)
        
        pool = EntropyPool()
        result = pool.find_highest_serial_number()
        
        assert result == 10
    
    def test_serial_cache_operations(self):
        """Test serial number caching."""
        from bastion.entropy import EntropyPool
        
        pool = EntropyPool()
        
        # Initially None
        assert pool._cached_max_serial is None
        
        # Set cache
        pool.set_cached_serial(42)
        assert pool._cached_max_serial == 42
        
        # Invalidate cache
        pool.invalidate_serial_cache()
        assert pool._cached_max_serial is None


class TestHKDFDerivation:
    """Test HKDF salt derivation."""
    
    def test_derive_salt_imports(self):
        """Verify derive_salt_from_entropy_pool can be imported."""
        from bastion.entropy import derive_salt_from_entropy_pool
        assert derive_salt_from_entropy_pool is not None
    
    @patch("bastion.entropy.EntropyPool")
    def test_derive_salt_too_small_raises(self, mock_pool_class):
        """Test derivation fails for pools smaller than 64 bytes."""
        from bastion.entropy import derive_salt_from_entropy_pool
        
        # Mock pool with only 32 bytes
        mock_pool = MagicMock()
        mock_pool.get_pool.return_value = (b"x" * 32, {"consumed": False})
        mock_pool_class.return_value = mock_pool
        
        with pytest.raises(RuntimeError, match="too small"):
            derive_salt_from_entropy_pool("test-uuid")
    
    @patch("bastion.entropy.EntropyPool")
    def test_derive_salt_consumed_raises(self, mock_pool_class):
        """Test derivation fails for already consumed pools."""
        from bastion.entropy import derive_salt_from_entropy_pool
        
        mock_pool = MagicMock()
        mock_pool.get_pool.return_value = (b"x" * 64, {"consumed": True})
        mock_pool_class.return_value = mock_pool
        
        with pytest.raises(RuntimeError, match="already been consumed"):
            derive_salt_from_entropy_pool("test-uuid")
    
    @patch("bastion.entropy.EntropyPool")
    def test_derive_salt_not_found_raises(self, mock_pool_class):
        """Test derivation fails for non-existent pools."""
        from bastion.entropy import derive_salt_from_entropy_pool
        
        mock_pool = MagicMock()
        mock_pool.get_pool.return_value = None
        mock_pool_class.return_value = mock_pool
        
        with pytest.raises(RuntimeError, match="not found"):
            derive_salt_from_entropy_pool("nonexistent-uuid")
    
    def test_hkdf_is_deterministic(self, sample_entropy_bytes):
        """Test that HKDF produces deterministic output."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        
        info = b"test-info-string"
        
        hkdf1 = HKDF(algorithm=hashes.SHA512(), length=64, salt=None, info=info)
        result1 = hkdf1.derive(sample_entropy_bytes)
        
        hkdf2 = HKDF(algorithm=hashes.SHA512(), length=64, salt=None, info=info)
        result2 = hkdf2.derive(sample_entropy_bytes)
        
        assert result1 == result2
    
    def test_hkdf_different_info_different_output(self, sample_entropy_bytes):
        """Test that different info strings produce different output."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        
        hkdf1 = HKDF(algorithm=hashes.SHA512(), length=64, salt=None, info=b"info-1")
        result1 = hkdf1.derive(sample_entropy_bytes)
        
        hkdf2 = HKDF(algorithm=hashes.SHA512(), length=64, salt=None, info=b"info-2")
        result2 = hkdf2.derive(sample_entropy_bytes)
        
        assert result1 != result2
