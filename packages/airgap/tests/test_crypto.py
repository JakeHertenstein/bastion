"""Tests for the airgap crypto module."""

import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import tempfile
import base64
from datetime import datetime, timezone

from airgap.crypto import (
    ENTAnalysis,
    EntropyQuality,
    SaltPayload,
    run_ent_analysis,
)


class TestEntropyQuality:
    """Tests for EntropyQuality enum."""

    def test_quality_values(self):
        """Test quality enum values."""
        assert EntropyQuality.EXCELLENT.value == "EXCELLENT"
        assert EntropyQuality.GOOD.value == "GOOD"
        assert EntropyQuality.FAIR.value == "FAIR"
        assert EntropyQuality.POOR.value == "POOR"

    def test_quality_ordering(self):
        """Test quality levels can be compared via string."""
        qualities = ["EXCELLENT", "GOOD", "FAIR", "POOR"]
        assert qualities.index("EXCELLENT") < qualities.index("POOR")

    def test_meets_threshold_excellent(self):
        """Test meets_threshold for EXCELLENT."""
        assert EntropyQuality.meets_threshold("EXCELLENT", EntropyQuality.EXCELLENT)
        assert EntropyQuality.meets_threshold("EXCELLENT", EntropyQuality.GOOD)
        assert EntropyQuality.meets_threshold("EXCELLENT", EntropyQuality.FAIR)

    def test_meets_threshold_good(self):
        """Test meets_threshold for GOOD."""
        assert not EntropyQuality.meets_threshold("GOOD", EntropyQuality.EXCELLENT)
        assert EntropyQuality.meets_threshold("GOOD", EntropyQuality.GOOD)
        assert EntropyQuality.meets_threshold("GOOD", EntropyQuality.FAIR)


class TestENTAnalysis:
    """Tests for ENTAnalysis dataclass."""

    def test_create_analysis(self):
        """Test creating an analysis result."""
        analysis = ENTAnalysis(
            entropy_bits_per_byte=7.99,
            chi_square=250.0,
            chi_square_pvalue=0.50,
            arithmetic_mean=127.5,
            monte_carlo_pi=3.14159,
            monte_carlo_error=0.01,
            serial_correlation=0.001,
        )
        assert analysis.entropy_bits_per_byte == 7.99
        assert analysis.chi_square == 250.0
        assert analysis.serial_correlation == 0.001

    def test_quality_rating_excellent(self):
        """Test EXCELLENT quality rating."""
        analysis = ENTAnalysis(
            entropy_bits_per_byte=7.99,
            chi_square=200.0,
            chi_square_pvalue=0.50,
            arithmetic_mean=127.5,
            monte_carlo_pi=3.14159,
            monte_carlo_error=0.01,
            serial_correlation=0.005,
        )
        assert analysis.quality_rating() == EntropyQuality.EXCELLENT

    def test_quality_rating_good(self):
        """Test GOOD quality rating."""
        analysis = ENTAnalysis(
            entropy_bits_per_byte=7.95,  # Between 7.9 and 7.985
            chi_square=200.0,
            chi_square_pvalue=0.50,
            arithmetic_mean=127.5,
            monte_carlo_pi=3.14159,
            monte_carlo_error=0.01,
            serial_correlation=0.03,
        )
        assert analysis.quality_rating() == EntropyQuality.GOOD

    def test_quality_rating_fair(self):
        """Test FAIR quality rating."""
        analysis = ENTAnalysis(
            entropy_bits_per_byte=7.7,  # Between 7.5 and 7.9
            chi_square=200.0,
            chi_square_pvalue=0.50,
            arithmetic_mean=127.5,
            monte_carlo_pi=3.14159,
            monte_carlo_error=0.05,
            serial_correlation=0.08,
        )
        assert analysis.quality_rating() == EntropyQuality.FAIR

    def test_quality_rating_poor(self):
        """Test POOR quality rating."""
        analysis = ENTAnalysis(
            entropy_bits_per_byte=6.0,  # Very low entropy
            chi_square=500.0,
            chi_square_pvalue=0.0001,  # Outside acceptable range
            arithmetic_mean=200.0,
            monte_carlo_pi=4.0,
            monte_carlo_error=0.5,
            serial_correlation=0.5,
        )
        assert analysis.quality_rating() == EntropyQuality.POOR

    def test_is_acceptable(self):
        """Test is_acceptable method."""
        excellent = ENTAnalysis(
            entropy_bits_per_byte=7.99,
            chi_square=200.0,
            chi_square_pvalue=0.50,
            arithmetic_mean=127.5,
            monte_carlo_pi=3.14159,
            monte_carlo_error=0.01,
            serial_correlation=0.005,
        )
        assert excellent.is_acceptable(EntropyQuality.EXCELLENT)
        assert excellent.is_acceptable(EntropyQuality.GOOD)

    def test_to_dict(self):
        """Test to_dict conversion."""
        analysis = ENTAnalysis(
            entropy_bits_per_byte=7.99,
            chi_square=200.0,
            chi_square_pvalue=0.50,
            arithmetic_mean=127.5,
            monte_carlo_pi=3.14159,
            monte_carlo_error=0.01,
            serial_correlation=0.005,
        )
        d = analysis.to_dict()
        assert "entropy_bits_per_byte" in d
        assert "quality_rating" in d


class TestSaltPayload:
    """Tests for SaltPayload dataclass."""

    def test_create_salt_payload(self):
        """Test creating a salt payload."""
        salt_bytes = b"test_salt_data_here"
        payload = SaltPayload(
            salt=salt_bytes,
            bits=256,
            entropy_source="infnoise",
            entropy_quality="EXCELLENT",
        )
        assert payload.salt == salt_bytes
        assert payload.bits == 256
        assert payload.entropy_source == "infnoise"
        assert payload.entropy_quality == "EXCELLENT"

    def test_to_json(self):
        """Test converting to JSON."""
        salt_bytes = b"test_salt"
        payload = SaltPayload(
            salt=salt_bytes,
            bits=128,
            entropy_source="yubikey",
            entropy_quality="GOOD",
        )
        json_str = payload.to_json()
        data = json.loads(json_str)
        assert data["salt"] == base64.b64encode(salt_bytes).decode()
        assert data["bits"] == 128
        assert data["entropy_source"] == "yubikey"
        assert data["entropy_quality"] == "GOOD"

    def test_from_json(self):
        """Test parsing from JSON."""
        salt_bytes = b"abcdef"
        json_str = json.dumps({
            "type": "bastion/salt/v1",
            "purpose": "username-generator",
            "salt": base64.b64encode(salt_bytes).decode(),
            "bits": 64,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "device_id": "test",
            "entropy_source": "system",
            "entropy_quality": "FAIR",
        })
        payload = SaltPayload.from_json(json_str)
        assert payload.salt == salt_bytes
        assert payload.bits == 64
        assert payload.entropy_source == "system"
        assert payload.entropy_quality == "FAIR"

    def test_roundtrip(self):
        """Test JSON roundtrip."""
        original = SaltPayload(
            salt=b"test_data_roundtrip",
            bits=256,
            entropy_source="infnoise",
            entropy_quality="EXCELLENT",
        )
        json_str = original.to_json()
        parsed = SaltPayload.from_json(json_str)
        assert parsed.salt == original.salt
        assert parsed.bits == original.bits
        assert parsed.entropy_source == original.entropy_source
        assert parsed.entropy_quality == original.entropy_quality


class TestRunEntAnalysis:
    """Tests for run_ent_analysis function."""

    @patch('subprocess.run')
    def test_run_ent_analysis_success(self, mock_run):
        """Test successful ENT analysis."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="""Entropy = 7.999835 bits per byte.

Chi square distribution for 131072 samples is 251.42, and randomly
would exceed this value 50.00 percent of the times.

Arithmetic mean value of data bytes is 127.5124 (127.5 = random).
Monte Carlo value for Pi is 3.141592653 (error 0.00 percent).
Serial correlation coefficient is 0.000234 (totally uncorrelated = 0.0).
""",
        )
        
        data = b'\x00' * 1000  # Dummy data
        analysis = run_ent_analysis(data)
        
        assert analysis is not None
        assert analysis.entropy_bits_per_byte == pytest.approx(7.999835, rel=1e-4)
        mock_run.assert_called_once()

    @patch('subprocess.run')
    def test_run_ent_analysis_failure(self, mock_run):
        """Test ENT analysis failure raises RuntimeError."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="ent: command not found",
        )
        
        data = b'\x00' * 1000
        with pytest.raises(RuntimeError, match="ENT analysis failed"):
            run_ent_analysis(data)

    @patch('subprocess.run')
    def test_run_ent_analysis_exception(self, mock_run):
        """Test ENT analysis handles exceptions by raising RuntimeError."""
        mock_run.side_effect = FileNotFoundError("ent not found")
        
        data = b'\x00' * 1000
        with pytest.raises(RuntimeError, match="ENT tool not installed"):
            run_ent_analysis(data)


class TestQualityMeetsMinimum:
    """Tests for quality comparison logic."""

    def test_excellent_meets_all(self):
        """Test EXCELLENT meets all minimum requirements."""
        assert EntropyQuality.meets_threshold("EXCELLENT", EntropyQuality.EXCELLENT)
        assert EntropyQuality.meets_threshold("EXCELLENT", EntropyQuality.GOOD)
        assert EntropyQuality.meets_threshold("EXCELLENT", EntropyQuality.FAIR)
        assert EntropyQuality.meets_threshold("EXCELLENT", EntropyQuality.POOR)

    def test_good_meets_good_and_below(self):
        """Test GOOD meets GOOD, FAIR, POOR minimums."""
        assert not EntropyQuality.meets_threshold("GOOD", EntropyQuality.EXCELLENT)
        assert EntropyQuality.meets_threshold("GOOD", EntropyQuality.GOOD)
        assert EntropyQuality.meets_threshold("GOOD", EntropyQuality.FAIR)
        assert EntropyQuality.meets_threshold("GOOD", EntropyQuality.POOR)

    def test_fair_only_meets_fair_and_poor(self):
        """Test FAIR only meets FAIR and POOR minimums."""
        assert not EntropyQuality.meets_threshold("FAIR", EntropyQuality.EXCELLENT)
        assert not EntropyQuality.meets_threshold("FAIR", EntropyQuality.GOOD)
        assert EntropyQuality.meets_threshold("FAIR", EntropyQuality.FAIR)
        assert EntropyQuality.meets_threshold("FAIR", EntropyQuality.POOR)
