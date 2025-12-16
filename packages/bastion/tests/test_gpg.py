"""Tests for GPG signing module."""

from datetime import datetime, timezone

import pytest

from bastion.sigchain.gpg import (
    GPGSigner,
    GPGSignature,
    SignatureStatus,
    VerificationResult,
    get_signer,
)


class TestMockGPGSigner:
    """Tests for mock GPG signing."""

    def test_create_mock_signer(self):
        """Test creating a mock signer."""
        signer = GPGSigner(mock=True)
        assert signer.mock is True
        assert signer.is_available() is True

    def test_mock_sign(self):
        """Test mock signing produces deterministic signature."""
        signer = GPGSigner(mock=True)
        data = b"test data to sign"
        
        sig = signer.sign(data)
        
        assert isinstance(sig, GPGSignature)
        assert sig.is_mock is True
        assert sig.key_id == GPGSigner.MOCK_KEY_ID
        assert sig.signer_name == GPGSigner.MOCK_SIGNER

    def test_mock_verify_valid(self):
        """Test mock verification with valid signature."""
        signer = GPGSigner(mock=True)
        data = b"test data to sign"
        
        sig = signer.sign(data)
        result = signer.verify(data, sig.signature)
        
        assert result.valid is True
        assert result.status == SignatureStatus.GOOD
        assert result.key_id == GPGSigner.MOCK_KEY_ID

    def test_mock_verify_tampered_data(self):
        """Test mock verification fails with tampered data."""
        signer = GPGSigner(mock=True)
        data = b"original data"
        tampered = b"tampered data"
        
        sig = signer.sign(data)
        result = signer.verify(tampered, sig.signature)
        
        assert result.valid is False
        assert result.status == SignatureStatus.BAD
        assert "mismatch" in result.error.lower()

    def test_mock_verify_invalid_signature(self):
        """Test mock verification fails with invalid signature."""
        signer = GPGSigner(mock=True)
        data = b"test data"
        invalid_sig = b"not a valid signature"
        
        result = signer.verify(data, invalid_sig)
        
        assert result.valid is False
        assert result.status == SignatureStatus.BAD

    def test_mock_signature_armor(self):
        """Test mock signature armor format."""
        signer = GPGSigner(mock=True)
        sig = signer.sign(b"data")
        
        armor = sig.to_armor()
        
        assert "BEGIN MOCK GPG SIGNATURE" in armor
        assert "END MOCK GPG SIGNATURE" in armor

    def test_get_default_key_mock(self):
        """Test getting default key in mock mode."""
        signer = GPGSigner(mock=True)
        key = signer.get_default_key()
        
        assert key == GPGSigner.MOCK_KEY_ID


class TestSignatureStatus:
    """Tests for SignatureStatus enum."""

    def test_status_values(self):
        """Test status enum values."""
        assert SignatureStatus.GOOD.value == "G"
        assert SignatureStatus.BAD.value == "B"
        assert SignatureStatus.UNKNOWN.value == "U"
        assert SignatureStatus.NONE.value == "N"


class TestVerificationResult:
    """Tests for VerificationResult dataclass."""

    def test_create_valid_result(self):
        """Test creating a valid verification result."""
        result = VerificationResult(
            valid=True,
            status=SignatureStatus.GOOD,
            key_id="ABC123",
            signer_name="Test User",
            timestamp=datetime.now(timezone.utc),
        )
        
        assert result.valid is True
        assert result.status == SignatureStatus.GOOD
        assert result.error is None

    def test_create_invalid_result(self):
        """Test creating an invalid verification result."""
        result = VerificationResult(
            valid=False,
            status=SignatureStatus.BAD,
            key_id=None,
            signer_name=None,
            timestamp=None,
            error="Signature verification failed",
        )
        
        assert result.valid is False
        assert result.error is not None


class TestGetSigner:
    """Tests for get_signer helper function."""

    def test_get_signer_force_mock(self):
        """Test forcing mock mode."""
        signer = get_signer(mock=True)
        assert signer.mock is True

    def test_get_signer_force_real(self):
        """Test forcing real mode (may not be available)."""
        signer = get_signer(mock=False)
        assert signer.mock is False

    def test_get_signer_auto_detect(self):
        """Test auto-detection mode."""
        signer = get_signer(mock=None)
        # Should return either real or mock based on GPG availability
        assert isinstance(signer, GPGSigner)
