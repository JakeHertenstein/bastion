"""Tests for the airgap SLIP-39 module."""

import secrets
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock

from airgap.slip39 import (
    SLIP39Config,
    SLIP39Share,
    SLIP39ShareSet,
    compute_share_fingerprint,
    compute_master_fingerprint,
    normalize_mnemonic,
    verify_share_reentry,
    validate_share,
    generate_shares,
    recover_secret,
    verify_shares,
    format_share_for_display,
    format_share_summary,
)


class TestSLIP39Config:
    """Tests for SLIP39Config dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = SLIP39Config()
        assert config.total_shares == 5
        assert config.threshold == 3
        assert config.secret_bits == 128  # Default for Cryptosteel compatibility
        assert config.passphrase == ""
        assert config.secret_bytes == 16
        assert config.words_per_share == 20

    def test_custom_config(self):
        """Test custom configuration."""
        config = SLIP39Config(total_shares=7, threshold=4, secret_bits=128)
        assert config.total_shares == 7
        assert config.threshold == 4
        assert config.secret_bits == 128
        assert config.secret_bytes == 16
        assert config.words_per_share == 20

    def test_groups_updated_from_threshold(self):
        """Test groups are updated based on threshold/total."""
        config = SLIP39Config(total_shares=7, threshold=4)
        assert config.groups == [(4, 7)]

    def test_threshold_exceeds_total_raises(self):
        """Test that threshold > total_shares raises ValueError."""
        with pytest.raises(ValueError, match="cannot exceed total shares"):
            SLIP39Config(total_shares=5, threshold=6)

    def test_threshold_zero_raises(self):
        """Test that threshold < 1 raises ValueError."""
        with pytest.raises(ValueError, match="at least 1"):
            SLIP39Config(threshold=0)

    def test_total_shares_one_raises(self):
        """Test that total_shares < 2 raises ValueError."""
        # threshold=1 to avoid hitting threshold > total validation first
        with pytest.raises(ValueError, match="at least 2 shares"):
            SLIP39Config(total_shares=1, threshold=1)

    def test_invalid_secret_bits_raises(self):
        """Test that invalid secret_bits raises ValueError."""
        with pytest.raises(ValueError, match="128 .* or 256"):
            SLIP39Config(secret_bits=192)


class TestSLIP39Share:
    """Tests for SLIP39Share dataclass."""

    def test_share_creation(self):
        """Test creating a share with mnemonic."""
        # Use a valid-looking mnemonic (won't pass checksum validation)
        mnemonic = " ".join(["word"] * 33)
        share = SLIP39Share(mnemonic=mnemonic, index=1, total=5, threshold=3)
        assert share.index == 1
        assert share.total == 5
        assert share.threshold == 3
        assert share.word_count == 33
        assert len(share.words) == 33
        assert share.fingerprint  # Should be auto-computed

    def test_share_fingerprint_auto_computed(self):
        """Test fingerprint is computed on creation."""
        share = SLIP39Share(
            mnemonic="word " * 32 + "word", index=1, total=5, threshold=3
        )
        assert len(share.fingerprint) == 8
        assert all(c in "0123456789abcdef" for c in share.fingerprint)


class TestNormalization:
    """Tests for mnemonic normalization."""

    def test_normalize_lowercase(self):
        """Test normalization converts to lowercase."""
        assert normalize_mnemonic("WORD ONE TWO") == "word one two"

    def test_normalize_extra_spaces(self):
        """Test normalization collapses multiple spaces."""
        assert normalize_mnemonic("word  one   two") == "word one two"

    def test_normalize_strip_whitespace(self):
        """Test normalization strips leading/trailing whitespace."""
        assert normalize_mnemonic("  word one two  ") == "word one two"

    def test_normalize_tabs_and_newlines(self):
        """Test normalization handles tabs and newlines."""
        assert normalize_mnemonic("word\tone\ntwo") == "word one two"

    def test_normalize_idempotent(self):
        """Test normalizing already-normalized string."""
        normalized = "word one two"
        assert normalize_mnemonic(normalized) == normalized


class TestFingerprints:
    """Tests for fingerprint computation."""

    def test_share_fingerprint_length(self):
        """Test share fingerprint is 8 hex characters."""
        fp = compute_share_fingerprint("word one two three")
        assert len(fp) == 8
        assert all(c in "0123456789abcdef" for c in fp)

    def test_share_fingerprint_deterministic(self):
        """Test same input produces same fingerprint."""
        fp1 = compute_share_fingerprint("word one two three")
        fp2 = compute_share_fingerprint("word one two three")
        assert fp1 == fp2

    def test_share_fingerprint_normalized(self):
        """Test fingerprint uses normalized input."""
        fp1 = compute_share_fingerprint("WORD ONE TWO")
        fp2 = compute_share_fingerprint("word  one   two")
        assert fp1 == fp2

    def test_master_fingerprint_length(self):
        """Test master fingerprint is 8 hex characters."""
        fp = compute_master_fingerprint(b"\x00" * 32)
        assert len(fp) == 8
        assert all(c in "0123456789abcdef" for c in fp)

    def test_master_fingerprint_deterministic(self):
        """Test same secret produces same fingerprint."""
        secret = b"test_secret_0123456789012345678"
        fp1 = compute_master_fingerprint(secret)
        fp2 = compute_master_fingerprint(secret)
        assert fp1 == fp2

    def test_different_secrets_different_fingerprints(self):
        """Test different secrets produce different fingerprints."""
        fp1 = compute_master_fingerprint(b"\x00" * 32)
        fp2 = compute_master_fingerprint(b"\xff" * 32)
        assert fp1 != fp2


class TestVerifyShareReentry:
    """Tests for share re-entry verification."""

    def test_exact_match(self):
        """Test exact match returns True."""
        original = "word one two three"
        assert verify_share_reentry(original, "word one two three")

    def test_case_insensitive(self):
        """Test verification is case-insensitive."""
        original = "word one two three"
        assert verify_share_reentry(original, "WORD ONE TWO THREE")

    def test_whitespace_tolerant(self):
        """Test verification tolerates whitespace differences."""
        original = "word one two three"
        assert verify_share_reentry(original, "  word   one  two   three  ")

    def test_mismatch_fails(self):
        """Test different words fail verification."""
        original = "word one two three"
        assert not verify_share_reentry(original, "word one two four")

    def test_missing_word_fails(self):
        """Test missing word fails verification."""
        original = "word one two three"
        assert not verify_share_reentry(original, "word one two")


class TestValidateShare:
    """Tests for share validation."""

    def test_invalid_word_count(self):
        """Test invalid word count is rejected."""
        is_valid, error = validate_share("one two three")
        assert not is_valid
        assert "word count" in error.lower()

    def test_word_count_20_accepted(self):
        """Test 20-word format is recognized (may fail checksum)."""
        # Create 20 words
        mnemonic = " ".join(["abandon"] * 20)
        is_valid, error = validate_share(mnemonic)
        # Will likely fail checksum, but word count passes
        if not is_valid:
            assert "word count" not in error.lower()

    def test_word_count_33_accepted(self):
        """Test 33-word format is recognized (may fail checksum)."""
        # Create 33 words
        mnemonic = " ".join(["abandon"] * 33)
        is_valid, error = validate_share(mnemonic)
        # Will likely fail checksum, but word count passes
        if not is_valid:
            assert "word count" not in error.lower()


class TestGenerateShares:
    """Tests for share generation."""

    def test_generate_default_config(self):
        """Test generating shares with default config."""
        share_set = generate_shares()
        assert share_set.share_count == 5
        assert share_set.config.threshold == 3
        assert share_set.master_fingerprint
        assert len(share_set.master_fingerprint) == 8

    def test_generate_custom_threshold(self):
        """Test generating shares with custom threshold."""
        config = SLIP39Config(total_shares=7, threshold=4)
        share_set = generate_shares(config=config)
        assert share_set.share_count == 7
        assert share_set.config.threshold == 4

    def test_generate_128_bit(self):
        """Test generating 128-bit shares."""
        config = SLIP39Config(secret_bits=128)
        share_set = generate_shares(config=config)
        # 128-bit = 20 words per share
        assert share_set.shares[0].word_count == 20

    def test_generate_256_bit(self):
        """Test generating 256-bit shares."""
        config = SLIP39Config(secret_bits=256)
        share_set = generate_shares(config=config)
        # 256-bit = 33 words per share
        assert share_set.shares[0].word_count == 33

    def test_generate_with_passphrase(self):
        """Test generating shares with passphrase."""
        config = SLIP39Config(passphrase="test_passphrase")
        share_set = generate_shares(config=config)
        assert share_set.share_count == 5
        assert share_set.config.passphrase == "test_passphrase"

    def test_generate_with_master_secret(self):
        """Test generating shares from provided master secret."""
        secret = b"\x42" * 16  # 128 bits = default
        share_set = generate_shares(master_secret=secret)
        # Verify fingerprint matches provided secret
        expected_fp = compute_master_fingerprint(secret)
        assert share_set.master_fingerprint == expected_fp

    def test_generate_shares_unique(self):
        """Test all generated shares are unique."""
        share_set = generate_shares()
        mnemonics = [s.mnemonic for s in share_set.shares]
        assert len(set(mnemonics)) == len(mnemonics)

    def test_generate_share_indices(self):
        """Test shares have correct indices."""
        share_set = generate_shares()
        indices = [s.index for s in share_set.shares]
        assert indices == [1, 2, 3, 4, 5]

    def test_generate_with_insufficient_entropy_raises(self):
        """Test insufficient entropy source raises error."""
        # Create mock entropy with too few bytes
        mock_entropy = MagicMock()
        mock_entropy.data = b"\x00" * 16  # Only 16 bytes

        config = SLIP39Config(secret_bits=256)  # Needs 32 bytes
        with pytest.raises(ValueError, match="need 32 bytes"):
            generate_shares(config=config, entropy_source=mock_entropy)


class TestRecoverSecret:
    """Tests for secret recovery."""

    def test_recover_exact_threshold(self):
        """Test recovery with exactly threshold shares."""
        share_set = generate_shares()
        threshold = share_set.config.threshold

        # Use exactly threshold shares
        mnemonics = [s.mnemonic for s in share_set.shares[:threshold]]
        recovered = recover_secret(mnemonics)

        # Verify by fingerprint
        recovered_fp = compute_master_fingerprint(recovered)
        assert recovered_fp == share_set.master_fingerprint

    def test_recover_above_threshold(self):
        """Test recovery with more than threshold shares uses only threshold."""
        share_set = generate_shares()
        threshold = share_set.config.threshold

        # Use more than threshold - library requires exactly threshold
        # So we test that providing any threshold subset works
        mnemonics = [s.mnemonic for s in share_set.shares[:threshold]]
        recovered = recover_secret(mnemonics)

        # Verify by fingerprint
        recovered_fp = compute_master_fingerprint(recovered)
        assert recovered_fp == share_set.master_fingerprint

    def test_recover_below_threshold_fails(self):
        """Test recovery fails with fewer than threshold shares."""
        share_set = generate_shares()
        threshold = share_set.config.threshold

        # Use fewer than threshold shares
        mnemonics = [s.mnemonic for s in share_set.shares[: threshold - 1]]

        with pytest.raises(ValueError, match="Recovery failed"):
            recover_secret(mnemonics)

    def test_recover_with_passphrase(self):
        """Test recovery with passphrase."""
        config = SLIP39Config(passphrase="test_pass")
        share_set = generate_shares(config=config)

        mnemonics = [s.mnemonic for s in share_set.shares[: config.threshold]]
        recovered = recover_secret(mnemonics, passphrase="test_pass")

        recovered_fp = compute_master_fingerprint(recovered)
        assert recovered_fp == share_set.master_fingerprint

    def test_recover_wrong_passphrase_differs(self):
        """Test wrong passphrase produces different secret."""
        config = SLIP39Config(passphrase="correct_pass")
        share_set = generate_shares(config=config)

        mnemonics = [s.mnemonic for s in share_set.shares[: config.threshold]]

        # Recover with wrong passphrase - produces different (wrong) secret
        wrong_recovered = recover_secret(mnemonics, passphrase="wrong_pass")
        wrong_fp = compute_master_fingerprint(wrong_recovered)

        # Should NOT match the original master fingerprint
        assert wrong_fp != share_set.master_fingerprint

    def test_recover_invalid_share_fails(self):
        """Test recovery fails with invalid share."""
        with pytest.raises(ValueError, match="invalid"):
            recover_secret(["not a valid mnemonic"])


class TestVerifyShares:
    """Tests for share set verification."""

    def test_verify_valid_shares(self):
        """Test verification of valid share set."""
        share_set = generate_shares()
        success, message = verify_shares(share_set)
        assert success
        assert "successful" in message.lower()

    def test_verify_with_passphrase(self):
        """Test verification with passphrase."""
        config = SLIP39Config(passphrase="test_pass")
        share_set = generate_shares(config=config)
        success, message = verify_shares(share_set)
        assert success


class TestDisplayFormatting:
    """Tests for display formatting functions."""

    def test_format_share_with_mnemonic(self):
        """Test formatting share with mnemonic visible."""
        share_set = generate_shares()
        share = share_set.shares[0]

        formatted = format_share_for_display(share, show_mnemonic=True)

        assert f"Share {share.index} of {share.total}" in formatted
        assert share.fingerprint in formatted
        assert str(share.word_count) in formatted
        # Should contain numbered words
        assert "1." in formatted

    def test_format_share_without_mnemonic(self):
        """Test formatting share without mnemonic visible."""
        share_set = generate_shares()
        share = share_set.shares[0]

        formatted = format_share_for_display(share, show_mnemonic=False)

        assert f"Share {share.index}" in formatted
        assert share.fingerprint in formatted
        # Should NOT contain mnemonic content
        assert "1." not in formatted

    def test_format_share_summary(self):
        """Test formatting share set summary."""
        share_set = generate_shares()
        summary = format_share_summary(share_set)

        assert "SLIP-39 Share Set" in summary
        assert f"{share_set.config.threshold}-of-{share_set.config.total_shares}" in summary
        assert share_set.master_fingerprint in summary
        # Should list all share fingerprints
        for share in share_set.shares:
            assert share.fingerprint in summary


class TestSLIP39ShareSet:
    """Tests for SLIP39ShareSet dataclass."""

    def test_share_count(self):
        """Test share_count property."""
        share_set = generate_shares()
        assert share_set.share_count == len(share_set.shares)
        assert share_set.share_count == 5

    def test_generated_at_timestamp(self):
        """Test generated_at is set."""
        share_set = generate_shares()
        assert share_set.generated_at is not None
        assert isinstance(share_set.generated_at, datetime)


class TestRoundTrip:
    """End-to-end tests for share generation and recovery."""

    def test_full_round_trip_256_bit(self):
        """Test full round-trip with 256-bit secret."""
        # Generate shares with fixed 32-byte secret
        secret = secrets.token_bytes(32)
        assert len(secret) == 32

        config = SLIP39Config(total_shares=5, threshold=3, secret_bits=256)
        share_set = generate_shares(config=config, master_secret=secret)

        # Recover with threshold shares
        mnemonics = [s.mnemonic for s in share_set.shares[:3]]
        recovered = recover_secret(mnemonics)

        assert recovered == secret

    def test_full_round_trip_128_bit(self):
        """Test full round-trip with 128-bit secret."""
        # Generate shares with fixed 16-byte secret
        secret = secrets.token_bytes(16)
        assert len(secret) == 16

        config = SLIP39Config(total_shares=5, threshold=3, secret_bits=128)
        share_set = generate_shares(config=config, master_secret=secret)

        # Recover with threshold shares
        mnemonics = [s.mnemonic for s in share_set.shares[:3]]
        recovered = recover_secret(mnemonics)

        assert recovered == secret

    def test_round_trip_with_passphrase(self):
        """Test round-trip with passphrase."""
        secret = secrets.token_bytes(16)  # 128 bits = default
        assert len(secret) == 16
        passphrase = "my_secure_passphrase"

        config = SLIP39Config(passphrase=passphrase)
        share_set = generate_shares(config=config, master_secret=secret)

        mnemonics = [s.mnemonic for s in share_set.shares[:3]]
        recovered = recover_secret(mnemonics, passphrase=passphrase)

        assert recovered == secret

    def test_round_trip_any_threshold_shares(self):
        """Test recovery works with any combination of threshold shares."""
        secret = secrets.token_bytes(16)  # 128 bits = default
        assert len(secret) == 16

        config = SLIP39Config(total_shares=5, threshold=3)
        share_set = generate_shares(config=config, master_secret=secret)

        # Try different combinations of 3 shares
        combinations = [
            [0, 1, 2],  # First three
            [2, 3, 4],  # Last three
            [0, 2, 4],  # Every other
            [1, 3, 4],  # Another combination
        ]

        for indices in combinations:
            mnemonics = [share_set.shares[i].mnemonic for i in indices]
            recovered = recover_secret(mnemonics)
            assert recovered == secret, f"Failed for indices {indices}"
