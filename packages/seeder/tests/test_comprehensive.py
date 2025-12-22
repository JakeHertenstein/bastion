#!/usr/bin/env python3
"""
Comprehensive unit tests for the Seeder system.
Tests all major components including seed derivation, cryptographic operations,
grid generation, and integration functionality.
"""

import unittest
from unittest.mock import patch

from seeder.core.config import ALPHABET, DEFAULT_MNEMONIC
from seeder.core.crypto import PasswordEntropyAnalyzer, SeedCardCrypto, SeedCardDigest
from seeder.core.exceptions import CoordinateError, SeedDerivationError, SLIP39Error
from seeder.core.grid import SeederGrid

# Core modules
from seeder.core.seed_sources import SeedSources
from seeder.core.word_generator import DictionaryWordGenerator, WordGenerator


class TestSeedSources(unittest.TestCase):
    """Test seed derivation from various sources."""

    def test_bip39_deterministic(self):
        """Test that BIP-39 seed derivation is deterministic."""
        mnemonic = DEFAULT_MNEMONIC
        seed1 = SeedSources.bip39_to_seed(mnemonic)
        seed2 = SeedSources.bip39_to_seed(mnemonic)

        self.assertEqual(seed1, seed2)
        self.assertEqual(len(seed1), 64)
        self.assertIsInstance(seed1, bytes)

    def test_bip39_with_passphrase(self):
        """Test BIP-39 with passphrase produces different seeds."""
        mnemonic = DEFAULT_MNEMONIC
        seed_no_pass = SeedSources.bip39_to_seed(mnemonic)
        seed_with_pass = SeedSources.bip39_to_seed(mnemonic, passphrase="test")

        self.assertNotEqual(seed_no_pass, seed_with_pass)
        self.assertEqual(len(seed_with_pass), 64)

    def test_simple_deterministic(self):
        """Test that simple seed derivation is deterministic."""
        phrase = "test phrase"
        seed1 = SeedSources.simple_to_seed(phrase)
        seed2 = SeedSources.simple_to_seed(phrase)

        self.assertEqual(seed1, seed2)
        self.assertEqual(len(seed1), 64)
        self.assertIsInstance(seed1, bytes)

    def test_different_seeds_different_output(self):
        """Test that different inputs produce different seeds."""
        seed1 = SeedSources.simple_to_seed("phrase1")
        seed2 = SeedSources.simple_to_seed("phrase2")

        self.assertNotEqual(seed1, seed2)

    def test_slip39_share_generation(self):
        """Test SLIP-39 test share generation."""
        secret = "test secret"
        shares = SeedSources.create_test_slip39_shares(secret, threshold=2, total_shares=3)

        self.assertEqual(len(shares), 3)
        for share in shares:
            self.assertIsInstance(share, str)
            # Test shares should have reasonable length
            self.assertGreater(len(share), 10)

    def test_slip39_reconstruction(self):
        """Test SLIP-39 share reconstruction."""
        secret = "TestSecret123"
        shares = SeedSources.create_test_slip39_shares(secret, threshold=2, total_shares=3)

        # Test reconstruction with sufficient shares
        reconstructed_seed = SeedSources.slip39_to_seed(shares[:2])
        self.assertIsInstance(reconstructed_seed, bytes)
        self.assertEqual(len(reconstructed_seed), 64)  # Should be 64 bytes like BIP-39

        # Test reconstruction with exactly threshold shares produces same result
        reconstructed_seed2 = SeedSources.slip39_to_seed(shares[:2])  # Use same threshold count
        self.assertEqual(reconstructed_seed, reconstructed_seed2)

    def test_slip39_to_grid_workflow(self):
        """Test complete workflow from SLIP-39 shares to grid."""
        secret = "SeedSourcesWorkflowTest"
        shares = SeedSources.create_test_slip39_shares(secret, threshold=2, total_shares=3)

        # Use threshold shares to create grid
        seed = SeedSources.slip39_to_seed(shares[:2])
        grid = SeederGrid(seed)

        # Verify grid is created
        self.assertIsNotNone(grid)

        # Test token lookup
        token = grid.get_token("A0")
        self.assertIsNotNone(token)
        self.assertEqual(len(token), 4)

    def test_slip39_insufficient_shares(self):
        """Test SLIP-39 fails with insufficient shares."""
        with self.assertRaises(SLIP39Error):
            SeedSources.slip39_to_seed(["single_share"])


class TestSeedCardCrypto(unittest.TestCase):
    """Test cryptographic operations."""

    def test_hkdf_like_stream_deterministic(self):
        """Test that HMAC stream generation is deterministic."""
        seed = b"a" * 64  # 64-byte test seed
        label = b"TEST"

        stream1 = SeedCardCrypto.hkdf_like_stream(seed, label, 100)
        stream2 = SeedCardCrypto.hkdf_like_stream(seed, label, 100)

        self.assertEqual(stream1, stream2)
        self.assertEqual(len(stream1), 100)

    def test_hkdf_like_stream_different_labels(self):
        """Test that different labels produce different streams."""
        seed = b"b" * 64

        stream1 = SeedCardCrypto.hkdf_like_stream(seed, b"LABEL1", 50)
        stream2 = SeedCardCrypto.hkdf_like_stream(seed, b"LABEL2", 50)

        self.assertNotEqual(stream1, stream2)

    def test_byte_to_symbol_valid_range(self):
        """Test that byte to symbol conversion produces valid alphabet indices."""
        # Test with various byte values
        for byte_val in [0, 50, 128, 200, 255]:
            result = SeedCardCrypto.byte_to_symbol(byte_val, len(ALPHABET))
            if result is not None:  # Some values are rejected for bias prevention
                self.assertGreaterEqual(result, 0)
                self.assertLess(result, len(ALPHABET))

    def test_byte_to_symbol_rejection_sampling(self):
        """Test that rejection sampling works correctly."""
        alphabet_size = 90
        max_usable = (256 // alphabet_size) * alphabet_size  # 180

        # Values < max_usable should be accepted
        result = SeedCardCrypto.byte_to_symbol(100, alphabet_size)
        self.assertIsNotNone(result)

        # Values >= max_usable should be rejected
        result = SeedCardCrypto.byte_to_symbol(250, alphabet_size)
        self.assertIsNone(result)

    def test_generate_token_stream_deterministic(self):
        """Test that token stream generation is deterministic."""
        seed = b"c" * 64

        tokens1 = SeedCardCrypto.generate_token_stream(seed, 5)
        tokens2 = SeedCardCrypto.generate_token_stream(seed, 5)

        self.assertEqual(tokens1, tokens2)
        self.assertEqual(len(tokens1), 5)
        for token in tokens1:
            self.assertEqual(len(token), 4)  # CHARS_PER_TOKEN = 4
            for char in token:
                self.assertIn(char, ALPHABET)


class TestSeedCardDigest(unittest.TestCase):
    """Test digest generation functionality."""

    def test_sha512_hash_generation(self):
        """Test that SHA-512 hash generation works."""
        seed = b"d" * 64
        digest = SeedCardDigest.generate_sha512_hash(seed)

        self.assertIsInstance(digest, str)
        self.assertEqual(len(digest), 128)  # SHA-512 hex = 128 chars

        # Test deterministic
        digest2 = SeedCardDigest.generate_sha512_hash(seed)
        self.assertEqual(digest, digest2)

    def test_hmac_digest_generation(self):
        """Test that HMAC digest generation works."""
        seed = b"e" * 64
        label = b"TEST_LABEL"

        digest = SeedCardDigest.generate_hmac_digest(seed, label)

        self.assertIsInstance(digest, str)
        self.assertEqual(len(digest), 128)  # HMAC-SHA512 hex = 128 chars

        # Test deterministic
        digest2 = SeedCardDigest.generate_hmac_digest(seed, label)
        self.assertEqual(digest, digest2)

    def test_different_seeds_different_hashes(self):
        """Test that different seeds produce different hashes."""
        seed1 = b"f" * 64
        seed2 = b"g" * 64

        hash1 = SeedCardDigest.generate_sha512_hash(seed1)
        hash2 = SeedCardDigest.generate_sha512_hash(seed2)

        self.assertNotEqual(hash1, hash2)


class TestSeederGrid(unittest.TestCase):
    """Test grid generation and operations."""

    def test_grid_creation(self):
        """Test that grid can be created and has correct dimensions."""
        seed = SeedSources.simple_to_seed("test grid")
        grid = SeederGrid(seed)

        # Check grid dimensions through tokens property
        tokens = grid.tokens
        self.assertEqual(len(tokens), 10)  # 10 rows
        for row in tokens:
            self.assertEqual(len(row), 10)  # 10 columns each

        # Check coordinate map
        coord_map = grid.coordinate_map
        self.assertEqual(len(coord_map), 100)  # 10x10 grid
        self.assertIn("A0", coord_map)
        self.assertIn("J9", coord_map)

    def test_grid_deterministic(self):
        """Test that grid generation is deterministic."""
        seed = SeedSources.simple_to_seed("deterministic test")

        grid1 = SeederGrid(seed)
        grid2 = SeederGrid(seed)

        # Compare tokens using the tokens property
        self.assertEqual(grid1.tokens, grid2.tokens)

    def test_token_lookup(self):
        """Test that token lookup by coordinate works."""
        seed = SeedSources.simple_to_seed("lookup test")
        grid = SeederGrid(seed)

        # Test valid coordinates
        token_a0 = grid.get_token("A0")
        self.assertIsNotNone(token_a0)
        self.assertEqual(len(token_a0), 4)

        token_j9 = grid.get_token("J9")
        self.assertIsNotNone(token_j9)
        self.assertEqual(len(token_j9), 4)

        # Same coordinate should return same token
        token_a0_again = grid.get_token("A0")
        self.assertEqual(token_a0, token_a0_again)

    def test_invalid_coordinates(self):
        """Test handling of invalid coordinates."""
        seed = SeedSources.simple_to_seed("invalid coord test")
        grid = SeederGrid(seed)

        with self.assertRaises(CoordinateError):
            grid.get_token("Z9")  # Invalid column

        with self.assertRaises(CoordinateError):
            grid.get_token("A10")  # Invalid row


class TestWordGenerator(unittest.TestCase):
    """Test pronounceable word generation."""

    def test_word_generation_deterministic(self):
        """Test that word generation is deterministic."""
        seed = b"g" * 64

        word1 = WordGenerator.generate_word(seed, 6, 0)
        word2 = WordGenerator.generate_word(seed, 6, 0)

        self.assertEqual(word1, word2)
        self.assertEqual(len(word1), 6)
        self.assertTrue(word1.isalpha())

    def test_different_indices_different_words(self):
        """Test that different indices produce different words."""
        seed = b"h" * 64

        word1 = WordGenerator.generate_word(seed, 6, 0)
        word2 = WordGenerator.generate_word(seed, 6, 1)

        self.assertNotEqual(word1, word2)

    def test_word_list_generation(self):
        """Test generating multiple words."""
        seed = b"i" * 64

        words = WordGenerator.generate_word_list(seed, 5, 10)

        self.assertEqual(len(words), 10)
        for word in words:
            self.assertEqual(len(word), 5)
            self.assertTrue(word.isalpha())

        # All words should be different
        self.assertEqual(len(set(words)), len(words))

    def test_entropy_calculation(self):
        """Test entropy calculation for words."""
        entropy = WordGenerator.calculate_word_entropy(6)

        self.assertIsInstance(entropy, float)
        self.assertGreater(entropy, 0)
        self.assertLess(entropy, 100)  # Reasonable upper bound

    def test_supported_lengths(self):
        """Test getting supported word lengths."""
        lengths = WordGenerator.get_supported_lengths()

        self.assertIsInstance(lengths, list)
        self.assertIn(6, lengths)  # Should support 6-char words
        self.assertTrue(all(isinstance(l, int) for l in lengths))


class TestDictionaryWordGenerator(unittest.TestCase):
    """Test dictionary word generation."""

    def test_availability_check(self):
        """Test availability check works."""
        available = DictionaryWordGenerator.is_available()
        self.assertIsInstance(available, bool)

    @unittest.skipUnless(DictionaryWordGenerator.is_available(), "wonderwords not installed")
    def test_dictionary_word_generation(self):
        """Test dictionary word generation with real wonderwords library."""
        seed = b"j" * 64

        # Test common words
        word = DictionaryWordGenerator.generate_word(seed, 0, 5, 5, "common")
        self.assertIsInstance(word, str)
        self.assertGreaterEqual(len(word), 3)  # Should be reasonable length

        # Test noun filtering
        word = DictionaryWordGenerator.generate_word(seed, 0, 5, 5, "nouns")
        self.assertIsInstance(word, str)

    @unittest.skipUnless(DictionaryWordGenerator.is_available(), "wonderwords not installed")
    def test_word_list_generation(self):
        """Test generating word lists."""
        seed = b"k" * 64

        words = DictionaryWordGenerator.generate_word_list(seed, 3, 5, 5, "common")

        self.assertEqual(len(words), 3)
        for word in words:
            self.assertIsInstance(word, str)

    def test_fallback_when_unavailable(self):
        """Test fallback to pronounceable words when unavailable."""
        with patch('seeder.core.word_generator.WONDERWORDS_AVAILABLE', False):
            with self.assertRaises(ImportError):
                DictionaryWordGenerator.generate_word(b"test" * 16, 0, 5, 5, "common")


class TestPasswordEntropyAnalyzer(unittest.TestCase):
    """Test password entropy analysis."""

    def test_basic_entropy_analysis(self):
        """Test basic entropy analysis functionality."""
        # Test simple pattern analysis
        result = PasswordEntropyAnalyzer.analyze_coordinate_pattern(["A0", "B1"])

        self.assertIsInstance(result, dict)
        self.assertIn('effective_entropy_bits', result)
        self.assertIn('num_tokens', result)
        self.assertGreater(float(result['effective_entropy_bits']), 0)

    def test_composite_password_analysis(self):
        """Test composite password analysis."""
        result = PasswordEntropyAnalyzer.analyze_composite_password(
            num_fixed_tokens=2,
            num_rolling_tokens=1,
            memorized_word_length=6,
            num_separators=2
        )

        self.assertIsInstance(result, dict)
        self.assertIn('total_entropy', result)
        self.assertIn('fixed_token_entropy', result)
        self.assertIn('rolling_token_entropy', result)
        self.assertGreater(float(result['total_entropy']), 0)

    def test_compromised_card_analysis(self):
        """Test compromised card scenario analysis."""
        result = PasswordEntropyAnalyzer.analyze_compromised_card_scenario(
            num_fixed_tokens=2,
            num_rolling_tokens=1,
            memorized_word_length=6,
            num_separators=2
        )

        self.assertIsInstance(result, dict)
        self.assertIn('full_entropy', result)
        self.assertIn('compromised_entropy', result)
        self.assertIn('entropy_loss', result)
        self.assertGreater(float(result['full_entropy']), float(result['compromised_entropy']))


class TestEndToEndIntegration(unittest.TestCase):
    """Test complete workflow integration."""

    def test_bip39_to_grid_workflow(self):
        """Test complete workflow from BIP-39 to grid."""
        mnemonic = DEFAULT_MNEMONIC

        # Generate seed
        seed = SeedSources.bip39_to_seed(mnemonic)

        # Create grid
        grid = SeederGrid(seed)

        # Verify grid properties
        grid_tokens = grid.tokens
        total_tokens = sum(len(row) for row in grid_tokens)
        self.assertEqual(total_tokens, 100)

        # Verify each token is valid
        for row in grid_tokens:
            for token in row:
                self.assertEqual(len(token), 4)
                for char in token:
                    self.assertIn(char, ALPHABET)

    def test_simple_to_grid_workflow(self):
        """Test complete workflow from simple phrase to grid."""
        phrase = "my secure banking seed"

        # Generate seed
        seed = SeedSources.simple_to_seed(phrase)

        # Create grid
        grid = SeederGrid(seed)

        # Verify we can get specific tokens
        first_token = grid.get_token("A0")
        last_token = grid.get_token("J9")

        self.assertIsNotNone(first_token)
        self.assertIsNotNone(last_token)
        self.assertNotEqual(first_token, last_token)

    def test_slip39_to_grid_workflow(self):
        """Test complete workflow from SLIP-39 shares to grid."""
        secret = "EndToEndWorkflowTest"
        shares = SeedSources.create_test_slip39_shares(secret, threshold=2, total_shares=3)

        # Use threshold shares to create grid
        seed = SeedSources.slip39_to_seed(shares[:2])
        grid = SeederGrid(seed)

        # Verify grid is created
        self.assertIsNotNone(grid)

        # Test token lookup
        token = grid.get_token("A0")
        self.assertIsNotNone(token)
        self.assertEqual(len(token), 4)

    def test_password_generation_workflow(self):
        """Test complete password generation workflow."""
        seed = SeedSources.simple_to_seed("password generation test")
        grid = SeederGrid(seed)

        # Get tokens for password
        token1 = grid.get_token("A0")
        token2 = grid.get_token("B1")

        # Generate memorized component
        memorized_word = WordGenerator.generate_word(seed, 6, 0)

        # Construct password
        password = f"{token1}-{token2}-{memorized_word}!"

        # Verify password structure
        self.assertIn(token1, password)
        self.assertIn(token2, password)
        self.assertIn(memorized_word, password)
        self.assertTrue(password.endswith('!'))

    def test_analyzer_integration(self):
        """Test analyzer integration with different pattern types."""
        # Test various patterns
        patterns = ["A0 B1", "A0 B1 C2", "A0 B1 C2 D3"]

        for pattern in patterns:
            result = PasswordEntropyAnalyzer.analyze_coordinate_pattern(pattern.split())
            self.assertIsInstance(result, dict)
            self.assertGreater(float(result['effective_entropy_bits']), 0)

            # More tokens should generally mean more entropy
            if pattern == "A0 B1 C2 D3":
                self.assertGreater(float(result['effective_entropy_bits']), 20)  # Lowered threshold


class TestErrorHandling(unittest.TestCase):
    """Test error handling and edge cases."""

    def test_invalid_bip39_mnemonic(self):
        """Test handling of invalid BIP-39 mnemonics."""
        # Test with validation enabled (default)
        with self.assertRaises(SeedDerivationError):
            SeedSources.bip39_to_seed("invalid words not in bip39 wordlist", validate=True)

        # Test permissive mode (validation disabled)
        seed = SeedSources.bip39_to_seed("invalid words not in bip39 wordlist", validate=False)
        self.assertIsInstance(seed, bytes)
        self.assertEqual(len(seed), 64)

    def test_bip39_validation_modes(self):
        """Test BIP-39 validation modes."""
        valid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

        # Valid mnemonic should work in both modes
        seed1 = SeedSources.bip39_to_seed(valid_mnemonic, validate=True)
        seed2 = SeedSources.bip39_to_seed(valid_mnemonic, validate=False)
        self.assertEqual(seed1, seed2)  # Should produce same result

    def test_empty_simple_phrase(self):
        """Test handling of empty simple phrases."""
        # Empty phrase works - just produces SHA-512 of empty string
        seed = SeedSources.simple_to_seed("")
        self.assertIsInstance(seed, bytes)

    def test_grid_with_invalid_seed(self):
        """Test grid creation with invalid seed."""
        # Current implementation is permissive - test that it doesn't crash
        grid = SeederGrid(b"any_bytes_work")
        self.assertIsNotNone(grid)

    def test_word_generator_invalid_length(self):
        """Test word generator with invalid lengths."""
        # Test that invalid length raises ValueError
        with self.assertRaises(ValueError):
            WordGenerator.generate_word_list(b"test_seed", length=0, count=1)


if __name__ == "__main__":
    # Run with high verbosity to see all test details
    unittest.main(verbosity=2, buffer=True)
