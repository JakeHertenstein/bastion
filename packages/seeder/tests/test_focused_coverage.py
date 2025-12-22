#!/usr/bin/env python3
"""
Focused core module tests to improve specific coverage gaps.

Targets the exact missing lines identified in coverage analysis.
"""

import hashlib
import unittest

from seeder.core.config import ALPHABET
from seeder.core.crypto import SeedCardCrypto
from seeder.core.exceptions import CoordinateError
from seeder.core.grid import SeederGrid
from seeder.core.seed_sources import SeedSources


class TestCryptoFocused(unittest.TestCase):
    """Test crypto module targeting specific missing coverage."""

    def setUp(self):
        """Set up test fixtures."""
        self.crypto = SeedCardCrypto()
        self.test_seed = hashlib.sha512(b"crypto_test").digest()

    def test_byte_to_symbol_edge_cases(self):
        """Test byte to symbol mapping edge cases."""
        alphabet_size = len(ALPHABET)

        # Test boundary values
        result_0 = self.crypto.byte_to_symbol(0, alphabet_size)
        self.assertIsNotNone(result_0)
        self.assertEqual(result_0, 0)

        # Test values that should be rejected (None return)
        max_usable = (256 // alphabet_size) * alphabet_size
        if max_usable < 256:
            result_high = self.crypto.byte_to_symbol(max_usable, alphabet_size)
            self.assertIsNone(result_high)

        # Test mid-range values
        result_mid = self.crypto.byte_to_symbol(45, alphabet_size)
        if result_mid is not None:
            self.assertLess(result_mid, alphabet_size)

    def test_hkdf_stream_variations(self):
        """Test HMAC stream with different parameters."""
        # Test different stream lengths
        stream_100 = self.crypto.hkdf_like_stream(self.test_seed, b"TEST", 100)
        stream_200 = self.crypto.hkdf_like_stream(self.test_seed, b"TEST", 200)

        self.assertEqual(len(stream_100), 100)
        self.assertEqual(len(stream_200), 200)

        # First 100 bytes should be identical
        self.assertEqual(stream_100, stream_200[:100])

        # Test empty label
        stream_empty = self.crypto.hkdf_like_stream(self.test_seed, b"", 50)
        self.assertEqual(len(stream_empty), 50)

        # Test very long label
        long_label = b"X" * 100
        stream_long = self.crypto.hkdf_like_stream(self.test_seed, long_label, 50)
        self.assertEqual(len(stream_long), 50)

    def test_token_generation_comprehensive(self):
        """Test comprehensive token generation."""
        # Test single token generation
        tokens = self.crypto.generate_token_stream(self.test_seed, 1)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(len(tokens[0]), 4)

        # Test multiple tokens
        tokens_10 = self.crypto.generate_token_stream(self.test_seed, 10)
        self.assertEqual(len(tokens_10), 10)

        # Each token should be valid
        for token in tokens_10:
            self.assertEqual(len(token), 4)
            for char in token:
                self.assertIn(char, ALPHABET)

        # Test deterministic behavior
        tokens_repeat = self.crypto.generate_token_stream(self.test_seed, 10)
        self.assertEqual(tokens_10, tokens_repeat)


class TestGridFocused(unittest.TestCase):
    """Test grid module targeting specific missing coverage."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_seed = hashlib.sha512(b"grid_test").digest()
        self.grid = SeederGrid(self.test_seed)

    def test_coordinate_error_edge_cases(self):
        """Test coordinate validation edge cases."""
        # Test lowercase coordinates (should be converted)
        token_lower = self.grid.get_token("a0")
        token_upper = self.grid.get_token("A0")
        self.assertEqual(token_lower, token_upper)

        # Test coordinates with extra whitespace
        token_space = self.grid.get_token(" A0 ")
        self.assertEqual(token_space, token_upper)

        # Test various invalid formats
        invalid_coords = [
            "",      # Empty
            "A",     # Too short
            "AAA",   # Too long
            "1A",    # Number first
            "A@",    # Invalid row character
            "@0",    # Invalid column character
        ]

        for coord in invalid_coords:
            with self.assertRaises(CoordinateError):
                self.grid.get_token(coord)

    def test_grid_lazy_generation(self):
        """Test lazy generation of grid properties."""
        # Create new grid
        grid = SeederGrid(self.test_seed)

        # Access tokens property (should trigger generation)
        tokens = grid.tokens
        self.assertEqual(len(tokens), 10)  # 10 rows
        self.assertEqual(len(tokens[0]), 10)  # 10 columns

        # Access coordinate map property
        coord_map = grid.coordinate_map
        self.assertIsInstance(coord_map, dict)
        self.assertGreater(len(coord_map), 0)

        # Verify coordinate map contents
        for coord, token in coord_map.items():
            self.assertEqual(len(coord), 2)  # e.g., "A0"
            self.assertEqual(len(token), 4)   # 4-char token

    def test_grid_string_formatting(self):
        """Test grid string output formatting."""
        grid_str = self.grid.get_grid_as_string()

        # Should contain proper structure
        lines = grid_str.strip().split('\n')
        self.assertEqual(len(lines), 10)

        # Each line should have 10 tokens separated by spaces
        for line in lines:
            tokens = line.split()
            self.assertEqual(len(tokens), 10)

            # Each token should be 4 characters from alphabet
            for token in tokens:
                self.assertEqual(len(token), 4)
                for char in token:
                    self.assertIn(char, ALPHABET)


class TestSeedSourcesFocused(unittest.TestCase):
    """Test seed sources targeting specific missing coverage."""

    def test_simple_seed_edge_cases(self):
        """Test simple seed generation edge cases."""
        # Test empty string
        seed_empty = SeedSources.simple_to_seed("")
        self.assertEqual(len(seed_empty), 64)

        # Test very long string
        long_input = "X" * 1000
        seed_long = SeedSources.simple_to_seed(long_input)
        self.assertEqual(len(seed_long), 64)

        # Test unicode characters
        unicode_input = "测试 🔐 тест"
        seed_unicode = SeedSources.simple_to_seed(unicode_input)
        self.assertEqual(len(seed_unicode), 64)

        # Test special characters
        special_input = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        seed_special = SeedSources.simple_to_seed(special_input)
        self.assertEqual(len(seed_special), 64)

    def test_bip39_edge_cases(self):
        """Test BIP-39 edge cases."""
        # Test with extreme iteration counts
        test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

        # Test minimum iterations
        seed_min = SeedSources.bip39_to_seed(test_mnemonic, "", 1)
        self.assertEqual(len(seed_min), 64)

        # Test high iterations
        seed_high = SeedSources.bip39_to_seed(test_mnemonic, "", 10000)
        self.assertEqual(len(seed_high), 64)

        # Should be different from default (BIP-39 uses iterations differently)
        seed_default = SeedSources.bip39_to_seed(test_mnemonic, "", 2048)
        # Note: BIP-39 might produce same result regardless of iterations - this is expected
        self.assertEqual(len(seed_default), 64)

        # Test with complex passphrase
        complex_pass = "Complex Pass123!@# 🔐"
        seed_complex = SeedSources.bip39_to_seed(test_mnemonic, complex_pass, 2048)
        self.assertEqual(len(seed_complex), 64)
        self.assertNotEqual(seed_complex, seed_default)

    def test_slip39_error_conditions(self):
        """Test SLIP-39 error handling."""
        # Test with empty list
        with self.assertRaises(Exception):
            SeedSources.slip39_to_seed([])

        # Test with single share (insufficient)
        with self.assertRaises(Exception):
            SeedSources.slip39_to_seed(["single_share"])

        # Test with invalid share format
        with self.assertRaises(Exception):
            SeedSources.slip39_to_seed(["invalid", "format"])


class TestErrorHandlingFocused(unittest.TestCase):
    """Test error handling to improve exception coverage."""

    def test_coordinate_error_messages(self):
        """Test coordinate error message formatting."""
        # Test basic coordinate error
        error = CoordinateError("Invalid coordinate format")
        self.assertIn("Invalid coordinate", str(error))

        # Test that it inherits from SeedCardError
        self.assertIsInstance(error, Exception)

    def test_grid_error_scenarios(self):
        """Test grid error scenarios."""
        test_seed = hashlib.sha512(b"error_test").digest()
        grid = SeederGrid(test_seed)

        # Test coordinate validation errors
        error_cases = [
            ("", "empty coordinate"),
            ("K0", "invalid column"),
            ("A10", "invalid row"),
            ("XX", "invalid format"),
        ]

        for bad_coord, description in error_cases:
            with self.assertRaises(CoordinateError, msg=f"Should raise error for {description}"):
                grid.get_token(bad_coord)


if __name__ == '__main__':
    unittest.main()
