#!/usr/bin/env python3
"""
Core functionality tests targeting specific missing coverage areas.

These tests focus on improving coverage of the core modules that support
the CLI commands, targeting the specific missing lines identified in coverage.
"""

import unittest

from seeder.core import config
from seeder.core.crypto import SeedCardCrypto
from seeder.core.exceptions import CoordinateError, SeedCardError
from seeder.core.grid import SeederGrid
from seeder.core.seed_sources import SeedSources


class TestGridCoverage(unittest.TestCase):
    """Test grid functionality to improve coverage."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_seed = b'x' * 64
        self.grid = SeederGrid(self.test_seed)

    def test_grid_coordinate_validation(self):
        """Test coordinate validation logic."""
        # Test valid coordinates
        token = self.grid.get_token("A0")
        self.assertIsInstance(token, str)
        self.assertEqual(len(token), 4)

        # Test invalid coordinates
        with self.assertRaises(CoordinateError):
            self.grid.get_token("K0")  # Invalid column

        with self.assertRaises(CoordinateError):
            self.grid.get_token("A10")  # Invalid row

        with self.assertRaises(CoordinateError):
            self.grid.get_token("AA")  # Invalid format

    def test_grid_bounds_checking(self):
        """Test grid boundary conditions."""
        # Test all valid corners
        corners = ["A0", "A9", "J0", "J9"]
        for corner in corners:
            token = self.grid.get_token(corner)
            self.assertIsInstance(token, str)
            self.assertEqual(len(token), 4)

    def test_grid_string_methods(self):
        """Test grid string output methods."""
        # Test as string conversion
        grid_str = self.grid.get_grid_as_string()
        self.assertIsInstance(grid_str, str)
        self.assertTrue(len(grid_str) > 0)

        # Should contain spaces and newlines for formatting
        self.assertIn(" ", grid_str)
        self.assertIn("\n", grid_str)

    def test_grid_tokens_property(self):
        """Test getting tokens from grid."""
        tokens = self.grid.tokens
        self.assertEqual(len(tokens), 10)  # 10 rows
        self.assertEqual(len(tokens[0]), 10)  # 10 columns

        # All tokens should be 4 characters
        for row in tokens:
            for token in row:
                self.assertEqual(len(token), 4)
                self.assertIsInstance(token, str)


class TestCryptoCoverage(unittest.TestCase):
    """Test crypto functionality to improve coverage."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_seed = b'x' * 64

    def test_crypto_alphabet_handling(self):
        """Test alphabet and symbol mapping."""
        alphabet_size = config.ALPHABET_SIZE

        # Test byte to symbol mapping with various values
        for byte_val in [0, 64, 128, 255]:
            symbol_idx = SeedCardCrypto.byte_to_symbol(byte_val, alphabet_size)
            if symbol_idx is not None:
                self.assertLess(symbol_idx, alphabet_size)
                self.assertGreaterEqual(symbol_idx, 0)

    def test_crypto_stream_generation(self):
        """Test cryptographic stream generation."""
        # Test stream generation with different labels
        stream1 = SeedCardCrypto.hkdf_like_stream(self.test_seed, b"TEST1", 100)
        stream2 = SeedCardCrypto.hkdf_like_stream(self.test_seed, b"TEST2", 100)

        self.assertEqual(len(stream1), 100)
        self.assertEqual(len(stream2), 100)
        self.assertNotEqual(stream1, stream2)  # Different labels should produce different streams

    def test_crypto_token_generation(self):
        """Test token generation from seeds."""
        # Test token generation
        tokens = SeedCardCrypto.generate_token_stream(self.test_seed, 10)
        self.assertEqual(len(tokens), 10)

        for token in tokens:
            self.assertEqual(len(token), 4)
            self.assertIsInstance(token, str)
            for char in token:
                self.assertIn(char, config.ALPHABET)

        # Test deterministic behavior
        tokens_repeat = SeedCardCrypto.generate_token_stream(self.test_seed, 10)
        self.assertEqual(tokens, tokens_repeat)


class TestSeedSourcesCoverage(unittest.TestCase):
    """Test seed sources to improve coverage."""

    def test_simple_seed_validation(self):
        """Test simple seed validation and processing."""
        # Test with various input types
        test_cases = [
            "simple_test",
            "test with spaces",
            "test123!@#",
            ""  # Empty string
        ]

        for test_input in test_cases:
            seed_bytes = SeedSources.simple_to_seed(test_input)
            self.assertIsInstance(seed_bytes, bytes)
            self.assertEqual(len(seed_bytes), 64)  # SHA-512 output

    def test_bip39_parameter_handling(self):
        """Test BIP-39 parameter variations."""
        test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

        # Test with different passphrases
        seed1 = SeedSources.bip39_to_seed(test_mnemonic, "", 2048)
        seed2 = SeedSources.bip39_to_seed(test_mnemonic, "test", 2048)

        self.assertNotEqual(seed1, seed2)
        self.assertEqual(len(seed1), 64)
        self.assertEqual(len(seed2), 64)

        # Note: BIP-39 PBKDF2 uses fixed 2048 iterations regardless of parameter
        seed3 = SeedSources.bip39_to_seed(test_mnemonic, "", 1024)
        # BIP-39 implementation ignores the iterations parameter
        self.assertEqual(len(seed3), 64)

    def test_slip39_error_handling(self):
        """Test SLIP-39 error conditions."""
        # Test with insufficient shares
        with self.assertRaises(Exception):
            SeedSources.slip39_to_seed(["single_share"])

        # Test with empty shares
        with self.assertRaises(Exception):
            SeedSources.slip39_to_seed([])


class TestConfigurationCoverage(unittest.TestCase):
    """Test configuration constants and validation."""

    def test_config_constants(self):
        """Test configuration constants."""
        # Test default values
        self.assertIsInstance(config.DEFAULT_MNEMONIC, str)
        self.assertGreater(config.DEFAULT_PBKDF2_ITERATIONS, 0)
        self.assertIsInstance(config.ALPHABET, list)  # ALPHABET is a list
        self.assertGreater(len(config.ALPHABET), 0)

        # Test grid dimensions
        self.assertEqual(config.TOKENS_WIDE, 10)
        self.assertEqual(config.TOKENS_TALL, 10)
        self.assertEqual(config.CHARS_PER_TOKEN, 4)

        # Test alphabet size validation
        self.assertEqual(len(config.ALPHABET), config.ALPHABET_SIZE)
        self.assertEqual(config.ALPHABET_SIZE, 90)


class TestExceptionCoverage(unittest.TestCase):
    """Test exception handling and error cases."""

    def test_seed_card_error_hierarchy(self):
        """Test exception inheritance and messages."""
        # Test base exception
        base_error = SeedCardError("Test error")
        self.assertEqual(str(base_error), "Test error")

        # Test coordinate error
        coord_error = CoordinateError("Invalid coordinate")
        self.assertIsInstance(coord_error, SeedCardError)
        self.assertEqual(str(coord_error), "Invalid coordinate")

    def test_error_with_context(self):
        """Test errors with additional context."""
        error = CoordinateError("Invalid coordinate: X1")
        self.assertIn("X1", str(error))


class TestIntegrationScenarios(unittest.TestCase):
    """Test end-to-end integration scenarios."""

    def test_simple_to_grid_workflow(self):
        """Test complete simple seed to grid workflow."""
        # Generate seed
        seed_bytes = SeedSources.simple_to_seed("test_phrase")

        # Create grid
        grid = SeederGrid(seed_bytes)

        # Extract tokens
        tokens = []
        for row in range(10):
            for col in range(10):
                coord = f"{chr(ord('A') + col)}{row}"
                token = grid.get_token(coord)
                tokens.append(token)

        # Verify tokens
        self.assertEqual(len(tokens), 100)
        for token in tokens:
            self.assertEqual(len(token), 4)
            self.assertIsInstance(token, str)

    def test_deterministic_generation(self):
        """Test that generation is deterministic."""
        seed_phrase = "deterministic_test"

        # Generate two grids from same seed
        seed1 = SeedSources.simple_to_seed(seed_phrase)
        seed2 = SeedSources.simple_to_seed(seed_phrase)

        grid1 = SeederGrid(seed1)
        grid2 = SeederGrid(seed2)

        # Should be identical
        self.assertEqual(grid1.get_token("A0"), grid2.get_token("A0"))
        self.assertEqual(grid1.get_token("J9"), grid2.get_token("J9"))
        self.assertEqual(grid1.get_grid_as_string(), grid2.get_grid_as_string())


if __name__ == '__main__':
    unittest.main()
