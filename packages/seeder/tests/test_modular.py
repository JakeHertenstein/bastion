#!/usr/bin/env python3
"""
Unit tests for the modular Seeder system.

Tests the new modular architecture:
- seed_sources.py: SeedSources class for various seed types
- crypto.py: SeedCardCrypto for cryptographic operations
- grid.py: SeederGrid for token grid generation
"""

import unittest

from seeder.core.config import ALPHABET, DEFAULT_MNEMONIC
from seeder.core.crypto import SeedCardCrypto
from seeder.core.grid import SeederGrid
from seeder.core.seed_sources import SeedSources


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
    
    def test_byte_to_symbol_valid_range(self):
        """Test that byte to symbol conversion produces valid alphabet indices."""
        # Test with various byte values
        for byte_val in [0, 50, 128, 200, 255]:
            result = SeedCardCrypto.byte_to_symbol(byte_val, len(ALPHABET))
            if result is not None:  # Some values are rejected for bias prevention
                self.assertGreaterEqual(result, 0)
                self.assertLess(result, len(ALPHABET))
    
    def test_generate_token_stream_deterministic(self):
        """Test that token stream generation is deterministic."""
        seed = b"b" * 64
        
        tokens1 = SeedCardCrypto.generate_token_stream(seed, 5)
        tokens2 = SeedCardCrypto.generate_token_stream(seed, 5)
        
        self.assertEqual(tokens1, tokens2)
        self.assertEqual(len(tokens1), 5)
        for token in tokens1:
            self.assertEqual(len(token), 4)  # CHARS_PER_TOKEN = 4


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
