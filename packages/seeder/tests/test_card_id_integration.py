#!/usr/bin/env python3
"""
Tests for card ID and card index integration in cryptographic functions.
Ensures card indices produce unique matrices and maintain deterministic behavior.

NOTE: With the v1 per-token HMAC label format, card_id is now metadata only.
The card_index (A0-J9) is what differentiates tokens in a batch.
"""

import sys
from pathlib import Path

import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from seeder.core.crypto import SeedCardCrypto
from seeder.core.grid import SeederGrid
from seeder.core.seed_sources import SeedSources


class TestCardIndexIntegration:
    """Test suite for card index cryptographic integration."""
    
    @pytest.fixture
    def test_seed_bytes(self):
        """Provide consistent test seed bytes."""
        return SeedSources.simple_to_seed("test")
    
    def test_card_index_produces_different_matrices(self, test_seed_bytes):
        """Verify different card indices produce different token matrices."""
        grid_a0 = SeederGrid(test_seed_bytes, card_index="A0")
        grid_b5 = SeederGrid(test_seed_bytes, card_index="B5")
        grid_j9 = SeederGrid(test_seed_bytes, card_index="J9")
        
        # Get first token from each grid
        token_a0 = grid_a0.get_token("A0")
        token_b5 = grid_b5.get_token("A0")
        token_j9 = grid_j9.get_token("A0")
        
        # All should be different
        assert token_a0 != token_b5, "A0 vs B5 card index should differ"
        assert token_b5 != token_j9, "B5 vs J9 card index should differ"
        assert token_a0 != token_j9, "A0 vs J9 card index should differ"
    
    def test_card_index_deterministic_behavior(self, test_seed_bytes):
        """Verify same card index produces identical results."""
        grid_1 = SeederGrid(test_seed_bytes, card_index="C3")
        grid_2 = SeederGrid(test_seed_bytes, card_index="C3")
        
        # Should produce identical tokens
        for row in range(5):  # Test first 5 rows
            for col in range(5):  # Test first 5 columns
                coord = f"{chr(ord('A') + col)}{row}"
                token_1 = grid_1.get_token(coord)
                token_2 = grid_2.get_token(coord)
                assert token_1 == token_2, f"Card index determinism failed at {coord}"
    
    def test_crypto_level_card_index_integration(self, test_seed_bytes):
        """Test card index integration at the crypto level."""
        crypto = SeedCardCrypto()
        
        # Generate tokens with different card indices
        tokens_a0 = crypto.generate_token_stream(test_seed_bytes, 10, card_index="A0")
        tokens_b5 = crypto.generate_token_stream(test_seed_bytes, 10, card_index="B5")
        tokens_j9 = crypto.generate_token_stream(test_seed_bytes, 10, card_index="J9")
        
        # All should be different
        assert tokens_a0 != tokens_b5, "Different card indices should produce different tokens"
        assert tokens_b5 != tokens_j9, "Different card indices should produce different tokens"
        assert tokens_a0 != tokens_j9, "Different card indices should produce different tokens"


class TestCardIdMetadata:
    """Test that card_id is properly preserved as metadata without affecting tokens."""
    
    @pytest.fixture
    def test_seed_bytes(self):
        """Provide consistent test seed bytes."""
        return SeedSources.simple_to_seed("test")
    
    def test_card_id_is_metadata_only(self, test_seed_bytes):
        """Verify that different card_ids with same card_index produce same tokens."""
        # With per-token HMAC, card_id no longer affects token generation
        # Only card_index matters for token differentiation
        grid_no_id = SeederGrid(test_seed_bytes, card_id=None, card_index="A0")
        grid_with_id = SeederGrid(test_seed_bytes, card_id="SYS.01.01", card_index="A0")
        grid_different_id = SeederGrid(test_seed_bytes, card_id="SYS.99.99", card_index="A0")
        
        # Same card_index should produce same tokens regardless of card_id
        token_no_id = grid_no_id.get_token("A0")
        token_with_id = grid_with_id.get_token("A0")
        token_different_id = grid_different_id.get_token("A0")
        
        assert token_no_id == token_with_id == token_different_id, \
            "card_id should not affect token generation (card_index does)"
    
    def test_card_id_stored_correctly(self, test_seed_bytes):
        """Verify card_id is stored as metadata on the grid."""
        card_id = "Banking-2025"
        grid = SeederGrid(test_seed_bytes, card_id=card_id, card_index="D4")
        
        assert grid.card_id == card_id
        assert grid.card_index == "D4"


class TestCardIndexVariations:
    """Test different card index variations."""
    
    @pytest.fixture
    def test_seed_bytes(self):
        """Provide consistent test seed bytes."""
        return SeedSources.simple_to_seed("test")
    
    def test_all_100_card_indices_unique(self, test_seed_bytes):
        """Test that all 100 card indices (A0-J9) produce unique tokens."""
        tokens_at_a0 = {}
        
        for row in range(10):
            for col in range(10):
                card_index = f"{chr(ord('A') + col)}{row}"
                grid = SeederGrid(test_seed_bytes, card_index=card_index)
                token = grid.get_token("A0")
                
                assert token not in tokens_at_a0.values(), \
                    f"Card index {card_index} produced duplicate token"
                tokens_at_a0[card_index] = token
        
        assert len(tokens_at_a0) == 100, "Should have 100 unique card indices"
    
    def test_card_index_integration_multiple_coordinates(self, test_seed_bytes):
        """Test card index integration across multiple coordinates."""
        grid_a0 = SeederGrid(test_seed_bytes, card_index="A0")
        grid_j9 = SeederGrid(test_seed_bytes, card_index="J9")
        
        # Check multiple coordinates to ensure the entire grid is affected
        coordinates = ["A0", "B5", "E2", "H7", "J9"]
        
        for coord in coordinates:
            token_a0 = grid_a0.get_token(coord)
            token_j9 = grid_j9.get_token(coord)
            assert token_a0 != token_j9, f"Card indices should produce different tokens at {coord}"
    
    def test_card_index_consistency_with_existing_api(self, test_seed_bytes):
        """Ensure card index parameter works with existing API."""
        # This should work without card_index (defaults to A0)
        grid_default = SeederGrid(test_seed_bytes)
        token_default = grid_default.get_token("A0")
        
        # This should work with explicit card_index
        grid_with_index = SeederGrid(test_seed_bytes, card_index="B5")
        token_with_index = grid_with_index.get_token("A0")
        
        # Both should be valid tokens (4 characters each)
        assert len(token_default) == 4, "Default grid should produce 4-char tokens"
        assert len(token_with_index) == 4, "Grid with card index should produce 4-char tokens"
        # Default is A0, so B5 should be different
        assert token_default != token_with_index, "Default (A0) and B5 index should differ"


class TestCLICardIdIntegration:
    """Test CLI integration with card IDs and indices."""
    
    def test_cli_card_id_and_index_parameters_exist(self):
        """Verify CLI accepts card_id and card_index parameters."""
        import inspect

        from seeder.cli.helpers import create_grid_from_args
        
        sig_args = inspect.signature(create_grid_from_args)
        assert 'card_id' in sig_args.parameters, "create_grid_from_args should accept card_id"
        assert 'card_index' in sig_args.parameters, "create_grid_from_args should accept card_index"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
