#!/usr/bin/env python3
"""
Test card index flexibility - verifies support for various card index formats.

NOTE: With the v1 per-token HMAC label format, card_index (A0-J9) determines
token differentiation, not card_id. card_id is now metadata only.
"""

import sys
from pathlib import Path

import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from seeder.core.grid import SeederGrid
from seeder.core.seed_sources import SeedSources


class TestCardIndexFlexibility:
    """Test suite for card index flexibility."""
    
    @pytest.fixture
    def test_seed_bytes(self):
        """Provide consistent test seed bytes."""
        return SeedSources.simple_to_seed("test")
    
    def test_all_valid_card_indices(self, test_seed_bytes):
        """Test all 100 valid card index formats (A0-J9)."""
        results = {}
        
        for row in range(10):
            for col in range(10):
                card_index = f"{chr(ord('A') + col)}{row}"
                grid = SeederGrid(test_seed_bytes, card_index=card_index)
                token = grid.get_token("A0")
                results[card_index] = token
                
                # Verify deterministic behavior
                grid2 = SeederGrid(test_seed_bytes, card_index=card_index)
                token2 = grid2.get_token("A0")
                assert token == token2, f"Non-deterministic behavior for card index: {card_index}"
        
        # All 100 card indices should produce unique tokens
        unique_tokens = set(results.values())
        assert len(unique_tokens) == 100, f"Expected 100 unique tokens, got {len(unique_tokens)}"
    
    def test_card_index_edge_cases(self, test_seed_bytes):
        """Test edge cases for card indices."""
        edge_cases = [
            ("A0", "First card (top-left)"),
            ("J0", "Last column first row"),
            ("A9", "First column last row"),
            ("J9", "Last card (bottom-right)"),
            ("E5", "Center of grid"),
        ]
        
        results = {}
        for card_index, description in edge_cases:
            grid = SeederGrid(test_seed_bytes, card_index=card_index)
            token = grid.get_token("A0")
            results[card_index] = token
            
            # Verify it's a valid 4-character token
            assert len(token) == 4, f"Invalid token length for {card_index}: {token}"
        
        # All edge cases should produce unique tokens
        tokens = list(results.values())
        assert len(set(tokens)) == len(tokens), "Edge case card indices should produce unique tokens"
    
    def test_card_index_default(self, test_seed_bytes):
        """Test default card index behavior."""
        # No card_index specified should default to A0
        grid_default = SeederGrid(test_seed_bytes)
        grid_explicit_a0 = SeederGrid(test_seed_bytes, card_index="A0")
        
        token_default = grid_default.get_token("A0")
        token_explicit = grid_explicit_a0.get_token("A0")
        
        assert token_default == token_explicit, "Default card_index should be A0"
    
    def test_card_id_metadata_preserved(self, test_seed_bytes):
        """Test that card_id is preserved as metadata but doesn't affect tokens."""
        test_cases = [
            ("SYS.01.01", "Traditional system format"),
            ("example", "Username/name format"),
            ("alice@example.com", "Email address format"),
            ("user-profile-2024", "Hyphenated identifier"),
            ("COMPANY_DEPT_001", "Corporate format with underscores"),
            ("unicode-café-🎲-test", "Unicode characters"),
            ("", "Empty string"),
            ("a", "Single character"),
        ]
        
        # All card_ids with same card_index should produce same tokens
        reference_grid = SeederGrid(test_seed_bytes, card_id=None, card_index="A0")
        reference_token = reference_grid.get_token("A0")
        
        for card_id, description in test_cases:
            grid = SeederGrid(test_seed_bytes, card_id=card_id, card_index="A0")
            token = grid.get_token("A0")
            
            # Token should match reference (card_id is metadata only)
            assert token == reference_token, \
                f"card_id '{card_id}' should not affect tokens"
            
            # card_id should be stored as metadata
            assert grid.card_id == card_id, \
                f"card_id should be stored: expected '{card_id}', got '{grid.card_id}'"
    
    def test_invalid_card_index_format(self, test_seed_bytes):
        """Test that invalid card index formats are handled gracefully."""
        # These should either work or raise a clear error
        invalid_cases = [
            "Z0",      # Invalid column (beyond J)
            "A10",     # Invalid row (beyond 9)
            "AA",      # Invalid row (not numeric)
            "1A",      # Reversed format
            "",        # Empty string
            "A",       # Missing row
            "0",       # Missing column
        ]
        
        # For now, we allow these but they shouldn't crash
        # Future versions might validate strictly
        for invalid_index in invalid_cases:
            try:
                grid = SeederGrid(test_seed_bytes, card_index=invalid_index)
                # If it doesn't raise, at least verify it produces a token
                token = grid.get_token("A0")
                assert len(token) == 4, f"Token should still be 4 chars for {invalid_index}"
            except (ValueError, KeyError) as e:
                # This is acceptable behavior for invalid indices
                pass
    
    def test_card_index_determinism_across_instances(self, test_seed_bytes):
        """Test that same card_index produces identical results across instances."""
        # Test a sampling of card indices
        sample_indices = ["A0", "B3", "E5", "H7", "J9"]
        
        for card_index in sample_indices:
            # Create multiple instances
            grids = [SeederGrid(test_seed_bytes, card_index=card_index) for _ in range(3)]
            
            # All should produce identical full grids
            first_grid_tokens = [grids[0].get_token(f"{chr(ord('A') + c)}{r}") 
                                for r in range(10) for c in range(10)]
            
            for grid in grids[1:]:
                grid_tokens = [grid.get_token(f"{chr(ord('A') + c)}{r}") 
                              for r in range(10) for c in range(10)]
                assert grid_tokens == first_grid_tokens, \
                    f"Non-deterministic grid for card_index {card_index}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
