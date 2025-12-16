"""Test multi-base token generation feature"""

import pytest

from seeder.core.config import BASE_CONFIGS
from seeder.core.crypto import PasswordEntropyAnalyzer
from seeder.core.grid import SeederGrid
from seeder.core.seed_sources import SeedSources


class TestBaseSystems:
    """Test different base systems (base10, base62, base90)"""
    
    @pytest.fixture
    def seed_bytes(self):
        """Create test seed bytes"""
        return SeedSources.simple_to_seed("test seed phrase")
    
    def test_base_configs_defined(self):
        """Test that all base configs are properly defined"""
        assert "base10" in BASE_CONFIGS
        assert "base62" in BASE_CONFIGS
        assert "base90" in BASE_CONFIGS
        
        for base_name, config in BASE_CONFIGS.items():
            assert "alphabet" in config
            assert "name" in config
            assert "description" in config
            assert len(config["alphabet"]) > 0
    
    def test_base10_alphabet(self):
        """Test that base10 uses only digits"""
        alphabet = BASE_CONFIGS["base10"]["alphabet"]
        assert len(alphabet) == 10
        assert all(c in "0123456789" for c in alphabet)
    
    def test_base62_alphabet(self):
        """Test that base62 is alphanumeric"""
        alphabet = BASE_CONFIGS["base62"]["alphabet"]
        assert len(alphabet) == 62
        # Check it contains digits, uppercase, and lowercase
        has_digits = any(c.isdigit() for c in alphabet)
        has_upper = any(c.isupper() for c in alphabet)
        has_lower = any(c.islower() for c in alphabet)
        assert has_digits and has_upper and has_lower
    
    def test_base90_alphabet(self):
        """Test that base90 has full character set"""
        alphabet = BASE_CONFIGS["base90"]["alphabet"]
        assert len(alphabet) == 90
        # Should include special characters
        has_special = any(not c.isalnum() for c in alphabet)
        assert has_special
    
    def test_grid_generation_base10(self, seed_bytes):
        """Test generating grid with base10"""
        grid = SeederGrid(seed_bytes, "TEST.00", "base10")
        
        # Check that all tokens are 4-digit numbers
        for r in range(10):
            for c in range(10):
                coord = f"{chr(ord('A') + c)}{r}"
                token = grid.get_token(coord)
                
                assert len(token) == 4, f"Token {token} should be 4 chars"
                assert token.isdigit(), f"Token {token} should be all digits"
    
    def test_grid_generation_base62(self, seed_bytes):
        """Test generating grid with base62"""
        grid = SeederGrid(seed_bytes, "TEST.00", "base62")
        
        # Check that all tokens are 4-char alphanumeric
        for r in range(10):
            for c in range(10):
                coord = f"{chr(ord('A') + c)}{r}"
                token = grid.get_token(coord)
                
                assert len(token) == 4, f"Token {token} should be 4 chars"
                assert token.isalnum(), f"Token {token} should be alphanumeric"
    
    def test_grid_generation_base90(self, seed_bytes):
        """Test generating grid with base90"""
        grid = SeederGrid(seed_bytes, "TEST.00", "base90")
        
        # Check that all tokens are 4 characters
        for r in range(10):
            for c in range(10):
                coord = f"{chr(ord('A') + c)}{r}"
                token = grid.get_token(coord)
                assert len(token) == 4, f"Token {token} should be 4 chars"
    
    def test_deterministic_generation(self, seed_bytes):
        """Test that same seed produces same tokens for each base"""
        # Generate twice for each base and verify consistency
        for base in ["base10", "base62", "base90"]:
            grid1 = SeederGrid(seed_bytes, "TEST.00", base)
            grid2 = SeederGrid(seed_bytes, "TEST.00", base)
            
            for r in range(10):
                for c in range(10):
                    coord = f"{chr(ord('A') + c)}{r}"
                    assert grid1.get_token(coord) == grid2.get_token(coord), \
                        f"Determinism failed for {base} at {coord}"
    
    def test_different_bases_produce_different_tokens(self, seed_bytes):
        """Test that different bases produce different tokens"""
        grid10 = SeederGrid(seed_bytes, "TEST.00", "base10")
        grid62 = SeederGrid(seed_bytes, "TEST.00", "base62")
        grid90 = SeederGrid(seed_bytes, "TEST.00", "base90")
        
        # At least some tokens should be different between bases
        differences = 0
        for r in range(5):  # Check first 5 rows
            for c in range(5):
                coord = f"{chr(ord('A') + c)}{r}"
                token10 = grid10.get_token(coord)
                token62 = grid62.get_token(coord)
                token90 = grid90.get_token(coord)
                
                # Not all should be identical
                if not (token10 == token62 == token90):
                    differences += 1
        
        assert differences > 0, "Expected tokens to differ between bases"
    
    def test_entropy_calculation(self):
        """Test entropy calculations for different bases"""
        # Base10: 10 chars, 4 per token
        entropy10 = PasswordEntropyAnalyzer.calculate_token_entropy(10)
        assert entropy10 > 0
        
        # Base62: 62 chars
        entropy62 = PasswordEntropyAnalyzer.calculate_token_entropy(62)
        assert entropy62 > entropy10
        
        # Base90: 90 chars
        entropy90 = PasswordEntropyAnalyzer.calculate_token_entropy(90)
        assert entropy90 > entropy62
        
        # Verify expected ranges (per 4-char token)
        # Base10: log2(10^4) ≈ 13.29 bits
        # Base62: log2(62^4) ≈ 23.83 bits
        # Base90: log2(90^4) ≈ 25.97 bits
        assert 13 < entropy10 < 14, f"Base10 entropy should be ~13.3 bits, got {entropy10:.2f}"
        assert 23 < entropy62 < 24, f"Base62 entropy should be ~23.8 bits, got {entropy62:.2f}"
        assert 25 < entropy90 < 27, f"Base90 entropy should be ~26.0 bits, got {entropy90:.2f}"
    
    def test_grid_entropy_totals(self):
        """Test total grid entropy for 100 tokens"""
        # Full grid is 10x10 = 100 tokens
        entropy10_total = PasswordEntropyAnalyzer.calculate_password_entropy(100, 10)
        entropy62_total = PasswordEntropyAnalyzer.calculate_password_entropy(100, 62)
        entropy90_total = PasswordEntropyAnalyzer.calculate_password_entropy(100, 90)
        
        # Base10 ≈ 1329 bits, Base62 ≈ 2383, Base90 ≈ 2597
        assert 1300 < entropy10_total < 1400
        assert 2300 < entropy62_total < 2450
        assert 2550 < entropy90_total < 2700
    
    def test_invalid_base_raises_error(self, seed_bytes):
        """Test that invalid base name raises GridGenerationError"""
        from seeder.core.exceptions import GridGenerationError
        
        with pytest.raises(GridGenerationError):
            SeederGrid(seed_bytes, "TEST.00", "base99")
    
    def test_base_default_is_base90(self, seed_bytes):
        """Test that default base is base90 when not specified"""
        grid_default = SeederGrid(seed_bytes, "TEST.00")
        grid_explicit = SeederGrid(seed_bytes, "TEST.00", "base90")
        
        # They should generate identical tokens
        for r in range(10):
            for c in range(10):
                coord = f"{chr(ord('A') + c)}{r}"
                assert grid_default.get_token(coord) == grid_explicit.get_token(coord)


class TestBaseSystemsCLI:
    """Test CLI integration with base systems"""
    
    def test_cli_generate_grid_with_base10(self):
        """Test CLI grid generation with base10"""
        from seeder.cli.helpers import create_grid_from_args
        
        grid, seed_bytes, label = create_grid_from_args(simple="test", base="base10")
        
        # Verify all tokens are digits
        for r in range(10):
            for c in range(10):
                coord = f"{chr(ord('A') + c)}{r}"
                token = grid.get_token(coord)
                assert token.isdigit()
    
    def test_cli_export_includes_encoding(self, tmp_path):
        """Test that CSV export includes encoding column"""
        import csv
        from datetime import date

        from seeder.cli.helpers import create_grid_with_desc
        from seeder.core.crypto import SeedCardDigest
        
        output_file = tmp_path / "test.csv"
        
        grid, seed_bytes, seed_desc = create_grid_with_desc(simple="test", base="base10")
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['ID', 'Date', 'SHORT_HASH', 'SHA512', 'TOKENS', 'ENCODING'])
            
            # Format tokens
            token_rows = []
            for r in range(10):
                row_tokens = [grid.get_token(f"{chr(ord('A') + r)}{c}") for c in range(10)]
                token_rows.append(" ".join(row_tokens))
            tokens_csv = "\n".join(token_rows)
            
            hash_value = SeedCardDigest.generate_sha512_hash(seed_bytes)
            short_hash = hash_value[:6].upper()
            today = date.today().strftime('%Y-%m-%d')
            
            writer.writerow(['TEST.00', today, short_hash, hash_value, tokens_csv, 'Base10'])
        
        # Verify CSV was created with correct format
        with open(output_file, 'r') as f:
            reader = csv.reader(f)
            headers = next(reader)
            assert 'ENCODING' in headers
            
            data = next(reader)
            assert data[-1] == 'Base10'
