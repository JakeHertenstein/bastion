"""Test Argon2id KDF implementation"""

import pytest

from seeder.core.config import (
    ARGON2_HASH_LENGTH,
    ARGON2_MEMORY_COST_KB,
    ARGON2_MEMORY_COST_MB,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    LABEL_VERSION,
    NONCE_BYTES,
    decode_argon2_params,
    encode_argon2_params,
    get_auto_parallelism,
)
from seeder.core.crypto import (
    build_hmac_label,
    build_label,
    generate_nonce,
    parse_hmac_label,
    parse_label,
)
from seeder.core.seed_sources import SeedSources


class TestArgon2Derivation:
    """Test Argon2id seed derivation"""
    
    def test_argon2_to_seed_basic(self):
        """Test basic Argon2 seed derivation"""
        seed_phrase = "test phrase for argon2"
        salt = b"test-salt-12345678"
        
        seed = SeedSources.argon2_to_seed(seed_phrase, salt)
        
        assert len(seed) == 64, "Seed should be 64 bytes"
        assert isinstance(seed, bytes)
    
    def test_argon2_to_seed_deterministic(self):
        """Test that same inputs produce same seed"""
        seed_phrase = "deterministic test"
        salt = b"consistent-salt"
        
        seed1 = SeedSources.argon2_to_seed(seed_phrase, salt)
        seed2 = SeedSources.argon2_to_seed(seed_phrase, salt)
        
        assert seed1 == seed2, "Same inputs should produce identical seeds"
    
    def test_argon2_different_salts_produce_different_seeds(self):
        """Test that different salts produce different seeds"""
        seed_phrase = "same phrase"
        salt1 = b"salt-one"
        salt2 = b"salt-two"
        
        seed1 = SeedSources.argon2_to_seed(seed_phrase, salt1)
        seed2 = SeedSources.argon2_to_seed(seed_phrase, salt2)
        
        assert seed1 != seed2, "Different salts should produce different seeds"
    
    def test_argon2_different_phrases_produce_different_seeds(self):
        """Test that different phrases produce different seeds"""
        salt = b"same-salt"
        
        seed1 = SeedSources.argon2_to_seed("phrase one", salt)
        seed2 = SeedSources.argon2_to_seed("phrase two", salt)
        
        assert seed1 != seed2, "Different phrases should produce different seeds"
    
    def test_argon2_custom_parameters(self):
        """Test Argon2 with custom parameters"""
        seed_phrase = "custom params test"
        salt = b"test-salt"
        
        # Use lower memory for faster test
        seed = SeedSources.argon2_to_seed(
            seed_phrase,
            salt,
            time_cost=2,
            memory_cost_kb=65536,  # 64MB
            parallelism=2,
            hash_length=64
        )
        
        assert len(seed) == 64
    
    def test_argon2_different_memory_produces_different_seeds(self):
        """Test that different memory costs produce different seeds"""
        seed_phrase = "memory test"
        salt = b"memory-salt"
        
        seed_64mb = SeedSources.argon2_to_seed(
            seed_phrase, salt, memory_cost_kb=65536
        )
        seed_128mb = SeedSources.argon2_to_seed(
            seed_phrase, salt, memory_cost_kb=131072
        )
        
        assert seed_64mb != seed_128mb, "Different memory costs should produce different seeds"


class TestArgon2ParamsEncoding:
    """Test Argon2 parameter encoding/decoding"""
    
    def test_encode_default_params(self):
        """Test encoding default Argon2 parameters"""
        encoded = encode_argon2_params()
        
        # Bastion URL-style format: TIME=3&MEMORY=2048&PARALLELISM=4
        expected = f"TIME={ARGON2_TIME_COST}&MEMORY={ARGON2_MEMORY_COST_MB}&PARALLELISM={ARGON2_PARALLELISM}"
        assert encoded == expected
    
    def test_encode_custom_params(self):
        """Test encoding custom Argon2 parameters"""
        encoded = encode_argon2_params(time_cost=5, memory_mb=512, parallelism=2)
        assert encoded == "TIME=5&MEMORY=512&PARALLELISM=2"
    
    def test_decode_params(self):
        """Test decoding Argon2 parameters"""
        time_cost, memory_mb, parallelism = decode_argon2_params("TIME=3&MEMORY=1024&PARALLELISM=4")
        
        assert time_cost == 3
        assert memory_mb == 1024
        assert parallelism == 4
    
    def test_encode_decode_roundtrip(self):
        """Test that encode/decode roundtrips correctly"""
        original_time = 5
        original_memory = 256
        original_parallelism = 8
        
        encoded = encode_argon2_params(original_time, original_memory, original_parallelism)
        decoded = decode_argon2_params(encoded)
        
        assert decoded == (original_time, original_memory, original_parallelism)
    
    def test_decode_invalid_format_raises(self):
        """Test that invalid format raises ValueError"""
        with pytest.raises(ValueError):
            decode_argon2_params("invalid-format")
        
        with pytest.raises(ValueError):
            decode_argon2_params("TIME=3&MEMORY=1024")  # Missing parallelism


class TestNonceGeneration:
    """Test nonce generation"""
    
    def test_nonce_length(self):
        """Test that nonce has expected length"""
        nonce = generate_nonce()
        # 6 bytes = 48 bits, Base64 = 8 chars (without padding)
        assert len(nonce) == 8, f"Nonce should be 8 chars, got {len(nonce)}"
    
    def test_nonce_url_safe(self):
        """Test that nonce uses URL-safe characters"""
        # Generate multiple nonces to check character set
        for _ in range(100):
            nonce = generate_nonce()
            # URL-safe Base64 uses A-Za-z0-9-_
            for char in nonce:
                assert char.isalnum() or char in '-_', f"Invalid char in nonce: {char}"
    
    def test_nonce_uniqueness(self):
        """Test that nonces are unique"""
        nonces = set()
        for _ in range(1000):
            nonce = generate_nonce()
            assert nonce not in nonces, "Nonce collision detected"
            nonces.add(nonce)
    
    def test_nonce_custom_length(self):
        """Test nonce with custom byte length"""
        nonce_4 = generate_nonce(num_bytes=4)
        nonce_8 = generate_nonce(num_bytes=8)
        
        # Base64: 4 bytes = 6 chars (rounded), 8 bytes = 11 chars
        assert len(nonce_4) <= 6
        assert len(nonce_8) <= 11


class TestLabelBuilding:
    """Test label building and parsing (Bastion format)"""
    
    def test_build_label_minimal(self):
        """Test building label with minimal parameters"""
        label = build_label(
            seed_type="SIMPLE",
            nonce="Kx7mQ9bL"
        )
        
        # Bastion format: Bastion/TOKEN/ALGO:IDENT:DATE#PARAMS|CHECK
        assert label.startswith("Bastion/TOKEN/")
        assert "SIMPLE-ARGON2ID" in label
        assert "NONCE=Kx7mQ9bL" in label
        assert "|" in label  # Has Luhn check digit
    
    def test_build_label_full(self):
        """Test building label with all parameters (Bastion format)"""
        label = build_label(
            seed_type="BIP39",
            kdf="ARGON2ID",
            kdf_params="TIME=3&MEMORY=1024&PARALLELISM=4",
            base="BASE62",
            date="2025-11-29",
            nonce="ABCD1234",
            card_id="test.01",
            card_index="B5"
        )
        
        # Bastion format: Bastion/TOKEN/BIP39-ARGON2ID:test.01.B5:2025-11-29#VERSION=1&TIME=3&MEMORY=1024&PARALLELISM=4&NONCE=ABCD1234&ENCODING=62|X
        assert label.startswith("Bastion/TOKEN/BIP39-ARGON2ID:")
        assert "TIME=3" in label
        assert "MEMORY=1024" in label
        assert "PARALLELISM=4" in label
        assert "NONCE=ABCD1234" in label
        assert "ENCODING=62" in label
        assert "test.01.B5" in label.lower() or "test.01.b5" in label.lower()
        assert "2025-11-29" in label
        assert "|" in label  # Luhn check digit
    
    def test_build_label_auto_nonce(self):
        """Test that label auto-generates nonce if not provided"""
        label1 = build_label(seed_type="SIMPLE")
        label2 = build_label(seed_type="SIMPLE")
        
        # Extract nonces from Bastion format: NONCE={nonce} in PARAMS
        import re
        nonce1 = re.search(r'NONCE=([^&|]+)', label1)
        nonce2 = re.search(r'NONCE=([^&|]+)', label2)
        
        assert nonce1 and nonce2, "Nonces should be present in labels"
        assert nonce1.group(1) != nonce2.group(1), "Auto-generated nonces should be unique"
        
        # card_index should default to A0 in IDENT
        assert ".a0:" in label1.lower()
    
    def test_parse_label_basic(self):
        """Test parsing a Bastion format label"""
        # Build a valid Bastion label using build_label
        label = build_label(
            seed_type="SIMPLE",
            kdf="ARGON2ID",
            kdf_params="TIME=3&MEMORY=1024&PARALLELISM=4",
            base="BASE90",
            date="2025-11-29",
            nonce="Kx7mQ9bL",
            card_id="card",
            card_index="A0"
        )
        
        parsed = parse_label(label)
        
        assert parsed["version"] == "1"
        assert parsed["seed_type"] == "SIMPLE"
        assert parsed["kdf"] == "ARGON2ID"
        assert "TIME=3" in parsed["kdf_params"]
        assert parsed["base"] == "BASE90"
        assert parsed["date"] == "2025-11-29"
        assert parsed["nonce"] == "Kx7mQ9bL"
        assert parsed["card_id"] == "CARD"
        assert parsed["card_index"] == "A0"
    
    def test_parse_label_extracts_argon2_params(self):
        """Test that parsing extracts Argon2 parameters"""
        label = build_label(
            seed_type="SIMPLE",
            kdf="ARGON2ID",
            kdf_params="TIME=5&MEMORY=512&PARALLELISM=2",
            nonce="nonce123"
        )
        
        parsed = parse_label(label)
        
        assert parsed["argon2_time"] == 5
        assert parsed["argon2_memory_mb"] == 512
        assert parsed["argon2_parallelism"] == 2
    
    def test_parse_label_invalid_version_raises(self):
        """Test that invalid prefix raises ValueError"""
        # Wrong prefix - should raise
        with pytest.raises(ValueError):
            parse_label("v2:TOKEN:SIMPLE-ARGON2ID:something|X")
    
    def test_parse_label_too_few_parts_raises(self):
        """Test that too few parts raises ValueError"""
        # Missing required fields
        with pytest.raises(ValueError):
            parse_label("Bastion/TOKEN/SIMPLE|X")
    
    def test_build_parse_roundtrip(self):
        """Test that build/parse roundtrips correctly"""
        original = build_label(
            seed_type="SLIP39",
            kdf="ARGON2ID",
            kdf_params="TIME=3&MEMORY=2048&PARALLELISM=4",
            base="BASE62",
            date="2025-12-01",
            nonce="TestNonc",
            card_id="prod.01.02",
            card_index="C7"
        )
        
        parsed = parse_label(original)
        
        assert parsed["seed_type"] == "SLIP39"
        assert parsed["kdf"] == "ARGON2ID"
        assert "TIME=3" in parsed["kdf_params"]
        assert parsed["base"] == "BASE62"
        assert parsed["date"] == "2025-12-01"
        assert parsed["nonce"] == "TestNonc"
        assert parsed["card_id"].lower() == "prod.01.02"
        assert parsed["card_index"] == "C7"


class TestHmacLabelBuilding:
    """Test per-token HMAC label building and parsing (Bastion format)"""
    
    def test_build_hmac_label_basic(self):
        """Test building basic HMAC label"""
        label = build_hmac_label("A0", "B3")
        # Bastion format: Bastion/TOKEN/HMAC:A0.B3:#VERSION=1|CHECK
        assert label.startswith("Bastion/TOKEN/HMAC:")
        assert "A0.B3" in label
        assert "|" in label  # Luhn check digit
    
    def test_build_hmac_label_different_indices(self):
        """Test HMAC labels with various card indices"""
        for card_idx in ["A0", "J9", "E5", "C2"]:
            for token_coord in ["A0", "J9", "D4", "F7"]:
                label = build_hmac_label(card_idx, token_coord)
                # Bastion format: Bastion/TOKEN/HMAC:{card_idx}.{token_coord}:#VERSION=1|CHECK
                assert label.startswith("Bastion/TOKEN/HMAC:")
                assert f"{card_idx}.{token_coord}" in label
    
    def test_build_hmac_label_default_card_index(self):
        """Test HMAC label with None card_index defaults to A0"""
        label = build_hmac_label(None, "C5")
        assert "A0.C5" in label
    
    def test_parse_hmac_label_basic(self):
        """Test parsing basic HMAC label (Bastion format)"""
        label = build_hmac_label("A0", "B3")
        parsed = parse_hmac_label(label)
        
        assert parsed["version"] == "1"
        assert parsed["card_index"] == "A0"
        assert parsed["token_coord"] == "B3"
    
    def test_parse_hmac_label_roundtrip(self):
        """Test HMAC label build/parse roundtrip"""
        for card_idx in ["A0", "J9", "E5"]:
            for token_coord in ["A0", "J9", "D4"]:
                label = build_hmac_label(card_idx, token_coord)
                parsed = parse_hmac_label(label)
                
                assert parsed["card_index"] == card_idx
                assert parsed["token_coord"] == token_coord
    
    def test_parse_hmac_label_invalid_format_raises(self):
        """Test that invalid HMAC label format raises ValueError"""
        with pytest.raises(ValueError):
            parse_hmac_label("invalid:format|X")
        
        # Wrong prefix - should raise
        with pytest.raises(ValueError):
            parse_hmac_label("v1:TOKEN:HMAC:A0.B3|X")
    
    def test_hmac_labels_unique_per_position(self):
        """Test that each token position gets a unique HMAC label"""
        labels = set()
        for row in range(10):
            for col in range(10):
                token_coord = f"{chr(ord('A') + col)}{row}"
                label = build_hmac_label("A0", token_coord)
                # Strip check digit for uniqueness comparison
                body = label.rsplit("|", 1)[0]
                assert body not in labels, f"Duplicate label body: {body}"
                labels.add(body)
        
        # Should have 100 unique label bodies
        assert len(labels) == 100


class TestCLIArgon2Integration:
    """Test CLI integration with Argon2 parameters"""
    
    def test_create_grid_from_args_with_argon2(self):
        """Test create_grid_from_args uses Argon2 by default for simple"""
        from seeder.cli.helpers import create_grid_from_args
        
        grid, seed_bytes, label = create_grid_from_args(
            simple="test phrase",
            nonce="TESTNONC"
        )
        
        assert "ARGON2" in label
        assert "TESTNONC" in label
        assert len(seed_bytes) == 64
        # Bastion format: Bastion/TOKEN/ALGO:IDENT:DATE#PARAMS|CHECK
        # IDENT contains card_index
        assert ".a0:" in label.lower()  # Default card_index
    
    def test_create_grid_from_args_with_card_index(self):
        """Test create_grid_from_args with custom card_index"""
        from seeder.cli.helpers import create_grid_from_args
        
        grid, seed_bytes, label = create_grid_from_args(
            simple="test phrase",
            nonce="TESTNONC",
            card_index="B5"
        )
        
        # Bastion format: IDENT is {card_id}.{card_index}
        assert ".B5:" in label or ".B5|" in label
        assert grid.card_index == "B5"
    
    def test_create_grid_from_args_with_time_cost(self):
        """Test create_grid_from_args with custom time_cost"""
        from seeder.cli.helpers import create_grid_from_args
        
        grid, seed_bytes, label = create_grid_from_args(
            simple="test phrase",
            nonce="TESTNONC",
            time_cost=5
        )
        
        # Label should contain TIME=5 (URL-style format)
        assert "TIME=5" in label
    
    def test_create_grid_from_args_with_parallelism(self):
        """Test create_grid_from_args with custom parallelism"""
        from seeder.cli.helpers import create_grid_from_args
        
        grid, seed_bytes, label = create_grid_from_args(
            simple="test phrase",
            nonce="TESTNONC",
            parallelism=8
        )
        
        # Label should contain PARALLELISM=8 (URL-style format)
        assert "PARALLELISM=8" in label
    
    def test_create_grid_from_args_legacy_mode(self):
        """Test create_grid_from_args with legacy SHA-512 mode"""
        from seeder.cli.helpers import create_grid_from_args
        
        grid, seed_bytes, label = create_grid_from_args(
            simple="test phrase",
            use_argon2=False
        )
        
        # Legacy mode should use different label format
        assert "legacy" in label.lower() or "SHA512" in label
        assert len(seed_bytes) == 64
    
    def test_create_grid_from_args_custom_memory(self):
        """Test create_grid_from_args with custom memory setting"""
        from seeder.cli.helpers import create_grid_from_args
        
        grid, seed_bytes, label = create_grid_from_args(
            simple="test phrase",
            memory_mb=128,  # 128MB instead of default
            nonce="TESTNONC"
        )
        
        # Label should contain the memory parameter
        assert "m128" in label or "128" in label
    
    def test_create_grid_from_args_with_base(self):
        """Test create_grid_from_args with different base systems"""
        from seeder.cli.helpers import create_grid_from_args
        
        for base in ["base10", "base62", "base90"]:
            grid, seed_bytes, label = create_grid_from_args(
                simple="test phrase",
                base=base,
                nonce="TESTNONC"
            )
            
            # URL-style format uses ENCODING=<number>
            base_num = base.replace("base", "")
            assert f"ENCODING={base_num}" in label


class TestArgon2Config:
    """Test Argon2 configuration constants"""
    
    def test_default_constants(self):
        """Test that default constants are reasonable"""
        assert ARGON2_TIME_COST >= 1
        assert ARGON2_MEMORY_COST_MB >= 64
        assert ARGON2_MEMORY_COST_KB == ARGON2_MEMORY_COST_MB * 1024
        assert ARGON2_PARALLELISM >= 1
        assert ARGON2_HASH_LENGTH == 64  # Standard seed size
    
    def test_nonce_bytes_constant(self):
        """Test nonce configuration"""
        assert NONCE_BYTES == 6  # 48 bits
    
    def test_label_version_constant(self):
        """Test label version"""
        assert LABEL_VERSION == "v1"
    
    def test_auto_parallelism(self):
        """Test auto-parallelism detection"""
        import os
        
        parallelism = get_auto_parallelism()
        
        # Should return a value between 1 and 16
        assert 1 <= parallelism <= 16
        
        # If cpu_count is available, should match cores (capped at 16)
        cores = os.cpu_count()
        if cores is not None:
            expected = min(cores, 16)
            assert parallelism == expected
        assert 1 <= parallelism <= 16
        
        # If cpu_count is available, should match cores (capped at 16)
        cores = os.cpu_count()
        if cores is not None:
            expected = min(cores, 16)
            assert parallelism == expected
