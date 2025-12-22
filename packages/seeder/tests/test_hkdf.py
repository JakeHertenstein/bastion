#!/usr/bin/env python3
"""
HKDF-Expand (RFC 5869) test vectors and cross-platform consistency tests.

These tests ensure:
1. Python HKDF implementation matches RFC 5869 specification
2. Test vectors can be used to verify JavaScript implementation consistency
3. Deterministic behavior across runs

Test vectors are loaded from test_vectors.json for single-source-of-truth
across Python and JavaScript implementations.
"""

import hashlib
import hmac
import json
import unittest
from pathlib import Path

from seeder.core.crypto import SeedCardCrypto

# Load test vectors from JSON
VECTORS_PATH = Path(__file__).parent / "test_vectors.json"
with open(VECTORS_PATH) as f:
    TEST_VECTORS = json.load(f)


class TestHKDFExpand(unittest.TestCase):
    """Test HKDF-Expand implementation against RFC 5869."""

    def test_hkdf_expand_basic(self):
        """Test basic HKDF-Expand functionality."""
        prk = b'\x00' * 64  # 64-byte PRK
        info = b"test-info"
        length = 64

        output = SeedCardCrypto.hkdf_expand(prk, info, length)

        self.assertEqual(len(output), length)
        self.assertIsInstance(output, bytes)

    def test_hkdf_expand_deterministic(self):
        """Test HKDF-Expand produces consistent output."""
        prk = bytes(range(64))  # Deterministic PRK
        info = b"CR80-TOKENS"
        length = 128

        output1 = SeedCardCrypto.hkdf_expand(prk, info, length)
        output2 = SeedCardCrypto.hkdf_expand(prk, info, length)

        self.assertEqual(output1, output2)

    def test_hkdf_expand_different_info_different_output(self):
        """Test different info labels produce different output."""
        prk = b'\x42' * 64
        length = 64

        output1 = SeedCardCrypto.hkdf_expand(prk, b"info-1", length)
        output2 = SeedCardCrypto.hkdf_expand(prk, b"info-2", length)

        self.assertNotEqual(output1, output2)

    def test_hkdf_expand_empty_info(self):
        """Test HKDF-Expand with empty info."""
        prk = bytes(range(64))
        output = SeedCardCrypto.hkdf_expand(prk, b"", 32)

        self.assertEqual(len(output), 32)
        # Should be deterministic even with empty info
        output2 = SeedCardCrypto.hkdf_expand(prk, b"", 32)
        self.assertEqual(output, output2)

    def test_hkdf_expand_max_length_validation(self):
        """Test HKDF-Expand rejects excessive length requests."""
        prk = b'\x00' * 64
        max_valid = 255 * 64  # SHA-512 hash_len * 255

        # Should work at max length
        output = SeedCardCrypto.hkdf_expand(prk, b"test", max_valid)
        self.assertEqual(len(output), max_valid)

        # Should fail at max + 1
        with self.assertRaises(ValueError):
            SeedCardCrypto.hkdf_expand(prk, b"test", max_valid + 1)

    def test_hkdf_expand_various_lengths(self):
        """Test HKDF-Expand with various output lengths."""
        prk = bytes(range(64))
        info = b"test"

        for length in [1, 16, 32, 64, 100, 128, 256, 512]:
            output = SeedCardCrypto.hkdf_expand(prk, info, length)
            self.assertEqual(len(output), length)


class TestHKDFTestVectors(unittest.TestCase):
    """
    Test vectors for cross-platform verification.
    
    These vectors ensure Python and JavaScript implementations produce
    identical output. Vectors are loaded from test_vectors.json.
    
    Note: Info labels use Bastion format (Bastion/TOKEN/HMAC:card.token:#VERSION=1|CHECK)
    """

    def test_all_hkdf_vectors(self):
        """Test all HKDF-Expand vectors from test_vectors.json."""
        vectors = TEST_VECTORS["hkdf_expand"]["vectors"]

        for vector in vectors:
            with self.subTest(name=vector["name"]):
                prk = bytes.fromhex(vector["prk_hex"])
                info = vector["info"].encode()
                length = vector["length"]
                expected = bytes.fromhex(vector["expected_hex"])

                output = SeedCardCrypto.hkdf_expand(prk, info, length)

                self.assertEqual(output, expected,
                    f"Vector '{vector['name']}' failed:\n"
                    f"  Expected: {expected.hex()}\n"
                    f"  Got:      {output.hex()}")

    def test_vector_1_zeros(self):
        """Test Vector 1: All-zero PRK with Bastion label."""
        vector = TEST_VECTORS["hkdf_expand"]["vectors"][0]
        prk = bytes.fromhex(vector["prk_hex"])
        info = vector["info"].encode()
        expected = bytes.fromhex(vector["expected_hex"])

        output = SeedCardCrypto.hkdf_expand(prk, info, vector["length"])
        self.assertEqual(output, expected)

    def test_vector_2_sequential(self):
        """Test Vector 2: Sequential PRK bytes."""
        vector = TEST_VECTORS["hkdf_expand"]["vectors"][1]
        prk = bytes.fromhex(vector["prk_hex"])
        info = vector["info"].encode()
        expected = bytes.fromhex(vector["expected_hex"])

        output = SeedCardCrypto.hkdf_expand(prk, info, vector["length"])
        self.assertEqual(output, expected)

    def test_vector_3_realistic(self):
        """Test Vector 3: Realistic seed-like PRK."""
        vector = TEST_VECTORS["hkdf_expand"]["vectors"][2]
        prk = bytes.fromhex(vector["prk_hex"])
        info = vector["info"].encode()
        expected = bytes.fromhex(vector["expected_hex"])

        output = SeedCardCrypto.hkdf_expand(prk, info, vector["length"])
        self.assertEqual(output, expected)

    def test_vector_4_multiblock(self):
        """Test Vector 4: Multi-block output spanning 3 SHA-512 blocks."""
        vector = TEST_VECTORS["hkdf_expand"]["vectors"][3]
        prk = bytes.fromhex(vector["prk_hex"])
        info = vector["info"].encode()
        expected = bytes.fromhex(vector["expected_hex"])

        output = SeedCardCrypto.hkdf_expand(prk, info, vector["length"])
        self.assertEqual(output, expected)


class TestHKDFStream(unittest.TestCase):
    """Test the hkdf_stream wrapper function."""

    def test_hkdf_stream_basic(self):
        """Test hkdf_stream basic functionality."""
        seed = b'\x42' * 64
        info = b"CR80-TOKENS"
        length = 256

        output = SeedCardCrypto.hkdf_stream(seed, info, length)

        self.assertEqual(len(output), length)
        self.assertIsInstance(output, bytes)

    def test_hkdf_stream_with_card_id(self):
        """Test hkdf_stream with card_id domain separation."""
        seed = b'\x42' * 64
        # Bastion format label
        info = b"Bastion/TOKEN/HMAC:A0.A0:#VERSION=1|C"
        length = 64

        # Different card_ids should produce different output
        output1 = SeedCardCrypto.hkdf_stream(seed, info, length, card_id="Banking")
        output2 = SeedCardCrypto.hkdf_stream(seed, info, length, card_id="Email")
        output3 = SeedCardCrypto.hkdf_stream(seed, info, length, card_id=None)

        self.assertNotEqual(output1, output2)
        self.assertNotEqual(output1, output3)
        self.assertNotEqual(output2, output3)

    def test_hkdf_stream_validates_seed_length(self):
        """Test hkdf_stream rejects invalid seed lengths."""
        with self.assertRaises(ValueError):
            SeedCardCrypto.hkdf_stream(b'\x00' * 32, b"test", 64)  # Too short

        with self.assertRaises(ValueError):
            SeedCardCrypto.hkdf_stream(b'\x00' * 128, b"test", 64)  # Too long

    def test_backward_compat_alias(self):
        """Test hkdf_like_stream is an alias for hkdf_stream."""
        seed = bytes(range(64))
        info = b"test-info"
        length = 100

        output1 = SeedCardCrypto.hkdf_stream(seed, info, length)
        output2 = SeedCardCrypto.hkdf_like_stream(seed, info, length)

        self.assertEqual(output1, output2)


class TestHKDFChaining(unittest.TestCase):
    """Test that HKDF-Expand properly chains blocks."""

    def test_chaining_verification(self):
        """Verify HKDF-Expand chains blocks correctly (RFC 5869)."""
        prk = bytes(range(64))
        info = b"test"

        # Get output for 128 bytes (2 full SHA-512 blocks)
        full_output = SeedCardCrypto.hkdf_expand(prk, info, 128)

        # Manually compute what the chaining should produce
        # T(1) = HMAC(PRK, "" || info || 0x01)
        t1 = hmac.new(prk, info + bytes([1]), hashlib.sha512).digest()

        # T(2) = HMAC(PRK, T(1) || info || 0x02)
        t2 = hmac.new(prk, t1 + info + bytes([2]), hashlib.sha512).digest()

        expected = t1 + t2

        self.assertEqual(full_output, expected)

    def test_chaining_differs_from_counter_mode(self):
        """Verify HKDF chaining produces different output than counter mode."""
        prk = bytes(range(64))
        info = b"test"

        # HKDF-Expand (chained)
        hkdf_output = SeedCardCrypto.hkdf_expand(prk, info, 128)

        # Old counter-mode (independent blocks)
        counter_output = b""
        for i in range(2):
            msg = info + i.to_bytes(2, "big")
            counter_output += hmac.new(prk, msg, hashlib.sha512).digest()

        # They should be different!
        self.assertNotEqual(hkdf_output, counter_output)


class TestTokenGenerationIntegration(unittest.TestCase):
    """Integration tests for token generation with HKDF."""

    def test_token_generation_deterministic(self):
        """Test token generation is deterministic with HKDF."""
        seed = hashlib.sha512(b"test-seed").digest()

        tokens1 = SeedCardCrypto.generate_token_stream(seed, 10)
        tokens2 = SeedCardCrypto.generate_token_stream(seed, 10)

        self.assertEqual(tokens1, tokens2)

    def test_different_seeds_different_tokens(self):
        """Test different seeds produce different tokens."""
        seed1 = hashlib.sha512(b"seed-one").digest()
        seed2 = hashlib.sha512(b"seed-two").digest()

        tokens1 = SeedCardCrypto.generate_token_stream(seed1, 10)
        tokens2 = SeedCardCrypto.generate_token_stream(seed2, 10)

        self.assertNotEqual(tokens1, tokens2)


if __name__ == "__main__":
    # Run with verbose output to show test vectors
    unittest.main(verbosity=2)
