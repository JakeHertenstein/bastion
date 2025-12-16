#!/usr/bin/env python3
"""Generate HKDF test vectors for JavaScript verification.

Uses Bastion label format for HMAC info labels:
- v1:TOKEN:HMAC:{card}.{token}|CHECK
"""

import hashlib
import sys

sys.path.insert(0, 'src')

from seeder.core.crypto import SeedCardCrypto, luhn_mod36_check

# Helper to build test HMAC labels
def test_hmac_label(card_idx: str, token_coord: str) -> str:
    """Build HMAC label with Luhn check for test vectors."""
    body = f"v1:TOKEN:HMAC:{card_idx}.{token_coord}"
    check = luhn_mod36_check(body)
    return f"{body}|{check}"

print('=== HKDF-Expand Test Vectors for JavaScript Verification ===')
print('=== Using Bastion Label Format ===')
print()

# Test Vector 1: All-zero PRK
prk1 = b'\x00' * 64
info1 = test_hmac_label("A0", "A0").encode()
output1 = SeedCardCrypto.hkdf_expand(prk1, info1, 32)
print('Test Vector 1 (zeros PRK):')
print(f'  PRK (hex): {prk1.hex()}')
print(f'  Info: {info1.decode()}')
print(f'  Length: 32')
print(f'  Output (hex): {output1.hex()}')
print()

# Test Vector 2: Sequential PRK
prk2 = bytes(range(64))
info2 = test_hmac_label("A0", "B5").encode()
output2 = SeedCardCrypto.hkdf_expand(prk2, info2, 64)
print('Test Vector 2 (sequential PRK):')
print(f'  PRK (hex): {prk2.hex()}')
print(f'  Info: {info2.decode()}')
print(f'  Length: 64')
print(f'  Output (hex): {output2.hex()}')
print()

# Test Vector 3: Realistic seed
prk3 = hashlib.sha512(b'test-seed-for-vectors').digest()
info3 = test_hmac_label("B2", "J9").encode()
output3 = SeedCardCrypto.hkdf_expand(prk3, info3, 128)
print('Test Vector 3 (realistic PRK):')
print(f'  PRK (hex): {prk3.hex()}')
print(f'  Info: {info3.decode()}')
print(f'  Length: 128')
print(f'  Output (hex): {output3.hex()}')
print()

# Test Vector 4: Multi-block
prk4 = b'\xAA' * 64
info4 = b'CR80-EXPANSION-TEST'
output4 = SeedCardCrypto.hkdf_expand(prk4, info4, 192)
print('Test Vector 4 (multi-block):')
print(f'  PRK (hex): {prk4.hex()}')
print(f'  Info: {info4.decode()}')
print(f'  Length: 192')
print(f'  Output (hex): {output4.hex()}')
