#!/usr/bin/env python3
"""Generate HKDF test vectors with Bastion format labels."""

import hashlib
import hmac
import json

def hkdf_expand(prk, info, length):
    """HKDF-Expand per RFC 5869 with SHA-512."""
    hash_len = 64
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t_prev = b""
    for i in range(1, n + 1):
        t_prev = hmac.new(prk, t_prev + info + bytes([i]), hashlib.sha512).digest()
        okm += t_prev
    return okm[:length]

def luhn_mod36_check(s):
    """Calculate Luhn mod-36 check digit."""
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    n = 36
    factor = 2
    total = 0
    for c in reversed(s.upper()):
        if c in chars:
            code = chars.index(c)
            addend = factor * code
            if addend >= n:
                addend = (addend // n) + (addend % n)
            total += addend
            factor = 3 - factor
    remainder = total % n
    return chars[(n - remainder) % n]

def build_label(card, token):
    """Build Bastion/TOKEN/HMAC label with check digit."""
    body = f"Bastion/TOKEN/HMAC:{card}.{token}:#VERSION=1"
    return f"{body}|{luhn_mod36_check(body)}"

# Generate vectors
vectors = []

# Vector 1: All-zero PRK
prk1 = b"\x00" * 64
info1 = build_label("A0", "A0")
out1 = hkdf_expand(prk1, info1.encode(), 32)
vectors.append({
    "name": "Vector 1: Zeros PRK with Bastion label",
    "prk_hex": prk1.hex(),
    "info": info1,
    "length": 32,
    "expected_hex": out1.hex()
})

# Vector 2: Sequential PRK
prk2 = bytes(range(64))
info2 = build_label("B5", "J9")
out2 = hkdf_expand(prk2, info2.encode(), 64)
vectors.append({
    "name": "Vector 2: Sequential PRK with Bastion label",
    "prk_hex": prk2.hex(),
    "info": info2,
    "length": 64,
    "expected_hex": out2.hex()
})

# Vector 3: Realistic SHA-512 derived PRK
prk3 = hashlib.sha512(b"test-seed-for-vectors").digest()
info3 = build_label("C3", "D4")
out3 = hkdf_expand(prk3, info3.encode(), 128)
vectors.append({
    "name": "Vector 3: Realistic PRK (SHA-512 of test seed)",
    "prk_hex": prk3.hex(),
    "info": info3,
    "length": 128,
    "expected_hex": out3.hex()
})

# Vector 4: Multi-block with 0xAA PRK (generic info)
prk4 = b"\xAA" * 64
info4 = "CR80-EXPANSION-TEST"
out4 = hkdf_expand(prk4, info4.encode(), 192)
vectors.append({
    "name": "Vector 4: Multi-block output (3 SHA-512 blocks)",
    "prk_hex": prk4.hex(),
    "info": info4,
    "length": 192,
    "expected_hex": out4.hex()
})

# Print as JSON
print(json.dumps({"hkdf_expand_vectors": vectors}, indent=2))
