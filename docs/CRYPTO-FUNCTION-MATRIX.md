# Bastion Cryptographic Function Matrix

**Version**: 0.3.0  
**Updated**: 2025-01-14

This document provides a comprehensive matrix of all cryptographic functions used in Bastion, their purposes, and their security properties.

---

## Overview

Bastion uses a simplified cryptographic design with clear function boundaries:

| Category | Algorithm | Purpose |
|----------|-----------|---------|
| **Entropy Stretching** | SHAKE256 | XOF for extending entropy pools |
| **Key Derivation** | HKDF-SHA512 | Deriving keys from master entropy |
| **Content Hashing** | SHA-512 | Hashing for usernames, labels, integrity |
| **Authenticated Hashing** | HMAC-SHA512 | YubiKey challenge-response |
| **Encryption** | Fernet (AES-128-CBC + HMAC-SHA256) | Local cache encryption |

---

## Detailed Function Matrix

### 1. Entropy Operations

| Operation | Algorithm | Input | Output | Security Property |
|-----------|-----------|-------|--------|-------------------|
| **Entropy combination** | XOR + SHAKE256 | Multiple entropy sources | Combined entropy | Information-theoretic: max entropy of any source |
| **Entropy stretching** | SHAKE256 | Seed entropy | Extended bits | Computational: PRF security |
| **YubiKey challenge** | HMAC-SHA512 | 64-byte challenge | 64-byte response | Hardware-backed, tamper-resistant |
| **Dice roll entropy** | von Neumann debiasing | Physical rolls | Raw entropy | Physical randomness |
| **Infinite Noise TRNG** | Hardware whitening | Analog noise | Raw entropy | True random, not pseudo-random |

### 2. Key/Username Derivation

| Operation | Algorithm | Input | Output | Security Property |
|-----------|-----------|-------|--------|-------------------|
| **Username generation** | HKDF-SHA512 | Master salt + domain | Deterministic username | One-way, domain-separated |
| **Salt initialization** | HKDF-SHA512 | Entropy pool | Master salt | One-way function |
| **Passphrase derivation** | Argon2id | Password + salt | Derived key | Memory-hard, side-channel resistant |

### 3. Hashing Operations

| Operation | Algorithm | Input | Output | Security Property |
|-----------|-----------|-------|--------|-------------------|
| **Label checksums** | SHA-512 (truncated) | Label content | Checksum chars | Collision resistance |
| **Content verification** | SHA-512 | File content | Hash digest | Integrity verification |
| **Sigchain hashing** | SHA-256 | Chain events | Event hash | Tamper evidence |

### 4. Encryption Operations

| Operation | Algorithm | Input | Output | Security Property |
|-----------|-----------|-------|--------|-------------------|
| **Cache encryption** | Fernet | Plaintext cache | Encrypted blob | AE (Authenticated Encryption) |
| **Key derivation for cache** | PBKDF2-SHA256 | Password | Fernet key | Memory-hard stretching |

---

## Algorithm Selection Rationale

### Why SHAKE256 for Entropy?

- **XOF (Extendable Output Function)**: Can produce arbitrary-length output
- **Preserves entropy**: Unlike fixed-length hashes, doesn't truncate entropy
- **NIST approved**: Part of SHA-3 family
- **Simple API**: No need to manage block sizes

### Why SHA-512 Family?

- **Hardware acceleration**: Widely supported on modern CPUs (SHA-NI)
- **Sufficient security margin**: 256-bit collision resistance
- **Consistency**: One algorithm family reduces implementation complexity
- **HMAC-compatible**: Clean composition with HMAC and HKDF

### Why Not SHA-256?

- SHA-512 is often *faster* on 64-bit systems due to native word size
- Higher security margin (256-bit vs 128-bit collision resistance)
- HMAC-SHA512 output fits YubiKey's 64-byte response exactly

### Why Fernet for Cache?

- **Battle-tested**: Python cryptography library's authenticated encryption
- **Simple API**: Encrypt/decrypt with a single key
- **Includes timestamp**: Automatic token expiration capability
- **No IV management**: Handled internally

---

## Parameter Standards

### HKDF Parameters

```
Algorithm: HKDF-SHA512
Salt: 64 bytes (from entropy pool)
Info: Domain-specific context string
Length: Varies by use case (typically 32-64 bytes)
```

### Argon2id Parameters

```
Algorithm: Argon2id
Time cost: 3 iterations
Memory cost: 65536 KB (64 MB)
Parallelism: 4 lanes
Output: 32 bytes
```

### YubiKey HMAC Parameters

```
Algorithm: HMAC-SHA1 (YubiKey native)
Slot: OATH (slot 1 or 2)
Challenge: 64 bytes
Response: 20 bytes (SHA1 output)
```

Note: YubiKey OATH uses HMAC-SHA1 internally. This is acceptable because:
1. HMAC-SHA1 remains secure for MAC purposes
2. The 160-bit output is XORed with other entropy sources
3. The final combination uses SHAKE256

---

## Security Boundaries

### Entropy Trust Model

```
┌─────────────────────────────────────────────────────────────┐
│                    Combined Entropy Pool                     │
│  Security: MAX(entropy_1, entropy_2, ..., entropy_n)         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  YubiKey    │  │  Inf Noise  │  │  System CSPRNG      │  │
│  │  (Hardware) │  │  (TRNG)     │  │  (/dev/urandom)     │  │
│  │  HMAC-SHA1  │  │  Physical   │  │  OS-managed         │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│         │                │                    │              │
│         └────────────────┼────────────────────┘              │
│                          │                                   │
│                     XOR + SHAKE256                           │
└─────────────────────────────────────────────────────────────┘
```

### Key Hierarchy

```
Entropy Pool (8192+ bits)
    │
    ├─► HKDF-SHA512 ─► Master Salt (stored in 1Password)
    │                       │
    │                       ├─► HKDF-SHA512 ─► Username for domain A
    │                       ├─► HKDF-SHA512 ─► Username for domain B
    │                       └─► HKDF-SHA512 ─► Username for domain N
    │
    └─► Fernet Key ─► Local Cache Encryption
```

---

## Version History

| Version | Changes |
|---------|---------|
| 0.3.0 | Standardized on SHA-512 family; documented SHAKE256 for entropy |
| 0.2.0 | Added Argon2id for passphrase derivation |
| 0.1.0 | Initial cryptographic design |

---

## References

- [NIST SP 800-185: SHA-3 Derived Functions](https://csrc.nist.gov/publications/detail/sp/800-185/final)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [RFC 9106: Argon2](https://www.rfc-editor.org/rfc/rfc9106)
- [FIPS 198-1: HMAC](https://csrc.nist.gov/publications/detail/fips/198/1/final)
