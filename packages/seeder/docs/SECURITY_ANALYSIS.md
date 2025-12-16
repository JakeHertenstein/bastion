# Security Analysis: Seed Card Password Token System

**Document Version:** 1.1  
**Analysis Date:** November 29, 2025  
**Analyzed Version:** v1 (HKDF-Expand per RFC 5869, 9-field format)

---

## Executive Summary

The Seed Card system is a deterministic password generation tool that derives a 10×10 grid of cryptographic tokens from seed material. Users construct passwords by combining tokens from memorized grid coordinates with optional personal components.

### Security Verdict: **STRONG** ✅

The cryptographic design is fundamentally sound:
- **Memory-hard KDF** (Argon2id with 2GB memory) provides excellent offline attack resistance
- **Perfect domain separation** through per-token HMAC labels prevents token correlation
- **Unbiased symbol selection** via rejection sampling ensures uniform token distribution
- **No seed material in exports** - only derived tokens and integrity hashes

### Key Strengths
| Property | Implementation | Rating |
|----------|----------------|--------|
| Offline attack resistance | Argon2id (2GB, t=3) | ⭐⭐⭐⭐⭐ |
| Token independence | Per-token HMAC labels | ⭐⭐⭐⭐⭐ |
| Symbol bias elimination | Rejection sampling | ⭐⭐⭐⭐⭐ |
| Cross-platform consistency | Python + JavaScript | ⭐⭐⭐⭐⭐ |
| Audit transparency | Open design, standard primitives | ⭐⭐⭐⭐ |

### Areas for Attention
| Concern | Severity | Mitigation |
|---------|----------|-----------|
| Simple mode lacks stretching | Medium | Use Argon2 mode for production |
| SLIP-39 single iteration expansion | Low | Master secret already high-entropy |

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Cryptographic Primitives](#2-cryptographic-primitives)
3. [Key Derivation Flow](#3-key-derivation-flow)
4. [Token Generation Algorithm](#4-token-generation-algorithm)
5. [Entropy Analysis](#5-entropy-analysis)
6. [Threat Model](#6-threat-model)
7. [Attack Cost Analysis](#7-attack-cost-analysis)
8. [Implementation Security](#8-implementation-security)
9. [Recommendations](#9-recommendations)
10. [Appendix: Mathematical Foundations](#appendix-mathematical-foundations)

---

## 1. System Overview

### 1.1 Purpose

The Seed Card system generates a physical card containing 100 cryptographic tokens arranged in a 10×10 grid. Users create passwords by:

1. Memorizing a simple pattern of coordinates (e.g., "A0 B1 C2 D3")
2. Optionally adding a memorized personal component
3. Looking up tokens from their card at those coordinates
4. Combining tokens (optionally with separators)

### 1.2 Design Goals

| Goal | Description |
|------|-------------|
| **Determinism** | Same seed → same tokens, always |
| **Memorability** | Remember pattern, not passwords |
| **Physical backup** | Card survives device loss |
| **High entropy** | Each token provides ~26 bits |
| **Offline generation** | No network required |
| **Cross-platform** | CLI and web produce identical output |

### 1.3 Security Model

The system assumes:
- **Seed phrase is secret** and stored securely (e.g., 1Password vault)
- **Card may be compromised** but attacker doesn't know pattern
- **Pattern is memorized** and not written on card
- **Optional components** add additional security layers

---

## 2. Cryptographic Primitives

### 2.1 Primitives Used

| Purpose | Primitive | Standard | Parameters |
|---------|-----------|----------|-----------|
| Key Stretching | Argon2id | RFC 9106 | t=3, m=2GB, p=4 |
| BIP-39 Derivation | PBKDF2-HMAC-SHA512 | BIP-39 | i=2048 |
| Token Stream | HKDF-Expand (HMAC-SHA512) | RFC 5869 | Chained block mode |
| Integrity Digest | HMAC-SHA512 | RFC 2104 | Fixed info label |
| Nonce Generation | CSPRNG | OS-provided | 48 bits |

### 2.2 Why These Choices?

**Argon2id** was selected because:
- Winner of the Password Hashing Competition (2015)
- Memory-hard: Resists GPU/ASIC parallelization
- Hybrid (id variant): Resists both side-channel and GPU attacks
- 2GB memory cost makes cloud cracking extremely expensive

**HMAC-SHA512** was selected because:
- Well-analyzed, no known weaknesses
- 512-bit output provides ample expansion material
- Available in all platforms (Python, JavaScript, hardware)

### 2.3 Primitives NOT Used (and Why)

| Primitive | Reason Not Used |
|-----------|-----------------|
| AES | Not needed - no encryption, only derivation |
| RSA/ECC | Asymmetric crypto unnecessary for this use case |
| bcrypt | Lower memory-hardness than Argon2 |
| scrypt | Less tunable than Argon2, older design |

---

## 3. Key Derivation Flow

### 3.1 High-Level Flow

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Seed Phrase    │────▶│  Argon2id KDF    │────▶│  64-byte Seed   │
│  (user input)   │     │  (2GB memory)    │     │  (master key)   │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
                        ┌─────────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Per-Token HMAC Derivation                                          │
│  ┌──────────────┐  ┌──────────────┐       ┌──────────────┐         │
│  │ v1|A0|TOKEN|A0│  │ v1|A0|TOKEN|B0│  ...  │ v1|A0|TOKEN|J9│        │
│  │    ↓         │  │    ↓         │       │    ↓         │         │
│  │ HMAC-SHA512  │  │ HMAC-SHA512  │       │ HMAC-SHA512  │         │
│  │    ↓         │  │    ↓         │       │    ↓         │         │
│  │  Token A0    │  │  Token B0    │       │  Token J9    │         │
│  └──────────────┘  └──────────────┘       └──────────────┘         │
└─────────────────────────────────────────────────────────────────────┘
                        │
                        ▼
              ┌─────────────────┐
              │   10×10 Grid    │
              │   100 Tokens    │
              └─────────────────┘
```

### 3.2 Seed Source Methods

#### Argon2id (Recommended)
```
seed = Argon2id(
    password = seed_phrase.encode('utf-8'),
    salt     = label.encode('utf-8'),  // v1|TYPE|KDF|...|NONCE|...
    time     = 3,
    memory   = 2097152 KB (2 GB),
    threads  = 4,
    length   = 64 bytes
)
```

**Security:** Excellent. 2GB memory makes each hash attempt cost ~$0.0001 on cloud infrastructure.

#### BIP-39 (Standard Mnemonic)
```
seed = PBKDF2-HMAC-SHA512(
    password   = mnemonic_words,
    salt       = "mnemonic" + passphrase,
    iterations = 2048,
    length     = 64 bytes
)
```

**Security:** Good. Standard BIP-39 compliance. 2048 iterations is dated but acceptable given mnemonic entropy.

#### Simple SHA-512 (Testing Only)
```
seed = SHA512(seed_phrase.encode('utf-8'))
```

**Security:** ⚠️ **WEAK for production.** No key stretching. Use only for testing or when input already has high entropy.

### 3.3 Label Format (Salt/Domain Separation)

The v1 label provides complete derivation reproducibility:

```
v1|SIMPLE|ARGON2|t3m2048p4|BASE90|2025-11-29|Kx7mQ9bL|Banking|A0
│    │      │       │        │       │          │        │     │
│    │      │       │        │       │          │        │     └─ Card Index (batch position)
│    │      │       │        │       │          │        └─ Card ID (user label)
│    │      │       │        │       │          └─ Nonce (48-bit random)
│    │      │       │        │       └─ Date (optional)
│    │      │       │        └─ Base system (10/62/90)
│    │      │       └─ KDF params (time/memory/parallelism)
│    │      └─ KDF algorithm
│    └─ Seed source type
└─ Version
```

---

## 4. Token Generation Algorithm

### 4.1 HKDF-Expand Stream Generator (RFC 5869)

The system uses standard HKDF-Expand with HMAC-SHA512 for byte stream generation:

```python
def hkdf_expand(prk, info, length):
    """RFC 5869 HKDF-Expand with HMAC-SHA512."""
    hash_len = 64  # SHA-512 output size
    n = (length + hash_len - 1) // hash_len
    
    okm = b""
    t = b""
    for i in range(1, n + 1):
        # T(i) = HMAC(PRK, T(i-1) || info || i)
        t = HMAC-SHA512(prk, t + info + bytes([i]))
        okm += t
    return okm[:length]
```

**Construction:** RFC 5869 HKDF-Expand with chained HMAC-SHA512 blocks

**Key Properties:**

| Property | Value |
|----------|-------|
| Extract phase | Skipped (Argon2 output is already uniform PRK) |
| Expand phase | Chained HMAC per RFC 5869 |
| Hash function | SHA-512 (64-byte output) |
| Max output | 255 × 64 = 16,320 bytes |

**Why HKDF-Expand:**
- Argon2 output is already uniformly random → extract phase unnecessary
- Standard RFC 5869 algorithm improves auditability
- Chained construction provides defense-in-depth
- Same output length capabilities as needed (~600 bytes for full grid)

### 4.1.1 Clarification: HKDF-Expand *is* HMAC

A common point of confusion: HKDF-Expand and HMAC are not alternatives—**HKDF-Expand is built on HMAC**. The relationship is:

```
HKDF-Expand(PRK, info, length) = T(1) || T(2) || ... || T(n)
where:
  T(0) = ""  (empty)
  T(i) = HMAC-SHA512(PRK, T(i-1) || info || i)
```

So when we say "per-token HMAC", we mean each token calls `hkdf_expand()` with a unique `info` label, which internally runs one or more HMAC operations:

| Concept | Implementation |
|---------|----------------|
| Per-token domain separation | Unique `info` label per token |
| Cryptographic primitive | HMAC-SHA512 (inside HKDF-Expand) |
| Chaining for long output | RFC 5869 block chaining via T(i-1) |

This design means:
- **Single token (≤64 bytes):** Exactly one HMAC call per token
- **Long output (>64 bytes):** Multiple chained HMAC calls per RFC 5869
- **Standard compliance:** Full RFC 5869 HKDF-Expand, not a custom HMAC scheme

### 4.2 Per-Token HMAC Labels

Each token derives from a unique info label:

```
Token at coordinate B3 on card A0:
  label = "v1|A0|TOKEN|B3"
  stream = HMAC-SHA512(seed, label || counter)
```

This provides **perfect domain separation**:
- No two tokens share an HMAC label
- Knowing one token reveals nothing about others
- Different cards (different `card_index`) produce completely different tokens

### 4.3 Rejection Sampling (Bias Elimination)

To convert random bytes to alphabet symbols without bias:

```python
def byte_to_symbol(byte_value, alphabet_size):
    # For Base90: max_usable = (256 // 90) * 90 = 180
    max_usable = (256 // alphabet_size) * alphabet_size
    
    if byte_value < max_usable:
        return byte_value % alphabet_size  # Accept
    else:
        return None  # Reject, fetch next byte
```

**For Base90 (alphabet_size = 90):**
- Bytes 0-179: Accepted (mapped to symbols 0-89)
- Bytes 180-255: Rejected (76 values, 29.7% rejection rate)
- Each symbol has exactly 2 accepting byte values → **perfectly uniform**

### 4.4 Token Construction

```python
def generate_token(byte_stream, alphabet, chars_per_token=4):
    token = ""
    stream_iter = iter(byte_stream)
    while len(token) < chars_per_token:
        byte_val = next(stream_iter)
        symbol_idx = byte_to_symbol(byte_val, len(alphabet))
        if symbol_idx is not None:
            token += alphabet[symbol_idx]
    return token
```

**Expected bytes consumed per token:**
- Base90: 4 chars × 1.42 bytes/char ≈ 5.7 bytes average
- Base62: 4 chars × 1.03 bytes/char ≈ 4.1 bytes average
- Base10: 4 chars × 1.02 bytes/char ≈ 4.1 bytes average

---

## 5. Entropy Analysis

### 5.1 Token Entropy

| Base System | Alphabet Size | Bits per Character | Bits per Token (4 chars) |
|-------------|---------------|--------------------|-----------------------------|
| Base10 | 10 | 3.32 bits | **13.29 bits** |
| Base62 | 62 | 5.95 bits | **23.82 bits** |
| Base90 | 90 | 6.49 bits | **25.98 bits** |

### 5.2 Password Entropy by Pattern

Using Base90 tokens:

| Pattern | Tokens | Token Entropy | + Memorized Word | + Separators | Total |
|---------|--------|---------------|------------------|--------------|-------|
| 2 coordinates | 2 | 51.96 bits | +28 bits | +3 bits | **~83 bits** |
| 3 coordinates | 3 | 77.94 bits | +28 bits | +4 bits | **~110 bits** |
| 4 coordinates | 4 | 103.92 bits | +28 bits | +5 bits | **~137 bits** |
| 5 coordinates | 5 | 129.90 bits | +28 bits | +6 bits | **~164 bits** |

**Reference: NIST Guidelines**
- 80 bits: Suitable for most applications
- 112 bits: Recommended for sensitive data
- 128+ bits: Cryptographic strength

### 5.3 Memorized Component Entropy

| Component | Example | Entropy |
|-----------|---------|---------|
| 6-char lowercase word | "purple" | ~28 bits |
| 4-digit PIN | "1984" | ~13 bits |
| Birth year | "1990" | ~7 bits |
| Special char | "!" | ~5 bits |

### 5.4 Pattern Entropy (If Card Compromised)

If an attacker has the physical card but not the pattern:

| Pattern Type | Search Space | Entropy |
|--------------|--------------|---------|
| 2 random coords | 100 × 99 = 9,900 | 13.3 bits |
| 3 random coords | 100 × 99 × 98 = 970,200 | 19.9 bits |
| 4 random coords | ~94 million | 26.5 bits |
| 4 coords + word | ~94M × 100K words | ~43 bits |

**Critical:** Pattern entropy alone is insufficient. The security model assumes:
1. Card + seed phrase are not both compromised, OR
2. Rate limiting prevents online enumeration

---

## 6. Threat Model

### 6.1 Threat Matrix

| Threat | Likelihood | Impact | Mitigation |
|--------|------------|--------|------------|
| **Seed phrase compromise** | Low | Critical | Secure storage (1Password, hardware wallet) |
| **Card theft without pattern** | Medium | Low | Pattern adds ~20-43 bits; rotate card if stolen |
| **Card + pattern compromise** | Low | High | Add memorized word; rotate immediately |
| **Offline brute force on seed** | Medium | Varies | Argon2 2GB makes this expensive |
| **Online password guessing** | High attempt | Low success | Rate limiting at service level |
| **Side-channel on generation** | Low | Medium | Generate on air-gapped device |
| **Implementation bug** | Low | High | Comprehensive test suite, cross-platform verification |

### 6.2 What We Protect Against

✅ **Password reuse** - Each service gets unique derived password  
✅ **Credential stuffing** - Compromised site doesn't affect others  
✅ **Offline cracking** - Argon2 2GB makes hash cracking expensive  
✅ **Database breaches** - Derived passwords don't reveal seed  
✅ **Device loss** - Physical card survives phone/laptop loss  
✅ **Memory attacks** - Nothing to extract from memory after generation  

### 6.3 What We DON'T Protect Against

❌ **Shoulder surfing** - Attacker watching you read the card  
❌ **Coercion** - Physical threats to reveal seed/pattern  
❌ **Keyloggers** - Malware capturing password entry  
❌ **Phishing** - User entering password on fake site  
❌ **Service compromise** - Server storing passwords in plaintext  

### 6.4 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│  TRUSTED ZONE                                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ Seed Phrase │  │ Air-gapped  │  │ Physical    │              │
│  │ (1Password) │  │ Generator   │  │ Card        │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
└─────────────────────────────────────────────────────────────────┘
                              │
                    Password Entry
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  UNTRUSTED ZONE                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ Browser     │  │ Network     │  │ Remote      │              │
│  │ Environment │  │ Transport   │  │ Service     │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. Attack Cost Analysis

### 7.1 Offline Seed Cracking

**Scenario:** Attacker has card, wants to find seed phrase

**Argon2id Parameters:** t=3, m=2GB, p=4

| Hardware | Hashes/Second | Cost/Hash |
|----------|---------------|-----------|
| Single CPU core | ~0.1 | $0.00001 |
| 8-core workstation | ~0.3 | $0.00003 |
| AWS r6i.24xlarge (768GB RAM) | ~100 | $0.0001 |
| Custom ASIC | Limited by memory bandwidth | ~$0.00005 |

**Attack Cost by Seed Entropy:**

| Seed Source | Entropy | Attempts | Time (100 h/s) | AWS Cost |
|-------------|---------|----------|----------------|----------|
| 4-word passphrase | ~44 bits | 2^44 | 5,500 years | $1.7B |
| 12-word BIP-39 | ~128 bits | 2^128 | Heat death | ∞ |
| 24-word BIP-39 | ~256 bits | 2^256 | Universe × 10^50 | ∞ |

### 7.2 Pattern Enumeration (Card Stolen)

**Scenario:** Attacker has card, tries all patterns online

| Pattern | Combinations | Time @ 10/min | Time @ 1/sec |
|---------|--------------|---------------|--------------|
| 2 coords | 9,900 | 16.5 hours | 2.75 hours |
| 3 coords | 970,200 | 67 days | 11 days |
| 4 coords | 94M | 18 years | 3 years |
| 4 coords + 10K words | 940B | 180,000 years | 30,000 years |

**Mitigation:** Most services lock after 5-10 failed attempts.

### 7.3 Rainbow Table Attacks

**Not applicable** because:
1. Each card has unique 48-bit nonce → 281 trillion possible salts
2. Per-token HMAC labels add another 100× multiplier
3. Total: 28.1 quadrillion unique derivation paths per seed

---

## 8. Implementation Security

### 8.1 Memory Safety

**Python Implementation:**
- Uses `hashlib` and `hmac` from standard library (C implementations)
- `argon2-cffi` wraps reference C implementation
- No manual memory management

**JavaScript Implementation:**
- Uses Web Crypto API where available
- Argon2 via WebAssembly (memory-isolated)
- Automatic garbage collection

### 8.2 Side-Channel Considerations

| Attack | Risk | Mitigation |
|--------|------|------------|
| Timing | Low | HMAC and Argon2 implementations are constant-time |
| Cache | Low | 2GB memory footprint makes cache attacks impractical |
| Power | N/A | Software implementation, not hardware |
| EM | N/A | Software implementation |

**Recommendation:** Generate cards on air-gapped device for highest security.

### 8.3 Random Number Generation

**Nonce generation uses OS CSPRNG:**
- Python: `os.urandom(6)` → 48 bits
- JavaScript: `crypto.getRandomValues()`

**No randomness in token generation** - tokens are fully deterministic from seed.

### 8.4 Cross-Platform Verification

The test suite verifies:
- ✅ Identical token output for same inputs (Python vs JavaScript)
- ✅ Identical HMAC label construction
- ✅ Identical rejection sampling behavior
- ✅ Identical Argon2 output (reference vectors)

---

## 9. Recommendations

### 9.1 For Users

| Priority | Recommendation |
|----------|----------------|
| **Critical** | Store seed phrase in password manager or hardware wallet |
| **Critical** | Never write pattern on the card |
| **High** | Use 3+ coordinate patterns for sensitive accounts |
| **High** | Add memorized word for critical accounts (banking, email) |
| **Medium** | Generate cards on air-gapped device |
| **Medium** | Rotate card if physical security is compromised |
| **Low** | Use different patterns for different security tiers |

### 9.2 For Deployment

| Priority | Recommendation |
|----------|----------------|
| **High** | Always use Argon2 mode (not Simple/SHA-512) |
| **High** | Use maximum memory that device supports |
| **Medium** | Enable auto-parallelism detection |
| **Medium** | Generate unique nonce for each card batch |
| **Low** | Consider SLIP-39 for shamir-split seed backup |

### 9.3 For Code Maintainers

| Priority | Recommendation |
|----------|----------------|
| **Medium** | Increase SLIP-39 PBKDF2 iterations (currently 1) |
| **Low** | Add label MAC for tamper detection on printed cards |
| **Low** | Document simple mode limitations more prominently |
| **Done** ✅ | Migrated to standard HKDF-Expand (RFC 5869) |

---

## Appendix: Mathematical Foundations

### A.1 Rejection Sampling Proof

**Claim:** The rejection sampling algorithm produces uniformly distributed symbols.

**Proof:**
- Let $n$ be alphabet size (90 for Base90)
- Let $k = \lfloor 256/n \rfloor = 2$ (for Base90)
- Accept bytes in range $[0, k \cdot n) = [0, 180)$
- Each symbol $s \in [0, n)$ is produced by exactly $k$ byte values
- $P(\text{symbol} = s) = k/180 = 2/180 = 1/90$ for all $s$
- Distribution is uniform. ∎

### A.2 Entropy Calculation

**Token entropy:**
$$H(\text{token}) = 4 \cdot \log_2(90) = 4 \cdot 6.492 = 25.97 \text{ bits}$$

**Grid entropy:**
$$H(\text{grid}) = 100 \cdot H(\text{token}) = 2597 \text{ bits}$$

**Pattern with k coordinates:**
$$H(\text{password}) = k \cdot H(\text{token}) + H(\text{memorized}) + H(\text{separators})$$

### A.3 Birthday Bound for Nonce Collision

**Nonce size:** 48 bits = 281 trillion values

**Birthday bound:** $\sqrt{2^{48}} \approx 16.8 \text{ million}$

**Interpretation:** After generating ~17 million cards with the same seed, there's a 50% chance of nonce collision. For practical usage (< 1000 cards), collision probability is negligible: $P \approx \frac{n^2}{2 \cdot 2^{48}} < 10^{-9}$

### A.4 Argon2 Memory-Hardness

**Memory bandwidth bound:**
- DDR4-3200: ~25 GB/s bandwidth
- 2GB Argon2: ~80ms minimum (bandwidth-limited)
- Cannot be parallelized beyond memory bandwidth

**ASIC resistance:**
- Custom ASICs cannot avoid memory access pattern
- Memory cost dominates silicon cost
- Economic advantage over CPU: ~10-20× (not 1000×+ like SHA-256)

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.1 | 2025-11-29 | Updated to reflect HKDF-Expand (RFC 5869) migration |
| 1.0 | 2025-11-29 | Initial security analysis |

---

*This document should be reviewed whenever significant cryptographic changes are made to the Seed Card system.*
