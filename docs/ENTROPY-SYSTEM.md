# Entropy Generation System - Implementation Complete

## Overview

The Security Architecture Tool (Bastion) now includes a comprehensive entropy generation system for creating cryptographic-quality randomness from multiple sources. This system is designed to generate high-entropy salts for the username generator and other cryptographic operations.

## Implementation Summary

### Completed Components

#### 1. Core Entropy Module (`entropy.py`)
- **EntropyAnalysis Class**: Stores and validates ENT statistical analysis results
  - Entropy bits/byte, chi-square, p-value, mean, Monte Carlo π, serial correlation
  - Quality rating system (EXCELLENT, GOOD, FAIR, POOR)
  - Acceptance thresholds for cryptographic use
  
- **EntropyPool Class**: Manages entropy storage in 1Password
  - Serial-numbered pools (#1, #2, #3...)
  - Base64 encoding for password field storage
  - Comprehensive metadata (source, size, creation date, expiry, consumed flag)
  - Automatic ENT analysis integration
  - Pool listing, retrieval, and consumption tracking

- **combine_entropy_sources()**: XOR + SHAKE256 entropy combining
  - Extends smaller sources using SHAKE256 (XOF) to match largest source
  - XOR combines all extended sources (preserves entropy if ANY source is good)
  - Produces output sized to largest input (not fixed 512 bits)

- **analyze_entropy_with_ent()**: External ENT tool integration
  - Subprocess call to `ent` command
  - Regex parsing of output
  - Returns structured EntropyAnalysis object

#### 2. YubiKey Entropy Collection (`entropy_yubikey.py`)
- **Entropy Explanation**: YubiKey's HMAC-SHA1 uses hardware-derived secret keys that are never exposed. Even with known challenges, responses are cryptographically unpredictable, providing ~160 bits per 20-byte response.

- **collect_yubikey_entropy()**: 
  - Uses `ykman otp chalresp` command
  - Slot 2 default (configurable to Slot 1)
  - Optional touch requirement for each challenge
  - Random 64-byte challenges for good mixing
  - Automatic retry calculation (20 bytes per response)
  - Error handling for missing YubiKey or ykman

- **check_yubikey_available()**: Validates ykman and YubiKey presence

- **estimate_collection_time()**: Calculates touches needed and time estimate

#### 3. Dice Entropy Collection (`entropy_dice.py`)
- **Entropy Explanation**: Physical dice rolls are fundamentally random chaotic events. Each roll of 5 dice in base-6 provides log2(6^5) ≈ 12.92 bits of entropy from unpredictable physics.

- **collect_dice_entropy()**:
  - Interactive Rich progress bar
  - Base-6 encoding (1-6 → 0-5)
  - 5 dice per roll default (configurable 1-5)
  - ~198 rolls for 512 bits
  - Input validation (digits 1-6 only, correct count)
  - Real-time entropy accumulation display

- **base6_to_bytes()**: Converts base-6 digits to bytes efficiently

- **calculate_rolls_needed()**: Calculates required rolls for target bits

#### 4. Infinite Noise TRNG (`entropy_infnoise.py`)
- **Hardware**: leetronics Infinite Noise True Random Number Generator
- **Technology**: Modular Entropy Multiplier using thermal noise
- **Output**: ~300,000 bits/second raw, Keccak-1600 whitened

- **collect_infnoise_entropy()**:
  - Uses `infnoise` CLI tool via subprocess
  - Reads exact byte count from continuous output stream
  - Optional raw mode (skip Keccak whitening)
  - Optional multiplier for stretched output
  - Returns entropy bytes with device metadata

- **check_infnoise_available()**: Validates device presence

- **list_infnoise_devices()**: Lists connected TRNG devices

- **InfNoiseMetadata**: Captures serial, byte count, whitening status

**Installation**: See [INFNOISE-INSTALLATION.md](INFNOISE-INSTALLATION.md)

#### 5. Visualization (`entropy_visual.py`)
- **visualize_entropy()**:
  - Byte frequency histogram (uniformity check)
  - Bit pattern grid (visual pattern detection)
  - Statistical annotations (mean, std dev, ones/zeros ratio)
  - PDF output (attached directly to 1Password items)

- **visualize_chi_square()**:
  - Chi-square contribution per byte value
  - Deviation from expected frequency
  - Total chi-square and degrees of freedom
  - Separate PDF output

#### 5. CLI Integration (`cli.py`)
- **bastion generate entropy**: Collect entropy from sources
  - Sources: yubikey, dice, infnoise, combined
  - Automatic ENT analysis (--analyze flag, default on)
  - 1Password storage with serial numbers
  - Optional visualization generation
  - Minimum 256 bits enforced
  
- **bastion show entropy**: Display unconsumed entropy pools
  - Rich table format
  - Shows serial, source, size, quality, created date, UUID
  - Excludes consumed pools by default

- **bastion show entropy --pool**: Re-analyze existing pool
  - Retrieves pool from 1Password
  - Runs fresh ENT analysis
  - Displays comprehensive statistics

- **bastion visualize entropy**: Generate visualizations
  - Main visualization (frequency + bit grid)
  - Chi-square analysis plot
  - Attaches PDFs directly to 1Password item (or use --output for file)

### Cleanup Completed

#### Username Generator (`username_generator.py`)
- ✅ Removed `username_length` field from metadata
- ✅ Removed `username_algorithm` field from metadata
- ✅ Removed `Bastion` tag (kept only `Bastion/Username/Generated`)
- Only essential fields remain: `username_label`, `username_salt_uuid`

#### Dependencies (`pyproject.toml`)
- ✅ Added `numpy>=1.26.0`
- ✅ Added `matplotlib>=3.8.0`
- ✅ All dependencies installed successfully

## Entropy Sources Explained

### Why YubiKey Provides Entropy

The YubiKey HMAC-SHA1 function uses a secret key that:
1. Was generated using hardware RNG during provisioning
2. Is stored in tamper-resistant hardware
3. Never leaves the device (not even during HMAC computation)

**Key principle**: Even when an attacker knows the challenge, they cannot predict the response without knowing the secret key. This makes each 20-byte HMAC output effectively random (unpredictable), containing ~160 bits of entropy.

**Analogy**: It's like having a secure random number generator locked in a vault. You can ask it questions (challenges), and it gives you answers (responses) based on a secret only it knows. Each answer is as unpredictable as if it came from /dev/urandom.

### Why Dice Provide Entropy

Physical dice rolls are governed by chaotic physics:
1. Initial conditions (hand position, force, spin) are unpredictable
2. Tumbling dynamics amplify small variations exponentially
3. Final resting state is determined by micro-level interactions
4. Assuming fair dice, all outcomes are equally probable

**Entropy per roll**:
- 1 die: log2(6) ≈ 2.585 bits
- 5 dice: log2(6^5) = log2(7776) ≈ 12.92 bits

**Key principle**: True randomness from physics, not pseudorandom algorithms. This is considered "true entropy" suitable for cryptographic key generation.

### Why Infinite Noise TRNG Provides Entropy

The leetronics Infinite Noise TRNG uses a "Modular Entropy Multiplier" architecture:
1. Thermal noise is the entropy source (fundamental physics)
2. Analog modular multiplication amplifies small noise variations
3. Loop gain K≈1.82 ensures ~0.86 bits of entropy per output bit
4. Built-in health monitoring detects device failures
5. Keccak-1600 (SHA3) whitening produces cryptographic-quality output

**Key principle**: Hardware true randomness from thermal noise, similar to Intel RDRAND but external and auditable. The device is open-source and can be verified.

**Throughput**: ~300,000 bits/second raw (~37,500 bytes/second)

### Combined Sources

Using `combine_entropy_sources()` with XOR + SHAKE256:
1. Find the largest source size as target length
2. Extend smaller sources using SHAKE256 (XOF) to match target length
3. XOR all extended sources together
4. Output size matches largest input (preserves maximum entropy)
5. Security: As strong as the strongest source (XOR preserves entropy)

## Usage Examples

### Generate Entropy from YubiKey
```bash
bastion generate entropy yubikey --bits 512
# Requires 2 touches (26 challenges × 2s = ~52s)
# Stores in 1Password as "Bastion Entropy Source #1"
```

### Generate Entropy from Dice
```bash
bastion generate entropy dice --bits 512 --dice 5
# Requires ~198 rolls of 5 dice
# Interactive prompts guide the process
# Shows progress bar and real-time entropy accumulation
```

### Generate Combined Entropy
```bash
bastion generate entropy combined --bits 512
# Collects from YubiKey first
# Then collects from dice
# Combines both with XOR+SHAKE256
# Highest security option
```

### Generate Entropy from Infinite Noise TRNG
```bash
bastion generate entropy infnoise --bits 512
# Fast hardware collection (~0.1s for 512 bits)
# Stores in 1Password as "Bastion Entropy Source #3"
# Requires infnoise CLI: https://github.com/leetronics/infnoise
```

### List Available Pools
```bash
bastion show entropy
# Shows table of unconsumed entropy pools
# Displays serial, source, size, quality, creation date
```

### Analyze Existing Pool
```bash
bastion show entropy --pool <uuid>
# Re-runs ENT analysis
# Shows detailed statistics
# Checks if entropy meets cryptographic standards
```

### Visualize Pool Quality
```bash
bastion visualize entropy <uuid> --output my_entropy.png
# Generates frequency histogram and bit pattern grid
# Creates chi-square analysis plot
# Visual inspection for patterns
```

## 1Password Storage Structure

### Entropy Pool Item
- **Category**: Password
- **Title**: \"Bastion Entropy Source v1 #1\" or \"Bastion Entropy Derived v1 #2\"
- **Password Field**: Base64-encoded entropy bytes
- **Tags**: `Bastion/Entropy/v1`

### Native Sections (Human-readable names, snake_case fields)

**Pool Info section:**
- `version`: \"v1\"
- `serial_number`: 1, 2, 3...
- `pool_type`: \"source\" or \"derived\"
- `source`: \"yubikey\" | \"dice\" | \"system\" | \"yubikey+dice\" | \"system+yubikey\"
- `source_type`: \"yubikey_openpgp\" | \"system_urandom\" | \"dice\"

**Device Metadata section** (dynamic fields from device):
- `serial`: YubiKey serial number, etc.
- `os`: Operating system name
- `version`: Device/OS version
- `manufacturer`: Device manufacturer

**Size section:**
- `bytes`: Number of bytes
- `bits`: Number of bits

**Lifecycle section:**
- `created_at`: Unix timestamp (native date field)
- `expires_at`: Unix timestamp (native date field, 90 days default)
- `consumed`: \"false\" | \"true\"

**Derivation section** (derived pools only):
- `method`: "xor_shake256"
- `source_count`: Number of source pools
- `source_uuids`: Comma-separated UUIDs

**Statistical Analysis section** (samples >= 1KB only):
- `entropy_per_byte`: Float (ideal: 8.0)
- `chi_square`: Float
- `chi_square_pvalue`: Float (ideal: 0.5)
- `arithmetic_mean`: Float (ideal: 127.5)
- `monte_carlo_pi`: Float approximation of π
- `monte_carlo_error_pct`: Error percentage
- `serial_correlation`: Float (ideal: 0.0)
- `quality_rating`: \"EXCELLENT\" | \"GOOD\" | \"FAIR\" | \"POOR\"

### Notes Field
No longer used - all data in native sections for better organization.
  Monte Carlo π: 3.141234 (error: 0.01%)
  Serial correlation: 0.000234
  Quality: EXCELLENT
```

## ENT Analysis Interpretation

### Ideal Values
- **Entropy**: 8.0 bits/byte (maximum possible)
- **Chi-square p-value**: 0.5 (perfect uniformity)
  - Acceptable range: 0.01 to 0.99
  - Too low (<0.01): Suspiciously non-uniform
  - Too high (>0.99): Suspiciously uniform (may indicate non-random data)
- **Mean**: 127.5 (midpoint of 0-255)
- **Monte Carlo π**: 3.14159... (closer is better)
- **Serial correlation**: 0.0 (no correlation between bytes)

### Quality Ratings
- **EXCELLENT**: ≥7.99 bits/byte, 0.1 ≤ p ≤ 0.9
- **GOOD**: ≥7.9 bits/byte, 0.05 ≤ p ≤ 0.95
- **FAIR**: ≥7.5 bits/byte, 0.01 ≤ p ≤ 0.99
- **POOR**: Below FAIR thresholds

### Acceptance Threshold
Entropy is considered acceptable for cryptographic use if:
- Entropy ≥ 7.5 bits/byte
- Chi-square p-value between 0.01 and 0.99
- |Serial correlation| < 0.1

## Salt Derivation from Entropy Pools

Entropy pools can be used as the source for username generator salts, providing
full traceability from hardware entropy → salt → username.

### Derivation Chain
```
Entropy Pool (hardware RNG: YubiKey/dice/infnoise)
    ↓ HKDF-SHA512
Salt (stored in 1Password)
    ↓ HMAC-SHA512
Username (deterministic output)
```

### HKDF-SHA512 Parameters
- **Input Key Material (IKM)**: Entropy pool bytes (≥512 bits required)
- **Salt**: None (entropy pool is already high-quality)
- **Info**: Bastion Label for domain separation
  - Format: `Bastion/SALT/HKDF/SHA2/512:{ident}:{date}#VERSION=1`
  - Example: `Bastion/SALT/HKDF/SHA2/512:username-generator:2025-11-30#VERSION=1`
- **Output Length**: 64 bytes (512 bits)

The `info` parameter ensures the same entropy pool would produce different
outputs if used for different purposes (domain separation).

### Usage
```bash
# Generate entropy first
bastion generate entropy infnoise --bits 8192
# Returns: Pool #1 created with UUID abc123...

# Initialize username generator with entropy pool
bastion generate username --init --entropy-source abc123...
# Derives salt from entropy pool using HKDF-SHA512
# Marks pool as consumed
# Stores derivation metadata in salt item

# Or use interactive selection (prompts for available pools)
bastion generate username --init
# Shows table of available pools ≥512 bits
# Enter pool number, UUID, or press Enter for system RNG
```

### Salt Item Metadata
When derived from an entropy pool, the salt item includes:

**Derivation Section:**
- `Entropy Source UUID`: UUID of consumed entropy pool
- `Label`: HKDF info parameter (Bastion Label)
- `Method`: HKDF-SHA512
- `Output Length`: 512 bits

This enables full audit trail: salt → entropy pool → hardware source.

## Future Enhancements

### Pool Expiry and Rotation
- Implement `bastion entropy prune --older-than 90d`
- Archive consumed pools (keep for audit, tag differently)
- Warn when pools approach expiry

### Advanced Analysis
- Optional Dieharder test suite integration (slow but thorough)
- Autocorrelation plots
- Spectral analysis

### Alternative Sources
- `/dev/random` collection (blocking, high-quality)
- `/dev/urandom` collection (non-blocking, good quality)
- Audio noise capture
- Webcam sensor noise

## Testing Recommendations

### Manual Testing Workflow
```bash
# 1. Test YubiKey collection (if available)
bastion generate entropy yubikey --bits 256 --no-touch

# 2. Test dice collection
bastion generate entropy dice --bits 256 --dice 2
# Enter some test rolls (faster with 2 dice)

# 3. List pools
bastion show entropy

# 4. Analyze a pool
bastion show entropy --pool <uuid-from-list>

# 5. Visualize a pool
bastion visualize entropy <uuid-from-list>

# 6. Check generated files
ls -lh entropy_*.png
```

### Production Usage
```bash
# Generate high-security combined entropy for salt creation
bastion generate entropy combined --bits 512

# This will:
# - Collect from YubiKey (with touch for each challenge)
# - Collect from dice (198 rolls)
# - Combine with XOR+SHAKE256
# - Run ENT analysis automatically
# - Store in 1Password with serial number
# - Display quality rating

# Use the pool UUID to initialize username generator salt (future)
```

## Design Decisions

### Why Serial Numbers?
- Simple numeric serial numbering (#1, #2, #3...)
- No limit on serial numbers (unlimited growth)
- Human-readable ordering
- Easy to reference ("use pool 003")
- Audit trail consistency

### Why Base64 for Storage?
- 1Password password field is text-based
- Base64 is standard, reversible encoding
- No data loss or corruption
- Easy to decode with standard libraries

### Why XOR + SHAKE256 for Combining?
- **XOR preserves entropy**: If ANY source has good entropy, output has good entropy
- **SHAKE256 (XOF)**: Extendable Output Function allows matching any input size
- **Size preservation**: Output matches largest input (no entropy truncation)
- **Quantum-resistant**: SHAKE256 is SHA-3 family (NIST approved 2015)
- **Deterministic extension**: Smaller sources extended consistently

### Why ENT Tool?
- Industry standard for entropy analysis
- Fast and lightweight
- Well-documented interpretation
- Available on all platforms
- Trusted by cryptographers

### Why 256-bit Minimum?
- 128-bit security level for symmetric crypto
- 256 bits provides 2x margin
- Future-proof against quantum computers (Grover's algorithm)
- Industry best practice (NIST SP 800-57)

### Why 90-day Expiry?
- Entropy should not be reused
- Encourages regular rotation
- Audit trail for security compliance
- Conservative timeline (can be adjusted)

## Security Considerations

### Entropy Pool Management
1. **Never reuse consumed pools**: Mark as consumed after derivation
2. **Expire old pools**: 90-day default ensures fresh entropy
3. **Secure storage**: 1Password encryption protects entropy
4. **Audit trail**: Creation dates, sources, and consumption tracked

### Source Selection
1. **YubiKey alone**: Good for convenience, hardware RNG trust
2. **Dice alone**: Good for maximum paranoia, no electronic trust
3. **Combined**: Best security, defense in depth

### Statistical Analysis
1. **Always analyze**: Default --analyze flag catches weak entropy
2. **Visual inspection**: Patterns may be visible to human eye
3. **Quality threshold**: FAIR minimum for production use
4. **Documentation**: Notes field preserves analysis for audit

## Conclusion

The entropy generation system is now fully implemented and integrated into Bastion. It provides:
- ✅ Multiple high-quality entropy sources
- ✅ Statistical validation (ENT analysis)
- ✅ Visual inspection tools
- ✅ Secure 1Password storage
- ✅ Comprehensive metadata and audit trail
- ✅ Clean CLI interface
- ✅ Extensible architecture for future enhancements

Ready for use in production to generate cryptographic salts for the username generator.
