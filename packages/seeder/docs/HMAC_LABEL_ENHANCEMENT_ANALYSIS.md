# HMAC512 Label Enhancement: Security and Entropy Analysis

## Current Implementation (Bastion Label Format)

### Label Structure
Seeder uses the Bastion Label Format for all cryptographic labels:

**Card Label Format**: `Seeder/TOKEN/ALGO:IDENT:DATE#PARAMS|CHECK`
```
Seeder/TOKEN/SIMPLE-ARGON2ID:banking.A0:2025-11-28#VERSION=1&TIME=3&MEMORY=2048&PARALLELISM=8&NONCE=Kx7mQ9bL&ENCODING=90|X
```

**HMAC Label Format**: `Seeder/TOKEN/HMAC:IDENT:#VERSION=1|CHECK`
```
Seeder/TOKEN/HMAC:A0.B3:#VERSION=1|Y
```

### URL-Style Parameters
Parameters use URL query-string notation with `&` separator and `=` assignment.
Canonical parameter order: VERSION, TIME, MEMORY, PARALLELISM, NONCE, ENCODING

### Previous Label Structure (Legacy)
The previous HMAC512 implementation used:
```python
message = working_info_label + counter.to_bytes(2, "big")
```

Where `working_info_label` consisted of:
- Base label: `b"SEEDER-TOKENS"` (13 bytes)
- Optional card ID: `b"-" + card_id.encode('utf-8')` (variable length)

### Example Legacy Labels
- Without card ID: `b"SEEDER-TOKENS"`
- With card ID: `b"SEEDER-TOKENS-SYS.01.01"`
- Counter: 2-byte big-endian (values 1-65535)

## Label Components Framework

### Current Bastion Format Structure
```
[Tool]/[TYPE]/[ALGO]:[IDENT]:[DATE]#[PARAMS]|[CHECK]
```

**Components**:
- **Tool**: `Seeder` (tool identifier)
- **TYPE**: `TOKEN` (always TOKEN for card generation)
- **ALGO**: `SIMPLE-ARGON2ID`, `BIP39-ARGON2ID`, `SLIP39-ARGON2ID`
- **IDENT**: `{card_id}.{card_index}` (e.g., `banking.A0`)
- **DATE**: `YYYY-MM-DD` format (optional)
- **PARAMS**: URL-style parameters (e.g., `VERSION=1&TIME=3&MEMORY=2048&PARALLELISM=8&NONCE=Kx7mQ9bL&ENCODING=90`)
- **CHECK**: Luhn mod-36 check digit

### 1. Version Component

**Purpose**: Track specification version for backward compatibility and security evolution

**Options**:
- **Numeric**: `VERSION=1`, `VERSION=2` (simple incrementing)
- **Semantic**: `VERSION=1.0.0`, `VERSION=2.1.3` (major.minor.patch)

**Entropy Analysis**:
- Numeric (1-99): ~6.6 bits (`log2(99)`)
- Semantic (reasonable range): ~10-13 bits

**Security Implications**:
- **Low Risk**: Version info typically known to attackers
- **Benefits**: 
  - Forces versioned token matrices (prevents replay attacks)
  - Enables cryptographic agility
  - Clear audit trail for specification changes
- **Recommendation**: Numeric version for simplicity

### 2. Date Component

**Purpose**: Time-based domain separation and expiration tracking

**Options**:
- **Generated Date**: When the matrix was created
- **Expiration Date**: When tokens should be rotated/retired
- **Historical Date**: Reference date for archival/forensic purposes

**Formats**:
- **Full Date**: `2025-11-28` (ISO 8601, ~15.3 bits practical entropy)
- **Year-Month**: `2025-11` (6 chars, ~8.6 bits for 12 months/year)

**Entropy Analysis**:
```
Full Date (daily granularity, 100 years): log2(365 * 100) ≈ 15.3 bits
Month (yearly cycle): log2(12 * 10) ≈ 6.9 bits  
Week (yearly cycle): log2(52 * 10) ≈ 9.0 bits
```

**Security Implications**:
- **Moderate Risk**: Date ranges often predictable by attackers
- **Benefits**:
  - Automatic key rotation through time
  - Forensic timeline reconstruction
  - Prevents long-lived token reuse
- **Recommendation**: Full ISO date for clarity and auditability

### 3. Enhanced Card ID System

**Current System**: User-defined strings like `banking`, `personal`

**IDENT Format**: `{card_id}.{card_index}`
```
banking.A0  (card_id=banking, card_index=A0)
personal.B5 (card_id=personal, card_index=B5)
```

**Examples**:
- `banking.A0` (banking card, first card)
- `alice.home.A0` (user categories with dots)
- `sys.2025.A0` (system with year)
- `temp.A3` (temporary card)

**Entropy Analysis**:
```
User prefix (8 chars, alphanumeric): log2(36^8) ≈ 41.4 bits
Sequential ID (3 digits): log2(1000) ≈ 9.97 bits
Combined: ~51.4 bits (but mostly known to user)
```

**Security Implications**:
- **Low Risk**: Usually known to legitimate user
- **High Value**: Critical for domain separation
- **Recommendation**: Keep flexible for user convenience

### 4. Separator Character Standardization

**Current**: Hyphen (`-`) separator
**Alternatives**:
- Pipe (`|`): `SEEDER-TOKENS|v1|20251031|SYS.01`
- Colon (`:`): `SEEDER-TOKENS:v1:20251031:SYS.01`
- Period (`.`): `SEEDER-TOKENS.v1.20251031.SYS.01`
- No separator: `SEEDERTOKENSv120251031SYS01` (compact but less readable)

**Entropy Impact**: Negligible (separator choice doesn't affect entropy)
**Recommendation**: Stick with hyphen for consistency

## Complete Proposed Label Format

### Production Format
```
SEEDER-TOKENS-v{version}-{YYYYMMDD}-{card_id}
```

**Example**: `SEEDER-TOKENS-v1.0-20251031-banking.001`

### Development Format (with git hash)
```
SEEDER-TOKENS-{git_hash}-{YYYYMMDD}-{card_id}
```

**Example**: `SEEDER-TOKENS-c4f2a1b-20251031-test.001`

### Minimal Format (backward compatibility)
```
SEEDER-TOKENS-{card_id}
```

**Example**: `SEEDER-TOKENS-SYS.01` (current behavior)

## Entropy Contribution Summary

| Component | Min Entropy | Max Entropy | Practical Entropy | Notes |
|-----------|-------------|-------------|-------------------|-------|
| Base Label | 0 bits | 0 bits | 0 bits | Known constant |
| Version | 6.6 bits | 28 bits | 10-15 bits | Depends on format choice |
| Date | 6.9 bits | 16.6 bits | 14-15 bits | Daily granularity recommended |
| Card ID | 10 bits | 50+ bits | 15-25 bits | User-dependent variability |
| Counter | 16 bits | 16 bits | 16 bits | 2-byte counter (unchanged) |
| **Total** | **39.5 bits** | **110.6 bits** | **55-71 bits** | **Domain separation focus** |

## Implementation Recommendations

### 1. Phased Rollout
```python
# Phase 1: Add version support (backward compatible)
def enhanced_hkdf_stream(seed_bytes, info_label, needed_bytes, 
                        card_id=None, version="v1.0", date=None):
    working_label = info_label
    
    # Add version if not default
    if version and version != "legacy":
        working_label += b"-" + version.encode('utf-8')
    
    # Add date if provided
    if date:
        working_label += b"-" + date.encode('utf-8')
    
    # Add card ID (existing logic)
    if card_id:
        working_label += b"-" + card_id.encode('utf-8')
    
    # Existing counter logic continues...
```

### 2. Configuration Options
```python
class LabelConfig:
    version_format: str = "semantic"  # "semantic", "numeric", "git", "timestamp"
    date_format: str = "epoch_days"   # "full_date", "epoch_days", "year_month"
    include_date: bool = True
    separator: str = "-"
    card_id_required: bool = False
```

### 3. Security Guidelines

**High-Security Applications**:
- Include all components: version + date + card_id
- Use semantic versioning for auditability
- Rotate based on expiration dates
- Validate label components before use

**Standard Applications**:
- Version + card_id (current + version)
- Optional date for periodic rotation
- Flexible card_id format for user convenience

**Low-Security/Testing**:
- Minimal format for backward compatibility
- Git hash versions for development tracking

## Migration Strategy

### 1. Backward Compatibility
- Default behavior unchanged (no version/date if not specified)
- Existing card IDs continue to work
- New features opt-in only

### 2. CLI Interface Updates
```bash
# Enhanced generation with new options
seeder generate grid --simple "test" --version "v1.0" --date "20251031" --id "banking.001"

# Backward compatible (unchanged)
seeder generate grid --simple "test" --id "banking.001"

# Development mode with git integration
seeder generate grid --simple "test" --dev-version --id "test.001"
```

### 3. API Changes
```python
# New enhanced API
SeedCardCrypto.generate_token_stream(
    seed_bytes, 
    num_tokens, 
    card_id="banking.001",
    version="v1.0",
    generation_date="20251031"
)

# Backward compatible API (unchanged)
SeedCardCrypto.generate_token_stream(seed_bytes, num_tokens, card_id="banking.001")
```

## Risk Assessment

### Security Risks
- **Low Risk**: Version and date information provide minimal attack surface
- **Medium Risk**: Card ID predictability (existing risk, not increased)
- **Mitigation**: Primary security still depends on seed strength, not label components

### Operational Risks
- **Low Risk**: Backward compatibility maintained
- **Medium Risk**: Increased complexity in label management
- **Mitigation**: Sensible defaults, comprehensive documentation

### Implementation Risks
- **Low Risk**: Changes are additive, not destructive
- **Medium Risk**: Testing matrix increases with new combinations
- **Mitigation**: Phased rollout, extensive test coverage

## Recommendations

### Immediate Implementation (Phase 1)
1. Add version parameter with default "v1.0"
2. Add optional date parameter
3. Maintain full backward compatibility
4. Update CLI to support new options

### Future Enhancement (Phase 2)
1. Make version mandatory for new generations
2. Add automatic date inclusion based on configuration
3. Enhanced card ID validation and suggestions
4. Git integration for development versions

### Long-term Evolution (Phase 3)
1. Deprecate legacy format (label only)
2. Add cryptographic hash of label components for integrity
3. Support for custom label templates
4. Integration with external key management systems

The proposed enhancements provide significant operational benefits while maintaining security properties and backward compatibility. The entropy contribution is meaningful for domain separation while keeping the primary security dependency on seed material strength.
