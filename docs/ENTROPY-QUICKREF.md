# Entropy System Quick Reference

## Commands

### Generate Entropy

#### From YubiKey (Hardware RNG)
```bash
# 512 bits with touch requirement (most secure)
bastion generate entropy yubikey --bits 512

# 256 bits without touch (faster)
bastion generate entropy yubikey --bits 256 --no-touch

# Custom slot
bastion generate entropy yubikey --bits 512 --slot 1
```

#### From Dice (True Random)
```bash
# 512 bits with 5 dice (198 rolls, ~16 minutes)
bastion generate entropy dice --bits 512 --dice 5

# 256 bits with 2 dice (faster, ~5 minutes)
bastion generate entropy dice --bits 256 --dice 2
```

#### Combined (Maximum Security)
```bash
# Combines YubiKey + Dice with SHA3-512
bastion generate entropy combined --bits 512
```

#### From Infinite Noise TRNG (Hardware TRNG)
```bash
# 512 bits (very fast, ~0.1 second)
bastion generate entropy infnoise --bits 512

# 2048 bits for extra security
bastion generate entropy infnoise --bits 2048
```

### List Pools
```bash
# Show unconsumed entropy pools
bastion show entropy

# Output: Table with Serial, Source, Size, Quality, Created, UUID
```

### Analyze Pool
```bash
# Run ENT statistical analysis
bastion show entropy --pool <uuid>

# Shows: Entropy bits/byte, Chi-square, Mean, π, Correlation, Quality
```

### Visualize Pool
```bash
# Attach PDF visualizations to 1Password item (default)
bastion visualize entropy <uuid>

# Or save to file instead
bastion visualize entropy <uuid> --output my_entropy.pdf

# Batch analyze all pools missing visualizations
bastion analyze entropy --all

# Force re-analyze (overwrites existing)
bastion analyze entropy --all --force
```

## Flags

| Flag | Description | Default |
|------|-------------|--------|
| `--source` | yubikey, dice, infnoise, or combined | Required |
| `--bits` | Target entropy bits (8192 minimum for ENT analysis) | 8192 |
| `--dice` | Dice per roll (1-5) | 5 |
| `--slot` | YubiKey slot (1 or 2) | 2 |
| `--no-touch` | Skip YubiKey touch requirement | false |
| `--analyze` | Run ENT analysis | true |
| `--output` | Visualization file path | auto |
| `--vault` | 1Password vault | Private |
| `--pool` | Pool UUID (for analyze/visualize) | Required |

## Entropy Sources

### YubiKey HMAC-SHA1
- **How it works**: Challenge-response using hardware-derived secret key
- **Entropy per response**: ~160 bits (20 bytes)
- **Responses for 512 bits**: 26 challenges (~52 seconds with touch)
- **Security**: Hardware RNG, tamper-resistant storage
- **Requires**: `ykman` installed, YubiKey connected

### Physical Dice
- **How it works**: Base-6 encoding of physical dice rolls
- **Entropy per roll**: log2(6^dice_count) bits
  - 1 die: 2.585 bits
  - 2 dice: 5.170 bits
  - 5 dice: 12.92 bits
- **Rolls for 512 bits**: 
  - 5 dice: 198 rolls (~16 minutes)
  - 2 dice: 496 rolls (~41 minutes)
- **Security**: True randomness from physics
- **Requires**: Casino-quality dice (fair)

### Combined
- **How it works**: XOR(SHAKE256(yubikey, max_len), SHAKE256(dice, max_len))
- **Security**: As strong as strongest source (XOR preserves entropy)
- **Output size**: Matches largest input source (not fixed 512 bits)
- **Time**: YubiKey time + Dice time + combining (~1 second)
- **Best for**: Maximum paranoia, defense in depth

### Infinite Noise TRNG
- **How it works**: Modular Entropy Multiplier using thermal noise
- **Throughput**: ~300,000 bits/second (whitened)
- **Time for 512 bits**: ~0.1 second
- **Security**: Hardware true randomness, open-source design
- **Requires**: `infnoise` CLI installed, device connected
- **Installation**: See [INFNOISE-INSTALLATION.md](INFNOISE-INSTALLATION.md)

## ENT Analysis

### Quality Ratings
- **EXCELLENT**: ≥7.99 bits/byte, 0.1 ≤ p-value ≤ 0.9
- **GOOD**: ≥7.9 bits/byte, 0.05 ≤ p-value ≤ 0.95
- **FAIR**: ≥7.5 bits/byte, 0.01 ≤ p-value ≤ 0.99
- **POOR**: Below FAIR thresholds

### Ideal Values
- **Entropy**: 8.0 bits/byte (maximum)
- **Chi-square p-value**: 0.5 (perfect uniformity)
- **Mean**: 127.5 (midpoint of 0-255)
- **Serial correlation**: 0.0 (no byte-to-byte correlation)

### Acceptance Criteria
Entropy is acceptable if:
- ✓ Entropy ≥ 7.5 bits/byte
- ✓ 0.01 ≤ p-value ≤ 0.99
- ✓ |correlation| < 0.1

## Storage Structure

### 1Password Item
- **Category**: Password
- **Title**: "Bastion Entropy Source #1" or "Bastion Entropy Derived #2"
- **Password**: Base64-encoded entropy
- **Tags**: Bastion/ENTROPY

### Native Sections (Title Case field names)
- **Pool Info**: Version, Serial Number, Pool Type, Source, Source Type, Derivation Method
- **Device Metadata**: Serial Number, Whitened, Collection Method (dynamic per source)
- **Entropy Sources**: Source 1, Source 2, ... (UUIDs for derived pools)
- **Size**: Bytes, Bits
- **Lifecycle**: Created At, Expires At, Consumed
- **Statistical Analysis**: Entropy Per Byte, Chi Square, Chi Square P-Value, Arithmetic Mean, Monte Carlo Pi, Monte Carlo Error Pct, Serial Correlation, Quality Rating (>= 1KB)

## Workflows

### Basic Workflow
```bash
# 1. Generate
bastion generate entropy yubikey --bits 512
# Output: Pool #1 created, UUID: abc123...

# 2. List
bastion show entropy
# Shows available pools

# 3. Analyze (optional)
bastion show entropy --pool abc123...

# 4. Visualize (optional)
bastion visualize entropy abc123...

# 5. Use for salt generation (future)
bastion generate username --init --entropy-source abc123...
```

### High-Security Workflow
```bash
# Use combined sources for maximum security
bastion generate entropy combined --bits 512 --dice 5

# Verify quality
bastion show entropy --pool <uuid>

# Visual inspection
bastion visualize entropy <uuid>

# Use if quality is EXCELLENT or GOOD
```

### Quick Testing Workflow
```bash
# Fast test with minimal entropy
bastion generate entropy yubikey --bits 256 --no-touch

# Or quick dice test
bastion generate entropy dice --bits 256 --dice 2
```

## Troubleshooting

### YubiKey not found
```bash
# Check ykman installed
which ykman

# Install if needed
brew install ykman  # macOS
apt install yubikey-manager  # Linux

# Check YubiKey connected
ykman list
```

### ENT not found
```bash
# Check ENT installed
which ent

# Install if needed
brew install ent  # macOS
apt install ent  # Linux
```

### Poor entropy quality
- Retry generation (may be statistical fluke)
- Try different source
- Use combined sources for best results
- Check dice are fair (casino quality)
- Verify YubiKey is genuine

### Import errors
```bash
# Reinstall dependencies
cd '/path/to/Security Architecture'
pip install -e .
```

## Time Estimates

| Source | Bits | Config | Time |
|--------|------|--------|------|
| YubiKey (touch) | 512 | Slot 2 | ~52s (26 touches) |
| YubiKey (no-touch) | 512 | Slot 2 | ~13s |
| YubiKey (touch) | 256 | Slot 2 | ~24s (12 touches) |
| Dice | 512 | 5 dice | ~16 min (198 rolls) |
| Dice | 512 | 2 dice | ~41 min (496 rolls) |
| Dice | 256 | 5 dice | ~8 min (99 rolls) |
| Combined | 512 | 5 dice + YK | ~17 min |

## Security Notes

### Do NOT
- ❌ Reuse consumed entropy pools
- ❌ Use expired pools (>90 days)
- ❌ Skip ENT analysis for production
- ❌ Use POOR quality entropy
- ❌ Share pool UUIDs publicly

### DO
- ✓ Mark pools as consumed after use
- ✓ Generate fresh entropy regularly
- ✓ Verify quality before use
- ✓ Use combined sources for critical operations
- ✓ Keep audit trail in 1Password notes

## Next Steps

### Integration with Username Generator
Coming soon:
```bash
# Generate entropy
bastion generate entropy combined --bits 512
# Returns: UUID abc123...

# Use for salt initialization
bastion generate username --init --entropy-source abc123...
# Derives salt from entropy pool using HKDF-SHA512
# Marks pool as consumed
```

### Pool Management
Coming soon:
```bash
# Prune old pools
bastion entropy prune --older-than 90d

# List consumed pools
bastion show entropy --include-consumed

# Export pool (for backup)
bastion entropy export --pool <uuid> --output entropy.bin
```
