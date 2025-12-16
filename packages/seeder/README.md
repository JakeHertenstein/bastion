# Seeder - Password Token Matrix Generator

> Part of the [Bastion](../README.md) security toolkit

A secure, deterministic password token generator that creates 10×10 matrices of cryptographic tokens from various seed sources. Designed for air-gapped systems with strong emphasis on reproducibility and security.

## ⚠️ Security Warning

**This tool is designed for online passwords with low lockout thresholds.**
- ❌ **NOT recommended for scenarios where offline attacks are likely**
- ✅ **Always use 2FA for sensitive accounts**
- ✅ **Appropriate for online services with rate limiting (3-5 login attempts)**
- ✅ **Best used with additional security layers**

## 🎯 Features

- **Web Interface**: Modern browser-based generator with matrix visualization and entropy analysis
- **Multiple Seed Sources**: BIP-39 mnemonics, simple phrases, SLIP-39 shares
- **Argon2id KDF**: Memory-hard key derivation resistant to GPU/ASIC attacks (configurable 64MB-2GB)
- **Multi-Base Systems**: Base10 (PIN), Base62 (alphanumeric), Base90 (full entropy)
- **Deterministic Generation**: Same seed + nonce always produces identical tokens
- **Cryptographic Security**: PBKDF2, HMAC-SHA512, Argon2id, rejection sampling
- **Modern CLI**: Professional interface with Rich formatting and bash completion
- **Password Entropy Analysis**: Analyze coordinate patterns for security strength
- **CSV Export**: Integration with password managers and matrix templates
- **Air-Gapped Design**: Works completely offline (Safari-compatible WASM)

## 🧮 Token Alphabets (Base Systems)

This tool supports three character alphabets for token generation:

### Base90 (Default - Maximum Entropy)
```
ABCDEFGHIJKLMNOPQRSTUVWXYZ
abcdefghijklmnopqrstuvwxyz  
0123456789
!@#$%&*+-=?^_|~()[]{}.:,;<>
```
- **90 characters** (~6.5 bits per character, ~26 bits per 4-char token)
- Excludes quotes, spaces, backslashes for copy/paste safety

### Base62 (Alphanumeric - Balanced)
```
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
```
- **62 characters** (~5.95 bits per character, ~23.8 bits per 4-char token)
- Works with systems that reject special characters

### Base10 (PIN Mode - Numeric Only)
```
0123456789
```
- **10 characters** (~3.32 bits per character, ~13.3 bits per 4-char token)
- For numeric PIN requirements

**Key points:**
- **Rejection sampling** eliminates modulo bias for uniform distribution
- Use `--base base10|base62|base90` in CLI or dropdown in web UI

## 🚀 Quick Start

### Installation

```bash
git clone <repository-url>
cd seed-card
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .
```

### Web Interface

Start the local web server to use the browser-based interface:

```bash
cd docs/web
npm install
npm run dev
```

Then open `http://localhost:3000` in your browser for the interactive matrix generator with:
- Real-time matrix generation from multiple seed sources
- Interactive entropy analysis and threat modeling
- Password pattern examples and coordinate selection
- Matrix export and verification tools

#### Install as Desktop App (PWA)

The web app can be installed as a standalone desktop application:

1. Open the web app in Chrome, Edge, or Safari
2. Click the **install icon** in the address bar (⊕ or "Install" prompt)
3. The app will be added to your desktop/dock

**PWA Features:**
- 📴 **Fully offline** - Works without network after first visit
- 🔒 **No storage** - No cookies, localStorage, or tracking
- 💻 **Standalone window** - Runs like a native app
- 🍎 **Safari-compatible** - Works on macOS and iOS

### CLI Usage

```bash
# Generate token matrices
python3 seeder generate grid --simple "my secure phrase"
python3 seeder generate grid --bip39 "abandon abandon abandon..."

# Quick demo
python3 seeder demo
```

### Bash Completion

```bash
# Install completion for your shell
python3 seeder install-completion

# Or manually for zsh
echo 'eval "$(_SEEDER_COMPLETE=zsh_source python3 seeder)"' >> ~/.zshrc
```

## � Flexible Date Labeling

**NEW**: Enhanced HMAC labeling with user-controlled date tracking for long-term card management.

### Features
- **User-Controlled Dating**: No forced quarterly rotation - cards work for their intended lifetime
- **Flexible Formats**: Support for year (`2025`), month (`2025-03`), specific dates (`2025-01-15`), or custom labels (`PROD-2025-BATCH-A`)
- **Perfect Determinism**: Same date always produces identical tokens (consistent for card lifetime)
- **Complete Isolation**: Different dates produce completely different tokens (perfect domain separation)
- **Enhanced Security**: Date variation adds ~30-40 bits entropy to HMAC labels

### Usage Examples

```bash
# Personal year-long card
python3 seeder generate grid --simple "MyBanking" --date "2025"

# Corporate monthly batch  
python3 seeder generate grid --bip39 "words..." --date "2025-03" --id "CORP-BATCH"

# Project-specific cards
python3 seeder generate grid --simple "DevTeam" --date "STAGING-2025-ALPHA"

# Emergency backup with specific date
python3 seeder generate grid --bip39 "emergency words..." --date "2025-01-15" --id "BACKUP"

# CSV export with date tracking
python3 seeder export csv CARD-001 --simple "test" --date "2025-Q1" --file cards.csv
```

### Enhanced HMAC Labels
When using date labeling, the system creates enhanced HMAC labels for complete transparency:

- **Simple**: `SEEDER-TOKENS` (legacy, no date)
- **With date**: `SEEDER-TOKENS-CARD|2025` (year-long card)
- **With ID + date**: `SEEDER-TOKENS-banking|2025-03` (monthly batch)
- **Custom project**: `SEEDER-TOKENS-CARD|STAGING-2025-ALPHA` (project tracking)

The system displays the exact HMAC label being used for full transparency and auditability.

## �📖 Command Reference

### Generate Commands
```bash
# Create token matrices
python3 seeder generate grid --simple "phrase"
python3 seeder generate grid --bip39 "word1 word2..." --passphrase "optional"
python3 seeder generate grid --slip39 "share1" "share2" "share3"

# With flexible date labeling
python3 seeder generate grid --simple "Banking" --date "2025"
python3 seeder generate grid --bip39 "words..." --date "2025-03" --id "CORP"

# With Argon2id KDF (memory-hard, default for --simple)
python3 seeder generate grid --simple "phrase" --memory 1024  # 1GB memory
python3 seeder generate grid --simple "phrase" --nonce "Kx7mQ9bL"  # Fixed nonce

# With different base systems
python3 seeder generate grid --simple "phrase" --base base10  # PIN codes
python3 seeder generate grid --simple "phrase" --base base62  # Alphanumeric
python3 seeder generate grid --simple "phrase" --base base90  # Full entropy (default)

# Legacy SHA-512 mode (skip Argon2)
python3 seeder generate grid --simple "phrase" --no-argon2

# Generate password patterns
python3 seeder generate patterns --simple "phrase" --pattern "A0 B1 C2 D3"

# Generate pronounceable words (for memorized password components)
python3 seeder generate words 6 --simple "Banking" --count 10
python3 seeder generate words 8 --bip39 "word1 word2..." --count 5

# Available options for grid generation:
#   --id TEXT        Card ID for HMAC labeling (default: "CARD")
#   --date TEXT      Date for enhanced HMAC labels (year/month/date/custom)
#   --base TEXT      Token alphabet: base10, base62, base90 (default: base90)
#   --nonce TEXT     8-char nonce for unique derivation (auto-generated if omitted)
#   --memory INT     Argon2 memory cost in MB (default: 2048 for 2GB)
#   --no-argon2      Use legacy SHA-512 instead of Argon2 for --simple
#   --show-secrets   Display sensitive cryptographic details
#   --color/--no-color    Control output colors
```

### Verify Commands
```bash
# Verify token sequences
python3 seeder verify tokens --simple "phrase" --tokens "XEHD J9cT oOad"
python3 seeder verify find --simple "phrase" --tokens "P7C4 iM6?"
```

### Export Commands
```bash
# Export to CSV
python3 seeder export csv --simple "phrase" --id "MATRIX001"
python3 seeder export csv --simple "phrase" --id "CARD-2025" --date "2025"
python3 seeder export onepassword --simple "phrase" --title "MyMatrix"
python3 seeder export onepassword --simple "phrase" --title "Banking-2025" --date "2025-Q1"

# Available options for exports:
#   --date TEXT      Date for enhanced HMAC labels (year/month/date/custom)
#   --file TEXT      Custom output filename
```

## 📊 CSV Export Format

### Secure CSV Schema
Seeder exports token grids in a secure CSV format optimized for 1Password integration and barcode scanning:

```csv
ID,Date,SHORT_HASH,SHA512,Tokens
MATRIX001,2025-10-26,7EF8BD,7ef8bd1f...,n_c> v^LC *=$P...
```

### Column Description
- **ID**: User-defined card identifier (e.g., "SYS.01.02", "MATRIX001")
- **Date**: Generation date in ISO format (YYYY-MM-DD)
- **SHORT_HASH**: First 6 characters of SHA512 hash in uppercase (Code39 barcode compatible)
- **SHA512**: Complete SHA-512 hash of seed bytes for integrity verification
- **Tokens**: 10×10 grid as newline-separated rows, space-separated tokens per row

### Security Features
- **🔒 No Seed Storage**: Seed material is never stored in CSV (security improvement)
- **🎯 Barcode Lookup**: SHORT_HASH enables 1Password vault searches via Code39 scanning
- **✅ Integrity Checking**: Full SHA512 hash verifies card authenticity
- **📱 Air-Gapped Export**: Complete offline generation without seed exposure
- **📋 Audit Trail**: Date and ID fields support rotation tracking

### 1Password Integration
```bash
# Export for 1Password with barcode-friendly ID
python3 seeder export csv --simple "phrase" --id "SYS001"
# Results in SHORT_HASH like "A1B2C3" for easy barcode scanning and vault lookup
```

### Analyze Commands
```bash
# Analyze password entropy for coordinate patterns
python3 seeder analyze entropy "A0 B1 C2 D3"
python3 seeder analyze entropy "B3 F7 D1 H5 A9" --online-rate 100 --offline-rate 10000000

# Compare multiple patterns
python3 seeder analyze compare "A0 B1 C2 D3" "B3 F7 D1 H5" "A0 A1 A2"

# Analyze composite password formats (tokens + memorized components)
python3 seeder analyze composite --fixed 2 --rolling 1 --memorized 6 --separators 4
python3 seeder analyze composite --fixed 1 --rolling 1 --memorized 4 --no-order

# Analyze threat scenarios (matrix compromised vs. secrets intact)
python3 seeder analyze threat --fixed 2 --rolling 1 --memorized 6
python3 seeder analyze threat --fixed 3 --memorized 0 --no-order
```

### Show Commands
```bash
# Display information
python3 seeder show grid --simple "phrase"
python3 seeder show info
python3 seeder demo
```

## 🔐 Seed Sources

### 1. Simple Phrases (SHA-512)
```bash
python3 seeder generate grid --simple "Banking Password Seed 2024"
```
- Direct SHA-512 hash of input phrase
- Fast and simple for testing
- 256 bits of entropy from hash function

### 2. BIP-39 Mnemonics (PBKDF2)
```bash
python3 seeder generate grid --bip39 "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```
- Standard cryptocurrency seed phrase format
- 12-24 words from BIP-39 wordlist
- Optional passphrase for additional security
- PBKDF2 key derivation with configurable iterations

### 3. SLIP-39 Shares (Shamir's Secret Sharing)
```bash
python3 seeder generate grid --slip39 "share1 words..." "share2 words..." "share3 words..."
```
- Threshold secret sharing scheme
- Reconstruct master secret from M-of-N shares
- Enhanced security through secret distribution

## 🧪 Base90 Technical Details

### Character Set
90 carefully selected characters avoiding problematic symbols:
```
ABCDEFGHIJKLMNOPQRSTUVWXYZ
abcdefghijklmnopqrstuvwxyz
0123456789
!@#$%&*+-=?^_|~()[]{}.:,;<>
```

**Excluded**: `"'` ` \` (quotes, space, backslash) for copy/paste safety

### Entropy Analysis
- **Characters**: 90 possible per position
- **Bits per character**: log₂(90) ≈ 6.49 bits
- **4-character tokens**: 6.49 × 4 ≈ 25.97 bits
- **Total combinations**: 90⁴ = 65,610,000
- **Security**: Suitable for online attacks with rate limiting

### 32-Bit Comparison
- **32 bits**: 2³² = 4,294,967,296 combinations
- **Optimal encoding**: Would need ⌈32 ÷ 6.49⌉ = 5 Base90 digits
- **Current 4 digits**: Efficient balance of security vs. usability

## 🏗️ Architecture

### Core Components

```
seed_sources.py    # BIP-39, SLIP-39, simple seed derivation
crypto.py          # HMAC stream generation, rejection sampling
grid.py            # 10×10 grid layout and coordinate management
seeder.py          # Modern CLI with Rich formatting and Typer
```

### Cryptographic Flow

1. **Seed Derivation**: Convert input → 64-byte seed
   - BIP-39: PBKDF2-HMAC-SHA512 (standard)
   - Simple: SHA-512 hash
   - SLIP-39: Shamir secret reconstruction

2. **Stream Generation**: HMAC-based expansion
   ```python
   HMAC-SHA512(seed_bytes, "TOKENS" + counter)
   ```

3. **Token Mapping**: Rejection sampling → Base90
   - Accept bytes 0-179 (uniform distribution)
   - Reject bytes 180-255 (eliminate bias)
   - 4 characters per token

4. **Grid Layout**: 10×10 coordinate system (A0-J9)

## 🔒 Security Model

### Threat Model
- **Primary Defense**: Online rate limiting (3-5 attempts before lockout)
- **Secondary Defense**: Two-factor authentication
- **Token Entropy**: ~26 bits per 4-character token
- **Grid Entropy**: 100 tokens × ~26 bits = ~2600 bits total entropy

### Appropriate Use Cases ✅
- Web services with login attempt limits
- Applications requiring 2FA
- Development and testing environments
- Non-critical account passwords

### Inappropriate Use Cases ❌
- Offline password storage (encrypted files, password managers)
- High-value targets without additional security
- Systems vulnerable to offline brute force
- Critical infrastructure requiring maximum security

## 🔍 Password Analysis

### Entropy Analysis Tool
The built-in analysis helps evaluate password strength using **RFC 4086** entropy standards for both simple coordinate patterns and composite formats:

```bash
# Analyze a coordinate pattern
python3 seeder analyze entropy "B3 F7 D1 H5 A9"

# Compare multiple patterns
python3 seeder analyze compare "A0 B1 C2" "B3 F7 D1 H5" "A0 A1 A2 A3"

# Analyze composite passwords (real-world usage)
python3 seeder analyze composite --fixed 2 --rolling 1 --memorized 6

# Threat analysis (matrix compromised scenarios)
python3 seeder analyze threat --fixed 2 --rolling 1 --memorized 6
```

### Threat Modeling
Analyzes security when your physical matrix is compromised:

**Scenarios:**
- **Full Security**: Normal operation (all components secret)
- **Compromised Matrix**: Tokens visible to attacker, memorized components still secret
- **Vulnerability Assessment**: Percentage of security lost if matrix is stolen

**What Remains Secret When Matrix Is Compromised:**
- **Coordinate Selection**: Which tokens you actually use (17-24 bits)
- **Memorized Words**: Dictionary words or custom phrases (28+ bits)
- **Separators**: Punctuation patterns (16-20 bits)
- **Component Ordering**: Sequence of password elements (2-6 bits)

**Example Output:**
```
🛡️  Full Security: 134.4 bits (EXCELLENT)
🚨  Compromised Matrix: 71.8 bits (STRONG) - 46.6% vulnerability
⏱️  Attack Time: 4.7 million years (online), 47 years (offline)
```

### Composite Password Formats
Real-world usage often combines tokens with memorized elements:

**Format**: `FixedToken1-FixedToken2-RollingToken-MemorizedWord!`

**Components:**
- **Fixed Tokens**: Static coordinates from your grid (e.g., B3, F7)
- **Rolling Tokens**: Coordinates that change quarterly/monthly (e.g., A0)
- **Memorized Word**: 4-8 character pronounceable word you generate (e.g., "Poquyo")
- **Separators**: Punctuation between components (e.g., "-", "!")

**Example**: `P7C4-iM6?-X9h!-Poquyo!` (23 characters, 84+ bits entropy)

### 🎲 Pronounceable Word Generation
The built-in word generator creates memorable words for the memorized component:

```bash
# Generate 6-character words for ~22 bits entropy
python3 seeder generate words 6 --simple "Banking" --count 5
# Output: Poquyo, Jkomiq, Hguyuv, Hxonon, Noxabw

# Generate 8-character words for ~30 bits entropy  
python3 seeder generate words 8 --simple "Banking" --count 3
# Output: Yezorebr, Qanejepw, Tqijejar
```

**⚠️ Important Distinction:**
- **BIP-39/SLIP-39 Words**: Use standardized 2048-word dictionaries for cryptocurrency seeds
- **Generated Words**: Custom pronounceable words for PASSWORD COMPONENTS (not mnemonic seeds)
- The word generator creates memorizable words like "Poquyo" or "Kdibob" for passwords
- BIP-39 seed phrases use words like "abandon", "ability", "about" from the official wordlist

**Word Features:**
- **Pronounceable patterns**: Consonant-Vowel combinations (CVCV, CCVC, etc.)
- **Deterministic**: Same seed always produces same words
- **Scalable entropy**: 3-12 character words (~11-35 bits)
- **Seed-based**: Uses same seed sources as token grids (simple/BIP-39/SLIP-39)

**Usage Tips:**
- 4-6 chars: Easy to remember (~15-22 bits)
- 6-8 chars: Good balance of security/memorability (~22-30 bits)
- 8+ chars: Higher security for sensitive accounts (~30+ bits)

### Security Factors
The analysis considers multiple entropy sources:

1. **Token Entropy**: Randomness from Base90 character generation (~26 bits per token)
2. **Pattern Entropy**: Unpredictability of coordinate selection (depends on combination count)
3. **Memorized Component**: Length and character set of user-provided words
4. **Rolling Timing**: Uncertainty from periodic token rotation
5. **Component Order**: Arrangement flexibility of password parts

**Effective entropy** is the sum of independent components.

### Security Guidelines (RFC 4086 Compliant)
- **Excellent Security (80+ bits)**: Approaching cryptographic key strength - best protection
- **Strong Security (64-80 bits)**: Very strong offline protection against advanced attacks  
- **Good Security (48-64 bits)**: Strong protection suitable for most high-value accounts
- **Basic Security (29-48 bits)**: Minimum for online attack protection (RFC 4086 threshold)
- **Insufficient Security (<29 bits)**: Below RFC 4086 minimum - not recommended

### Example Analysis Results
```
Simple Pattern: B3 F7 D1 H5 A9 (5 tokens)
- Effective Entropy: 26.2 bits (INSUFFICIENT)
- Online Attack: 10.5 hours average

Composite Format: 2 fixed + 1 rolling + 6-char word
- Total Entropy: 84.4 bits (EXCELLENT)  
- Online Attack: 404,664 billion years average
```

### Inappropriate Use Cases ❌
- Critical infrastructure requiring maximum security

## 📁 File Reference

### Core Files
- **`seeder.py`**: Modern CLI with Typer framework
- **`config.py`**: Configuration constants and parameters
- **`crypto.py`**: Cryptographic functions and rejection sampling
- **`grid.py`**: Grid generation and coordinate management
- **`seed_sources.py`**: BIP-39, SLIP-39, and simple seed handling

### Integration Files
- **`onepassword_integration.py`**: 1Password CLI integration
- **`password_patterns.py`**: Password pattern generation
- **`exceptions.py`**: Custom exception classes
- **`logging_config.py`**: Logging configuration

### Documentation
- **`design.md`**: Complete technical specification
- **`COMPLETION.md`**: Bash completion setup guide
- **`SECURITY_NAMING_UPDATE.md`**: Security warnings and naming changes

## 🧪 Testing

### Quick Verification
```bash
# Test basic functionality
python3 seeder demo

# Verify deterministic output
python3 seeder generate grid --simple "test" --format table
python3 seeder generate grid --simple "test" --format table
# (should produce identical grids)

# Verify token sequence
python3 seeder verify tokens --simple "test" --tokens "XEHD J9cT oOad"
```

### Development Testing
```bash
# Run test suite
python3 test_quick.py
python3 test_seed_card.py

# Performance analysis
python3 security_performance.py
```

### Dependencies

### Required
- **Python 3.8+**: Core language support
- **typer**: Modern CLI framework
- **rich**: Terminal formatting and tables

### Optional
- **1Password CLI**: For password manager integration
- **Label LIVE**: For card template rendering (Seed Card.lsc)

### Installation
```bash
pip install typer rich
# or
pip install -r requirements.txt  # if provided
```

## 🤝 Contributing

### Development Setup
```bash
git clone <repository-url>
cd seed-card
python3 -m venv venv
source venv/bin/activate
pip install typer rich
```

### Code Style
- Follow existing patterns and naming conventions
- Maintain deterministic behavior (no randomness in generation)
- Include comprehensive docstrings and type hints
- Test all changes thoroughly

### Security Considerations
- Never add real seed material to the repository
- Preserve cryptographic properties in any modifications
- Maintain backward compatibility for existing seed derivation
- Document any changes to security assumptions

## 📜 License

This project is licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/). See [../LICENSE](../LICENSE) for full terms.

- ✅ Personal, academic, and non-profit use allowed
- ✅ Modifications and derivatives allowed (non-commercial)
- ❌ Commercial use requires separate agreement

## ⚠️ Disclaimer

This tool generates deterministic password tokens based on cryptographic principles. While designed with security best practices, users must:

1. **Evaluate their threat model** before use
2. **Implement appropriate additional security measures** (2FA, rate limiting)
3. **Never use for high-security scenarios** without proper security analysis
4. **Keep seed material secure and confidential**

The authors assume no responsibility for security breaches or misuse of generated tokens.

---

**🎯 Ready for secure, deterministic password generation with proper understanding of the underlying cryptography.**

## 📚 Technical References

### Detailed Base90 Analysis

For a complete technical explanation of rejection sampling and modulo bias, see [REJECTION_SAMPLING_EXPLAINED.md](REJECTION_SAMPLING_EXPLAINED.md).

**The Modulo Bias Problem:**
When converting random bytes (0-255) to Base90 (90 characters), naive modulo creates bias:
- 256 ÷ 90 = 2.84... (not evenly divisible)
- Characters 0-75 appear 3 times each
- Characters 76-89 appear only 2 times each
- Result: 50% bias toward certain characters

**Rejection Sampling Solution:**
```python
def byte_to_symbol(byte_value: int, alphabet_size: int) -> Optional[int]:
    max_usable = (256 // alphabet_size) * alphabet_size  # 180 for Base90
    
    if byte_value < max_usable:
        return byte_value % alphabet_size  # Accept - now unbiased!
    else:
        return None  # Reject - get next byte
```

**Results:**
- Perfect uniform distribution (no bias)
- 29.7% rejection rate for Base90
- Industry standard approach (used in OpenSSL, Linux /dev/random)
- Cryptographically secure token generation

### Entropy Calculations

- **Base90 entropy**: log₂(90) ≈ 6.49 bits per character
- **4-character tokens**: 6.49 × 4 ≈ 25.97 bits
- **Total combinations**: 90⁴ = 65,610,000
- **32-bit comparison**: Would need 5 Base90 digits for full representation
- **Security model**: Designed for online attacks with rate limiting

### Implementation Details

**Stream Generation:**
```python
HMAC-SHA512(seed_bytes, "TOKENS" + counter)
```

**Grid Layout:**
- 10×10 coordinate system (A0 through J9)
- 100 total tokens per grid
- Row-major order generation

**Cryptographic Flow:**
1. Seed derivation (BIP-39/PBKDF2, Simple/SHA-512, SLIP-39/Shamir)
2. HMAC-based stream expansion
3. Rejection sampling to Base90 alphabet
4. 4-character token assembly
5. Grid coordinate mapping
