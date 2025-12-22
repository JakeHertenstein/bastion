# Copilot Instructions for Bastion

## Purpose

Bastion is a comprehensive security management suite for 1Password featuring:
- Password rotation tracking with deterministic audit trails
- Deterministic username generation with hardware entropy
- Air-gapped cryptographic key generation (SLIP-39 with geographic distribution)
- Hardware entropy collection from YubiKey, Infinite Noise TRNG, dice rolls, and TPM
- Deep 1Password CLI v2 integration for secure persistent storage

The project is organized as a monorepo with multiple specialized packages.

## Quick Facts

- Main PyPI package: bastion-security (pip install bastion-security)
- Primary CLI: bsec (alias: bastion for backward compatibility)
- Current version: 0.3.1 (pre-1.0 development phase)
- Version source: VERSION file in repo root, dynamically read by all packages
- 1Password integration: All data stored in 1Password vaults via op CLI
- Documentation: docs/ directory; package-specific docs in packages/*/

## Monorepo Structure

Bastion uses a uv workspace with four specialized packages under packages/:

| Package | Purpose | Path | PyPI Name |
|---------|---------|------|-----------|
| bastion | Main CLI + password rotation, username generation, entropy | packages/bastion/ | bastion-security |
| bastion-core | Shared utilities (platform detection, hardware probing) | packages/core/ | bastion-core |
| bastion-airgap | Air-gapped SLIP-39 key generation system | packages/airgap/ | bastion-airgap |
| bastion-seeder | Seed card generator (CR80 password cards) | packages/seeder/ | bastion-seeder |

Development setup: install dependencies from workspace root:

```
uv sync
```

This installs all packages in editable mode. Individual packages can be installed separately for production use.

## Versioning (SemVer)

Bastion follows Semantic Versioning 2.0.0.

Format: MAJOR.MINOR.PATCH

| Component | When to Increment | Example |
|-----------|-------------------|---------|
| MAJOR | Breaking changes to CLI, config, or stored data formats | 1.0.0 → 2.0.0 |
| MINOR | New features, backward-compatible | 0.1.0 → 0.2.0 |
| PATCH | Bug fixes, documentation, refactoring | 0.1.0 → 0.1.1 |

Pre-1.0 rules (current phase):
- API and CLI may change between minor versions
- 0.x.y versions are for initial development
- Breaking changes can occur in 0.MINOR bumps

Version source of truth:
- Single source: VERSION file in repository root
- All packages read version dynamically via {attr = ...} in their pyproject.toml
- Tagging format: git tag v0.3.1

Release workflow:
1) Update VERSION file with new version
2) Create git tag: git tag v0.3.1
3) Push tag: git push origin-private v0.3.1
4) Create GitHub release from tag on private repo

Public repo sync (squash workflow):

```
./scripts/sync-to-public.sh "v0.3.1: Feature summary"
```

- Private repo (origin-private): Full commit history, WIP commits
- Public repo (public): Squashed releases only, clean history
- Always push to origin-private first, then sync to public

Breaking changes include:
- CLI command/option renames or removals
- 1Password field/section format changes
- Config file format changes
- Cache/database schema changes
- Tag format changes (Bastion/* hierarchy)

## Core Modules (bastion package)

| Module | Purpose |
|--------|---------|
| cli/ | CLI commands organized by domain (1p, generate, tags, etc.) |
| config.py | Cache paths and infrastructure |
| db.py | Encrypted cache and database management |
| entropy.py | Entropy pool management and combination |
| entropy_yubikey.py | YubiKey HMAC-SHA1 entropy collection |
| entropy_dice.py | Physical dice roll entropy collection |
| entropy_infnoise.py | Infinite Noise TRNG integration |
| username_generator.py | Deterministic username generation |
| models.py | Pydantic models for accounts and passwords |
| op_client.py | 1Password CLI wrapper |
| tag_operations.py | Hierarchical tag management |
| linking.py | 1Password field/section linking with passkey safety checks |

## Cache and Data Storage

All cache files are stored in ~/.bsec/cache/ (auto-migrates from legacy ~/.bastion/):
- db.enc - Fernet-encrypted 1Password sync cache
- yubikey-slots.json - YubiKey OATH slot mappings
- password-rotation.json - Rotation tracking database

Backups stored in ~/.bsec/backups/.

Configuration in bastion/config.py provides:
- get_yubikey_cache_path() - Auto-migrates from legacy ./yubikey-slots-cache.json
- get_password_rotation_db_path() - Auto-migrates from legacy ./password-rotation-database.json
- get_encrypted_db_path() - Auto-migrates from legacy ~/.bastion/cache.db.enc

### Machine UUID System (v0.3.1+)

Stable machine identifier for multi-machine key rotation resilience:

**UUID Generation (Priority Order):**
1. macOS: SHA-512 hash of system serial number
2. Linux/Windows: SHA-512 hash of primary MAC address
3. Fallback: Generated UUID (only if hardware methods fail)

**UUID Storage:**
- Computed on-demand (no file created unless fallback needed)
- Stored in 1Password key entry `machine_uuid` field on key creation/rotation
- Persisted in cache metadata `machine_uuid` field on every sync
- Command to view: `bsec show machine`

**Auto-Recovery on UUID Mismatch:**
- If cache UUID doesn't match 1P key entry UUID:
  - Backs up old cache to `~/.bsec/backups/db.enc.bad-<timestamp>`
  - Initializes fresh database
  - Syncs from 1Password
  - Updates 1P key entry with current machine UUID
- Prevents decryption with wrong key across machines
- Preserves data via timestamped backups

See docs/MULTI-MACHINE-CACHE-SYNC.md for detailed guide (TODO: create doc).

## CLI Commands

```
# Initialize configuration
bsec init

# Machine identity (v0.3.1+)
bsec show machine                    # Display machine UUID and identity

# Entropy generation
bsec generate entropy yubikey --bits 8192
bsec generate entropy combined --sources yubikey,infnoise --bits 32768
bsec generate entropy dice --bits 256

# Username generation
bsec generate username --init
bsec generate username github.com
bsec generate username github.com --no-save
bsec verify username github.com <username>

# 1Password integration
bsec 1p sync vault
bsec 1p check passkeys
bsec 1p check breaches
bsec 1p analyze risk

# Reporting
audit
bsec report
bsec audit untagged

# YubiKey management
bsec yubikey cache-slots
bsec yubikey cache-slots --force-refresh
bsec refresh yubikey
bsec clean yubikey

# Tag management
bsec tags list
bsec tags apply <item-id> --tag "Bastion/Type/Bank"

# Signature chain and session management
bsec sigchain list
bsec session list
bsec ots generate
```

## Architecture Patterns

### 1Password Field Conventions
- Section format: Section Name.Field Name[type]=value
- Field types: text, date, concealed
- Tags: Hierarchical format Bastion/Category/Subcategory

### Entropy System
- Sources: YubiKey HMAC, Infinite Noise TRNG, dice rolls, system RNG, airgap hardware
- Combination: XOR + SHAKE256 extension (preserves max entropy size)
- Storage: Base64 in 1Password password field with metadata sections
- Analysis: ENT tool for statistical validation

### Cryptographic Standards (v0.3.1)
| Category | Algorithm | Purpose |
|----------|-----------|---------|
| Entropy stretching | SHAKE256 | XOF for extending entropy pools |
| Key derivation | HKDF-SHA512 | Deriving keys from master entropy |
| Content hashing | SHA-512 | Usernames, labels, integrity checks |
| Authenticated hashing | HMAC-SHA512 | YubiKey challenge-response |
| Encryption | Fernet | Local cache encryption |
| LUKS2 disk | AES-XTS-256 | Airgap microSD encryption |
| Secret sharing | SLIP-39 | Airgap backup distribution (3-of-5) |

See docs/CRYPTO-FUNCTION-MATRIX.md for complete documentation.

### Bastion Labels
Format: Bastion/<Category>/<Type>/<Algorithm>:<data>:<date>#PARAMS|CHECK
Parameters use URL query-string notation. VERSION holds Bastion tool SemVer.
Examples:
- Bastion/SALT/HKDF/SHA2/512:username-generator:2025-11-30#VERSION=0.3.1
- Bastion/USER/SHA2/512:github.com:2025-11-30#VERSION=0.3.1&LENGTH=16|K
- Bastion/Airgap/CARD/SECRETS:home.master:2025-12-09#VERSION=1|M

See docs/LABEL-FORMAT-SPECIFICATION.md for complete specification.

## Airgap Package

The bastion-airgap package implements a security-focused air-gapped cryptographic key generation system using a Libre Computer Sweet Potato (AML-S905X-CC-V2) SBC with geographic backup distribution.

### Hardware Platform
- SBC: Libre Computer Sweet Potato AML-S905X-CC-V2 (2GB RAM, quad-core ARM Cortex-A53)
- CRITICAL: Must verify NO wireless hardware before deployment
- Storage: 7x SanDisk Industrial MLC 8GB microSD cards (6 system + 1 copy/temp)
- Boot: Internal microSD slot (Card 1 - Live OS)
- Entropy Source: Infinite Noise USB HWRNG + custom CLI toolkit with ENT validation
- Status Indication: 3.3V active buzzer on GPIO17

### USB Port Configuration
```
Port 1 (OTG): Infinite Noise HWRNG (direct connection)
Port 2:       Atolla 7-Port USB Hub (powered via USB-to-DC barrel cable)
              ├─ Hub Port 1-5: Card readers (Cards 2-6)
              ├─ Hub Port 6:   Card reader (Copy/Temp operations)
              └─ Hub Port 7:   USB Camera (QR codes)
Port 3:       Keyboard (wired USB, direct connection)
Port 4:       Mouse (wired USB, direct connection)
```

### 6-Card Domain Architecture
| Card | Domain | Encryption | FS Protection | Color |
|------|--------|------------|---------------|-------|
| 1 | Live OS | None | SquashFS (RO) | GREEN |
| 2 | Scratch | None | tmpfs (RAM) | GREEN |
| 3 | SLIP-39 + KEKs/DEKs | LUKS2 | chattr +i | RED |
| 4 | Backup Data | LUKS2 | None | ORANGE |
| 5 | Audit + Metadata | LUKS2 (optional) | chattr +a (logs), +i (docs) | YELLOW |
| 6 | Parity/Recovery | None | chattr +i | YELLOW |

### Airgap Security Conventions

#### ⚠️ Important: Operational Isolation Tiers vs Risk Analysis (Removed in v0.3.1)

**KEEP**: Operational Isolation Tiers (below) define legitimate hardware security boundaries for airgap operations.

**REMOVED**: Risk Analysis Tiers (Tier 1/2/3 for accounts) were deprecated in v0.3.0 and removed in v0.3.1. These have been replaced with qualitative RiskLevel enum: CRITICAL/HIGH/MEDIUM/LOW, computed from account capabilities, 2FA strength, and security controls. Do NOT add back tier-based risk classification—use RiskLevel enum for all account risk assessment.

#### Operational Isolation Tiers
```
TIER 1 (Complete Isolation):
  Operations: Entropy generation, master key generation
  Connections: Power bank + Infinite Noise HWRNG only
  Enforcement: Hard block if wireless detected (no override)
  NO HDMI, NO USB hub during these operations

TIER 2 (Minimal Connections):
  Operations: SLIP-39 generation, KEK generation
  Connections: Add HDMI (display only) + Card 5 (Audit)

TIER 3 (Normal Operations):
  Operations: QR code display, verification, backup
  Connections: All peripherals as needed
```

#### Hardware Verification
- Boot: Warning banner, requires explicit CONTINUE input to proceed
- Tier 1: Hard block with no override
- Detection checks: /sys/class/net/wlan*, /sys/class/net/wlp*, rfkill list, USB vendor IDs (Ralink/Realtek/Atheros/Intel)

#### Data Transfer
- Inbound: SD cards with physical write-protect switch OR QR codes via USB camera
- Outbound: QR codes displayed on monitor
- Error Correction: Use QR level H (30% recovery)
- Max Chunk Size: 2KB per QR code
- NEVER: Use bidirectional USB drives

#### QR Code Multi-Part Protocol
```
BASTION:seq/total:data
```
Example for a 5KB GPG message:
```
BASTION:1/3:<base64_chunk_1>
BASTION:2/3:<base64_chunk_2>
BASTION:3/3:<base64_chunk_3>
```
Implementation:
```python
from airgap.qr import split_for_qr, reassemble_qr_parts
parts = split_for_qr(gpg_message, max_bytes=2000)
for part in parts:
    display_qr(part.to_qr_string())
data = reassemble_qr_parts(collected_parts)
```

#### GPG Key and Salt Transfer Workflow
```
AIRGAP                              MANAGER
┌─────────────────┐                 ┌─────────────────┐
│ 1. keygen master│                 │                 │
│    (ENT-verified│                 │                 │
│     entropy)    │                 │                 │
├─────────────────┤                 │                 │
│ 2. export pubkey│ ────QR─────────▶│ import pubkey   │
│    --qr         │                 │                 │
├─────────────────┤                 │                 │
│ 3. export salt  │ ────QR─────────▶│ import salt     │
│    -r <KEY_ID>  │  (encrypted)    │ (decrypt + 1PW) │
└─────────────────┘                 └─────────────────┘
```

CLI Commands:
```
# On airgap
airgap keygen master --algorithm rsa4096 --name "Name" --email "email"
airgap keygen subkeys
airgap keygen transfer-to-yubikey
airgap backup create --device /dev/sdX
airgap export pubkey --qr
airgap export salt --recipient <KEY_ID> --bits 256

# On manager
bastion import pubkey
bastion import salt
bastion generate username --init
```

#### Airgap Cryptographic Standards
- Encryption: LUKS2 with AES-XTS-256, Argon2id PBKDF
- Hashing: SHA-512 for key derivation, SHA-256 for checksums
- Secret Sharing: SLIP-39 (5 shares, 3-of-5 threshold)
- Minimum Entropy: 2000 bits required before key operations
- Secure Erase: Cryptographic erase via cryptsetup luksErase

#### Filesystem Protection
- SquashFS: Read-only filesystem for Live OS (Card 1)
- chattr +i: Immutable files (Cards 3, 5 docs, 6)
- chattr +a: Append-only audit logs (Card 5 logs)
- mount -o ro: Read-only mounts when appropriate
- tmpfs: RAM-only scratch space (Card 2)

### Airgap Code Generation Guidelines

#### When writing shell scripts
- Use absolute paths (no relative)
- Verify entropy >= 2000 bits before critical operations
- Append-only audit logging to /mnt/audit/operations/operations.log
- Secure mount options: rw,noexec,nosuid,nodev for writable mounts

#### When working with LUKS encryption
- Use cryptsetup luksOpen/Close
- Mount with noexec,nosuid
- Unmount and close cleanly

#### Filesystem protection
- Use chattr +i for immutable
- Use chattr +a for append-only logs

#### Par2 parity files
- par2create -r10 -n7 /mnt/parity/card3.par2 /mnt/slip39/*
- par2verify /mnt/parity/card3.par2
- par2repair /mnt/parity/card3.par2

#### Buzzer status patterns (GPIO17)
- Entropy start: 2 medium beeps
- Entropy complete: 3 long beeps
- Key gen complete: 1 very long beep
- Error: 5 rapid beeps

#### Backup verification (checksums + signatures)
- sha256sum * > checksums.txt
- gpg --detach-sign --armor checksums.txt
- Verify signature + checksums annually; log to /mnt/audit/verification.log

#### Encrypted microSD backup (from SLIP-39)
- LUKS2 AES-XTS-256, PBKDF Argon2id
- Derive key from SLIP-39 master secret (conceptual PBKDF2 placeholder)

### Airgap Geographic Distribution
- 5 sites: Primary (home safe), Bank A, Bank B, Trusted (Bob), Offsite (Carol)
- Recovery: any 3 of 5 SLIP-39 splits
- Package contents per site: 1x SLIP-39 split (metal), 1x full card set (encrypted microSD), 1x recovery doc, tamper-evident packaging
- Annual verification of flash media and seals

### Airgap Physical Security
- Storage: Fireproof safe + dual-layer Faraday bag
- Tamper evidence: Numbered seals, UV markings, photographed
- Perimeter: 100ft control at home
- Power: 20,000mAh power bank; wired keyboard/mouse only
- Tamper-evident packaging: desiccant, anti-static, clear inner bag, UV marks, opaque outer bag
- UV protocol: mark seals, photograph, verify at checks

### Airgap Do NOT
- Generate keys without entropy >= 2000 bits
- Use bidirectional USB drives
- Update OS in place (use golden image)
- Store passphrases digitally
- Connect HDMI during Tier 1
- Use phone cameras for QR
- Run network commands
- Trust physical write-protect switches
- Use wireless keyboards/mice
- Store all SLIP-39 shares together
- Skip annual verification
- Use clear bags as outer layer
- Skip UV photo documentation

## Seeder Package

The bastion-seeder package generates high-quality seed phrase cards (CR80 password cards) for offline storage of recovery phrases.

Features:
- Deterministic seed card generation with hardware entropy
- Multi-format support (BIP39, SLIP39, raw entropy)
- Custom branding and security markings
- Tamper-evidence integration with seals

Documentation: packages/seeder/README.md and packages/seeder/docs/

Version: Follows parent Bastion version (currently 0.3.1)

## Bastion-Core Package

The bastion-core package provides platform detection and hardware probing utilities used by other packages.

Capabilities:
- Platform detection (macOS, Linux, Windows, ARM)
- Hardware detection (YubiKey, Infinite Noise TRNG, TPM availability)
- Network/air-gap detection
- Zero external dependencies (stdlib only)

Used by:
- bastion (entropy ops, YubiKey detection)
- bastion-airgap (airgap validation, hardware inventory)
- bastion-seeder (platform helpers)

## Development Guidelines

### Development Environment Setup

CRITICAL - Python 3.14 + iCloud Drive incompatibility:
- iCloud sets UF_HIDDEN on files beginning with _
- uv sync writes .pth files like _bastion_security.pth
- Python 3.14 skips hidden .pth, causing ModuleNotFoundError

Solution: .venv is a symlink outside iCloud:

```
.venv -> ~/.local/venvs/bastion
```

If ModuleNotFoundError:
- Check symlink: ls -la .venv
- Recreate: rm -rf .venv; mkdir -p ~/.local/venvs/bastion; ln -s ~/.local/venvs/bastion .venv; uv sync

For new machines: create venv outside iCloud, symlink, run uv sync.

### Workspace Development Workflow

```
uv sync
uv run pytest tests/
uv run pytest packages/bastion/tests/
uv run pyright packages/bastion/
uv run ruff check packages/bastion/
```

Package interdependencies:
- bastion -> bastion-core
- bastion-airgap -> bastion-core
- bastion-seeder independent (optionally uses bastion-core)

Test dependents when changing bastion-core.

### Security Requirements
- No hardcoded secrets
- Determinism for username and entropy operations
- Offline capability for core crypto
- 1Password for persistence
- Airgap isolation must be verifiable

### 1Password CLI Limitations
CRITICAL - Passkey Data Loss Bug (see docs/PASSKEY-SAFETY.md):
- op item get --format json omits passkeys
- op item edit <uuid> - will delete passkeys
- Items tagged Bastion/2FA/Passkey/Software are at risk
- Use field assignment syntax: op item edit <uuid> "field[type]=value"
- linking.py blocks unsafe edits when tag present

### Code Conventions
- Type hints everywhere
- Google-style docstrings for public functions
- Use typer.Exit(1) for CLI errors; raise exceptions for library errors
- Rich console output
- Use absolute imports for cross-package code

### Testing
- Tests in tests/ and packages/*/tests/
- Mock 1Password CLI for unit tests
- Integration tests require 1Password auth
- Skip integration: pytest -m 'not integration'

## File Patterns to Avoid Committing
- output/
- docs/internal/
- docs/private/
- Legacy data files (now in ~/.bsec/cache/): backup-*.json, *-salts.json, password-rotation-database.json, yubikey-slots-cache.json, yubikey_migration.log.json

## Label Format Reference

```
Bastion/<Category>/<Type>/<Algorithm>:<data>:<date>#PARAMS|CHECK
```

Categories: SALT, USER, Airgap, Entropy, etc.
Types: HKDF, SHA2, CARD, HWRNG, etc.
Algorithms: Algorithm identifier (e.g., SHA2, AES-XTS)
Parameters: URL query notation (e.g., VERSION=0.3.1&LENGTH=16)
Check: Single character checksum or validation marker

See docs/LABEL-FORMAT-SPECIFICATION.md for details.

## Documentation References

Core docs in docs/:
- GETTING-STARTED.md
- CRYPTO-FUNCTION-MATRIX.md
- LABEL-FORMAT-SPECIFICATION.md
- ENTROPY-SYSTEM.md
- USERNAME-GENERATOR-GUIDE.md
- AIRGAP-DESIGN-DECISIONS.md
- AIRGAP-CARD-PROVISIONING.md

Package docs:
- packages/bastion/README.md
- packages/airgap/README.md
- packages/seeder/README.md
- packages/core/README.md
