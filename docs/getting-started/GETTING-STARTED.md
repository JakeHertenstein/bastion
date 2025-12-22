# Getting Started with Bastion

> ⏱️ **Time Required:** ~10 minutes for basic setup, ~30 minutes for full configuration

This guide walks you through setting up Bastion from scratch. By the end, you'll have:
- ✅ Bastion CLI installed and working
- ✅ 1Password vault synced to local encrypted cache
- ✅ Hardware entropy pool generated
- ✅ Username generator initialized
- ✅ First status report generated
 - ✅ Option to generate offline seed cards (Seeder) for high‑entropy passwords without a manager

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Initial Setup](#initial-setup)
- [First Steps](#first-steps)
- [Verify Everything Works](#verify-everything-works)
- [What's Next](#whats-next)

---

## Prerequisites

### Required

| Requirement | Version | Check Command |
|------------|---------|---------------|
| **Python** | 3.11 - 3.14 | `python3 --version` |
| **1Password CLI** | v2.x | `op --version` |
| **1Password Account** | Any plan | Sign in via `op signin` |

### Optional (Recommended)

| Hardware | Purpose |
|----------|---------|
| **YubiKey** (5 series) | HMAC-SHA1 challenge-response for entropy |
| **Infinite Noise TRNG** | Hardware true random number generator |
| **Physical Dice** | Manual entropy input for air-gapped setups |

### Install 1Password CLI

```bash
# macOS (Homebrew)
brew install 1password-cli

# Verify installation
op --version

# Sign in (first time)
eval $(op signin)
```

---

## Installation

### Option 1: From PyPI (Recommended)

```bash
pip install bastion-security
```

### Option 2: From Source (Development)

```bash
git clone https://github.com/jakehertenstein/bastion.git
cd bastion
uv sync  # or: pip install -e packages/bastion
```

### Verify Installation

```bash
bsec --version
# Output: bastion-security, version 0.3.0
```

> 💡 **Tip:** Both `bsec` and `bastion` commands work. `bsec` is the primary command.

---

## Initial Setup

### Step 1: Initialize Configuration

```bash
bsec init
```

This creates `~/.bsec/config.toml` with default settings:
- Default vault: `Personal`
- Default entropy bits: `8192`
- Cache location: `~/.bsec/cache/`

**Custom initialization:**

```bash
bsec init --vault "Work" --entropy-bits 16384
```

### Step 2: Authenticate 1Password

```bash
# Sign in to 1Password CLI
eval $(op signin)

# Verify authentication
op vault list
```

### Step 3: Sync Vault Data

```bash
# First sync - fetches all Bastion-tagged items
bsec 1p sync vault
```

**Expected output:**

```
Syncing vault 'Personal'...
  Fetched 847 items
  Encrypted cache saved to ~/.bsec/cache/db.enc
✓ Sync complete in 12.3s
```

> ⚠️ **First sync can take 30-60 seconds** depending on vault size. Subsequent syncs are faster due to caching.

---

## First Steps

### Generate Initial Entropy (YubiKey)

If you have a YubiKey with HMAC-SHA1 configured:

```bash
# Generate 8192 bits (1KB) of entropy
bsec generate entropy yubikey --bits 8192
```

**Expected output:**

```
🔑 Collecting entropy from YubiKey...
   Serial: 12345678
   Challenges: 128
✓ Generated 8192 bits of entropy
  Pool ID: abc123-def456-...
  Stored in 1Password as "Entropy Pool: 2025-12-15"
```

### Generate Entropy Without YubiKey

```bash
# System RNG (always available)
bsec generate entropy system --bits 4096

# Physical dice rolls (manual input)
bsec generate entropy dice --bits 256
```

### Initialize Username Generator

```bash
# Creates a cryptographic salt stored in 1Password
bsec generate username --init
```

**Expected output:**

```
✓ Username salt initialized
  Salt stored in 1Password item: "Bastion Username Salt"
  Algorithm: HMAC-SHA3-512
  Ready to generate usernames!
```

### Generate Your First Username

```bash
# Generate a deterministic username for GitHub
bsec generate username github.com
```

**Expected output:**

```
Domain: github.com
Username: xk7m2p9n4w3q
  
✓ Username stored in 1Password item for github.com
  Label: Bastion/USER/SHA3/512:github.com:2025-12-15#VERSION=0.3.0&LENGTH=12|K
```

---

## Verify Everything Works

### Run Status Report

```bash
bsec 1p report status
```

**Expected output:**

```
📊 Password Rotation Status Report
═══════════════════════════════════

Total Accounts: 847
  Tier 1 (Critical):    23
  Tier 2 (Important):   156
  Tier 3 (Standard):    412
  Tier 4 (Low):         256

Rotation Status:
  ✓ Up to date:        612 (72%)
  ⚠ Due soon:          147 (17%)
  ✗ Overdue:           88 (10%)

Next Actions:
  1. Rotate 'Bank of America' (Tier 1, 45 days overdue)
  2. Rotate 'Gmail' (Tier 1, 12 days overdue)
  ...
```

### Check YubiKey Status

```bash
bsec 1p yubikey list
```

### Verify Sync Cache

```bash
# View cache info
ls -la ~/.bsec/cache/

# Expected files:
# db.enc          - Encrypted 1Password sync cache
```

---

## What's Next

### Daily Workflows

| Task | Command |
|------|---------|
| Check rotation status | `bsec 1p report status` |
| Scan for breaches | `bsec 1p check breaches` |
| Re-sync after 1Password changes | `bsec 1p sync vault` |
| Generate username for new account | `bsec generate username example.com` |
| Show dependency tree for an account | `bsec 1p analyze dependencies --account-uuid <uuid>` |

### Security Hardening

```bash
# Scan for breach exposure (HIBP with k-anonymity)
bsec 1p check breaches

# Analyze risk across all accounts
bsec 1p analyze risk
bsec 1p analyze dependencies --account-uuid <uuid>

# Show risk for a single account
bsec 1p analyze risk --account "Google"
bsec 1p analyze risk --account-uuid 123e4567-e89b-12d3-a456-426614174000

# Find items without proper tags
bsec 1p audit no-tags
```

### YubiKey Management

```bash
# Compare physical YubiKey OATH slots with 1Password
bsec 1p yubikey scan

# Update 1Password from connected YubiKey
bsec 1p yubikey scan --update
```

### Offline Passwords (Seeder)

Generate deterministic seed cards for high‑entropy passwords without a manager. See packages/seeder/README.md for usage and security notes.

Why Seeder: outcome-focused — high‑entropy offline passwords, validated by entropy and attack‑cost analysis.

```bash
# Example (offline password token grid)
python3 seeder generate grid --simple "my secure phrase"
```

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'bastion'"

**If your project is in iCloud Drive with Python 3.14:**

```bash
# The .venv must be symlinked outside iCloud
rm -rf .venv
mkdir -p ~/.local/venvs/bastion
ln -s ~/.local/venvs/bastion .venv
uv sync
```

See [Development Environment Setup](#development-environment-setup) for details.

### "op: command not found"

Install 1Password CLI:

```bash
brew install 1password-cli
```

### "Error: Not signed in to 1Password"

```bash
eval $(op signin)
```

### Slow Sync Performance

```bash
# Sync only specific tags for faster performance
bsec 1p sync vault --tags "YubiKey/Token"
bsec 1p sync vault --tier 1  # Only critical items
```

---

## Quick Reference Card

```bash
# Setup
bsec init                              # Initialize config
bsec 1p sync vault                     # Sync from 1Password

# Entropy
bsec generate entropy yubikey --bits 8192
bsec generate entropy combined --sources yubikey,infnoise

# Usernames
bsec generate username --init          # One-time setup
bsec generate username github.com      # Generate for domain

# Reports
bsec 1p report status                  # Rotation status
bsec 1p check breaches                 # Breach detection
bsec 1p analyze risk                   # Risk analysis
bsec 1p analyze dependencies --account-uuid <uuid>  # Dependency tree

# YubiKey
bsec 1p yubikey list                   # Show YubiKey items
bsec 1p yubikey scan                   # Compare with hardware
```

---

## Further Reading

| Topic | Guide |
|-------|-------|
| Entropy collection in depth | [ENTROPY-SYSTEM](../features/entropy/ENTROPY-SYSTEM.md) |
| Username generation details | [USERNAME-GENERATOR-GUIDE](../features/username/USERNAME-GENERATOR-GUIDE.md) |
| YubiKey sync workflows | [YUBIKEY-SYNC-GUIDE](../features/yubikey/YUBIKEY-SYNC-GUIDE.md) |
| Tagging your items | [BASTION-TAGGING-GUIDE](../security/BASTION-TAGGING-GUIDE.md) |
| Label format specification | [LABEL-FORMAT-SPECIFICATION](../reference/LABEL-FORMAT-SPECIFICATION.md) |
