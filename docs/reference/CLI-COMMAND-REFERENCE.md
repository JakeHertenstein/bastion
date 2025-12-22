# Bastion CLI Command Reference

**Version**: 0.3.2
**Last Updated**: 2025-12-22

Complete reference for all `bsec` commands and options.

---

## Table of Contents

- [Installation & Initialization](#installation--initialization)
- [1Password Integration](#1password-integration)
- [YubiKey Management](#yubikey-management)
- [Entropy Generation](#entropy-generation)
- [Username Generation](#username-generation)
- [Reporting & Analysis](#reporting--analysis)

---

## Installation & Initialization

### bsec init

Initialize Bastion configuration and caches.

```bash
bsec init
```

**Options:**
- None

**Example:**
```bash
bsec init
# ✓ Configuration initialized
# ✓ Cache directories created at ~/.bsec/cache/
```

**See Also**: [Getting Started Guide](../getting-started/GETTING-STARTED.md)

### bsec show machine

Display machine UUID and identity information (v0.3.1+).

```bash
bsec show machine
```

**Output:**
- Machine UUID (SHA-512 hash of system serial/MAC)
- Hardware type detected
- 1Password sync status

**Example:**
```bash
bsec show machine
# Machine UUID: a3f8b2c...7e9d
# Hardware: macOS (Apple Silicon)
# 1P Synced: Yes (cache updated 2 hours ago)
```

---

## 1Password Integration

### bsec 1p sync

Synchronize vault data from 1Password to local cache.

```bash
bsec 1p sync vault [OPTIONS]
```

**Options:**
- `--full` - Full refresh (re-fetch all items)
- `--vault <NAME>` - Sync specific vault (default: all)

**Example:**
```bash
bsec 1p sync vault
# ✓ Synced 247 items from Private vault
# ✓ Cache updated (2,847 items total)
```

### bsec 1p check

Run security checks against 1Password vault.

```bash
bsec 1p check <check-type> [OPTIONS]
```

**Check Types:**
- `passkeys` - Validate passkey security (v0.3+)
- `breaches` - Check Watchtower breach exposure
- `2fa` - Analyze 2FA coverage across accounts

**Example:**
```bash
bsec 1p check passkeys
# ⚠ Items with risky passkeys: 3
#   - Service A (Software passkey on phone)
#   - Service B (Synced passkey)
# ✓ Hardware passkeys (safe): 12

bsec 1p check breaches
# ⚠ CRITICAL: 2 items exposed in breaches
#   - LinkedIn (2023 breach)
# ⚠ WARNING: 5 items with weak passwords
```

### bsec 1p analyze

Analyze risk and security posture.

```bash
bsec 1p analyze risk [OPTIONS]
```

**Options:**
- `--by-type` - Group by account type
- `--by-capability` - Group by capability
- `--export <FORMAT>` - Export to CSV, JSON

**Example:**
```bash
bsec 1p analyze risk
# Risk Summary:
#   CRITICAL: 2 items (exposed in breaches)
#   HIGH: 8 items (weak password or no 2FA)
#   MEDIUM: 24 items (single 2FA method)
#   LOW: 156 items
```

---

## YubiKey Management

### bsec 1p yubikey scan

Detect YubiKeys and read TOTP accounts.

```bash
bsec 1p yubikey scan [OPTIONS]
```

**Options:**
- `--serial <SN>` - Scan specific YubiKey
- `--update` - Save account list to 1Password
- `--force-refresh` - Bypass cache

**Example:**
```bash
bsec 1p yubikey scan
# YubiKey 9858158 (5 NFC)
#   Accounts: 32/64 slots
#   GitHub, Google, AWS, ...

bsec 1p yubikey scan --serial 9858158 --update
# ✓ Updated 1Password item with 32 accounts
```

### bsec 1p yubikey list

List all YubiKeys in 1Password vault.

```bash
bsec 1p yubikey list [OPTIONS]
```

**Options:**
- `--connected` - Only show currently connected devices
- `--with-accounts <N>` - Filter by account count

**Example:**
```bash
bsec 1p yubikey list
# YubiKey 9858158 (Primary) - 32 accounts
# YubiKey 3849201 (Backup)  - 32 accounts
# YubiKey 5821937 (Travel)  - 8 accounts
```

### bsec 1p yubikey status

Show current connection status and slot availability.

```bash
bsec 1p yubikey status [OPTIONS]
```

**Options:**
- `--serial <SN>` - Check specific device

**Example:**
```bash
bsec 1p yubikey status
# Connected YubiKeys:
#   9858158: ✓ Firmware 5.4.3, 32/64 OATH slots used
#   3849201: ✓ Firmware 5.4.3, 32/64 OATH slots used
#   5821937: ✓ Firmware 5.4.3, 8/32 OATH slots used
```

### bsec 1p yubikey provision

**[NEW in v0.3.1]** Provision TOTP accounts to YubiKey using profile-based selection.

```bash
bsec 1p yubikey provision --serial <SN> [OPTIONS]
```

**Options:**
- `--serial <SN>` *(required)* - Target YubiKey serial number
- `--profile <NAME>` - Profile name (overrides 1P setting)
- `--dry-run` - Show plan without executing (default)
- `--no-touch` - Disable touch requirement
- `--verbose` - Show detailed otpauth URIs

**Examples:**
```bash
# Preview provisioning plan
bsec 1p yubikey provision --serial 9858158 --profile Daily --dry-run
# Profile: Daily
# Capacity: 32/32 slots
# Accounts:
#   1. Amazon
#   2. AWS
#   ... (17 more)
# Touch required: Yes

# Provision with confirmation prompt
bsec 1p yubikey provision --serial 9858158 --profile Daily
# Continue with provisioning? [y/N] y
# ✓ Reset OATH app
# ✓ Added 18 accounts
# Next: Run 'bsec 1p yubikey scan --serial 9858158 --update' to verify

# Provision without touch (for backup devices)
bsec 1p yubikey provision --serial 3849201 --profile Backup --no-touch
```

**Workflow**: [YubiKey TOTP Provisioning Guide](../features/YUBIKEY-TOTP-PROVISIONING.md)

**Tag Format**: Use `Bastion/2FA/TOTP/YubiKey/Include/<Profile>` to include accounts

---

## Entropy Generation

### bsec generate entropy

Generate cryptographic entropy from hardware sources.

```bash
bsec generate entropy <source> [OPTIONS]
```

**Entropy Sources:**
- `yubikey` - HMAC-SHA1 from YubiKey challenge-response
- `infnoise` - Infinite Noise TRNG USB device
- `dice` - Physical dice rolls
- `combined` - XOR + SHAKE256 from multiple sources

**Options:**
- `--bits <N>` - Entropy size (default: 256)
- `--sources <LIST>` - For combined: comma-separated sources (e.g., `yubikey,infnoise`)
- `--save` - Save to 1Password vault
- `--verify` - Run ENT statistical tests

**Examples:**
```bash
# Generate from YubiKey (8KB)
bsec generate entropy yubikey --bits 8192

# Generate from multiple sources combined
bsec generate entropy combined --sources yubikey,infnoise --bits 32768 --save

# Generate from dice rolls (256 bits = 84 rolls)
bsec generate entropy dice --bits 256

# Generate and verify
bsec generate entropy combined --sources yubikey,infnoise --bits 2048 --verify
# ENT Analysis:
#   Entropy: 7.998 bits/byte ✓
#   Chi-squared: 245 (good)
#   Correlation: 0.002 (excellent)
```

**See Also**: [Entropy System Guide](../features/entropy/ENTROPY-SYSTEM.md)

---

## Username Generation

### bsec generate username

Generate deterministic usernames for privacy.

```bash
bsec generate username [domain] [OPTIONS]
```

**Arguments:**
- `domain` - Target service domain (e.g., `github.com`, `amazon.com`)
- If omitted, initializes generator with master entropy

**Options:**
- `--init` - Initialize with master entropy from 1Password
- `--no-save` - Show username without saving
- `--length <N>` - Custom username length

**Examples:**
```bash
# Initialize generator (one-time setup)
bsec generate username --init
# ✓ Master entropy loaded from 1Password
# ✓ Generator initialized

# Generate for a service
bsec generate username github.com
# Username: a7f8b2c9e3d5

# Generate for multiple services
bsec generate username amazon.com
bsec generate username paypal.com

# Verify determinism
bsec verify username github.com a7f8b2c9e3d5
# ✓ Verified: Username matches domain
```

**See Also**: [Username Generator Guide](../features/username/USERNAME-GENERATOR-GUIDE.md)

---

## Reporting & Analysis

### bsec report

Generate comprehensive security report.

```bash
bsec report [OPTIONS]
```

**Options:**
- `--format <FORMAT>` - Output format (text, json, csv)
- `--include-untagged` - Include items without Bastion tags
- `--output <PATH>` - Save to file

**Example:**
```bash
bsec report --format text
# Bastion Security Report
# Generated: 2025-12-22
#
# Summary:
#   Total items: 247
#   With tags: 224 (91%)
#   Untagged: 23
#
# 2FA Coverage:
#   FIDO2 Hardware: 180 (73%)
#   Passkey: 45 (18%)
#   TOTP: 156 (63%)
#   SMS: 12 (5%)
#
# Risk Distribution:
#   ...
```

### bsec audit

Audit command for security review.

```bash
bsec audit [OPTIONS]
```

**Options:**
- `untagged` - List items without Bastion tags
- `--include-private` - Include Private vault

**Example:**
```bash
bsec audit untagged
# Items without Bastion tags (23):
#   - Test Account 1
#   - Legacy Service
#   ... (21 more)
```

---

## Global Options

All commands support:

```
--verbose, -v      Enable verbose output
--debug            Enable debug logging
--help, -h         Show help
--version          Show version
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Command not found |
| 3 | Configuration error |
| 4 | 1Password connection error |
| 5 | Hardware error (YubiKey, etc.) |

---

## Command Quick Reference

| Task | Command |
|------|---------|
| Initial setup | `bsec init` |
| Sync 1Password | `bsec 1p sync vault` |
| List YubiKeys | `bsec 1p yubikey list` |
| Provision YubiKey | `bsec 1p yubikey provision --serial <SN>` |
| Verify provisioning | `bsec 1p yubikey scan --serial <SN> --update` |
| Generate entropy | `bsec generate entropy yubikey --bits 8192` |
| Generate username | `bsec generate username github.com` |
| Generate report | `bsec report` |

---

## See Also

- [Getting Started](../getting-started/GETTING-STARTED.md)
- [YubiKey TOTP Provisioning](../features/YUBIKEY-TOTP-PROVISIONING.md)
- [YubiKey Sync Guide](../features/yubikey/YUBIKEY-SYNC-GUIDE.md)
- [Tagging Guide](../security/BASTION-TAGGING-GUIDE.md)
