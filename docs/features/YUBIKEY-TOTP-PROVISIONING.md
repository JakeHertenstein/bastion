# YubiKey TOTP Provisioning Guide

**Version**: 0.3.2+  
**Status**: Stable  
**Last Updated**: 2025-12-22  
**Quick Reference**: [YUBIKEY-TOTP-PROVISIONING-QUICKREF.md](YUBIKEY-TOTP-PROVISIONING-QUICKREF.md)

## Overview

Automatically provision TOTP accounts from 1Password to YubiKeys using profile-based selection. This ensures:
- **1Password as source of truth**: All TOTP secrets stay in 1Password
- **Profile-based targeting**: Different YubiKeys get different account sets
- **Deterministic ordering**: Alphabetical sort ensures consistent slot assignment
- **Capacity safety**: Prevents overfilling device slots (32 vs 64)
- **Dry-run safety**: Preview changes before execution
- **Automatic verification**: Scan updates 1Password after provisioning

---

## Quick Start

### 1. Set YubiKey Profile

Add a "TOTP Configuration" section to each YubiKey item in 1Password:

| Field | Example | Notes |
|-------|---------|-------|
| **Profile** | `Daily`, `Backup`, `Travel` | Name of the profile |
| **Capacity** | `32` or `64` | Device slot limit |

### 2. Tag Accounts for Inclusion

On each account with TOTP, add tags to include it in specific profiles:

```
Bastion/2FA/TOTP/YubiKey/Include/Daily
Bastion/2FA/TOTP/YubiKey/Include/Backup
```

Optionally exclude from specific profiles:

```
Bastion/2FA/TOTP/YubiKey/Exclude/Travel
```

### 3. Preview Provisioning Plan

```bash
bsec 1p yubikey provision --serial 12345678 --dry-run
```

Output shows:
- Account list sorted alphabetically
- Capacity status (e.g., "18/32 slots")
- Full `ykman` commands to be executed

### 4. Provision YubiKey

```bash
bsec 1p yubikey provision --serial 12345678
```

This will:
1. Reset the OATH application (clears existing accounts and password)
2. Add all included accounts in alphabetical order
3. Require confirmation before executing
4. Prompt to verify with `bsec 1p yubikey scan --serial 12345678 --update`

### 5. Verify Provisioning

```bash
bsec 1p yubikey scan --serial 12345678 --update
```

This scans the YubiKey and updates 1Password with the actual slot contents.

---

## Command Reference

### Provision a YubiKey

```bash
bsec 1p yubikey provision --serial <SERIAL> [OPTIONS]
```

**Options:**
- `--profile <NAME>` - Override profile from 1Password
- `--dry-run` - Show plan without executing (default behavior now)
- `--no-touch` - Disable touch requirement (default: require touch)

**Examples:**
```bash
# Show provisioning plan for Daily profile
bsec 1p yubikey provision --serial 9858158 --profile Daily --dry-run

# Provision with touch enabled (default)
bsec 1p yubikey provision --serial 9858158 --profile Daily

# Provision without touch requirement
bsec 1p yubikey provision --serial 9858158 --profile Daily --no-touch

# Override profile at runtime
bsec 1p yubikey provision --serial 9858158 --profile Backup
```

---

## Profile Strategy

### Recommended Profiles

| Profile | Use Case | Touch | Notes |
|---------|----------|-------|-------|
| **Daily** | Everyday carry | Yes | Primary device, requires physical confirmation |
| **Backup** | Safe storage | No | Secondary device kept secure |
| **Travel** | Limited accounts | Yes | Subset of critical accounts only |
| **Work** | Business accounts | Yes | Work-specific services |

### Tag Placement Examples

```
Account: GitHub
├─ Bastion/2FA/TOTP/YubiKey/Include/Daily
└─ Bastion/2FA/TOTP/YubiKey/Include/Backup

Account: AWS (Personal)
├─ Bastion/2FA/TOTP/YubiKey/Include/Daily
├─ Bastion/2FA/TOTP/YubiKey/Include/Backup
└─ Bastion/2FA/TOTP/YubiKey/Exclude/Travel

Account: AWS (Work)
├─ Bastion/2FA/TOTP/YubiKey/Include/Work
└─ Bastion/2FA/TOTP/YubiKey/Exclude/Travel
```

---

## How It Works

### Provisioning Flow

```
1. User selects YubiKey and profile
   ↓
2. Load profile from YubiKey item ("TOTP Configuration.Profile")
   ↓
3. Find all accounts with Bastion/2FA/TOTP/YubiKey/Include/<Profile>
   ↓
4. Filter out accounts with Bastion/2FA/TOTP/YubiKey/Exclude/<Profile>
   ↓
5. Extract TOTP secrets from 1Password OTP fields
   ↓
6. Build otpauth:// URIs (use 1P URI if present, else construct)
   ↓
7. Sort alphabetically by issuer then username
   ↓
8. Validate against device capacity (32 or 64 slots)
   ↓
9. Display dry-run plan with ykman commands
   ↓
10. Prompt for confirmation
    ↓
11. Execute: ykman oath reset --force
    ↓
12. For each account: ykman --device <SN> oath accounts uri '<otpauth>' --touch
    ↓
13. Done! Prompt to scan and verify
```

### otpauth:// URI Handling

Bastion automatically handles two formats:

**1. 1Password-provided otpauth:// URI**
- If the OTP field contains a full `otpauth://...` URI, use it directly
- Preserves all parameters from 1Password

**2. Base32 secret reconstruction**
- If the OTP field contains only the secret, construct a standards-compliant URI:
  ```
  otpauth://totp/<Issuer:Account>?secret=<SECRET>&issuer=<Issuer>&digits=6&period=30
  ```
- Label and issuer are properly URL-encoded

---

## Capacity Management

### Detecting Overflow

If more accounts are selected than the device can hold:

```
Error: Too many accounts (45) for device capacity (32)
Refine profile inclusion/exclusion tags to fit within capacity.
```

**Solution**: Adjust tags to exclude lower-priority accounts:

```bash
# Add exclude tag to work accounts on daily carry
Bastion/2FA/TOTP/YubiKey/Exclude/Daily

# Create a separate Work profile with limited accounts
Bastion/2FA/TOTP/YubiKey/Include/Work
```

### Auto-Detection of Device Capacity

If the "TOTP Configuration.Capacity" field is empty:
1. Bastion detects device model via `ykman info`
2. Displays detected capacity (32 or 64)
3. Optionally saves to 1Password for future runs

---

## Troubleshooting

### Issue: "No TOTP profile configured"

**Cause**: YubiKey item missing "TOTP Configuration.Profile" field.

**Solution**:
1. Open YubiKey item in 1Password
2. Add "TOTP Configuration" section (if not present)
3. Add field: `Profile[text]` with value (e.g., "Daily")
4. Save and retry

### Issue: "No accounts found for profile 'Daily'"

**Cause**: No accounts tagged with `Bastion/2FA/TOTP/YubiKey/Include/Daily`.

**Solution**:
1. Check which accounts should be in this profile
2. Add tag: `Bastion/2FA/TOTP/YubiKey/Include/Daily`
3. Run sync: `bsec 1p sync vault`
4. Retry provisioning

### Issue: ykman says "URI seems to have the wrong format"

**Cause**: TOTP secret is malformed or contains invalid characters.

**Solution**:
1. Verify the secret in 1Password is valid base32
2. Check that the account issuer/username don't contain special characters that need escaping
3. If using a 1Password-provided otpauth URI, verify it starts with `otpauth://`
4. Run with verbose: `bsec 1p yubikey provision --serial <SN> -vv` to see URI construction

### Issue: "Failed to add account" partway through

**Cause**: Device may have been disconnected mid-provisioning.

**Solution**:
1. Reconnect YubiKey
2. Run again (reset will be re-applied, clearing partial state)
3. If stuck, manually reset via: `ykman --device <SN> oath reset --force`

---

## Advanced Usage

### Programmatic Provisioning

Export provisioning plan as JSON:

```bash
bsec 1p yubikey provision --serial 9858158 --profile Daily --dry-run --format json
```

Output contains:
- Account list with otpauth URIs
- ykman commands for automation
- Capacity validation results

### Password-Protected YubiKeys

If your YubiKey has an OATH password:
1. Store it in the YubiKey item (password field)
2. Bastion auto-fetches and uses it
3. After provisioning, OATH password is reset (cleared by `ykman oath reset`)

If needed again, update the YubiKey item and re-provision.

### Custom Touch Requirement

**Default**: All accounts require touch

**Disable touch**:
```bash
bsec 1p yubikey provision --serial 9858158 --no-touch
```

**Per-account control** (future): Tag individual accounts with `Bastion/2FA/TOTP/RequireTouch` to vary per account.

---

## Reference: 1Password Item Structure

### YubiKey Item Template

```
Title: YubiKey [Serial] [Type] (e.g., "YubiKey 9858158 (5 NFC)")
Category: Crypto Wallet

SN: 9858158
Model: YubiKey 5 NFC
Vault: Private

[TOTP Configuration]
  Profile: Daily
  Capacity: 32

[OATH Slot 1]
  Issuer: GitHub
  Username: jake.hertenstein@gmail.com

[OATH Slot 2]
  Issuer: Google
  Username: jake.hertenstein@gmail.com
  
... (populated by `bsec 1p yubikey scan --update`)
```

### Login Item Template (with TOTP)

```
Title: GitHub
Username: jake.hertenstein@gmail.com
Password: ***

[Token 1]
  Type: YubiKey
  Serial: 9858158
  OATH Name: GitHub:jake.hertenstein@gmail.com
  TOTP Enabled: yes

[OTP]
  otpauth: otpauth://totp/GitHub:jake@example.com?secret=JBSWY3DPEBLW64TMMQ======&issuer=GitHub&digits=6&period=30
```

---

## See Also

- [BASTION-TAGGING-GUIDE.md](../security/BASTION-TAGGING-GUIDE.md) - Profile tag reference
- [TOKEN-SECTION-STRUCTURE.md](../integration/TOKEN-SECTION-STRUCTURE.md) - TOTP Configuration section spec
- [YubiKey Status & Scanning](./yubikey/) - Monitoring existing provisioning
