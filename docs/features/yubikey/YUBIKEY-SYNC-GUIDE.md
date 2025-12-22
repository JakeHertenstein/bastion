# YubiKey TOTP Sync Guide

**Date**: 2025-11-21  
**Purpose**: Complete guide for syncing TOTP accounts between YubiKeys

---

## Overview

The Bastion tool provides powerful commands to sync TOTP accounts between YubiKeys, enabling easy setup of redundant YubiKeys with the same accounts.

### Key Features

✅ **Password Auto-Loading**: Automatically retrieves OATH passwords from 1Password vault  
✅ **Batch Syncing**: Copy all accounts from one YubiKey to another in one command  
✅ **Smart Conflict Resolution**: Handles existing accounts intelligently  
✅ **Idempotent Operations**: Safe to run multiple times, produces consistent results  
✅ **Progress Tracking**: Clear feedback on what's being synced  
✅ **Automatic Updates**: Keeps 1Password vault items in sync with hardware

---

## Prerequisites

### 1. Link YubiKeys to 1Password

Before syncing, your YubiKeys should be linked to their corresponding 1Password crypto wallet items. This enables automatic password retrieval.

```bash
# Link all connected YubiKeys automatically
bsec 1p link yubikey --all

# Or link a specific YubiKey
bsec 1p link yubikey 12345678

# Link with specific 1Password UUID (if auto-search doesn't work)
bsec 1p link yubikey 12345678 abc123example456def789ghi
```

**What linking does**:
- Searches 1Password for crypto wallet items with matching SN (Serial Number) field
- Stores the correlation in the cache (`yubikey-slots-cache.json`)
- Enables automatic OATH password retrieval during migrations and syncs

**1Password Item Requirements**:
- **Category**: Crypto Wallet
- **SN field**: Must contain the YubiKey serial number (e.g., "12345678")
- **password field**: Contains the OATH password for the YubiKey

### 2. Ensure Cache is Current

```bash
# Refresh the cache to see current accounts on all YubiKeys
bsec refresh yubikey
```

---

## Sync Commands

### Basic Sync: One YubiKey to Another

Copy all TOTP accounts from a source YubiKey to a target YubiKey:

```bash
# Sync from YubiKey 12345678 to YubiKey 34567890
bsec sync yubikey --from 12345678 --to 34567890
```

**What happens**:
1. Reads the cache to find all accounts on source YubiKey
2. Extracts the 1Password UUIDs for those accounts
3. Checks if target YubiKey is linked to 1Password
4. Auto-loads OATH password from 1Password (if linked)
5. Migrates each account to the target YubiKey
6. Updates the `oath_accounts` field in the target YubiKey's 1Password item
7. Updates the `yubikey_serials` field in each account's 1Password item

### Sync to All Other YubiKeys

Copy accounts to all YubiKeys except the source:

```bash
# Sync from YubiKey 12345678 to all other YubiKeys in cache
bsec sync yubikey --from 12345678 --to all
```

**Use case**: You've set up one YubiKey with all your accounts and want to copy them to your backup YubiKeys.

### Interactive Selection

If you don't specify `--to`, the tool prompts you:

```bash
bsec sync yubikey --from 12345678

# Prompts:
# Available target YubiKeys:
#   34567890 (Backup #1) - 5 accounts
#   56789012 (Backup #2) - 0 accounts
#
# Sync to which YubiKeys? (comma-separated serials or 'all') [all]:
```

---

## Password Handling

### Automatic Password Loading (Recommended)

When YubiKeys are **linked** to 1Password:

```bash
bsec sync yubikey --from 12345678 --to 34567890

# Output:
# Checking YubiKey 34567890 for password in 1Password...
#   Found 1Password UUID: abc123example456def789ghi
# ✓ Loaded OATH password from 1Password for YubiKey 34567890
# ✓ All target YubiKeys use the same OATH password (auto-loaded from 1Password)
#
# Starting sync...
```

**No password prompts!** The tool automatically uses the stored password.

### Multiple Different Passwords

If target YubiKeys have different OATH passwords stored in 1Password:

```
Warning: Target YubiKeys have different OATH passwords
Will use stored passwords per YubiKey

Syncing: 1Password
✓ Added to YubiKey 34567890
✓ Added to YubiKey 56789012
```

The tool uses the correct password for each YubiKey automatically.

### Manual Password Entry

If YubiKeys are **not linked** to 1Password:

```bash
bsec sync yubikey --from 12345678 --to 34567890

# Output:
# Warning: 1 YubiKey(s) not linked to 1Password:
#   • 34567890
#
# To link these YubiKeys and store passwords in 1Password:
#   1. Run: bsec 1p link yubikey --serial 34567890
#   2. Or run: bsec 1p link yubikey --all to link all connected YubiKeys
#
# Linking allows automatic password retrieval for future migrations.
#
# Would you like to continue with manual password entry? [Y/n]:
```

If you proceed, you'll be prompted once for the OATH password:

```
No OATH passwords found in 1Password for target YubiKeys
Enter YubiKey OATH password (or press Enter if none): 
```

**Pro tip**: Link your YubiKeys first to avoid password prompts!

---

## What Gets Updated

### 1. YubiKey Hardware

Each TOTP account is added to the target YubiKey(s) with:
- **Touch policy required**: You must physically touch the YubiKey to generate codes
- **Unique OATH name**: Uses smart disambiguation to avoid conflicts
- **Same secret**: Exact copy of the TOTP secret from 1Password

### 2. 1Password Account Items

For each synced account, the tool updates:

**`yubikey_serials` field** (appends, doesn't replace):
```
Before: 12345678
After:  12345678,34567890
```

**`yubikey_oath_name` field** (if not present):
```
Value: "1Password:user@example.com"
```

### 3. 1Password YubiKey Items

The crypto wallet item for each target YubiKey gets updated:

**`oath_accounts` field** (comma-separated list):
```
1Password:user@example.com, Gmail:user@example.com, AWS:user@example.com, ...
```

This provides visibility into what's on each YubiKey directly in 1Password.

---

## Sync Workflow Example

### Scenario: Setting Up Redundant YubiKeys

You have:
- **YubiKey 12345678** (Daily Carry) - Fully configured with 17 accounts
- **YubiKey 34567890** (Backup #1) - Empty
- **YubiKey 56789012** (Backup #2) - Empty

**Goal**: Copy all 17 accounts to both backup YubiKeys.

#### Step 1: Ensure Cache is Current

```bash
bsec refresh yubikey
```

#### Step 2: Link YubiKeys (if not already done)

```bash
bsec 1p link yubikey --all
```

This searches 1Password for items with matching serial numbers and links them.

#### Step 3: Sync to All Backups

```bash
bsec sync yubikey --from 12345678 --to all
```

**Output**:
```
Found 17 accounts on source YubiKey 12345678

Will sync 17 accounts to 2 YubiKey(s)
  → 34567890 (Backup #1)
  → 56789012 (Backup #2)

Proceed with sync? [Y/n]: y

Starting sync...

✓ Loaded OATH password from 1Password for YubiKey 34567890
✓ Loaded OATH password from 1Password for YubiKey 56789012
✓ All target YubiKeys use the same OATH password (auto-loaded from 1Password)

Will migrate 17 unique accounts

Syncing: 1Password
✓ 1Password
Syncing: Gmail
✓ Gmail
[... 15 more accounts ...]

Sync complete: 17/17 accounts synced

Updating YubiKey crypto wallet items...
  Checking YubiKey 34567890...
    Found 17 OATH accounts in cache
✓ Updated YubiKey 34567890 crypto wallet with 17 OATH accounts
  Checking YubiKey 56789012...
    Found 17 OATH accounts in cache
✓ Updated YubiKey 56789012 crypto wallet with 17 OATH accounts
```

#### Step 4: Verify

Check the 1Password items:

1. **Each account** (e.g., "1Password") now has:
   - `yubikey_serials = "12345678,34567890,56789012"`

2. **Each YubiKey crypto wallet item** now has:
   - `oath_accounts = "1Password:user@example.com, Gmail:user@example.com, ..."`

---

## Troubleshooting

### "Source YubiKey not found in cache"

```bash
bsec refresh yubikey
```

The source YubiKey must be in the cache. Connect it and refresh.

### "YubiKey not linked to 1Password"

```bash
bsec 1p link yubikey --serial 34567890
```

Or update the 1Password crypto wallet item to include the serial number in the SN field.

### "No 1Password linked accounts found on YubiKey"

The accounts on the source YubiKey must have been migrated using the Bastion tool (not added manually). Only accounts with 1Password UUID mappings can be synced.

To check which accounts have mappings:
```bash
# View the cache
cat yubikey-slots-cache.json | grep -A 5 "12345678"
```

### Duplicate Accounts on Target

The sync command is **idempotent** - it detects existing accounts using:
1. The `yubikey_oath_name` custom field in 1Password
2. UUID mapping in the cache
3. Direct OATH name matching

If an account already exists, it's replaced with the updated version. Safe to run multiple times!

### Different OATH Passwords

If your YubiKeys have different OATH passwords:
1. Link each YubiKey to its 1Password item
2. Ensure the password field is set correctly in each item
3. The sync command will use the appropriate password for each YubiKey

---

## Advanced Usage

### Sync Specific Accounts Only

The sync command copies **all** accounts from the source. If you want to sync specific accounts:

```bash
# Migrate individual accounts
bsec 1p migrate yubikey "Account Name"

# When prompted for target YubiKeys, select the ones you want
```

### Re-sync After Changes

If you've updated TOTP secrets in 1Password:

```bash
# Re-sync will update existing accounts
bsec sync yubikey --from 12345678 --to all
```

The tool detects existing accounts and replaces them with updated versions.

### Audit Slot Usage

After syncing, check how many slots are used:

```bash
bsec 1p audit yubikey
```

Output shows slot usage per YubiKey (32 max for OATH-TOTP).

### Clean Stale Cache Entries

If you've manually removed accounts from YubiKeys:

```bash
bsec clean yubikey
```

This syncs the cache with actual hardware state.

---

## Field Reference

### 1Password Custom Fields

These fields are automatically created/updated by the Bastion tool:

#### In Account Items (Login category)

**`yubikey_oath_name`** (text):
- Format: `Issuer:AccountName`
- Example: `1Password:user@example.com`
- Purpose: Exact OATH account name as stored on YubiKey
- Created by: `bsec 1p migrate yubikey`
- Used for: Precise matching during re-migration and syncing

**`yubikey_serials`** (text):
- Format: `serial1,serial2,serial3` (comma-separated)
- Example: `12345678,34567890,56789012`
- Purpose: Tracks which YubiKeys have this TOTP
- Created by: `bsec 1p migrate yubikey`
- Updated by: `bsec sync yubikey` (appends new serials)
- Used for: Tracking redundancy and slot usage

#### In YubiKey Items (Crypto Wallet category)

**`SN`** (text):
- Format: `12345678` (just the serial number)
- Example: `12345678`
- Purpose: Links cache to 1Password item
- Created by: User (manual)
- Used for: Auto-linking via `bsec 1p link yubikey --all`

**`oath_accounts`** (text):
- Format: `Name1, Name2, Name3` (comma-separated)
- Example: `1Password:user@example.com, Gmail:user@example.com`
- Purpose: Shows all OATH accounts on this YubiKey
- Created by: `bsec 1p migrate yubikey` or `bsec sync yubikey`
- Updated by: Both commands after each operation
- Used for: Visibility into YubiKey contents from 1Password

**`password`** (password):
- Format: Plain text password
- Purpose: OATH password for this YubiKey
- Created by: User (manual)
- Used for: Auto-loading during migrations and syncs

---

## Best Practices

### 1. Link Before Syncing
Always run `bsec 1p link yubikey --all` before your first sync to enable password auto-loading.

### 2. Sync in One Direction
Pick one YubiKey as the "source of truth" and sync from it to others. Don't sync in multiple directions as this can cause confusion.

### 3. Verify After Syncing
Check the `oath_accounts` field in 1Password to confirm all accounts were added.

### 4. Keep Cache Fresh
Run `bsec refresh yubikey` regularly, especially after manually adding/removing accounts.

### 5. Test TOTP Codes
After syncing, generate a test code from each YubiKey to ensure it's working:
```bash
ykman --device 34567890 oath accounts code "1Password:user@example.com"
```

### 6. Document YubiKey Roles
Use clear role names when linking YubiKeys:
- "Daily Carry"
- "Backup #1"
- "Backup #2"
- "Office Drawer"

This makes it clear which YubiKey is which in audit outputs.

---

## Related Commands

```bash
# Link YubiKeys to 1Password
bsec 1p link yubikey --all

# Refresh cache
bsec refresh yubikey

# Migrate single account
bsec 1p migrate yubikey "Account Name"

# Audit slot usage
bsec 1p audit yubikey

# Clean cache
bsec clean yubikey

# View help
bsec sync --help
```

---

## Summary

The `bsec sync yubikey` command makes it trivial to set up redundant YubiKeys:

1. **Set up one YubiKey** with all your accounts
2. **Link all YubiKeys** to 1Password: `bsec 1p link yubikey --all`
3. **Sync to backups**: `bsec sync yubikey --from SOURCE --to all`
4. **Done!** All YubiKeys now have the same TOTP accounts

With automatic password loading and smart conflict resolution, syncing is fast and error-free.
